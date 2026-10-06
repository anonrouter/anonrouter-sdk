// SDK port of NEAR AI's RELEASE AUTHORITY check. Mirrors
// src/providers/attestation/authority/{near,github,dstackImage,dstackOnchain,
// githubReleases,pythonJson}.ts and src/gateway/eventLog.ts (replay) using only
// Noble hashes and Web-platform primitives. The browser never trusts the
// gateway's verdict alone: before encrypting to a NEAR enclave it re-checks
// that the TD runs what NEAR PUBLISHES, from the same evidence and the
// collateral the worker attached (`anonrouter_release_collateral`):
//
//   base image    MRTD/RTMR0-2 = registers of dstack's published image named by
//                 the replayed RTMR3 "os-image-hash" event;
//   boot compose  measured (MRCONFIGID, replayed compose-hash), registered on
//                 NEAR's on-chain KMS registry, pinning compose-manager to
//                 github.com/nearai/cvm-compose-files;
//   manager       every compose-manager image that ran and the boot compose's
//                 launcher are nearai/compose-manager production releases;
//   runtime       every compose file run since boot is published in the
//                 official repository with the hash the TD logged (a second
//                 quote binds that log and this nonce).
//
// What the browser cannot re-check by itself is stated as residual trust:
// GitHub's tag/branch answers, the release notes and the chain RPC reach it
// through the attested content plane's fetch layer.
//
// Every function throws ConfidentialError on a failure; none returns a partial pass.

import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8Encode } from "../bytes.js";
import { ConfidentialError } from "../errors.js";
import { hexEqual } from "./crypto.js";
import { parseTdxQuote, type ParsedTdxQuote } from "./tdx.js";
export interface NearReleaseAuthorityPolicy {
  authority: "near-compose-manager-github/v1";
  composeRepository: string;
  maxPublicationAgeMs: number;
  image: { authority: "dstack-published-os-images/v1"; allowPrerelease: boolean };
  kms: { chainId: number; kms: string };
  composeManagerRepository: string;
}
export function isNearReleaseAuthorityPolicy(value: unknown): value is NearReleaseAuthorityPolicy {
  return Boolean(value && typeof value === "object"
    && (value as NearReleaseAuthorityPolicy).authority === "near-compose-manager-github/v1");
}

export const RELEASE_COLLATERAL_FIELD = "anonrouter_release_collateral";

interface EventEntry {
  imr: number;
  event_type: number;
  digest: string;
  event: string;
  event_payload: string;
  preimage?: string;
}

interface PublishedFile { commit: string; path: string; sha256: string | null }
interface GithubPublication {
  v: number;
  repository: string;
  fetchedAtMs: number;
  defaultBranch: string;
  defaultBranchHead: string;
  tags: Record<string, string>;
  defaultBranchAncestors: string[];
  files: PublishedFile[];
}
interface ReleaseImages { v: number; repository: string; fetchedAtMs: number; images: Array<{ release: string; component: string; digest: string }> }
interface OnchainRecord {
  v: number; chainId: number; kms: string; blockNumber: number; fetchedAtMs: number;
  appId: string; appRegistered: boolean; composeHash: string; composeHashAllowed: boolean;
  osImageHash: string; osImageAllowed: boolean;
}
interface ImageRecord {
  osImageHash: string; image: string; prerelease: boolean; isDev: boolean;
  measurements: Array<{ mrtd: string; rtmr0: string; rtmr1: string; rtmr2: string }>;
}
interface ReleaseCollateral {
  github?: GithubPublication[];
  githubReleases?: ReleaseImages[];
  dstackImages?: ImageRecord[];
  onchain?: OnchainRecord[];
}

function fail(message: string): never {
  throw new ConfidentialError("measurement_untrusted", message);
}

// --- dstack event log -------------------------------------------------------

function parseEvents(raw: unknown): EventEntry[] {
  let value = raw;
  if (typeof value === "string") {
    try { value = JSON.parse(value); } catch { fail("The enclave event log is not valid JSON."); }
  }
  if (!Array.isArray(value) || value.length > 4096) fail("The enclave event log is missing or oversized.");
  return (value as Array<Record<string, unknown>>).map((entry) => {
    const imr = entry?.imr;
    if (typeof imr !== "number" || !Number.isInteger(imr) || imr < 0 || imr > 3) fail("The enclave event log is malformed.");
    return {
      imr,
      event_type: typeof entry.event_type === "number" ? entry.event_type : -1,
      digest: typeof entry.digest === "string" ? entry.digest.toLowerCase() : "",
      event: typeof entry.event === "string" ? entry.event : "",
      event_payload: typeof entry.event_payload === "string" ? entry.event_payload.toLowerCase() : "",
      preimage: typeof entry.preimage === "string" ? entry.preimage.toLowerCase() : undefined
    };
  });
}

function rtmr3Digest(event: EventEntry): string | null {
  if (!/^[0-9a-f]*$/.test(event.event_payload) || event.event_payload.length % 2 !== 0) return null;
  if (event.preimage !== undefined) {
    if (!/^[0-9a-f]+$/.test(event.preimage) || event.preimage.length % 2 !== 0) return null;
    const bytes = hexToBytes(event.preimage);
    if (bytesToHex(sha384(bytes)) !== event.digest) return null;
    try {
      const decoded = JSON.parse(new TextDecoder().decode(bytes)) as { name?: unknown; payload?: unknown; type?: unknown };
      const payload = typeof decoded.payload === "string" ? decoded.payload.toLowerCase().replace(/^0x/, "") : null;
      return decoded.name === event.event && payload === event.event_payload
        && (decoded.type === undefined || decoded.type === event.event_type) ? event.digest : null;
    } catch {
      return null;
    }
  }
  if (event.event_type < 0) return null;
  const type = new Uint8Array(4);
  new DataView(type.buffer).setUint32(0, event.event_type >>> 0, true);
  const payload = hexToBytes(event.event_payload);
  const parts = [type, utf8Encode(":"), utf8Encode(event.event), utf8Encode(":"), payload];
  const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { joined.set(part, offset); offset += part.length; }
  const derived = bytesToHex(sha384(joined));
  return event.digest && event.digest !== derived ? null : derived;
}

function replay(events: EventEntry[]): string[] {
  const out: string[] = [];
  for (let index = 0; index < 4; index += 1) {
    let register: Uint8Array = new Uint8Array(48);
    for (const event of events.filter((e) => e.imr === index)) {
      const digest = index === 3 ? rtmr3Digest(event) ?? "ff".repeat(48) : event.digest;
      const content = new Uint8Array(48);
      content.set(hexToBytes(/^[0-9a-f]*$/.test(digest) && digest.length % 2 === 0 ? digest : "").subarray(0, 48));
      const joined = new Uint8Array(96);
      joined.set(register, 0);
      joined.set(content, 48);
      register = sha384(joined);
    }
    out.push(bytesToHex(register));
  }
  return out;
}

function singlePayload(events: EventEntry[], name: string): string | null {
  const matches = events.filter((e) => e.event === name);
  if (matches.length === 0) return null;
  if (matches.length > 1 || matches[0].imr !== 3 || rtmr3Digest(matches[0]) === null) {
    fail(`The enclave event log's "${name}" event is ambiguous or does not commit to its value.`);
  }
  return matches[0].event_payload;
}

// --- canonical action-log JSON (compose-manager: serde_json, sorted keys) -----

function canonicalJson(value: unknown, depth = 0): string | null {
  if (depth > 64) return null;
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return Number.isSafeInteger(value) ? String(value) : null;
  if (typeof value === "string") {
    let out = "\"";
    for (let i = 0; i < value.length; i += 1) {
      const unit = value.charCodeAt(i);
      const ch = value[i];
      if (ch === "\"") out += "\\\"";
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (unit === 0x08) out += "\\b";
      else if (unit === 0x0c) out += "\\f";
      else if (unit < 0x20) out += "\\u" + unit.toString(16).padStart(4, "0");
      else out += ch;
    }
    return out + "\"";
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value) {
      const encoded = canonicalJson(item, depth + 1);
      if (encoded === null) return null;
      parts.push(encoded);
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(record).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      const encoded = canonicalJson(record[key], depth + 1);
      if (encoded === null) return null;
      parts.push(`${canonicalJson(key)}:${encoded}`);
    }
    return `{${parts.join(",")}}`;
  }
  return null;
}

// --- the authority ------------------------------------------------------------

function fresh(fetchedAtMs: unknown, now: number, maxAgeMs: number): boolean {
  return typeof fetchedAtMs === "number" && now - fetchedAtMs <= maxAgeMs && fetchedAtMs - now <= 30_000;
}

function composeManagerRepository(dockerComposeFile: string): string | null {
  const values = new Set<string>();
  for (const match of dockerComposeFile.matchAll(/GITHUB_REPO\s*[=:]\s*["']?([^\s"'#]+)/g)) values.add(match[1]);
  if (values.size !== 1) return null;
  const [value] = [...values];
  const repo = value.toLowerCase().replace(/^https:\/\/github\.com\//, "").replace(/\.git$/, "").replace(/\/$/, "");
  return value.startsWith("https://github.com/") && /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9._-]{1,100}$/.test(repo) ? repo : null;
}

/**
 * Throws unless the NEAR serving TD in `document` runs what NEAR publishes.
 * `quote` is the parsed main quote; `nonce` the caller's.
 */
export function verifyNearReleaseAuthority(input: {
  document: unknown;
  quote: ParsedTdxQuote;
  nonce: string;
  now?: number;
  policy: NearReleaseAuthorityPolicy;
}): void {
  const policy = input.policy;
  const now = input.now ?? Date.now();
  const { quote, nonce } = input;
  const doc = input.document as {
    event_log?: unknown;
    info?: { tcb_info?: { app_compose?: unknown; event_log?: unknown } };
    compose_manager_attestation?: { actions?: unknown; actions_hash?: unknown; quote?: unknown };
    [RELEASE_COLLATERAL_FIELD]?: ReleaseCollateral;
  } | undefined;
  const collateral = doc?.[RELEASE_COLLATERAL_FIELD];

  // Boot compose: measured, replayed.
  const appCompose = typeof doc?.info?.tcb_info?.app_compose === "string" ? doc.info.tcb_info.app_compose : null;
  if (!appCompose) fail("The enclave did not return its boot compose.");
  const composeHash = bytesToHex(sha256(utf8Encode(appCompose)));
  if (!hexEqual(quote.mrConfigId, ("01" + composeHash).padEnd(96, "0"))) fail("The enclave's MRCONFIGID does not bind its boot compose.");
  const events = parseEvents(doc?.event_log ?? doc?.info?.tcb_info?.event_log);
  const replayed = replay(events);
  if (![quote.rtmr0, quote.rtmr1, quote.rtmr2, quote.rtmr3].every((value, index) => hexEqual(value, replayed[index]))) {
    fail("The enclave event log does not replay to its RTMRs.");
  }
  if (!hexEqual(singlePayload(events, "compose-hash"), composeHash)) fail("The measured compose hash disagrees with the boot compose.");
  const osImageHash = singlePayload(events, "os-image-hash");
  const appId = singlePayload(events, "app-id");
  if (!osImageHash || !appId) fail("The enclave event log names no image or app.");

  let dockerCompose: string;
  try {
    const manifest = JSON.parse(appCompose) as { docker_compose_file?: unknown };
    if (typeof manifest.docker_compose_file !== "string") fail("The boot compose has no docker-compose document.");
    dockerCompose = manifest.docker_compose_file;
  } catch (error) {
    if (error instanceof ConfidentialError) throw error;
    fail("The boot compose is not a dstack app-compose manifest.");
  }
  if (composeManagerRepository(dockerCompose) !== policy.composeRepository) {
    fail(`The enclave's compose-manager is not pinned to github.com/${policy.composeRepository}.`);
  }

  // Base image: registers of dstack's published image.
  const image = collateral?.dstackImages?.find((record) => record?.osImageHash === osImageHash);
  if (!image) fail("No registers computed from dstack's published image were supplied for this enclave.");
  if (image.isDev !== false || typeof image.prerelease !== "boolean" || (image.prerelease && !policy.image.allowPrerelease)) fail(`${image.image} is not an accepted published image.`);
  if (!image.measurements?.some((set) => hexEqual(set.mrtd, quote.mrTd) && hexEqual(set.rtmr0, quote.rtmr0)
    && hexEqual(set.rtmr1, quote.rtmr1) && hexEqual(set.rtmr2, quote.rtmr2))) {
    fail(`The enclave's MRTD/RTMR0-2 do not reproduce from dstack's published ${image.image}.`);
  }

  // On-chain registry.
  const onchain = collateral?.onchain?.[0];
  if (!onchain || onchain.v !== 1 || onchain.chainId !== policy.kms.chainId || onchain.kms !== policy.kms.kms
    || !fresh(onchain.fetchedAtMs, now, policy.maxPublicationAgeMs)) {
    fail("No recent on-chain authorization from the provider's KMS was supplied.");
  }
  if (onchain.appId !== `0x${appId}` || onchain.composeHash !== composeHash || onchain.osImageHash !== osImageHash
    || onchain.appRegistered !== true || onchain.composeHashAllowed !== true || onchain.osImageAllowed !== true) {
    fail("The provider's on-chain registry does not authorize this enclave's app, compose and image.");
  }

  // The compose-manager log, bound by a second quote from the same TD.
  const manager = doc?.compose_manager_attestation;
  const second = typeof manager?.quote === "string" ? parseTdxQuote(manager.quote) : null;
  if (!manager || !second || !Array.isArray(manager.actions)) fail("The enclave returned no compose-manager attestation.");
  const sameTd = hexEqual(second.mrTd, quote.mrTd) && hexEqual(second.mrConfigId, quote.mrConfigId)
    && hexEqual(second.rtmr0, quote.rtmr0) && hexEqual(second.rtmr1, quote.rtmr1)
    && hexEqual(second.rtmr2, quote.rtmr2) && hexEqual(second.rtmr3, quote.rtmr3);
  const text = canonicalJson(manager.actions);
  const actionsHash = text === null ? null : bytesToHex(sha256(utf8Encode(text)));
  if (!sameTd || second.debugEnabled || !actionsHash || !hexEqual(second.reportData.slice(0, 64), actionsHash)
    || !hexEqual(String(manager.actions_hash ?? ""), actionsHash) || !hexEqual(second.reportData.slice(64, 128), nonce)) {
    fail("The compose-manager log is not bound to this enclave and nonce.");
  }
  const actions = manager.actions as Array<Record<string, unknown>>;

  // compose-manager images: production releases.
  const releases = collateral?.githubReleases?.find((record) => record?.repository === policy.composeManagerRepository);
  if (!releases || !fresh(releases.fetchedAtMs, now, policy.maxPublicationAgeMs)) fail("No recent compose-manager release record was supplied.");
  const released = (component: string, digest: string) => releases.images.some((i) => i.component === component && i.digest === digest);
  let started = 0;
  for (const action of actions) {
    if (action.action !== "compose_manager_started") continue;
    const match = typeof action.image === "string" ? /^nearaidev\/compose-manager@(sha256:[0-9a-f]{64})$/.exec(action.image) : null;
    if (!match || !released("compose-manager", match[1])) fail("A compose-manager image that ran is not a production release.");
    started += 1;
  }
  if (started === 0) fail("The compose-manager log records no manager start.");
  for (const [component, repo] of [["compose-manager", "nearaidev\\/compose-manager"], ["compose-manager-launcher", "nearaidev\\/compose-manager-launcher"]] as const) {
    for (const match of dockerCompose.matchAll(new RegExp(`${repo}@(sha256:[0-9a-f]{64})`, "g"))) {
      if (!released(component, match[1])) fail("The boot compose names an unreleased compose-manager image.");
    }
  }

  // Runtime compose files: published in the official repository.
  const publication = collateral?.github?.find((record) => record?.repository === policy.composeRepository);
  if (!publication || publication.v !== 1 || !fresh(publication.fetchedAtMs, now, policy.maxPublicationAgeMs)) {
    fail(`No recent publication record for ${policy.composeRepository} was supplied.`);
  }
  let claims = 0;
  for (const action of actions) {
    if (typeof action.file_sha256 !== "string") continue;
    claims += 1;
    const commit = typeof action.commit === "string" ? action.commit.toLowerCase() : "";
    const path = typeof action.file === "string" ? action.file : "";
    const tag = typeof action.tag === "string" ? action.tag : null;
    const published = (tag !== null && publication.tags[tag] === commit) || publication.defaultBranchAncestors.includes(commit);
    const file = publication.files.find((entry) => entry.commit === commit && entry.path === path);
    if (!published || !file || file.sha256 === null || file.sha256 !== action.file_sha256.toLowerCase()) {
      fail(`The enclave ran a compose file the provider did not publish (${path.slice(0, 80)}).`);
    }
  }
  if (claims === 0 || !actions.some((action) => action.action === "compose_up")) fail("The compose-manager log starts no compose file.");
}

const MAX_GPU_EVIDENCE_ENTRIES = 64;
export function verifyNearGpuEvidence(raw: unknown, nonce: string): void {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new ConfidentialError("attestation_untrusted", "The enclave GPU evidence is missing.");
  }
  let document: { nonce?: unknown; evidence_list?: unknown } | null = null;
  try {
    document = JSON.parse(raw) as { nonce?: unknown; evidence_list?: unknown };
  } catch {
    throw new ConfidentialError("evidence_invalid", "The enclave GPU evidence is malformed.");
  }
  const list = document?.evidence_list;
  if (!Array.isArray(list) || list.length === 0 || list.length > MAX_GPU_EVIDENCE_ENTRIES) {
    throw new ConfidentialError("attestation_untrusted", "The enclave GPU evidence lists no GPU.");
  }
  if (!hexEqual(typeof document?.nonce === "string" ? document.nonce : null, nonce)) {
    throw new ConfidentialError("nonce_mismatch", "The enclave GPU evidence is not bound to this request's nonce.");
  }
  for (const entry of list as Array<Record<string, unknown> | null>) {
    if (typeof entry?.certificate !== "string" || entry.certificate.length === 0
      || typeof entry.evidence !== "string" || entry.evidence.length === 0) {
      throw new ConfidentialError("attestation_untrusted", "The enclave GPU evidence is incomplete.");
    }
    if (!hexEqual(typeof entry.nonce === "string" ? entry.nonce : null, nonce)) {
      throw new ConfidentialError("nonce_mismatch", "The enclave GPU evidence is not bound to this request's nonce.");
    }
  }
}

