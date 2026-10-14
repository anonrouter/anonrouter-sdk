// Owner-signed release policy v3: the GCP-native gateway approval path.
//
// The owner (two Ed25519 custodian keys, usb then laptop) signs a release
// policy once per release or revocation. It has NO expiry: it stays valid until
// a higher sequence supersedes it. This module verifies such a policy against
// an owner root the caller pins, keeps a monotonic checkpoint (no lower
// sequence, no fork at one sequence, no revocation reversal) and turns it into
// a gcp-tdx-native gateway policy whose exact register tuples the verifier
// matches against the connection-bound quote.
//
// Transport is untrusted. Keys never come from the feed. When the feed is
// unreachable the last verified policy serves for at most one hour, then every
// resolve refuses until the feed answers again.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, hexToBytes, utf8Decode, utf8Encode } from "../bytes.js";
import type { GatewayPolicyStateStore } from "./authority.js";
import { canonicalGatewayOrigin } from "./binding.js";
import {
  assertGatewayPlatformSecurityFloor, GatewayPolicyError, validateGatewayMeasuredTupleV3,
  MAX_RELEASE_V3_REVOKED_TUPLES, MAX_RELEASE_V3_TUPLES,
  type GatewayMeasuredTupleV3, type GatewayMeasurementPolicy
} from "./policy.js";
import {
  canonicalReleaseBytes, ReleaseCanonicalError, releaseDigestHex, releasePolicySha256, releaseTupleDigest,
  RELEASE_V3_DIGEST_PROTOCOL
} from "./release-v3-canonical.js";
import { createDefaultGatewayPolicyStateStore } from "./state.js";
import productionAuthority from "./release-policy-v3-authority.json" with { type: "json" };

/** Independently packaged owner roots and publication location. No image pins. */
export function packagedReleasePolicyV3Authority(): { trust: ReleasePolicyV3Trust; url: string; origins: string[] } {
  return structuredClone(productionAuthority) as { trust: ReleasePolicyV3Trust; url: string; origins: string[] };
}

export const RELEASE_V3_ENVELOPE_PROTOCOL = "anonrouter-content-release-envelope-v3";
export const RELEASE_V3_SIGNATURE_DOMAIN_PREFIX = "anonrouter-content-release-v3/authority/";
export const RELEASE_V3_POLICY_KIND = "content-node-release-policy";
export const RELEASE_V3_ROLES = ["release-policy", "generation"] as const;
export type ReleaseV3Role = (typeof RELEASE_V3_ROLES)[number];
/** Fixed signer order: both required, usb first. */
export const RELEASE_V3_KEY_IDS = ["custodian.prod.usb", "custodian.prod.laptop"] as const;
/** Longest a cached policy may serve while the feed is unreachable. */
export const MAX_RELEASE_V3_OFFLINE_MS = 3_600_000;
export const MAX_RELEASE_V3_REFRESH_MS = 300_000;
/** 16 tuples plus 4096 revoked tuples and 4096 revoked generations fit easily. */
export const MAX_RELEASE_POLICY_V3_BYTES = 1_048_576;

export type ReleasePolicyV3RefusalCode =
  | "contract_invalid" | "trust_invalid" | "wrong_owner_root" | "wrong_group" | "wrong_role"
  | "signature_invalid" | "wrong_deployment" | "revoked_tuple_approved" | "policy_rollback"
  | "policy_fork" | "revocation_reversed" | "unauthorized_origin" | "feed_unavailable"
  | "cache_stale" | "cancelled";

/** Every v3 refusal. Fail-closed: callers never fall back to another policy. */
export class ReleasePolicyV3Error extends GatewayPolicyError {
  readonly code: ReleasePolicyV3RefusalCode;
  constructor(code: ReleasePolicyV3RefusalCode, detail?: string) {
    super(`release policy v3: ${code}${detail ? ` (${detail})` : ""}`);
    this.name = "ReleasePolicyV3Error";
    this.code = code;
  }
}

function refuse(code: ReleasePolicyV3RefusalCode, detail?: string): never {
  throw new ReleasePolicyV3Error(code, detail);
}

export interface ReleaseOwnerKeyV3 {
  keyId: (typeof RELEASE_V3_KEY_IDS)[number];
  /** Raw Ed25519 public key, 64 lowercase hex. */
  publicKey: string;
}

/**
 * The owner root a client pins. `ownerRootSha256` is recomputed from the other
 * fields and must match, so a typo in any of them refuses instead of trusting
 * a different root.
 */
export interface ReleasePolicyV3Trust {
  deploymentId: string;
  groupId: string;
  /** Exactly [usb, laptop], distinct keys. */
  keys: ReleaseOwnerKeyV3[];
  /** digest("release-owner-root", {deploymentId, groupId, keys}). */
  ownerRootSha256: string;
  /** Lowest sequence ever accepted (the measured image minimum, or higher). */
  minimumPolicySequence: number;
}

/** What a client must hold to judge the next policy. */
export interface ReleasePolicyV3Checkpoint {
  sequence: number;
  policySha256: string;
  /** The held policy's revoked tuple digests; a successor must keep them all. */
  revokedTuples: readonly string[];
}

/** A release policy whose two owner signatures verified against the pinned root. */
export interface VerifiedReleasePolicyV3 {
  /** Optional signed tightening: require a quote-bound GCE machine identity. */
  requireGcePzid?: boolean;
  deploymentId: string;
  groupId: string;
  ownerRootSha256: string;
  sequence: number;
  issuedAtMs: number;
  policySha256: string;
  tuples: (GatewayMeasuredTupleV3 & { tupleDigest: string })[];
  revokedTuples: string[];
  revokedGenerations: string[];
  minimumGenerationRevision: number;
  maxEvidenceAgeMs: number;
  tcbStatus: "UpToDate";
}

const IDENTIFIER = /^[a-z0-9][a-z0-9_.-]{0,127}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function record(value: unknown, code: ReleasePolicyV3RefusalCode = "contract_invalid"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return refuse(code, "expected object");
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return refuse(code, "expected plain object");
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, names: readonly string[], code: ReleasePolicyV3RefusalCode = "contract_invalid"): void {
  const keys = Object.keys(value);
  if (keys.length !== names.length || keys.some((key) => !names.includes(key))) refuse(code, "unexpected or missing fields");
}
function safeInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER, code: ReleasePolicyV3RefusalCode = "contract_invalid"): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) return refuse(code, "invalid integer");
  return value;
}
function identifier(value: unknown, code: ReleasePolicyV3RefusalCode = "contract_invalid"): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) return refuse(code, "invalid identifier");
  return value;
}
function hex32List(value: unknown, maximum: number): string[] {
  if (!Array.isArray(value) || value.length > maximum) return refuse("contract_invalid", "invalid digest list");
  return value.map((entry) => {
    if (typeof entry !== "string" || !HEX32.test(entry)) return refuse("contract_invalid", "invalid digest");
    return entry;
  });
}

/** ownerRootSha256 = digest("release-owner-root", {deploymentId, groupId, keys}). */
export function releaseOwnerRootSha256(input: { deploymentId: string; groupId: string; keys: readonly ReleaseOwnerKeyV3[] }): string {
  try {
    return releaseDigestHex("release-owner-root", {
      deploymentId: input.deploymentId,
      groupId: input.groupId,
      keys: input.keys.map((key) => ({ keyId: key.keyId, publicKey: key.publicKey }))
    });
  } catch (error) {
    if (error instanceof ReleaseCanonicalError) return refuse("trust_invalid", "owner root fields are not canonical");
    throw error;
  }
}

/** tupleDigest = digest("measured-tuple", tuple without tupleId). */
export { releaseTupleDigest };

export function validateReleasePolicyV3Trust(trust: ReleasePolicyV3Trust): void {
  const t = record(trust, "trust_invalid");
  fields(t, ["deploymentId", "groupId", "keys", "ownerRootSha256", "minimumPolicySequence"], "trust_invalid");
  identifier(t.deploymentId, "trust_invalid"); identifier(t.groupId, "trust_invalid");
  safeInteger(t.minimumPolicySequence, 1, Number.MAX_SAFE_INTEGER, "trust_invalid");
  if (!Array.isArray(t.keys) || t.keys.length !== RELEASE_V3_KEY_IDS.length) refuse("trust_invalid", "expected the usb and laptop keys");
  (t.keys as unknown[]).forEach((entry, index) => {
    const key = record(entry, "trust_invalid"); fields(key, ["keyId", "publicKey"], "trust_invalid");
    if (key.keyId !== RELEASE_V3_KEY_IDS[index] || typeof key.publicKey !== "string" || !HEX32.test(key.publicKey)) {
      refuse("trust_invalid", "keys must be usb then laptop, 32-byte lowercase hex");
    }
  });
  if (trust.keys[0]!.publicKey === trust.keys[1]!.publicKey) refuse("trust_invalid", "owner keys must be distinct");
  if (typeof t.ownerRootSha256 !== "string" || !HEX32.test(t.ownerRootSha256)
    || releaseOwnerRootSha256(trust) !== t.ownerRootSha256) refuse("wrong_owner_root", "pinned owner root does not match its keys");
}

/**
 * msg = SHA256(ASCII(prefix + role + "\0") || canonical({groupId, ownerRootSha256, payload})).
 * Both owner signatures cover these same 32 bytes.
 */
export function releaseEnvelopeV3Message(role: ReleaseV3Role, groupId: string, ownerRootSha256: string, payload: unknown): Uint8Array {
  let body: Uint8Array;
  try { body = canonicalReleaseBytes({ groupId, ownerRootSha256, payload }); }
  catch (error) {
    if (error instanceof ReleaseCanonicalError) return refuse("contract_invalid", "payload is not canonical");
    throw error;
  }
  return sha256(concatBytes(utf8Encode(`${RELEASE_V3_SIGNATURE_DOMAIN_PREFIX}${role}\0`), body));
}

/**
 * Verify an envelope's protocol, role, group, owner root and BOTH signatures in
 * the fixed order, and return its payload. Never accepts a v1/v2 envelope.
 */
export function verifyReleaseEnvelopeV3(envelope: unknown, trust: ReleasePolicyV3Trust, role: ReleaseV3Role): unknown {
  validateReleasePolicyV3Trust(trust);
  if (!RELEASE_V3_ROLES.includes(role)) refuse("wrong_role");
  const e = record(envelope);
  fields(e, ["protocol", "role", "groupId", "ownerRootSha256", "payload", "signatures"]);
  if (e.protocol !== RELEASE_V3_ENVELOPE_PROTOCOL) refuse("contract_invalid", "not a release envelope v3");
  if (e.role !== role) refuse("wrong_role");
  if (e.groupId !== trust.groupId) refuse("wrong_group");
  if (e.ownerRootSha256 !== trust.ownerRootSha256) refuse("wrong_owner_root");
  if (!Array.isArray(e.signatures) || e.signatures.length !== RELEASE_V3_KEY_IDS.length) refuse("signature_invalid", "exactly two signatures are required");
  const message = releaseEnvelopeV3Message(role, trust.groupId, trust.ownerRootSha256, e.payload);
  (e.signatures as unknown[]).forEach((entry, index) => {
    const signature = record(entry); fields(signature, ["keyId", "signature"]);
    const key = trust.keys[index]!;
    if (signature.keyId !== key.keyId || typeof signature.signature !== "string" || !HEX64.test(signature.signature)) {
      refuse("signature_invalid", "signers must be usb then laptop with 64-byte lowercase hex signatures");
    }
    let valid = false;
    try {
      valid = ed25519.verify(hexToBytes(signature.signature as string), message, hexToBytes(key.publicKey), { zip215: false });
    } catch {
      valid = false;
    }
    if (!valid) refuse("signature_invalid", `${key.keyId} signature does not verify`);
  });
  return e.payload;
}

const PAYLOAD_FIELDS = ["protocol", "kind", "deploymentId", "sequence", "issuedAtMs", "tuples", "revokedTuples",
  "revokedGenerations", "minimumGenerationRevision", "maxEvidenceAgeMs", "tcbStatus"];

/**
 * Verify a `release-policy` envelope and, when a checkpoint is held, that this
 * policy may follow it. Pure: no clock, no network, no storage.
 */
export function verifyReleasePolicyV3(
  envelope: unknown, trust: ReleasePolicyV3Trust, previous?: ReleasePolicyV3Checkpoint
): VerifiedReleasePolicyV3 {
  const payload = verifyReleaseEnvelopeV3(envelope, trust, "release-policy");
  const p = record(payload);
  fields(p, p.requireGcePzid === undefined ? PAYLOAD_FIELDS : [...PAYLOAD_FIELDS, "requireGcePzid"]);
  if (p.requireGcePzid !== undefined && typeof p.requireGcePzid !== "boolean") refuse("contract_invalid", "requireGcePzid must be boolean");
  if (p.protocol !== RELEASE_V3_DIGEST_PROTOCOL || p.kind !== RELEASE_V3_POLICY_KIND) refuse("contract_invalid", "not a release policy");
  if (identifier(p.deploymentId) !== trust.deploymentId) refuse("wrong_deployment");
  const sequence = safeInteger(p.sequence, 1);
  const issuedAtMs = safeInteger(p.issuedAtMs, 1);
  if (!Array.isArray(p.tuples) || p.tuples.length === 0 || p.tuples.length > MAX_RELEASE_V3_TUPLES) refuse("contract_invalid", "invalid tuple count");
  const tuples = (p.tuples as unknown[]).map((entry, index) => {
    let tuple: GatewayMeasuredTupleV3;
    try { tuple = validateGatewayMeasuredTupleV3(entry, index); }
    catch (error) { return refuse("contract_invalid", error instanceof Error ? error.message : undefined); }
    return { ...tuple, tupleDigest: releaseTupleDigest(tuple) };
  });
  if (new Set(tuples.map((tuple) => tuple.tupleId)).size !== tuples.length) refuse("contract_invalid", "duplicate tupleId");
  const revokedTuples = hex32List(p.revokedTuples, MAX_RELEASE_V3_REVOKED_TUPLES);
  for (let index = 1; index < revokedTuples.length; index++) {
    if (revokedTuples[index - 1]! >= revokedTuples[index]!) refuse("contract_invalid", "revokedTuples must be sorted and unique");
  }
  const revokedGenerations = hex32List(p.revokedGenerations, 4096);
  const minimumGenerationRevision = safeInteger(p.minimumGenerationRevision, 1);
  const maxEvidenceAgeMs = safeInteger(p.maxEvidenceAgeMs, 1_000, 300_000);
  if (p.tcbStatus !== "UpToDate") refuse("contract_invalid", "tcbStatus must be UpToDate");
  const revoked = new Set(revokedTuples);
  if (tuples.some((tuple) => revoked.has(tuple.tupleDigest))) refuse("revoked_tuple_approved");
  const policySha256 = releasePolicySha256(payload);
  checkReleasePolicyV3Successor(trust, previous, { sequence, policySha256, revokedTuples });
  return {
    deploymentId: trust.deploymentId, groupId: trust.groupId, ownerRootSha256: trust.ownerRootSha256,
    sequence, issuedAtMs, policySha256, tuples, revokedTuples, revokedGenerations, minimumGenerationRevision,
    maxEvidenceAgeMs, tcbStatus: "UpToDate",
    ...(p.requireGcePzid === undefined ? {} : { requireGcePzid: p.requireGcePzid as boolean })
  };
}

function validateCheckpoint(checkpoint: ReleasePolicyV3Checkpoint): void {
  const c = record(checkpoint); fields(c, ["sequence", "policySha256", "revokedTuples"]);
  safeInteger(c.sequence, 1);
  if (typeof c.policySha256 !== "string" || !HEX32.test(c.policySha256)) refuse("contract_invalid", "invalid checkpoint digest");
  hex32List(c.revokedTuples, MAX_RELEASE_V3_REVOKED_TUPLES);
}

/**
 * The monotonic rules: refuse a sequence below max(minimum, held), a different
 * policy at the held sequence, and a successor that drops a held revocation.
 */
export function checkReleasePolicyV3Successor(
  trust: ReleasePolicyV3Trust, previous: ReleasePolicyV3Checkpoint | undefined, next: ReleasePolicyV3Checkpoint
): void {
  if (previous !== undefined) validateCheckpoint(previous);
  const floor = Math.max(trust.minimumPolicySequence, previous?.sequence ?? 0);
  if (next.sequence < floor) refuse("policy_rollback", `sequence ${next.sequence} < ${floor}`);
  if (!previous) return;
  if (next.sequence === previous.sequence) {
    if (next.policySha256 !== previous.policySha256) refuse("policy_fork", `sequence ${next.sequence}`);
    return;
  }
  const kept = new Set(next.revokedTuples);
  if (previous.revokedTuples.some((digest) => !kept.has(digest))) refuse("revocation_reversed");
}

/** The fixed gcp-tdx-native floor; only tuples, revocations and evidence age come from the policy. */
export function releasePolicyV3GatewayPolicy(verified: VerifiedReleasePolicyV3, origins: readonly string[]): GatewayMeasurementPolicy {
  const policy: GatewayMeasurementPolicy = {
    platformKind: "gcp-tdx-native",
    releasePolicyV3: {
      ownerRootSha256: verified.ownerRootSha256,
      deploymentId: verified.deploymentId,
      sequence: verified.sequence,
      policySha256: verified.policySha256,
      tuples: verified.tuples.map(({ tupleDigest: _digest, ...tuple }) => structuredClone(tuple)),
      revokedTuples: [...verified.revokedTuples],
      ...(verified.requireGcePzid === undefined ? {} : { requireGcePzid: verified.requireGcePzid })
    },
    source: `anonrouter-release-policy-v3:${verified.deploymentId}:${verified.policySha256}`,
    version: `release-policy-v3/${verified.sequence}`,
    origins: origins.map((origin) => canonicalGatewayOrigin(origin)),
    appIds: [],
    composeHashes: [],
    releaseIds: [],
    requireInTeeTls: true,
    requirePrivateLogs: true,
    requireDigestPinnedImages: true,
    requireHardwareVerified: true,
    acceptableTcbStatuses: [verified.tcbStatus],
    requireEvidenceExpiry: true,
    maxEvidenceAgeMs: verified.maxEvidenceAgeMs
  };
  assertGatewayPlatformSecurityFloor(policy);
  return policy;
}

/** A resolved v3 approval, shaped to fit the existing GatewayPolicySource. */
export interface VerifiedReleasePolicyV3Approval {
  format: "release-policy-v3";
  policy: GatewayMeasurementPolicy;
  release: VerifiedReleasePolicyV3;
  /** `anonrouter.release-policy-v3/<ownerRootSha256>`: the durable checkpoint key. */
  authority: string;
  sequence: number;
  /** The policy's SHA-256 (same as release.policySha256). */
  payloadSha256: string;
  /** When the feed last served this verified policy. */
  confirmedAtMs: number;
  /**
   * NOT a policy expiry (v3 has none): the instant this cached approval stops
   * being usable without a new answer from the feed, confirmedAtMs plus the
   * offline window. The client refuses at or after it.
   */
  expiresAtMs: number;
}

export interface ReleasePolicyV3SourceOptions {
  /** The pinned owner root. */
  trust?: ReleasePolicyV3Trust;
  /** https publication URL, on a host separate from every gateway origin. */
  url?: string;
  /** Gateway origins this owner root may approve. */
  origins?: string[];
  /** Feed check interval. Default 0: check on every resolve (every connection). Max 300000. */
  refreshMs?: number;
  /** Offline use of the last verified policy. Default and maximum 3600000 (one hour). */
  maxOfflineMs?: number;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  /** Durable sequence/digest checkpoint, shared with the v1 store format. */
  stateStore?: GatewayPolicyStateStore;
  /** A checkpoint carried over from earlier, e.g. a previous process. */
  checkpoint?: ReleasePolicyV3Checkpoint;
}

export interface ReleasePolicyV3Source {
  resolve(origin: string, signal?: AbortSignal, forceRefresh?: boolean): Promise<VerifiedReleasePolicyV3Approval>;
}

function validateSourceOptions(options: ReleasePolicyV3SourceOptions & { trust: ReleasePolicyV3Trust; url: string; origins: string[] }): { refreshMs: number; maxOfflineMs: number; origins: string[] } {
  validateReleasePolicyV3Trust(options.trust);
  let url: URL;
  try { url = new URL(options.url); } catch { return refuse("trust_invalid", "invalid publication URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) refuse("trust_invalid", "invalid publication URL");
  if (!Array.isArray(options.origins) || options.origins.length === 0) refuse("trust_invalid", "no gateway origins");
  const origins = options.origins.map((origin) => {
    let canonical: string;
    try { canonical = canonicalGatewayOrigin(origin); } catch { return refuse("trust_invalid", "invalid gateway origin"); }
    if (canonical !== origin || new URL(canonical).host === url.host) refuse("trust_invalid", "publication must be separate from authorized gateways");
    return canonical;
  });
  const refreshMs = safeInteger(options.refreshMs ?? 0, 0, MAX_RELEASE_V3_REFRESH_MS, "trust_invalid");
  const maxOfflineMs = safeInteger(options.maxOfflineMs ?? MAX_RELEASE_V3_OFFLINE_MS, 1, MAX_RELEASE_V3_OFFLINE_MS, "trust_invalid");
  if (options.checkpoint !== undefined) validateCheckpoint(options.checkpoint);
  return { refreshMs, maxOfflineMs, origins };
}

/**
 * Follow the owner-signed release policy feed. Only verified policies are
 * cached. A transport failure or 5xx may reuse the last verified policy until
 * `maxOfflineMs` after the feed last confirmed it; any 4xx, malformed answer,
 * bad signature, rollback, fork or revocation reversal refuses at once and never
 * falls back to the cache or to bundled pins.
 */
export function createReleasePolicyV3Source(options: ReleasePolicyV3SourceOptions = {}): ReleasePolicyV3Source {
  const defaults = packagedReleasePolicyV3Authority();
  const trust = structuredClone(options.trust ?? defaults.trust);
  const url = options.url ?? defaults.url;
  const { refreshMs, maxOfflineMs, origins } = validateSourceOptions({ ...options, trust, url, origins: options.origins ?? defaults.origins });
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const now = options.now ?? Date.now;
  const stateStore = options.stateStore ?? createDefaultGatewayPolicyStateStore();
  const authority = `anonrouter.release-policy-v3/${trust.ownerRootSha256}`;
  let checkpoint: ReleasePolicyV3Checkpoint | undefined = options.checkpoint && structuredClone(options.checkpoint);
  let cached: { release: VerifiedReleasePolicyV3; confirmedAtMs: number } | undefined;
  let tail = Promise.resolve();

  async function fetchEnvelope(signal?: AbortSignal): Promise<unknown | "offline"> {
    let response: Response;
    try {
      response = await fetchImpl(url, { method: "GET", credentials: "omit", redirect: "error", cache: "no-store",
        headers: { accept: "application/json" },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000) });
    } catch {
      if (signal?.aborted) return refuse("cancelled");
      return "offline";
    }
    if (!response.ok) {
      if (response.status >= 500) return "offline";
      return refuse("feed_unavailable", `status ${response.status}`);
    }
    if (!response.body) return refuse("feed_unavailable", "empty publication");
    const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) {
        const item = await reader.read(); if (item.done) break;
        size += item.value.length;
        if (size > MAX_RELEASE_POLICY_V3_BYTES) return refuse("contract_invalid", "publication too large");
        chunks.push(item.value);
      }
    } catch {
      if (signal?.aborted) return refuse("cancelled");
      return "offline";
    } finally { await reader.cancel().catch(() => {}); }
    try { return JSON.parse(utf8Decode(concatBytes(...chunks))); }
    catch { return refuse("contract_invalid", "invalid publication JSON"); }
  }

  return { async resolve(origin, signal, forceRefresh = false) {
    let unlock!: () => void;
    const prior = tail; tail = new Promise<void>((resolve) => { unlock = resolve; });
    await prior;
    try {
      if (signal?.aborted) return refuse("cancelled");
      let canonical: string;
      try { canonical = canonicalGatewayOrigin(origin); } catch { return refuse("unauthorized_origin"); }
      if (!origins.includes(canonical)) refuse("unauthorized_origin");
      if (forceRefresh || !cached || now() - cached.confirmedAtMs >= refreshMs) {
        const envelope = await fetchEnvelope(signal);
        if (envelope === "offline") {
          if (!cached) refuse("feed_unavailable", "no verified policy is cached");
        } else {
          const release = verifyReleasePolicyV3(envelope, trust, checkpoint);
          await stateStore.observe(authority, { sequence: release.sequence, payloadSha256: release.policySha256 });
          checkpoint = { sequence: release.sequence, policySha256: release.policySha256, revokedTuples: [...release.revokedTuples] };
          cached = { release, confirmedAtMs: now() };
        }
      }
      const held = cached!;
      if (now() - held.confirmedAtMs >= maxOfflineMs) refuse("cache_stale", "the feed has not confirmed the policy within the offline window");
      const release = structuredClone(held.release);
      return {
        format: "release-policy-v3",
        policy: releasePolicyV3GatewayPolicy(release, origins),
        release,
        authority,
        sequence: release.sequence,
        payloadSha256: release.policySha256,
        confirmedAtMs: held.confirmedAtMs,
        expiresAtMs: held.confirmedAtMs + maxOfflineMs
      };
    } finally { unlock(); }
  } };
}
