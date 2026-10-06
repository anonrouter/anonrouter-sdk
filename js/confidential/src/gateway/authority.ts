// Independent release approval. Transport is untrusted; only packaged/caller
// roots authorize measurements. This never trusts keys supplied by the feed.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8Encode, utf8Decode } from "../bytes.js";
import { canonicalGatewayOrigin } from "./binding.js";
import { GatewayPolicyError, loadGatewayPolicy, type GatewayMeasurementPolicy } from "./policy.js";
import roots from "./gateway-policy-authority.json" with { type: "json" };
import { createDefaultGatewayPolicyStateStore } from "./state.js";

export const GATEWAY_POLICY_DOMAIN = "anonrouter.gateway-policy-signature/v1\n";
export const MAX_GATEWAY_POLICY_BYTES = 262_144;
export interface GatewayPolicyAuthority {
  schema: string;
  enabled: boolean;
  authority: string;
  url: string;
  origins: string[];
  threshold: number;
  keys: Record<string, string>;
  minSequence: number;
  maxLifetimeMs: number;
  refreshMs: number;
  maxStaleMs: number;
}
export interface GatewayPolicyCheckpoint { sequence: number; payloadSha256: string }
/** Implement atomic, durable compare-and-set for protection across restarts.
 * The session checkpoint is always enforced as well. A failed store refuses.
 * Never store credentials, prompts or inference content here. */
export interface GatewayPolicyStateStore {
  observe(authority: string, checkpoint: GatewayPolicyCheckpoint): Promise<void>;
}
export interface VerifiedGatewayPolicy extends GatewayPolicyCheckpoint {
  policy: GatewayMeasurementPolicy;
  authority: string;
  manifestSha256: string;
  issuedAtMs: number;
  expiresAtMs: number;
  acceptedKeyIds: string[];
}
export interface GatewayPolicySource {
  resolve(origin: string, signal?: AbortSignal, forceRefresh?: boolean): Promise<VerifiedGatewayPolicy>;
}
function reject(why: string): never { throw new GatewayPolicyError(`signed gateway policy: ${why}`); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return reject("expected object");
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, names: string[]): void {
  if (Object.keys(value).sort().join(",") !== names.sort().join(",")) reject("unexpected or missing fields");
}
function integer(value: unknown, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) return reject("invalid integer");
  return value;
}
/** Deliberately restricted canonical JSON: ASCII strings and safe integers.
 * This rejects duplicate keys, floats and JS/Python encoding ambiguities. */
export function canonicalGatewayPolicyJson(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(integer(value));
  if (typeof value === "string") {
    if (/[^\x00-\x7f]/.test(value)) return reject("non-ASCII string");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalGatewayPolicyJson).join(",")}]`;
  const obj = record(value);
  return `{${Object.keys(obj).sort().map(k => `${canonicalGatewayPolicyJson(k)}:${canonicalGatewayPolicyJson(obj[k])}`).join(",")}}`;
}
export function packagedGatewayPolicyAuthority(): GatewayPolicyAuthority {
  return structuredClone(roots);
}
export function validateGatewayPolicyAuthority(root: GatewayPolicyAuthority): void {
  if (root.schema !== "anonrouter.gateway-policy-authority/v1" || !root.authority || typeof root.enabled !== "boolean") reject("invalid authority");
  const url = new URL(root.url);
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) reject("invalid publication URL");
  if (!Array.isArray(root.origins) || !root.origins.length || root.origins.some(o => canonicalGatewayOrigin(o) !== o || new URL(o).host === url.host)) reject("publication must be separate from authorized gateways");
  integer(root.threshold, 2); integer(root.minSequence, 1); integer(root.maxLifetimeMs, 1); integer(root.refreshMs, 1);
  integer(root.maxStaleMs, root.refreshMs);
  if (root.maxLifetimeMs > 604_800_000 || root.refreshMs > 300_000 || root.maxStaleMs > 7_200_000) reject("excessive lifetime/refresh");
  const values = Object.values(record(root.keys));
  if (values.length < root.threshold || new Set(values).size !== values.length
    || values.some(v => typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v))) reject("invalid distinct signing keys");
}
export function assertGatewayPolicySecurityFloor(policy: GatewayMeasurementPolicy): void {
  if (!policy.requireHardwareVerified || !policy.requireInTeeTls || !policy.requirePrivateLogs
    || !policy.requireDigestPinnedImages || !policy.requireEvidenceExpiry || !policy.keyProviderId || !policy.platform
    || policy.maxEvidenceAgeMs > 300_000 || policy.acceptableTcbStatuses.length !== 1
    || policy.acceptableTcbStatuses[0] !== "UpToDate") reject("policy weakens mandatory security requirements");
}
export function verifySignedGatewayPolicy(
  envelope: unknown, root: GatewayPolicyAuthority, origin: string, nowMs: number,
  previous?: GatewayPolicyCheckpoint
): VerifiedGatewayPolicy {
  validateGatewayPolicyAuthority(root); integer(nowMs);
  const e = record(envelope); fields(e, ["schema", "payload", "signatures"]);
  if (e.schema !== "anonrouter.gateway-policy-envelope/v1" || typeof e.payload !== "string"
    || utf8Encode(e.payload).length > MAX_GATEWAY_POLICY_BYTES) reject("invalid envelope");
  let raw: Record<string, unknown>;
  try { raw = record(JSON.parse(e.payload as string)); } catch { return reject("invalid payload JSON"); }
  if (canonicalGatewayPolicyJson(raw) !== e.payload) reject("noncanonical payload");
  fields(raw, ["schema", "authority", "sequence", "issuedAtMs", "expiresAtMs", "manifestSha256", "policy"]);
  if (raw.schema !== "anonrouter.gateway-policy/v1" || raw.authority !== root.authority
    || typeof raw.manifestSha256 !== "string" || !/^[0-9a-f]{64}$/.test(raw.manifestSha256)) reject("wrong authority/manifest");
  const sequence = integer(raw.sequence, root.minSequence);
  const issuedAtMs = integer(raw.issuedAtMs); const expiresAtMs = integer(raw.expiresAtMs);
  if (issuedAtMs > nowMs || expiresAtMs <= nowMs || expiresAtMs <= issuedAtMs
    || expiresAtMs - issuedAtMs > root.maxLifetimeMs) reject("expired, future or excessive validity");
  const payloadSha256 = bytesToHex(sha256(utf8Encode(e.payload as string)));
  if (previous && (sequence < previous.sequence || (sequence === previous.sequence && payloadSha256 !== previous.payloadSha256))) reject("rollback or conflicting sequence");
  if (!Array.isArray(e.signatures) || e.signatures.length > 16) reject("invalid signatures");
  const acceptedKeyIds: string[] = [];
  for (const item of e.signatures) {
    const s = record(item); fields(s, ["keyId", "signature"]);
    if (typeof s.keyId !== "string" || !Object.hasOwn(root.keys, s.keyId) || acceptedKeyIds.includes(s.keyId)
      || typeof s.signature !== "string" || !/^[0-9a-f]{128}$/.test(s.signature)) reject("unknown/duplicate signer or malformed signature");
    if (!ed25519.verify(hexToBytes(s.signature), utf8Encode(GATEWAY_POLICY_DOMAIN + e.payload), hexToBytes(root.keys[s.keyId]!), { zip215: false })) reject("invalid signature");
    acceptedKeyIds.push(s.keyId);
  }
  if (acceptedKeyIds.length < root.threshold) reject("signature threshold not met");
  const policy = loadGatewayPolicy(raw.policy); assertGatewayPolicySecurityFloor(policy);
  const canonical = canonicalGatewayOrigin(origin);
  if (!root.origins.includes(canonical) || !policy.origins.includes(canonical)
    || policy.origins.some(o => !root.origins.includes(o))) reject("unauthorized origin");
  if (policy.source !== `anonrouter-release-manifest-sha256:${raw.manifestSha256}`) reject("manifest binding mismatch");
  return { policy, sequence, payloadSha256, authority: root.authority, manifestSha256: raw.manifestSha256, issuedAtMs, expiresAtMs, acceptedKeyIds };
}

export interface SignedGatewayPolicySourceOptions {
  authority?: GatewayPolicyAuthority;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
  stateStore?: GatewayPolicyStateStore;
  checkpoint?: GatewayPolicyCheckpoint;
}
/** Cache only verified approvals. Transport failures may use an unexpired cached
 * approval; bad signatures/rollback/security downgrades always fail closed.
 * Never falls back to bundled measurements after selecting this source. */
export function createSignedGatewayPolicySource(options: SignedGatewayPolicySourceOptions = {}): GatewayPolicySource {
  const root = structuredClone(options.authority ?? packagedGatewayPolicyAuthority());
  validateGatewayPolicyAuthority(root);
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const now = options.now ?? Date.now;
  const stateStore = options.stateStore ?? createDefaultGatewayPolicyStateStore();
  let checkpoint = options.checkpoint && { ...options.checkpoint };
  let cached: { envelope: unknown; refreshedAt: number } | undefined;
  let tail = Promise.resolve();
  return { async resolve(origin, signal, forceRefresh = false) {
    let unlock!: () => void;
    const prior = tail; tail = new Promise<void>(r => { unlock = r; });
    await prior;
    try {
      if (signal?.aborted) return reject("update cancelled");
      const time = now(); let envelope: unknown = cached?.envelope;
      let refreshedAt = cached?.refreshedAt ?? 0;
      if (forceRefresh || !cached || time - cached.refreshedAt >= root.refreshMs) {
        let response: Response;
        try {
          response = await fetchImpl(root.url, { method: "GET", credentials: "omit", redirect: "error", cache: "no-store",
            headers: { accept: "application/json" }, signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000) });
        } catch {
          if (signal?.aborted) return reject("update cancelled");
          if (!cached) return reject("publication unavailable");
          response = new Response(null, { status: 503 });
        }
        if (response.ok) {
          if (!response.body) return reject("empty publication");
          const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
          try {
            for (;;) { const item = await reader.read(); if (item.done) break;
              size += item.value.length; if (size > MAX_GATEWAY_POLICY_BYTES) return reject("publication too large"); chunks.push(item.value); }
          } finally { await reader.cancel(); }
          const bytes = new Uint8Array(size); let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
          try { envelope = JSON.parse(utf8Decode(bytes)); } catch { return reject("invalid publication JSON"); }
          refreshedAt = now();
        } else if (!cached || response.status < 500) return reject("publication unavailable");
        // A refresh does not extend signed expiry. Verification below always
        // rechecks time and sequence, including on cached or offline answers.
      }
      if (now() - refreshedAt > root.maxStaleMs) return reject("publication cache too stale");
      const verified = verifySignedGatewayPolicy(envelope, root, origin, now(), checkpoint);
      await stateStore.observe(root.authority, { sequence: verified.sequence, payloadSha256: verified.payloadSha256 });
      checkpoint = { sequence: verified.sequence, payloadSha256: verified.payloadSha256 };
      cached = { envelope: structuredClone(envelope), refreshedAt };
      return verifySignedGatewayPolicy(envelope, root, origin, now(), checkpoint);
    } finally { unlock(); }
  } };
}
