// Byte-exact encoding for AnonRouter release policy v3 (GCP-native content
// nodes). It mirrors the server's canonical()/digest() helpers so that both
// sides derive the same signed message, owner root and tuple digests.
//
// Kept free of every other gateway module so the policy floor and the verifier
// can both use it without an import cycle. Browser-safe: noble only.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8Encode } from "../bytes.js";

/** The server's PROTOCOL constant: the prefix of every v3 digest domain. */
export const RELEASE_V3_DIGEST_PROTOCOL = "anonrouter-content-node-bootstrap-v1";

export class ReleaseCanonicalError extends Error {
  constructor() {
    super("value has no canonical release encoding");
    this.name = "ReleaseCanonicalError";
  }
}

const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/**
 * Sorted keys (UTF-16 code unit order), printable ASCII strings, non-negative
 * safe integers, plain objects and arrays, depth at most 12. Anything else
 * refuses rather than being coerced, exactly like the server's canonical().
 */
export function canonicalReleaseJson(value: unknown, depth = 0): string {
  if (depth > 12) throw new ReleaseCanonicalError();
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new ReleaseCanonicalError();
    return String(value);
  }
  if (typeof value === "string") {
    if (!PRINTABLE_ASCII.test(value)) throw new ReleaseCanonicalError();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalReleaseJson(item, depth + 1)).join(",")}]`;
  if (typeof value !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new ReleaseCanonicalError();
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => {
    const entry = record[key];
    if (entry === undefined || !PRINTABLE_ASCII.test(key)) throw new ReleaseCanonicalError();
    return `${JSON.stringify(key)}:${canonicalReleaseJson(entry, depth + 1)}`;
  }).join(",")}}`;
}

/** The canonical encoding is printable ASCII, so UTF-8 and ASCII bytes agree. */
export function canonicalReleaseBytes(value: unknown): Uint8Array {
  return utf8Encode(canonicalReleaseJson(value));
}

/** digest(domain, v) = SHA-256(ASCII(PROTOCOL + "/" + domain + "\0") || canonical(v)). */
export function releaseDigestHex(domain: string, value: unknown): string {
  return bytesToHex(sha256(concatBytes(utf8Encode(`${RELEASE_V3_DIGEST_PROTOCOL}/${domain}\0`), canonicalReleaseBytes(value))));
}

/** The ten quote registers a v3 measured tuple pins, without its label. */
export interface ReleaseMeasuredRegisters {
  mrTd: string;
  mrConfigId: string;
  mrOwner: string;
  mrOwnerConfig: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  tdAttributes: string;
  xfam: string;
}

export const RELEASE_MEASURED_REGISTER_FIELDS: readonly (keyof ReleaseMeasuredRegisters)[] = [
  "mrTd", "mrConfigId", "mrOwner", "mrOwnerConfig", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "tdAttributes", "xfam"
];

/**
 * tupleDigest = digest("measured-tuple", tuple without tupleId). Only the ten
 * register fields are encoded, so a label never changes a tuple's identity.
 */
export function releaseTupleDigest(registers: ReleaseMeasuredRegisters): string {
  const unlabeled: Record<string, string> = {};
  for (const field of RELEASE_MEASURED_REGISTER_FIELDS) unlabeled[field] = registers[field];
  return releaseDigestHex("measured-tuple", unlabeled);
}

/** SHA-256 of the canonical payload bytes: the checkpoint's policy identity. */
export function releasePolicySha256(payload: unknown): string {
  return bytesToHex(sha256(canonicalReleaseBytes(payload)));
}
