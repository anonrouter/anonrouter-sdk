// GCE "PZID": what MROWNER means on a Google Cloud C3 Intel TDX VM.
//
// On GCE C3 TDX VMs Google writes MR_OWNER = SHA-384(PZID), where PZID is the
// canonical ASCII JSON of the VM's numeric project, zone and instance id,
// exactly go-tdx-guest `gce/pzid.go` `PZIDPayload`:
//
//   {"instanceId":<uint64>,"numericalProjectId":<uint64>,"zone":"<zone>"}
//
// No spaces, keys in that order, Go `%d` numbers (no sign, no leading zero) and
// the zone through `strconv.Quote` after `validateZone` (non-empty, a-z, 0-9 and
// hyphen only, so Quote equals a plain JSON string). C4 VMs leave MR_OWNER zero.
//
// MR_OWNER therefore differs on every C3 VM, so an exact release tuple admits at
// most one C3 VM. A release policy v3 tuple may instead carry the owner-signed
// rule `mrOwnerRule: {kind: "gce-pzid", projectNumber, zones}` with the zero
// MR_OWNER placeholder. A quote then matches only with a PZID whose SHA-384 is
// the quoted MR_OWNER, whose project is the pinned one and whose zone is listed.
//
// A PZID is never trusted by itself. It comes from the host-controlled metadata
// server, and what binds it is the comparison against the hardware-quoted
// register: SHA-384 preimage resistance means a quote's MR_OWNER determines
// exactly one PZID. That is also why a PZID can travel outside report_data.
//
// Numbers travel as decimal strings: instance ids exceed 2^53.
// Mirrors the server's src/contentNodes/bootstrap/gcePzid.ts and the guest's
// native/gcp-content-guest/src/gce_pzid.rs; shared vectors in
// shared/vectors/gce-pzid.json. Browser-safe: noble only.
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8Encode } from "../bytes.js";

export const GCE_PZID_RULE_KIND = "gce-pzid" as const;
/** The 48-byte zero MR_OWNER: C4, and the placeholder a gce-pzid tuple carries. */
export const GCE_ZERO_MR_OWNER = "00".repeat(48);
/** At most this many zones in one rule (the server's bound). */
export const MAX_GCE_PZID_RULE_ZONES = 8;
/** A PZID is at most 20 + 20 + 63 characters plus its fixed text. */
export const MAX_GCE_PZID_CHARS = 256;

const U64_MAX = "18446744073709551615";
const UINT64_DIGITS = /^(?:0|[1-9][0-9]{0,19})$/;
const ZONE = /^[a-z0-9-]{1,63}$/;
const PZID = /^\{"instanceId":(0|[1-9][0-9]{0,19}),"numericalProjectId":(0|[1-9][0-9]{0,19}),"zone":"([a-z0-9-]{1,63})"\}$/;

/** The owner-signed MROWNER rule a release policy v3 tuple may carry. */
export interface GceMrOwnerRule {
  kind: typeof GCE_PZID_RULE_KIND;
  /** The numeric GCP project, canonical decimal uint64, nonzero. */
  projectNumber: string;
  /** 1..8 GCE zones, sorted ascending and unique. */
  zones: string[];
}

/** A GCE VM identity, numbers as canonical decimal strings. */
export interface GceInstance {
  projectNumber: string;
  zone: string;
  instanceId: string;
}

/** Go `%d` of a uint64: canonical decimal, no sign, no leading zero, at most 2^64-1. */
export function isGceUint64(value: unknown): value is string {
  return typeof value === "string" && UINT64_DIGITS.test(value)
    && (value.length < U64_MAX.length || value <= U64_MAX);
}

/** A nonzero uint64: GCE never assigns 0 to a project or an instance. */
export function isGcePositiveUint64(value: unknown): value is string {
  return isGceUint64(value) && value !== "0";
}

/** go-tdx-guest `validateZone`, bounded to a GCE name's 63 characters. */
export function isGceZone(value: unknown): value is string {
  return typeof value === "string" && ZONE.test(value);
}

export class GcePzidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GcePzidError";
  }
}

/**
 * Validate an `mrOwnerRule` exactly as the server's gcePzidRuleSchema does:
 * these three fields only, the gce-pzid kind, a nonzero canonical project
 * number and 1..8 zones sorted ascending and unique. Returns a fresh copy.
 */
export function validateGceMrOwnerRule(input: unknown, at = "mrOwnerRule"): GceMrOwnerRule {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new GcePzidError(`${at} must be an object`);
  const proto = Object.getPrototypeOf(input);
  if (proto !== Object.prototype && proto !== null) throw new GcePzidError(`${at} must be a plain object`);
  const raw = input as Record<string, unknown>;
  const keys = Object.keys(raw);
  if (keys.length !== 3 || !["kind", "projectNumber", "zones"].every((key) => keys.includes(key))) {
    throw new GcePzidError(`${at} must have exactly the fields kind, projectNumber, zones`);
  }
  if (raw.kind !== GCE_PZID_RULE_KIND) throw new GcePzidError(`${at}.kind must be ${GCE_PZID_RULE_KIND}`);
  if (!isGcePositiveUint64(raw.projectNumber)) throw new GcePzidError(`${at}.projectNumber must be a nonzero canonical uint64 decimal string`);
  if (!Array.isArray(raw.zones) || raw.zones.length === 0 || raw.zones.length > MAX_GCE_PZID_RULE_ZONES) {
    throw new GcePzidError(`${at}.zones must contain 1..${MAX_GCE_PZID_RULE_ZONES} zones`);
  }
  const zones = raw.zones.map((zone, index) => {
    if (!isGceZone(zone)) throw new GcePzidError(`${at}.zones[${index}] is not a GCE zone`);
    return zone;
  });
  for (let index = 1; index < zones.length; index++) {
    if (!(zones[index - 1]! < zones[index]!)) throw new GcePzidError(`${at}.zones must be sorted and unique`);
  }
  return { kind: GCE_PZID_RULE_KIND, projectNumber: raw.projectNumber, zones };
}

/** go-tdx-guest `PZIDPayload`, byte for byte. Refuses what Go refuses, and non-canonical numbers. */
export function gcePzidPayload(input: GceInstance): string {
  if (!/^[a-z0-9-]+$/.test(input.zone)) throw new GcePzidError("zone contains non-GCE zone characters");
  if (!isGceUint64(input.instanceId) || !isGceUint64(input.projectNumber)) throw new GcePzidError("not a canonical uint64");
  return `{"instanceId":${input.instanceId},"numericalProjectId":${input.projectNumber},"zone":"${input.zone}"}`;
}

/** SHA-384 of a PZID payload string, lowercase hex: the MR_OWNER Google writes for it. */
export function gcePzidDigestHex(payload: string): string {
  return bytesToHex(sha384(utf8Encode(payload)));
}

/**
 * Parse a presented PZID payload strictly: exactly the go-tdx-guest form, both
 * numbers nonzero canonical uint64, a GCE zone. Returns null for anything
 * else, so a caller records a refusal rather than guessing.
 */
export function parseGcePzid(payload: unknown): GceInstance | null {
  if (typeof payload !== "string" || payload.length > MAX_GCE_PZID_CHARS) return null;
  const match = PZID.exec(payload);
  if (!match) return null;
  const [, instanceId, projectNumber, zone] = match;
  if (!isGcePositiveUint64(instanceId) || !isGcePositiveUint64(projectNumber) || !isGceZone(zone)) return null;
  const instance = { projectNumber, zone, instanceId };
  // Belt and braces: the parsed fields must re-render to the exact bytes.
  return gcePzidPayload(instance) === payload ? instance : null;
}

/**
 * The VM a quoted MR_OWNER names, from a presented PZID: the payload must be
 * canonical and its SHA-384 must equal `mrOwner` (a nonzero 96-hex register).
 * Null on any mismatch.
 */
export function gceInstanceFromMrOwner(payload: unknown, mrOwner: string): GceInstance | null {
  const normalized = typeof mrOwner === "string" ? mrOwner.toLowerCase() : "";
  if (!/^[0-9a-f]{96}$/.test(normalized) || normalized === GCE_ZERO_MR_OWNER) return null;
  const instance = parseGcePzid(payload);
  if (!instance || gcePzidDigestHex(payload as string) !== normalized) return null;
  return instance;
}

/** Whether a digest-verified instance satisfies a rule: the pinned project and a listed zone. */
export function gcePzidRuleAdmits(rule: GceMrOwnerRule, instance: GceInstance): boolean {
  // Defensive against a hand-built rule: the verifier never throws on hostile input.
  return instance.projectNumber === rule.projectNumber && Array.isArray(rule.zones) && rule.zones.includes(instance.zone);
}

/** `projects/<number>/zones/<zone>/instances/<id>`, for display. */
export function gceInstanceResource(instance: GceInstance): string {
  return `projects/${instance.projectNumber}/zones/${instance.zone}/instances/${instance.instanceId}`;
}
