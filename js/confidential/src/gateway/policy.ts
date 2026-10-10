// The accepted-measurement policy for AnonRouter's own confidential gateway.
//
// CRITICAL PROPERTY: a verifier must never download this policy from the server
// it is verifying. A gateway that could hand a client the list of builds the
// client will accept could always name itself. The policy therefore ships INSIDE
// this package (gateway-policies.json, a parity-gated copy of the monorepo's
// canonical shared/gateway-policies.json) or is supplied by the caller from an
// independently distributed release manifest.
//
// Nothing in this file reads the network. `loadGatewayPolicy` parses an
// already-obtained document and fails closed on anything unexpected.

import registryJson from "./gateway-policies.json" with { type: "json" };
import { hexToBytes, utf8Decode } from "../bytes.js";
import { canonicalGatewayOrigin } from "./binding.js";
import { RELEASE_MEASURED_REGISTER_FIELDS, releaseTupleDigest } from "./release-v3-canonical.js";

/** Platform-level measurements (firmware + OS image), when pinned. */
export interface GatewayPlatformMeasurements {
  /** Accepted MRTD values (48-byte SHA-384 hex). */
  mrTd: string[];
  /**
   * Accepted MRCONFIGID values (48 bytes hex).
   *
   * Measured by the CPU at TD build time, so unlike anything in the event log it
   * cannot be re-narrated by the guest. Pin the value observed for the platform
   * you reviewed; pin 96 zeros on a stack that leaves it empty, so "empty" is an
   * explicit decision rather than an unchecked field.
   */
  mrConfigId: string[];
  /** Accepted RTMR0 values (virtual firmware / VM configuration). */
  rtmr0: string[];
  /** Accepted RTMR1 values (kernel). */
  rtmr1: string[];
  /** Accepted RTMR2 values (kernel cmdline / initrd). */
  rtmr2: string[];
  /**
   * Accepted dstack OS image hashes (32 bytes hex), as measured in the RTMR3
   * `os-image-hash` event. This names the guest OS in one legible value rather
   * than three opaque registers, and it is what `dstack-mr` reproduces.
   */
  osImageHash: string[];
}

/**
 * Which kind of confidential platform a policy describes. Each kind has its own
 * security floor and its own evidence rules, so a policy can never be satisfied
 * by evidence shaped for a different platform.
 *
 *   phala-dstack-kms  The current Phala/dstack deployment, whose app keys come
 *                     from a pinned KMS. A policy document WITHOUT `platformKind`
 *                     is the legacy form of this kind and parses exactly as it
 *                     always has.
 *   gcp-tdx-native    A Google Cloud Intel TDX content node whose application
 *                     (compose and images) is baked into a dm-verity root named
 *                     on the UKI command line, which firmware measures into
 *                     RTMR1. It has guest-only per-boot keys, no KMS, no dstack
 *                     application events (RTMR3 stays zero) and is pinned only
 *                     through the hardware registers in the quote. Never vTPM
 *                     evidence. Requires same-connection verification and,
 *                     until its native boot chain is qualified, an explicit
 *                     caller pilot opt-in.
 */
export type GatewayPlatformKind = "phala-dstack-kms" | "gcp-tdx-native";

export const GATEWAY_PLATFORM_KINDS: readonly GatewayPlatformKind[] = ["phala-dstack-kms", "gcp-tdx-native"];

/**
 * Whether a platform kind's boot chain has been qualified for this SDK release.
 *
 * gcp-tdx-native is NOT qualified: a small C4 TDX VM has produced a genuine,
 * natively verified quote, but no AnonRouter guest has yet proved that Google's
 * firmware measures its UKI (with the command line naming the verity root that
 * holds the application) into RTMR1 on this platform. Until a
 * reviewed SDK release flips this, the packaged registry and the signed feed
 * refuse the kind, and the verifier fails it unless the caller explicitly opted
 * into an unqualified pilot.
 */
export const GATEWAY_PLATFORM_QUALIFIED: Readonly<Record<GatewayPlatformKind, boolean>> = Object.freeze({
  "phala-dstack-kms": true,
  "gcp-tdx-native": false
});

/**
 * One approved release, as the WHOLE tuple of values that must be observed
 * together. A policy that lists several tuples accepts evidence matching ANY ONE
 * of them completely, never a mixture: an old firmware register with a new
 * compose hash matches no tuple and fails.
 *
 * Firmware rolls and machine shapes are expressed as additional complete tuples,
 * because Google's MRTD changes with firmware and RTMR0 changes with shape.
 */
export interface GatewayReleaseTuple {
  /** Operator label for the audit trail, 1..128 of [A-Za-z0-9._:@+-]. */
  tupleId: string;
  /** The binding's release_id. */
  releaseId: string;
  /**
   * The binding's app id, lowercase hex. Measured in RTMR3 on Phala; on GCP it
   * is the 32-byte dm-verity root hash that the UKI command line (RTMR1) names.
   */
  appId: string;
  /** The binding's compose hash, 64 lowercase hex. */
  composeHash: string;
  /** Quote registers, 96 lowercase hex each, compared exactly. */
  mrTd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  /** phala-dstack-kms only: MRCONFIGID (GCP requires it to be zero). */
  mrConfigId?: string;
  /** phala-dstack-kms only: the measured dstack os-image-hash event. */
  osImageHash?: string;
  /**
   * phala-dstack-kms only: the exact payload (lowercase hex) of the measured
   * RTMR3 key-provider event, which must decode to a JSON object naming `kms`.
   */
  keyProviderPayload?: string;
  /** gcp-tdx-native only: the quote's exact td_attributes, 16 lowercase hex. */
  tdAttributes?: string;
  /**
   * gcp-tdx-native only: the quote's exact XFAM, 16 lowercase hex. It selects
   * which extended CPU state (AVX-512, AMX, PKS, CET, ...) the TD may use, so a
   * node launched with a different feature set is a different boot.
   */
  xfam?: string;
  /** Validity window, epoch ms: notBeforeMs <= now < expiresAtMs. */
  notBeforeMs: number;
  expiresAtMs: number;
}

/** The longest validity window a single tuple may claim (366 days). */
export const MAX_RELEASE_TUPLE_LIFETIME_MS = 31_622_400_000;
/** At most this many tuples, so a hostile policy cannot pin the CPU. */
export const MAX_RELEASE_TUPLES = 64;

/**
 * One measured tuple of an owner-signed release policy v3: the exact quote
 * registers of an approved image, matched all at once. It carries no release
 * id, app id, compose hash or validity window. On gcp-tdx-native the
 * application is the dm-verity root named on the UKI command line, which RTMR1
 * measures, so the registers already pin it.
 */
export interface GatewayMeasuredTupleV3 {
  /** Operator label, `^[a-z0-9][a-z0-9_.-]{0,127}$`. Not part of the digest. */
  tupleId: string;
  /** 96 lowercase hex each. */
  mrTd: string;
  mrConfigId: string;
  mrOwner: string;
  mrOwnerConfig: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  /** 16 lowercase hex each. */
  tdAttributes: string;
  xfam: string;
}

/**
 * The verified facts of an owner-signed release policy v3 that a verdict needs.
 * Only `release-v3.ts` builds this, from an envelope whose two owner signatures
 * verified against a pinned owner root; `loadGatewayPolicy` never accepts it.
 */
export interface GatewayReleasePolicyV3 {
  /** The pinned owner root the envelope was verified against. */
  ownerRootSha256: string;
  deploymentId: string;
  sequence: number;
  /** SHA-256 of the canonical payload bytes. */
  policySha256: string;
  /** 1..16 approved tuples, unique tupleId, none revoked. */
  tuples: GatewayMeasuredTupleV3[];
  /** Revoked tuple digests, sorted ascending and unique. */
  revokedTuples: string[];
}

export const MAX_RELEASE_V3_TUPLES = 16;
export const MAX_RELEASE_V3_REVOKED_TUPLES = 4096;

export interface GatewayMeasurementPolicy {
  /**
   * Explicit platform discriminator. Absent means the legacy phala-dstack-kms
   * form (independent allowlists plus `platform`/`keyProviderId`). Present means
   * the tuple form: `releaseTuples` is the only source of accepted identities and
   * the list fields below are derived from it for display only.
   */
  platformKind?: GatewayPlatformKind;
  /** Tuple form only: the approved releases, evaluated as OR of whole tuples. */
  releaseTuples?: GatewayReleaseTuple[];
  /**
   * gcp-tdx-native only, instead of `releaseTuples`: an owner-signed release
   * policy v3. Tuples are exact quote registers with no expiry, a quote whose
   * tuple digest is revoked fails, and the identity lists below stay empty.
   */
  releasePolicyV3?: GatewayReleasePolicyV3;
  /** Where this policy came from, for the audit trail. Never a gateway URL. */
  source: string;
  /** Policy version so a stale pin is visible in output. */
  version: string;
  /** Origins this policy authorizes. A quote for another origin fails closed. */
  origins: string[];
  /** Accepted dstack application ids (lowercase hex, no 0x). */
  appIds: string[];
  /** Accepted compose hashes: the exact reviewed configurations. */
  composeHashes: string[];
  /** Accepted AnonRouter release identifiers. */
  releaseIds: string[];
  /**
   * The KMS identity allowed to hold this app's derived keys, as it appears in
   * the measured "key-provider" RTMR3 event (the KMS contract's k256 public key
   * for a `kms` provider). Omit only in local development: without it, a CVM
   * whose keys came from a different key provider still passes every other check.
   */
  keyProviderId?: string;
  /** Optional firmware/OS pinning. Omit to accept any platform stack. */
  platform?: GatewayPlatformMeasurements;
  /**
   * Require the TD itself to terminate TLS and to name the certificate the
   * client is using. Fails closed when the platform gateway terminates TLS.
   */
  requireInTeeTls: boolean;
  /**
   * Require the attested app-compose to declare public_logs=false. This turns
   * "we do not publish logs" from a promise into a measured configuration fact.
   */
  requirePrivateLogs: boolean;
  /**
   * Require every image in the attested docker-compose to be pinned by digest.
   * Without this, the compose hash pins a tag that can be repointed later.
   */
  requireDigestPinnedImages: boolean;
  /**
   * Require the quote's signature to be chained to Intel's roots with TCB
   * collateral, so the verdict is `hardware-verified` rather than
   * `provider-attested`.
   *
   * Without this, a client whose DCAP engine is missing, broken, or unbuilt
   * silently accepts at the weaker level and reports success. That is precisely
   * the silent downgrade this SDK refuses to make. This package ships NO DCAP
   * engine, so a policy with this set true fails closed unless the caller
   * supplies a `chainVerifier`. That is deliberate: see the SDK README.
   */
  requireHardwareVerified: boolean;
  /**
   * TCB statuses this policy accepts from a chain verifier.
   *
   * A DCAP verdict is not a boolean: a quote can verify against Intel's roots
   * while the platform's TCB is out of date, which means known vulnerabilities
   * are unpatched on the machine holding your data. Accepting `OutOfDate`
   * because the signature checked out is the mistake this list exists to
   * prevent. `UpToDate` alone is the conservative choice; widening it (for
   * example to `SWHardeningNeeded`) is a reviewed decision and must be written
   * down here rather than assumed.
   *
   * Enforced whenever a chain verifier reports a status, INCLUDING when it
   * reports `verified: true`. A verifier that says verified with a status this
   * policy does not accept is a failure, not a pass.
   */
  acceptableTcbStatuses: string[];
  /**
   * Require the evidence document to carry a timestamp inside the age window.
   *
   * The nonce is the real anti-replay proof, so this is defence in depth rather
   * than the primary control. It matters because a document with NO timestamp
   * cannot be aged at all, and treating "no timestamp" as "fresh enough" is the
   * quiet way an expiry check stops existing.
   */
  requireEvidenceExpiry: boolean;
  /** Maximum age of the evidence document itself, in milliseconds. */
  maxEvidenceAgeMs: number;
}

export class GatewayPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayPolicyError";
  }
}

function hexList(field: string, value: unknown, exactChars?: number): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new GatewayPolicyError(`${field} must be a non-empty array`);
  }
  if (value.length > 64) throw new GatewayPolicyError(`${field} must contain at most 64 entries`);
  return value.map((entry) => {
    if (typeof entry !== "string") throw new GatewayPolicyError(`${field} entries must be strings`);
    const normalized = entry.trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(normalized)) throw new GatewayPolicyError(`${field} entries must be hex`);
    if (exactChars !== undefined && normalized.length !== exactChars) {
      throw new GatewayPolicyError(`${field} entries must be ${exactChars} hex characters`);
    }
    return normalized;
  });
}

function stringList(field: string, value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new GatewayPolicyError(`${field} must be a non-empty array`);
  }
  if (value.length > 64) throw new GatewayPolicyError(`${field} must contain at most 64 entries`);
  return value.map((entry) => {
    if (typeof entry !== "string" || entry.trim().length === 0) {
      throw new GatewayPolicyError(`${field} entries must be non-empty strings`);
    }
    return entry.trim();
  });
}

function requiredBoolean(field: string, value: unknown): boolean {
  if (typeof value !== "boolean") throw new GatewayPolicyError(`${field} must be a boolean`);
  return value;
}

const RELEASE_LABEL = /^[A-Za-z0-9._:@+-]{1,128}$/;
const LEGACY_IDENTITY_FIELDS = ["appIds", "composeHashes", "releaseIds", "keyProviderId", "platform"] as const;
const TUPLE_POLICY_FIELDS = new Set([
  "platformKind", "source", "version", "origins", "releaseTuples", "requireInTeeTls", "requirePrivateLogs",
  "requireDigestPinnedImages", "requireHardwareVerified", "acceptableTcbStatuses", "requireEvidenceExpiry",
  "maxEvidenceAgeMs"
]);
const COMMON_TUPLE_FIELDS = ["tupleId", "releaseId", "appId", "composeHash", "mrTd", "rtmr0", "rtmr1", "rtmr2",
  "notBeforeMs", "expiresAtMs"];
const KIND_TUPLE_FIELDS: Readonly<Record<GatewayPlatformKind, readonly string[]>> = {
  "phala-dstack-kms": ["mrConfigId", "osImageHash", "keyProviderPayload"],
  // No MRCONFIGID (required zero), OS image or key provider: the application is
  // the verity root in RTMR1, and the node has no KMS and no RTMR3 events.
  "gcp-tdx-native": ["tdAttributes", "xfam"]
};

/** The platform a parsed policy describes; the legacy form is phala-dstack-kms. */
export function gatewayPolicyPlatformKind(policy: GatewayMeasurementPolicy): GatewayPlatformKind {
  return policy.platformKind ?? "phala-dstack-kms";
}

/**
 * True when evidence for this policy is only meaningful if its TLS key was
 * observed on the very socket that will carry content. Behind a load balancer
 * with a different key per node, a separately observed certificate proves
 * nothing about the node that receives the request.
 */
export function gatewayPolicyRequiresRetainedConnection(policy: GatewayMeasurementPolicy): boolean {
  return gatewayPolicyPlatformKind(policy) === "gcp-tdx-native";
}

function exactHex(field: string, value: unknown, chars: number): string {
  if (typeof value !== "string" || value.length !== chars || !/^[0-9a-f]+$/.test(value)) {
    throw new GatewayPolicyError(`${field} must be exactly ${chars} lowercase hex characters`);
  }
  return value;
}

function tupleTime(field: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new GatewayPolicyError(`${field} must be a non-negative safe integer (epoch ms)`);
  }
  return value;
}

/**
 * Validate one tuple for its platform kind. Idempotent over its own output, so
 * the security floor can re-run it on an already-parsed (or hand-built) policy.
 * Values must already be canonical lowercase hex: a tuple is compared exactly,
 * so it is written exactly.
 */
export function validateGatewayReleaseTuple(kind: GatewayPlatformKind, input: unknown, index: number): GatewayReleaseTuple {
  const at = `policy.releaseTuples[${index}]`;
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new GatewayPolicyError(`${at} must be an object`);
  const raw = input as Record<string, unknown>;
  const expected = [...COMMON_TUPLE_FIELDS, ...KIND_TUPLE_FIELDS[kind]];
  const keys = Object.keys(raw).filter((key) => raw[key] !== undefined);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    // A field of the other kind, or any vTPM/PCR field, is refused, never ignored.
    throw new GatewayPolicyError(`${at} must have exactly the fields ${expected.join(", ")}`);
  }
  for (const field of ["tupleId", "releaseId"] as const) {
    if (typeof raw[field] !== "string" || !RELEASE_LABEL.test(raw[field] as string)) {
      throw new GatewayPolicyError(`${at}.${field} must be 1..128 chars of [A-Za-z0-9._:@+-]`);
    }
  }
  const appId = kind === "gcp-tdx-native"
    ? exactHex(`${at}.appId`, raw.appId, 64)
    : typeof raw.appId === "string" && /^[0-9a-f]{1,512}$/.test(raw.appId) ? raw.appId : undefined;
  if (appId === undefined) throw new GatewayPolicyError(`${at}.appId must be lowercase hex`);
  let kindFields: Partial<GatewayReleaseTuple>;
  if (kind === "phala-dstack-kms") {
    const keyProviderPayload = raw.keyProviderPayload;
    if (typeof keyProviderPayload !== "string" || keyProviderPayload.length < 2 || keyProviderPayload.length > 2048
        || keyProviderPayload.length % 2 !== 0 || !/^[0-9a-f]+$/.test(keyProviderPayload)) {
      throw new GatewayPolicyError(`${at}.keyProviderPayload must be 2..2048 lowercase hex characters`);
    }
    let provider: unknown;
    try {
      provider = JSON.parse(utf8Decode(hexToBytes(keyProviderPayload)));
    } catch {
      throw new GatewayPolicyError(`${at}.keyProviderPayload must decode to a UTF-8 JSON object`);
    }
    if (!provider || typeof provider !== "object" || Array.isArray(provider)
        || (provider as Record<string, unknown>).name !== "kms") {
      throw new GatewayPolicyError(`${at}.keyProviderPayload must name the kms key provider for ${kind}`);
    }
    kindFields = {
      mrConfigId: exactHex(`${at}.mrConfigId`, raw.mrConfigId, 96),
      osImageHash: exactHex(`${at}.osImageHash`, raw.osImageHash, 64),
      keyProviderPayload
    };
  } else {
    const tdAttributes = exactHex(`${at}.tdAttributes`, raw.tdAttributes, 16);
    // TUD.DEBUG is bit 0 of the first byte. A debug TD is never approvable.
    if ((parseInt(tdAttributes.slice(0, 2), 16) & 0x01) !== 0) {
      throw new GatewayPolicyError(`${at}.tdAttributes must not enable debug`);
    }
    kindFields = { tdAttributes, xfam: exactHex(`${at}.xfam`, raw.xfam, 16) };
  }
  const notBeforeMs = tupleTime(`${at}.notBeforeMs`, raw.notBeforeMs);
  const expiresAtMs = tupleTime(`${at}.expiresAtMs`, raw.expiresAtMs);
  if (expiresAtMs <= notBeforeMs || expiresAtMs - notBeforeMs > MAX_RELEASE_TUPLE_LIFETIME_MS) {
    throw new GatewayPolicyError(`${at} validity must be a non-empty window of at most ${MAX_RELEASE_TUPLE_LIFETIME_MS} ms`);
  }
  return {
    tupleId: raw.tupleId as string,
    releaseId: raw.releaseId as string,
    appId,
    composeHash: exactHex(`${at}.composeHash`, raw.composeHash, 64),
    mrTd: exactHex(`${at}.mrTd`, raw.mrTd, 96),
    rtmr0: exactHex(`${at}.rtmr0`, raw.rtmr0, 96),
    rtmr1: exactHex(`${at}.rtmr1`, raw.rtmr1, 96),
    rtmr2: exactHex(`${at}.rtmr2`, raw.rtmr2, 96),
    ...kindFields,
    notBeforeMs,
    expiresAtMs
  };
}

const RELEASE_V3_IDENTIFIER = /^[a-z0-9][a-z0-9_.-]{0,127}$/;
const RELEASE_V3_TUPLE_FIELDS = ["tupleId", ...RELEASE_MEASURED_REGISTER_FIELDS];
const RELEASE_V3_POLICY_FIELDS = ["ownerRootSha256", "deploymentId", "sequence", "policySha256", "tuples", "revokedTuples"];

function exactFields(at: string, raw: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Object.keys(raw);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) {
    throw new GatewayPolicyError(`${at} must have exactly the fields ${expected.join(", ")}`);
  }
}

/** Validate one release policy v3 measured tuple. Idempotent over its output. */
export function validateGatewayMeasuredTupleV3(input: unknown, index: number): GatewayMeasuredTupleV3 {
  const at = `releasePolicyV3.tuples[${index}]`;
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new GatewayPolicyError(`${at} must be an object`);
  const raw = input as Record<string, unknown>;
  exactFields(at, raw, RELEASE_V3_TUPLE_FIELDS);
  if (typeof raw.tupleId !== "string" || !RELEASE_V3_IDENTIFIER.test(raw.tupleId)) {
    throw new GatewayPolicyError(`${at}.tupleId must match ${RELEASE_V3_IDENTIFIER.source}`);
  }
  const register = (field: keyof GatewayMeasuredTupleV3, chars: number) => exactHex(`${at}.${field}`, raw[field], chars);
  return {
    tupleId: raw.tupleId,
    mrTd: register("mrTd", 96), mrConfigId: register("mrConfigId", 96),
    mrOwner: register("mrOwner", 96), mrOwnerConfig: register("mrOwnerConfig", 96),
    rtmr0: register("rtmr0", 96), rtmr1: register("rtmr1", 96), rtmr2: register("rtmr2", 96), rtmr3: register("rtmr3", 96),
    tdAttributes: register("tdAttributes", 16), xfam: register("xfam", 16)
  };
}

/**
 * Validate the release policy v3 facts carried in a gateway policy. The owner
 * signatures were checked when the envelope was verified; this re-checks the
 * shape and the revocation rule on every use, so a mutated or hand-built object
 * cannot approve a revoked tuple.
 */
export function validateGatewayReleasePolicyV3(input: unknown): GatewayReleasePolicyV3 {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new GatewayPolicyError("releasePolicyV3 must be an object");
  const raw = input as Record<string, unknown>;
  exactFields("releasePolicyV3", raw, RELEASE_V3_POLICY_FIELDS);
  const ownerRootSha256 = exactHex("releasePolicyV3.ownerRootSha256", raw.ownerRootSha256, 64);
  const policySha256 = exactHex("releasePolicyV3.policySha256", raw.policySha256, 64);
  if (typeof raw.deploymentId !== "string" || !RELEASE_V3_IDENTIFIER.test(raw.deploymentId)) {
    throw new GatewayPolicyError("releasePolicyV3.deploymentId is invalid");
  }
  if (typeof raw.sequence !== "number" || !Number.isSafeInteger(raw.sequence) || raw.sequence < 1) {
    throw new GatewayPolicyError("releasePolicyV3.sequence must be a positive safe integer");
  }
  if (!Array.isArray(raw.tuples) || raw.tuples.length === 0 || raw.tuples.length > MAX_RELEASE_V3_TUPLES) {
    throw new GatewayPolicyError(`releasePolicyV3.tuples must contain 1..${MAX_RELEASE_V3_TUPLES} tuples`);
  }
  const tuples = raw.tuples.map((entry, index) => validateGatewayMeasuredTupleV3(entry, index));
  if (new Set(tuples.map((tuple) => tuple.tupleId)).size !== tuples.length) {
    throw new GatewayPolicyError("releasePolicyV3.tuples tupleIds must be unique");
  }
  if (!Array.isArray(raw.revokedTuples) || raw.revokedTuples.length > MAX_RELEASE_V3_REVOKED_TUPLES) {
    throw new GatewayPolicyError(`releasePolicyV3.revokedTuples must contain at most ${MAX_RELEASE_V3_REVOKED_TUPLES} digests`);
  }
  const revokedTuples = raw.revokedTuples.map((entry, index) => exactHex(`releasePolicyV3.revokedTuples[${index}]`, entry, 64));
  for (let index = 1; index < revokedTuples.length; index++) {
    if (revokedTuples[index - 1]! >= revokedTuples[index]!) {
      throw new GatewayPolicyError("releasePolicyV3.revokedTuples must be sorted ascending and unique");
    }
  }
  const revoked = new Set(revokedTuples);
  if (tuples.some((tuple) => revoked.has(releaseTupleDigest(tuple)))) {
    throw new GatewayPolicyError("releasePolicyV3 approves a tuple it also revokes");
  }
  return { ownerRootSha256, deploymentId: raw.deploymentId, sequence: raw.sequence, policySha256, tuples, revokedTuples };
}

function validateReleaseTuples(kind: GatewayPlatformKind, value: unknown): GatewayReleaseTuple[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_RELEASE_TUPLES) {
    throw new GatewayPolicyError(`policy.releaseTuples must contain 1..${MAX_RELEASE_TUPLES} tuples`);
  }
  const tuples = value.map((entry, index) => validateGatewayReleaseTuple(kind, entry, index));
  if (new Set(tuples.map((tuple) => tuple.tupleId)).size !== tuples.length) {
    throw new GatewayPolicyError("policy.releaseTuples tupleIds must be unique");
  }
  return tuples;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

/**
 * The per-kind floor every policy must meet before any evidence is judged
 * against it. The legacy form keeps exactly its historical floor. The tuple form
 * additionally refuses a mixed document and re-validates every tuple.
 */
export function assertGatewayPlatformSecurityFloor(policy: GatewayMeasurementPolicy): void {
  const refuse = (why: string): never => { throw new GatewayPolicyError(`policy security floor: ${why}`); };
  if (!policy.requireHardwareVerified || !policy.requireInTeeTls || !policy.requirePrivateLogs
    || !policy.requireDigestPinnedImages || !policy.requireEvidenceExpiry
    || policy.maxEvidenceAgeMs > 300_000 || policy.acceptableTcbStatuses.length !== 1
    || policy.acceptableTcbStatuses[0] !== "UpToDate") refuse("policy weakens mandatory security requirements");
  if (policy.platformKind === undefined) {
    if (policy.releaseTuples !== undefined) refuse("release tuples require an explicit platformKind");
    if (policy.releasePolicyV3 !== undefined) refuse("a release policy v3 requires platformKind gcp-tdx-native");
    if (!policy.keyProviderId || !policy.platform) refuse("policy weakens mandatory security requirements");
    return;
  }
  if (!GATEWAY_PLATFORM_KINDS.includes(policy.platformKind)) refuse("unknown platformKind");
  if (policy.keyProviderId !== undefined || policy.platform !== undefined) {
    refuse("a tuple-form policy cannot also carry independent platform or key-provider allowlists");
  }
  if (policy.releasePolicyV3 !== undefined) {
    if (policy.platformKind !== "gcp-tdx-native") refuse("a release policy v3 requires platformKind gcp-tdx-native");
    if (policy.releaseTuples !== undefined) refuse("a release policy v3 cannot also carry release tuples");
    if (policy.appIds.length !== 0 || policy.composeHashes.length !== 0 || policy.releaseIds.length !== 0) {
      refuse("a release policy v3 pins quote registers only; the identity lists must be empty");
    }
    try {
      validateGatewayReleasePolicyV3(policy.releasePolicyV3);
    } catch (error) {
      if (error instanceof GatewayPolicyError) refuse(error.message);
      throw error;
    }
    return;
  }
  try {
    const tuples = validateReleaseTuples(policy.platformKind, policy.releaseTuples);
    const derived = (pick: (tuple: GatewayReleaseTuple) => string) => unique(tuples.map(pick)).join("\n");
    if (policy.appIds.join("\n") !== derived((tuple) => tuple.appId)
      || policy.composeHashes.join("\n") !== derived((tuple) => tuple.composeHash)
      || policy.releaseIds.join("\n") !== derived((tuple) => tuple.releaseId)) {
      refuse("derived identity lists disagree with the release tuples");
    }
  } catch (error) {
    if (error instanceof GatewayPolicyError) refuse(error.message);
    throw error;
  }
}

function loadTupleGatewayPolicy(raw: Record<string, unknown>): GatewayMeasurementPolicy {
  const kind = raw.platformKind;
  if (typeof kind !== "string" || !GATEWAY_PLATFORM_KINDS.includes(kind as GatewayPlatformKind)) {
    throw new GatewayPolicyError(`policy.platformKind must be one of ${GATEWAY_PLATFORM_KINDS.join(", ")}`);
  }
  for (const field of LEGACY_IDENTITY_FIELDS) {
    if (field in raw) {
      // Ambiguity is refused rather than resolved: a document carrying both forms
      // could be read as either, and the two readings accept different evidence.
      throw new GatewayPolicyError(`policy.${field} is not allowed with platformKind; use releaseTuples`);
    }
  }
  const unknown = Object.keys(raw).filter((key) => !TUPLE_POLICY_FIELDS.has(key));
  if (unknown.length > 0) throw new GatewayPolicyError(`policy has unknown field(s): ${unknown.join(", ")}`);
  const releaseTuples = validateReleaseTuples(kind as GatewayPlatformKind, raw.releaseTuples);
  const base = loadLegacyGatewayPolicy({
    ...raw,
    appIds: unique(releaseTuples.map((tuple) => tuple.appId)),
    composeHashes: unique(releaseTuples.map((tuple) => tuple.composeHash)),
    releaseIds: unique(releaseTuples.map((tuple) => tuple.releaseId))
  });
  return { platformKind: kind as GatewayPlatformKind, releaseTuples, ...base };
}

/**
 * Parse an untrusted policy document. Every security-relevant switch is REQUIRED:
 * there are no permissive defaults, so a truncated or hand-edited policy cannot
 * silently disable a check.
 *
 * Two forms exist. Without `platformKind` the document is the legacy
 * phala-dstack-kms form and parses exactly as it always has. With
 * `platformKind` it must carry `releaseTuples` and none of the independent
 * allowlists; mixing the two forms is refused.
 */
export function loadGatewayPolicy(input: unknown): GatewayMeasurementPolicy {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new GatewayPolicyError("policy must be a JSON object");
  }
  const raw = input as Record<string, unknown>;
  if ("platformKind" in raw) return loadTupleGatewayPolicy(raw);
  if ("releaseTuples" in raw) {
    throw new GatewayPolicyError("policy.releaseTuples requires an explicit platformKind");
  }
  return loadLegacyGatewayPolicy(raw);
}

function loadLegacyGatewayPolicy(raw: Record<string, unknown>): GatewayMeasurementPolicy {
  if (typeof raw.source !== "string" || raw.source.trim().length === 0) {
    throw new GatewayPolicyError("policy.source is required");
  }
  if (typeof raw.version !== "string" || raw.version.trim().length === 0) {
    throw new GatewayPolicyError("policy.version is required");
  }
  const maxAge = raw.maxEvidenceAgeMs;
  if (typeof maxAge !== "number" || !Number.isFinite(maxAge) || maxAge <= 0 || maxAge > 3_600_000) {
    throw new GatewayPolicyError("policy.maxEvidenceAgeMs must be 1..3600000");
  }

  let platform: GatewayPlatformMeasurements | undefined;
  if (raw.platform !== undefined) {
    if (!raw.platform || typeof raw.platform !== "object" || Array.isArray(raw.platform)) {
      throw new GatewayPolicyError("policy.platform must be an object when present");
    }
    const p = raw.platform as Record<string, unknown>;
    platform = {
      mrTd: hexList("policy.platform.mrTd", p.mrTd, 96),
      mrConfigId: hexList("policy.platform.mrConfigId", p.mrConfigId, 96),
      rtmr0: hexList("policy.platform.rtmr0", p.rtmr0, 96),
      rtmr1: hexList("policy.platform.rtmr1", p.rtmr1, 96),
      rtmr2: hexList("policy.platform.rtmr2", p.rtmr2, 96),
      osImageHash: hexList("policy.platform.osImageHash", p.osImageHash, 64)
    };
  }

  return {
    source: raw.source.trim(),
    version: raw.version.trim(),
    origins: stringList("policy.origins", raw.origins).map(canonicalGatewayOrigin),
    appIds: hexList("policy.appIds", raw.appIds),
    composeHashes: hexList("policy.composeHashes", raw.composeHashes, 64),
    releaseIds: stringList("policy.releaseIds", raw.releaseIds),
    ...(raw.keyProviderId === undefined
      ? {}
      : { keyProviderId: hexList("policy.keyProviderId", [raw.keyProviderId])[0] }),
    platform,
    requireInTeeTls: requiredBoolean("policy.requireInTeeTls", raw.requireInTeeTls),
    requirePrivateLogs: requiredBoolean("policy.requirePrivateLogs", raw.requirePrivateLogs),
    requireDigestPinnedImages: requiredBoolean("policy.requireDigestPinnedImages", raw.requireDigestPinnedImages),
    requireHardwareVerified: requiredBoolean("policy.requireHardwareVerified", raw.requireHardwareVerified),
    acceptableTcbStatuses: stringList("policy.acceptableTcbStatuses", raw.acceptableTcbStatuses),
    requireEvidenceExpiry: requiredBoolean("policy.requireEvidenceExpiry", raw.requireEvidenceExpiry),
    maxEvidenceAgeMs: maxAge
  };
}

// ---- The shipped, origin-keyed registry --------------------------------------

/**
 * How far along a shipped pin is.
 *
 *   published  The origin is a released AnonRouter confidential plane and the
 *              pins were reviewed for it. Resolved by default.
 *   candidate  The origin is a reviewed but pre-release plane whose pins are
 *              expected to move. Requires an explicit opt-in, so a default
 *              `verifyGateway()` can never quietly pass against a plane the
 *              operator has not released.
 */
export type GatewayPolicyStatus = "published" | "candidate";

export interface GatewayPolicyEntry {
  status: GatewayPolicyStatus;
  /** When the pins in this entry were reviewed (ISO date). */
  reviewedAt: string;
  /** Free-form provenance note carried into the verdict for the audit trail. */
  notes: string;
  policy: GatewayMeasurementPolicy;
}

interface RawRegistry {
  schemaVersion?: number;
  policies?: unknown[];
}

const REGISTRY = registryJson as unknown as RawRegistry;

function parseEntry(raw: unknown): GatewayPolicyEntry {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new GatewayPolicyError("registry entry must be an object");
  }
  const record = raw as Record<string, unknown>;
  if (record.status !== "published" && record.status !== "candidate") {
    throw new GatewayPolicyError("registry entry status must be published or candidate");
  }
  const policy = loadGatewayPolicy(record.policy);
  // The package must never ship an approval for a platform whose boot chain this
  // release has not qualified, not even as a candidate.
  if (!GATEWAY_PLATFORM_QUALIFIED[gatewayPolicyPlatformKind(policy)]) {
    throw new GatewayPolicyError("registry entry names a platform kind this release has not qualified");
  }
  return {
    status: record.status,
    reviewedAt: typeof record.reviewedAt === "string" ? record.reviewedAt : "",
    notes: typeof record.notes === "string" ? record.notes : "",
    policy
  };
}

/** Every pinned gateway policy this package ships, parsed and validated. */
export function gatewayPolicyRegistry(): GatewayPolicyEntry[] {
  return Array.isArray(REGISTRY.policies) ? REGISTRY.policies.map(parseEntry) : [];
}

export interface ResolveGatewayPolicyOptions {
  /**
   * Also resolve `candidate` entries. Off by default: a pre-release plane's pins
   * move, so accepting one has to be a decision the caller made in their own
   * code rather than something the package did for them.
   */
  allowCandidate?: boolean;
}

/**
 * Resolve the shipped policy for an origin, or undefined when this package pins
 * nothing for it. Undefined is a fail-closed outcome, not a permissive one: the
 * caller has no policy, so it cannot verify, so it must not proceed.
 */
export function pinnedGatewayPolicyFor(
  origin: string,
  options: ResolveGatewayPolicyOptions = {}
): GatewayPolicyEntry | undefined {
  let canonical: string;
  try {
    canonical = canonicalGatewayOrigin(origin);
  } catch {
    return undefined;
  }
  return gatewayPolicyRegistry().find((entry) =>
    entry.policy.origins.includes(canonical)
    && (entry.status === "published" || options.allowCandidate === true));
}
