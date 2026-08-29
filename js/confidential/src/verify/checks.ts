// Shared fail-closed check primitives and result assembly for the provider-neutral
// verifier. These are the same check semantics AnonRouter's gateway applies
// server-side, so an independent verdict and the gateway's own verdict agree by
// construction rather than by coincidence. Kept tiny and pure so every
// provider verifier composes the SAME semantics: a required check that fails forces
// overall status "failed", and the derived level is never stronger than justified.

import { hexEqual } from "./crypto.js";
import type {
  AttestationCheck,
  AttestationEnvelope,
  AttestationExpectations,
  HardwareType,
  NormalizedAttestationResult,
  PrivacyModality,
  VerificationLevel
} from "./types.js";

export const DEFAULT_EVIDENCE_MAX_AGE_MS = 5 * 60_000;
export const DEFAULT_CACHE_TTL_MS = 5 * 60_000;

/** Build a check result. `detail` must be safe/content-free. */
export function check(name: string, passed: boolean, required: boolean, detail?: string): AttestationCheck {
  return { name, required, passed, detail };
}

/** Defensively read an AttestationEnvelope. A bare provider payload (no envelope)
 *  is tolerated: fetch time defaults to now and endpoint to the expectations. */
export function readEnvelope(evidence: unknown, expectations: AttestationExpectations): AttestationEnvelope {
  if (evidence && typeof evidence === "object" && "payload" in (evidence as Record<string, unknown>)) {
    const env = evidence as Partial<AttestationEnvelope>;
    return {
      fetchedAtMs: typeof env.fetchedAtMs === "number" ? env.fetchedAtMs : (expectations.now ?? Date.now()),
      endpointIdentity: typeof env.endpointIdentity === "string" ? env.endpointIdentity : expectations.endpointIdentity,
      payload: env.payload
    };
  }
  return { fetchedAtMs: expectations.now ?? Date.now(), endpointIdentity: expectations.endpointIdentity, payload: evidence };
}

/** True when every REQUIRED check passed. Non-required checks are advisory. */
export function allRequiredPassed(checks: AttestationCheck[]): boolean {
  return checks.every((c) => !c.required || c.passed);
}

/** The first failed required check's name (the sanitized failure reason). */
export function firstRequiredFailure(checks: AttestationCheck[]): string | null {
  const failed = checks.find((c) => c.required && !c.passed);
  return failed ? failed.name : null;
}

/**
 * Nonce freshness: the expectations nonce must be non-empty hex of adequate entropy
 * and must equal the nonce the evidence bound. This is the anti-replay anchor; a
 * stale or absent nonce binding is always a required failure.
 */
export function nonceBindingCheck(expectedNonce: string, boundNonce: string | null): AttestationCheck {
  const validShape = /^[0-9a-f]{32,128}$/i.test(expectedNonce);
  if (!validShape) {
    return check("nonce_binding", false, true, "caller nonce missing or too short");
  }
  return check("nonce_binding", hexEqual(expectedNonce, boundNonce), true, boundNonce ? undefined : "evidence bound no nonce");
}

/**
 * Freshness/expiry: the evidence's generation instant must be within the allowed
 * age window relative to `now`. A future-dated or too-old quote fails closed.
 */
export function freshnessCheck(evidenceEpochMs: number | null, expectations: AttestationExpectations): AttestationCheck {
  const now = expectations.now ?? Date.now();
  const maxAge = expectations.maxEvidenceAgeMs ?? DEFAULT_EVIDENCE_MAX_AGE_MS;
  if (evidenceEpochMs === null || !Number.isFinite(evidenceEpochMs)) {
    return check("evidence_freshness", false, true, "evidence carried no verifiable timestamp");
  }
  const age = now - evidenceEpochMs;
  // Allow small clock skew into the future (30s), reject stale beyond maxAge.
  const passed = age >= -30_000 && age <= maxAge;
  return check("evidence_freshness", passed, true, passed ? undefined : "evidence outside freshness window");
}

/** Resolve the overall verification level, clamped by the check outcomes: any
 *  required-check failure caps the level at "unverified". */
export function resolveLevel(requestedLevel: VerificationLevel, checks: AttestationCheck[]): VerificationLevel {
  if (!allRequiredPassed(checks)) return "unverified";
  return requestedLevel;
}

export interface AssembleInput {
  expectations: AttestationExpectations;
  hardwareType: HardwareType;
  requestedLevel: VerificationLevel;
  privacyModality: PrivacyModality;
  measurementIdentities: Record<string, string>;
  modelWeightIdentity: string | null;
  attestedTlsSpki: string | null;
  attestedEncryptionKey: string | null;
  attestedSigningKey: string | null;
  boundNonce: string | null;
  verifierVersion: string;
  supportsClientOpaqueE2ee: boolean;
  checks: AttestationCheck[];
}

/** Assemble the normalized result, deriving status/level/expiry from the checks. */
export function assembleResult(input: AssembleInput): NormalizedAttestationResult {
  const now = input.expectations.now ?? Date.now();
  const ttl = input.expectations.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const ok = allRequiredPassed(input.checks);
  const level = resolveLevel(input.requestedLevel, input.checks);
  return {
    provider: input.expectations.provider,
    canonicalModel: input.expectations.canonicalModel,
    upstreamModel: input.expectations.upstreamModel,
    routeId: input.expectations.routeId,
    endpointIdentity: input.expectations.endpointIdentity,
    hardwareType: input.hardwareType,
    verificationLevel: level,
    privacyModality: input.privacyModality,
    measurementIdentities: input.measurementIdentities,
    modelWeightIdentity: input.modelWeightIdentity,
    attestedTlsSpki: input.attestedTlsSpki,
    attestedEncryptionKey: input.attestedEncryptionKey,
    attestedSigningKey: input.attestedSigningKey,
    nonce: input.boundNonce,
    verifiedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttl).toISOString(),
    policySource: input.expectations.measurementPolicy?.source ?? null,
    verifierVersion: input.verifierVersion,
    supportsClientOpaqueE2ee: input.supportsClientOpaqueE2ee,
    status: ok ? "ok" : "failed",
    reason: ok ? null : firstRequiredFailure(input.checks) ?? "verification_failed",
    checks: input.checks
  };
}

/** A fully-failed result for the unsupported/error path (no evidence, wrong
 *  provider binding, unparseable evidence). Never throws. */
export function failedResult(
  expectations: AttestationExpectations,
  reason: string,
  verifierVersion: string,
  opts: { level?: VerificationLevel; hardwareType?: HardwareType; supportsClientOpaqueE2ee?: boolean } = {}
): NormalizedAttestationResult {
  return assembleResult({
    expectations,
    hardwareType: opts.hardwareType ?? "unknown",
    requestedLevel: opts.level ?? "unverified",
    privacyModality: expectations.privacyModality,
    measurementIdentities: {},
    modelWeightIdentity: null,
    attestedTlsSpki: null,
    attestedEncryptionKey: null,
    attestedSigningKey: null,
    boundNonce: null,
    verifierVersion,
    supportsClientOpaqueE2ee: opts.supportsClientOpaqueE2ee ?? false,
    checks: [check("evidence_present", false, true, reason)]
  });
}

export { hexEqual };
