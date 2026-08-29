// Provider-neutral verification entry point. Resolves the verifier for a provider
// and runs it over raw evidence, returning the public snake_case NormalizedVerdict.
// This is the trust core: it never consults, and never needs, the gateway's own
// verdict. Callers pass raw evidence and the expectations to bind it to.

import { pinnedEndpointIdentityFor, pinnedMeasurementPolicyFor } from "../measurements.js";
import { failedResult } from "./checks.js";
import { NearTeeVerifier } from "./near.js";
import { VeniceTeeVerifier } from "./venice.js";
import { ChutesTeeVerifier } from "./chutes.js";
import { TinfoilTeeVerifier } from "./tinfoil.js";
import {
  toNormalizedVerdict,
  type AttestationExpectations,
  type NormalizedVerdict,
  type PrivacyModality,
  type TeeVerifier
} from "./types.js";

/** The providers this SDK can verify. */
export type VerifiableProvider = "near-ai" | "venice" | "chutes" | "tinfoil";

/** Public expectations for `verifyRawEvidence`. Only `upstreamModel` + `nonce` are
 *  required; everything else is derived from the pinned policy or sensible defaults. */
export interface VerifyExpectations {
  /** Provider-native (upstream) model id the evidence must attest. Also the key for
   *  the pinned NEAR measurement policy + endpoint identity. */
  upstreamModel: string;
  /** The exact fresh nonce (hex) that was sent to obtain this evidence. */
  nonce: string;
  /** Public catalog model id (defaults to `upstreamModel`). */
  canonicalModel?: string;
  /** Route id / slug (defaults to `${provider}/${upstreamModel}`). */
  routeId?: string;
  /** Endpoint identity the evidence must be bound to (defaults to the pinned direct
   *  host for NEAR, else the provider name). */
  endpointIdentity?: string;
  /** Privacy modality (defaults to `tee` for tinfoil, `e2ee` for the others). */
  privacyModality?: PrivacyModality;
  /** Injectable clock (ms) for deterministic freshness/expiry. */
  now?: number;
  maxEvidenceAgeMs?: number;
  cacheTtlMs?: number;
}

const VERIFIERS: Record<VerifiableProvider, TeeVerifier> = {
  "near-ai": new NearTeeVerifier(),
  venice: new VeniceTeeVerifier(),
  chutes: new ChutesTeeVerifier(),
  tinfoil: new TinfoilTeeVerifier()
};

/** Resolve the verifier for a provider, or null when the provider has none. */
export function verifierFor(provider: string): TeeVerifier | null {
  return (VERIFIERS as Record<string, TeeVerifier>)[provider] ?? null;
}

function defaultPrivacyModality(provider: string): PrivacyModality {
  return provider === "tinfoil" ? "tee" : "e2ee";
}

/** Build full internal expectations from the public shape, resolving pins. */
export function buildExpectations(provider: string, input: VerifyExpectations): AttestationExpectations {
  const privacyModality = input.privacyModality ?? defaultPrivacyModality(provider);
  const endpointIdentity = input.endpointIdentity
    ?? pinnedEndpointIdentityFor(provider, input.upstreamModel)
    ?? provider;
  return {
    provider,
    canonicalModel: input.canonicalModel ?? input.upstreamModel,
    upstreamModel: input.upstreamModel,
    routeId: input.routeId ?? `${provider}/${input.upstreamModel}`,
    endpointIdentity,
    nonce: input.nonce,
    privacyModality,
    measurementPolicy: pinnedMeasurementPolicyFor(provider, input.upstreamModel),
    now: input.now,
    maxEvidenceAgeMs: input.maxEvidenceAgeMs,
    cacheTtlMs: input.cacheTtlMs
  };
}

/**
 * Independently verify raw provider evidence and return the normalized verdict.
 * PURE: no network, no clock except `expectations.now`. Fails closed: an unknown
 * provider or unparseable evidence yields a `failed`/`unsupported` verdict rather
 * than throwing.
 */
export function verifyRawEvidence(
  provider: string,
  rawEvidence: unknown,
  expectations: VerifyExpectations
): NormalizedVerdict {
  const built = buildExpectations(provider, expectations);
  const verifier = verifierFor(provider);
  if (!verifier) {
    const result = failedResult(built, "provider_not_verifiable", "sdk/1", { level: "unsupported" });
    return toNormalizedVerdict(result);
  }
  return toNormalizedVerdict(verifier.verifyAttestation(rawEvidence, built));
}
