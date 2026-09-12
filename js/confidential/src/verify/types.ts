// Provider-neutral TEE attestation verification contracts. These mirror the verdict
// shape AnonRouter's gateway produces server-side, so the verdict this SDK computes
// independently is directly comparable to the one the gateway returns.
//
// Design invariants:
//   - Verification FAILS CLOSED: a missing/expired/mismatched required check yields
//     status "failed"; a route is never upgraded on unverified evidence.
//   - An upstream `verified: true` field, a `-TEE` id suffix, or a
//     `confidential_compute` flag is a routing hint, never cryptographic proof.
//   - verifyAttestation is PURE over its inputs (no network, no clock except an
//     injectable `now`) so every check is deterministically testable.
//   - Nothing here logs or returns raw prompts, responses, keys, or decrypted
//     content. Only sanitized, structured facts.

/**
 * Honest description of HOW strongly a route's TEE claim was actually checked. We
 * must never label a route `hardware-verified` unless the implementation performed
 * and passed the full cryptographic chain verification that level requires.
 */
export type VerificationLevel =
  /** Full cryptographic verification of the hardware quote / certificate chain to
   *  the silicon vendor's roots (Intel PCS/QVL, NVIDIA NRAS, AMD KDS). This SDK
   *  never emits this level: the chain-to-vendor-roots is deliberately not wired. */
  | "hardware-verified"
  /** Verified via the provider's official attestation SDK (Tinfoil's `Verifier`),
   *  which performs the vendor-root checks for us. */
  | "sdk-verified"
  /** Structurally valid, freshness/binding/measurement checks passed, but the raw
   *  quote signature was not chained to vendor roots in-process. A strong hint,
   *  not proof of hardware. This is the ceiling for near/venice/chutes. */
  | "provider-attested"
  /** Evidence present but a REQUIRED check failed, or verification was not
   *  attempted. Treat as untrusted. */
  | "unverified"
  /** The provider/route does not expose this capability at all. */
  | "unsupported";

/** The hardware a verdict reports evidence for. Combined variants mean BOTH
 *  parts were evidenced; do not use one as shorthand for "runs on a GPU".
 *  `amd-sev-snp+nvidia-cc` was removed in 0.1.2: the only route that emitted it
 *  was Tinfoil, whose official verifier establishes no NVIDIA
 *  confidential-compute evidence at all, so the value named a chain nothing had
 *  walked. Tinfoil now reports `amd-sev-snp`. */
export type HardwareType =
  | "intel-tdx"
  | "amd-sev-snp"
  | "nvidia-cc"
  | "intel-tdx+nvidia-cc"
  | "unknown";

/** The two verified-execution privacy modalities. `tee`: enclave-verified but the
 *  gateway may see plaintext. `e2ee`: client ciphertext stays opaque to the gateway
 *  and terminates inside the verified enclave. */
export type PrivacyModality = "tee" | "e2ee";

/** A single fail-closed verification step outcome. `detail` is always safe and
 *  content-free (never echoes prompts, keys, or raw bodies). */
export interface AttestationCheck {
  name: string;
  /** A required check that fails forces the overall status to "failed". */
  required: boolean;
  passed: boolean;
  detail?: string;
}

/** Per-provider accepted-measurement policy the verifier binds evidence against. */
export interface MeasurementPolicy {
  source: string;
  version: string;
  /** Provider-specific accepted measurement identities. */
  accepted: unknown;
}

/** What the verifier binds the evidence to. A mismatch on any of these is a
 *  fail-closed rejection (prevents cross-provider / cross-route substitution). */
export interface AttestationExpectations {
  provider: string;
  canonicalModel: string;
  /** Provider-native (upstream) model id. */
  upstreamModel: string;
  /** Public route id / slug (unambiguous route binding). */
  routeId: string;
  /** Endpoint identity the evidence must be bound to (host / enclave url). */
  endpointIdentity: string;
  /** Fresh caller-provided nonce/challenge (hex). Bound into the quote. */
  nonce: string;
  privacyModality: PrivacyModality;
  measurementPolicy?: MeasurementPolicy;
  /** Injectable clock (ms) for deterministic freshness/expiry tests. */
  now?: number;
  /** Max age of the evidence before it is considered stale. Default 5 min. */
  maxEvidenceAgeMs?: number;
  /** How long a successful verification result may be cached. Default 5 min. */
  cacheTtlMs?: number;
}

/** The normalized, safe attestation result (camelCase, internal). Contains only
 *  sanitized structured facts an advanced client can use to independently
 *  re-verify: never secrets, raw evidence bodies, prompts, or responses. */
export interface NormalizedAttestationResult {
  provider: string;
  canonicalModel: string;
  upstreamModel: string;
  routeId: string;
  endpointIdentity: string;
  hardwareType: HardwareType;
  verificationLevel: VerificationLevel;
  privacyModality: PrivacyModality;
  measurementIdentities: Record<string, string>;
  modelWeightIdentity: string | null;
  attestedTlsSpki: string | null;
  attestedEncryptionKey: string | null;
  attestedSigningKey: string | null;
  nonce: string | null;
  verifiedAt: string;
  expiresAt: string;
  policySource: string | null;
  verifierVersion: string;
  supportsClientOpaqueE2ee: boolean;
  status: "ok" | "failed";
  reason: string | null;
  checks: AttestationCheck[];
}

/** The public, snake_case verdict returned by `verifyRawEvidence` and carried on a
 *  `verifyAttestation` result. Mirrors the gateway's `/v1/tee/attestation`
 *  `attestation` object exactly (the shape defined in the SDK API contract). */
export interface NormalizedVerdict {
  status: "ok" | "failed";
  verification_level: VerificationLevel;
  privacy_modality: PrivacyModality;
  hardware_type: HardwareType;
  measurement_identities: Record<string, string>;
  model_weight_identity: string | null;
  attested_tls_spki: string | null;
  attested_encryption_key: string | null;
  attested_signing_key: string | null;
  nonce: string | null;
  verified_at: string;
  expires_at: string;
  policy_source: string | null;
  verifier_version: string;
  supports_client_opaque_e2ee: boolean;
  reason: string | null;
  checks: AttestationCheck[];
}

/** The provider-neutral verifier contract. Implementations are PURE over their
 *  inputs. Fetching the raw evidence bytes is the caller's job; the verifier only
 *  interprets and validates what was fetched, and fails closed. */
export interface TeeVerifier {
  readonly provider: string;
  readonly verifierVersion: string;
  /** Whether the route supports client-opaque E2EE (ciphertext body). */
  supportsClientOpaqueE2ee(routeId: string): boolean;
  /** Verify raw provider evidence against the expectations. Fails closed. */
  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult;
}

/**
 * The envelope the credential-isolated worker wraps raw provider evidence in
 * before handing it to a (pure) verifier. It adds the fetch instant (the freshness
 * anchor for providers whose quotes carry no timestamp) and the fetched endpoint.
 * A bare provider payload (no envelope) is also accepted.
 */
export interface AttestationEnvelope {
  fetchedAtMs: number;
  endpointIdentity: string;
  payload: unknown;
}

/** Project the internal camelCase result to the public snake_case verdict. */
export function toNormalizedVerdict(result: NormalizedAttestationResult): NormalizedVerdict {
  return {
    status: result.status,
    verification_level: result.verificationLevel,
    privacy_modality: result.privacyModality,
    hardware_type: result.hardwareType,
    measurement_identities: result.measurementIdentities,
    model_weight_identity: result.modelWeightIdentity,
    attested_tls_spki: result.attestedTlsSpki,
    attested_encryption_key: result.attestedEncryptionKey,
    attested_signing_key: result.attestedSigningKey,
    nonce: result.nonce,
    verified_at: result.verifiedAt,
    expires_at: result.expiresAt,
    policy_source: result.policySource,
    verifier_version: result.verifierVersion,
    supports_client_opaque_e2ee: result.supportsClientOpaqueE2ee,
    reason: result.reason,
    checks: result.checks
  };
}
