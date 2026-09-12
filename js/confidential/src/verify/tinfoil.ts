// Tinfoil verifier. Tinfoil's own SDK (`tinfoil` on npm, an OPTIONAL dependency)
// performs the hard cryptographic work: AMD SEV-SNP + NVIDIA confidential-compute
// hardware attestation, a Sigstore-transparency-log code measurement, and TLS/HPKE
// key binding, refusing to connect if any check fails. This verifier binds the SDK's
// verification DOCUMENT to the route and reports `sdk-verified` when the SDK
// confirmed security for a release signed by the supported provider authority.
// It never fabricates `hardware-verified`.

import { assembleResult, check, freshnessCheck, readEnvelope } from "./checks.js";
import { hexEqual } from "./crypto.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  TeeVerifier
} from "./types.js";

/** The sanitized verification document obtained from the Tinfoil SDK's
 *  `Verifier.verify()` / `getVerificationDocument()`. Only attested public
 *  fingerprints, which are safe to surface. */
export interface TinfoilVerificationDocument {
  schemaVersion?: number;
  securityVerified?: boolean;
  enclaveHost?: string;
  configRepo?: string;
  releaseTag?: string;
  releaseDigest?: string;
  codeMeasurement?: { type?: string; registers?: string[] };
  enclaveMeasurement?: {
    tlsPublicKeyFingerprint?: string;
    hpkePublicKey?: string;
    measurement?: { type?: string; registers?: string[] };
  };
  codeFingerprint?: string;
  enclaveFingerprint?: string;
  selectedRouterEndpoint?: string;
  tlsPublicKey?: string;
  hpkePublicKey?: string;
  verifier?: { name?: string; version?: string };
  steps?: Record<string, { status?: string; error?: string }>;
}

interface TinfoilProviderAuthorityPolicy {
  authority?: string;
  configRepo?: string;
  releaseSelection?: string;
  requireTaggedRelease?: boolean;
}

export interface TinfoilVerifierOptions {
  verifierVersion?: string;
}

export class TinfoilTeeVerifier implements TeeVerifier {
  readonly provider = "tinfoil";
  readonly verifierVersion: string;

  constructor(opts: TinfoilVerifierOptions = {}) {
    this.verifierVersion = opts.verifierVersion ?? "tinfoil-sdk/1";
  }

  // Provider capability is not gateway capability. EHBP/HPKE is not wired here.
  supportsClientOpaqueE2ee(): boolean {
    return false;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const doc = envelope.payload as TinfoilVerificationDocument | undefined;
    const checks: AttestationCheck[] = [];

    const present = Boolean(doc && typeof doc === "object");
    checks.push(check("evidence_present", present, true, present ? undefined : "no SDK verification document"));

    // The SDK is the crypto root of trust: it verified hardware + signed release
    // provenance + code/enclave equality + key binding, or refused.
    const securityVerified = doc?.securityVerified === true;
    checks.push(check("sdk_security_verified", securityVerified, true, securityVerified ? undefined : "Tinfoil SDK did not confirm enclave security"));

    const verifierIdentityOk = doc?.schemaVersion === 1
      && doc?.verifier?.name === "@tinfoilsh/verifier"
      && typeof doc.verifier.version === "string"
      && doc.verifier.version.length > 0;
    checks.push(check("official_verifier_identity", verifierIdentityOk, true,
      verifierIdentityOk ? undefined : "verification document is not from the official Tinfoil verifier"));

    const selectedRouterHost = hostFromUrl(doc?.selectedRouterEndpoint);
    const hostOk = selectedRouterHost === expectations.endpointIdentity;
    checks.push(check("enclave_host_binding", hostOk, true, hostOk ? undefined : "attested enclave host does not match route endpoint"));

    const requiredSteps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"];
    const stepsOk = requiredSteps.every((name) => doc?.steps?.[name]?.status === "success");
    checks.push(check("sdk_verification_steps", stepsOk, true, stepsOk ? undefined : "one or more SDK cryptographic steps did not succeed"));

    // The official verifier already validates the DSSE signature, Fulcio
    // repository identity, tagged workflow ref, Rekor consistency, AMD chain,
    // live measurement equality, and serving certificate. Pin that authority
    // and repository rather than copying every release fingerprint into this SDK.
    const authority = expectations.measurementPolicy?.accepted as TinfoilProviderAuthorityPolicy | undefined;
    const authorityOk = authority?.authority === "github-actions-sigstore"
      && authority.configRepo === "tinfoilsh/confidential-model-router"
      && authority.releaseSelection === "latest"
      && authority.requireTaggedRelease === true
      && doc?.configRepo === authority.configRepo;
    checks.push(check("provider_release_authority", authorityOk, true,
      authorityOk ? undefined : "release is not bound to the supported Tinfoil GitHub authority"));

    const releaseIdentityOk = typeof doc?.releaseTag === "string"
      && doc.releaseTag.length > 0
      && typeof doc.releaseDigest === "string"
      && /^[0-9a-f]{64}$/i.test(doc.releaseDigest)
      && typeof doc.codeFingerprint === "string"
      && /^[0-9a-f]{64,192}$/i.test(doc.codeFingerprint)
      && typeof doc.enclaveFingerprint === "string"
      && /^[0-9a-f]{64,192}$/i.test(doc.enclaveFingerprint);
    checks.push(check("signed_release_identity", releaseIdentityOk, true,
      releaseIdentityOk ? undefined : "signed release identity is missing or malformed"));

    const measurementOk = hexEqual(doc?.codeFingerprint, doc?.enclaveFingerprint);
    checks.push(check("code_matches_live_enclave", measurementOk, true,
      measurementOk ? undefined : "signed release measurement does not match the live enclave"));

    const servingModalitySupported = expectations.privacyModality === "tee";
    checks.push(check("serving_modality_supported", servingModalitySupported, true,
      servingModalitySupported ? undefined : "the Tinfoil route is verified TEE, not client-opaque E2EE"));

    const e2ee = expectations.privacyModality === "e2ee";
    const hpkePublicKey = doc?.enclaveMeasurement?.hpkePublicKey ?? doc?.hpkePublicKey;
    const tlsPublicKeyFingerprint = doc?.enclaveMeasurement?.tlsPublicKeyFingerprint;
    const keyOk = e2ee
      ? typeof hpkePublicKey === "string" && hpkePublicKey.length > 0
      : /^[0-9a-f]{64}$/i.test(tlsPublicKeyFingerprint ?? "")
        && hexEqual(tlsPublicKeyFingerprint, doc?.tlsPublicKey);
    checks.push(check("attested_key_binding", keyOk, true, keyOk ? undefined : "no attested key for the serving modality"));

    // Tinfoil attestation is connection-bound (SDK handshake), not caller-nonce
    // bound; record the caller's freshness intent as advisory, not required.
    checks.push(check("nonce_binding", false, false, "Tinfoil attestation is connection-bound, not nonce-bound"));
    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    return assembleResult({
      expectations,
      hardwareType: "amd-sev-snp+nvidia-cc",
      requestedLevel: "sdk-verified",
      privacyModality: expectations.privacyModality,
      measurementIdentities: {
        ...(typeof doc?.codeFingerprint === "string" ? { code: doc.codeFingerprint } : {}),
        ...(typeof doc?.enclaveFingerprint === "string" ? { enclave: doc.enclaveFingerprint } : {})
      },
      modelWeightIdentity: null,
      attestedTlsSpki: typeof tlsPublicKeyFingerprint === "string" ? tlsPublicKeyFingerprint : null,
      attestedEncryptionKey: null,
      attestedSigningKey: null,
      boundNonce: null,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: false,
      checks
    });
  }
}

function hostFromUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}
