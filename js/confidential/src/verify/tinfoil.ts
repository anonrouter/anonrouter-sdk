// Tinfoil verifier. Tinfoil's own SDK (`tinfoil` on npm, an OPTIONAL dependency)
// performs the hard cryptographic work: AMD SEV-SNP + NVIDIA confidential-compute
// hardware attestation, a Sigstore-transparency-log code measurement, and TLS/HPKE
// key binding, refusing to connect if any check fails. This verifier binds the SDK's
// verification DOCUMENT to the route and reports `sdk-verified` when the SDK
// confirmed security AND the code fingerprint is on the operator-reviewed allowlist.
// It never fabricates `hardware-verified`.

import { assembleResult, check, freshnessCheck, readEnvelope } from "./checks.js";
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
  steps?: Record<string, { status?: string; error?: string }>;
}

interface TinfoilAcceptedRelease {
  codeFingerprint: string;
  releaseDigest?: string;
  releaseTag?: string;
  enclaveFingerprint?: string;
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

    // The SDK is the crypto root of trust: it verified hardware + code + weights +
    // key binding, or refused. Require its explicit securityVerified === true.
    const securityVerified = doc?.securityVerified === true;
    checks.push(check("sdk_security_verified", securityVerified, true, securityVerified ? undefined : "Tinfoil SDK did not confirm enclave security"));

    const selectedRouterHost = hostFromUrl(doc?.selectedRouterEndpoint);
    const hostOk = selectedRouterHost === expectations.endpointIdentity;
    checks.push(check("enclave_host_binding", hostOk, true, hostOk ? undefined : "attested enclave host does not match route endpoint"));

    const requiredSteps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"];
    const stepsOk = requiredSteps.every((name) => doc?.steps?.[name]?.status === "success");
    checks.push(check("sdk_verification_steps", stepsOk, true, stepsOk ? undefined : "one or more SDK cryptographic steps did not succeed"));

    // Pin the Sigstore-verified code fingerprint/release tuple against the
    // operator-reviewed allowlist. A mutable upstream "latest" tag never earns
    // sdk-verified on its own.
    const accepted = (expectations.measurementPolicy?.accepted as TinfoilAcceptedRelease[] | undefined) ?? [];
    if (accepted.length > 0) {
      const measurementOk = accepted.some((entry) =>
        typeof doc?.codeFingerprint === "string"
        && doc.codeFingerprint === entry.codeFingerprint
        && (!entry.releaseDigest || doc.releaseDigest === entry.releaseDigest)
        && (!entry.releaseTag || doc.releaseTag === entry.releaseTag)
        && (!entry.enclaveFingerprint || doc.enclaveFingerprint === entry.enclaveFingerprint)
      );
      checks.push(check("code_measurement_allowlist", measurementOk, true, measurementOk ? undefined : "code measurement not in accepted allowlist"));
    } else {
      checks.push(check("code_measurement_allowlist", false, true, "no accepted code-measurement policy pinned"));
    }

    const servingModalitySupported = expectations.privacyModality === "tee";
    checks.push(check("serving_modality_supported", servingModalitySupported, true,
      servingModalitySupported ? undefined : "the Tinfoil route is verified TEE, not client-opaque E2EE"));

    const e2ee = expectations.privacyModality === "e2ee";
    const hpkePublicKey = doc?.enclaveMeasurement?.hpkePublicKey ?? doc?.hpkePublicKey;
    const tlsPublicKeyFingerprint = doc?.enclaveMeasurement?.tlsPublicKeyFingerprint;
    const keyOk = e2ee
      ? typeof hpkePublicKey === "string" && hpkePublicKey.length > 0
      : typeof tlsPublicKeyFingerprint === "string" && tlsPublicKeyFingerprint.length > 0
        && typeof doc?.tlsPublicKey === "string" && doc.tlsPublicKey.length > 0;
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
