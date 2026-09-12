// Tinfoil verifier. Tinfoil's own SDK (`tinfoil` on npm, an OPTIONAL dependency)
// performs the hard cryptographic work: AMD SEV-SNP hardware attestation, a
// Sigstore-transparency-log code measurement, and the enclave key binding,
// refusing to connect if any check fails. This verifier binds the SDK's
// verification DOCUMENT to the route and reports `sdk-verified` when the SDK
// confirmed security for a release signed by the supported provider authority.
// It never fabricates `hardware-verified`.
//
// What this verifier does NOT establish, and must never be read as establishing:
// no NVIDIA GPU confidential-compute evidence is checked anywhere on this route,
// and nothing binds the model weights. The hardware claim is AMD SEV-SNP alone.
//
// The serving TLS key is the one place where a document can look self-proving
// and not be. The official document repeats the SAME AMD-report field as
// `enclaveMeasurement.tlsPublicKeyFingerprint` and `tlsPublicKey`, so comparing
// those two to each other is a tautology: it passes for any document, including
// one an endpoint substitution forged wholesale. The attested fingerprint is
// therefore only accepted against a `transportBinding` that whoever produced the
// document recorded from a REAL pinned connection to the enclave. A document
// carrying no such observation fails closed, however well formed it is.

import { assembleResult, check, freshnessCheck, readEnvelope } from "./checks.js";
import { hexEqual } from "./crypto.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  TeeVerifier
} from "./types.js";

/** The one Tinfoil endpoint this SDK supports. Fixed, not caller-supplied: an
 *  endpoint the caller could name is an endpoint an attacker could name. */
export const TINFOIL_ENDPOINT_IDENTITY = "inference.tinfoil.sh";

/** An independently observed pinned-TLS binding for the serving connection.
 *  Produced by whoever actually opened the connection (AnonRouter's measured
 *  worker on the gateway path, or `verifyTinfoilEnclave()` locally), never
 *  copied out of the attestation document. */
export interface TinfoilTransportBinding {
  /** Only `tls-pinned` is accepted. */
  mode?: string;
  /** Host the pinned connection was actually made to. */
  endpointIdentity?: string;
  /** SHA-256 of the peer certificate's SPKI, read off that connection. */
  observedTlsSpki?: string;
  /** True only after ordinary PKI/hostname validation AND the exact SPKI match. */
  verified?: boolean;
}

/** The sanitized verification document obtained from the Tinfoil SDK's
 *  `Verifier.verify()` / `getVerificationDocument()`, plus the transport binding
 *  observed on the serving connection. Only attested public fingerprints, which
 *  are safe to surface. */
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
  transportBinding?: TinfoilTransportBinding;
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

    // The SDK is the crypto root of trust for the EVIDENCE: it verified the AMD
    // SEV-SNP report, the signed release provenance, and code/enclave equality,
    // or refused. It cannot vouch for the connection this route is served over,
    // which is why `attested_key_binding` below needs an observation instead.
    const securityVerified = doc?.securityVerified === true;
    checks.push(check("sdk_security_verified", securityVerified, true, securityVerified ? undefined : "Tinfoil SDK did not confirm enclave security"));

    const verifierIdentityOk = doc?.schemaVersion === 1
      && doc?.verifier?.name === "@tinfoilsh/verifier"
      && typeof doc.verifier.version === "string"
      && doc.verifier.version.length > 0;
    checks.push(check("official_verifier_identity", verifierIdentityOk, true,
      verifierIdentityOk ? undefined : "verification document is not from the official Tinfoil verifier"));

    // BOTH endpoint identities the document carries must be the fixed Tinfoil
    // host, and so must the route the caller is verifying. Checking only
    // `selectedRouterEndpoint` left `enclaveHost` free to name somewhere else,
    // and comparing either field to a caller-supplied endpoint would be a
    // tautology that accepts whatever host the document itself chose.
    const selectedRouterHost = hostFromUrl(doc?.selectedRouterEndpoint);
    const enclaveHost = hostFromUrl(doc?.enclaveHost);
    const hostOk = selectedRouterHost === TINFOIL_ENDPOINT_IDENTITY
      && enclaveHost === TINFOIL_ENDPOINT_IDENTITY
      && expectations.endpointIdentity === TINFOIL_ENDPOINT_IDENTITY;
    checks.push(check("enclave_host_binding", hostOk, true, hostOk ? undefined : "attested enclave host does not match route endpoint"));

    const requiredSteps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"];
    const stepsOk = requiredSteps.every((name) => doc?.steps?.[name]?.status === "success");
    checks.push(check("sdk_verification_steps", stepsOk, true, stepsOk ? undefined : "one or more SDK cryptographic steps did not succeed"));

    // The official verifier already validates the DSSE signature, Fulcio
    // repository identity, tagged workflow ref, Rekor consistency, AMD chain,
    // live measurement equality, and serving certificate. Pin that authority
    // and repository rather than copying every release fingerprint into this SDK.
    //
    // Read the four policy fields for what they are. `configRepo` is load-bearing
    // here: it is compared against the repository the document names, so a
    // different repository fails closed. `authority`, `releaseSelection` and
    // `requireTaggedRelease` are LABELS. They record which Tinfoil workflow this
    // package was reviewed against and pin the policy file against a silent edit;
    // nothing in this SDK re-derives them from the evidence, because the document
    // does not carry the Fulcio identity or workflow ref they would be checked
    // against. The tagged-release and release-selection guarantees are the
    // official verifier's, exercised by `verifyCode` / `fetchDigest`, and that is
    // where they are enforced. Do not describe them as independent SDK checks.
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

    // The wired TLS modality must bind the ACTUAL serving connection. The
    // attested fingerprint on its own is not enough, and neither is the document
    // agreeing with itself: `tlsPublicKeyFingerprint` and `tlsPublicKey` are two
    // copies of one AMD-report field, so comparing them passes for every
    // document ever produced. Require instead a transport binding recorded from
    // a real pinned connection, and require the key observed there to equal the
    // key in the verified report.
    const e2ee = expectations.privacyModality === "e2ee";
    const hpkePublicKey = doc?.enclaveMeasurement?.hpkePublicKey ?? doc?.hpkePublicKey;
    const tlsPublicKeyFingerprint = doc?.enclaveMeasurement?.tlsPublicKeyFingerprint;
    const binding = doc?.transportBinding;
    const keyOk = e2ee
      ? typeof hpkePublicKey === "string" && hpkePublicKey.length > 0
      : /^[0-9a-f]{64}$/i.test(tlsPublicKeyFingerprint ?? "")
        && binding?.mode === "tls-pinned"
        && binding.verified === true
        && binding.endpointIdentity === TINFOIL_ENDPOINT_IDENTITY
        && hexEqual(tlsPublicKeyFingerprint, binding.observedTlsSpki);
    const keyDetail = e2ee
      ? "no attested HPKE key for the client-opaque modality"
      : "attested TLS key is missing, or was not confirmed by an observed pinned connection to the enclave";
    checks.push(check("attested_key_binding", keyOk, true, keyOk ? undefined : keyDetail));

    // Tinfoil attestation is connection-bound (SDK handshake), not caller-nonce
    // bound; record the caller's freshness intent as advisory, not required.
    checks.push(check("nonce_binding", false, false, "Tinfoil attestation is connection-bound, not nonce-bound"));
    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    return assembleResult({
      expectations,
      // AMD SEV-SNP alone. The official verifier establishes no NVIDIA GPU
      // confidential-compute evidence, so reporting a combined hardware type
      // would claim a chain nobody checked.
      hardwareType: "amd-sev-snp",
      requestedLevel: "sdk-verified",
      privacyModality: expectations.privacyModality,
      measurementIdentities: {
        ...(typeof doc?.codeFingerprint === "string" ? { code: doc.codeFingerprint } : {}),
        ...(typeof doc?.enclaveFingerprint === "string" ? { enclave: doc.enclaveFingerprint } : {})
      },
      // The document proves the release/code measurement and the enclave keys. It
      // exposes no model-weight digest, so never invent one from the requested
      // model id.
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
