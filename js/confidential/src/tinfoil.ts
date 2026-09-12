// Direct, gateway-independent Tinfoil verification.
//
// Tinfoil is TEE-only (not client-opaque E2EE). Its own verifier (`tinfoil` on
// npm, an OPTIONAL dependency) does the hard cryptographic work: AMD SEV-SNP
// hardware attestation, a Sigstore-transparency-log code measurement, and the
// enclave key binding, refusing to continue if any step fails.
//
// This wrapper is what makes the check INDEPENDENT rather than a second reading
// of the same document. It runs that verifier against the enclave host, then
// opens its own content-free, pinned TLS connection and reads the peer's SPKI
// off the wire, and only then hands the document plus that observation to the
// ported TinfoilTeeVerifier. Without the observation the TLS part of the verdict
// would be a tautology: the document states the attested key twice, so the two
// copies always agree, including in a document that describes no real enclave.
//
// Fails CLOSED throughout, and never fabricates a passing verdict. Each refusal
// returns `status: "failed"` with `reason: "evidence_present"` (the required
// check that could not be satisfied) and one of these in that check's `detail`,
// which is where the specific cause is reported:
//   - `tinfoil` not installed          -> "tinfoil_sdk_not_installed"
//   - unsupported host / repository    -> "tinfoil_enclave_host_not_supported",
//                                         "tinfoil_config_repo_not_supported"
//   - verifier absent or threw         -> "tinfoil_sdk_verification_unavailable"
//   - no usable attested TLS key       -> "tinfoil_attested_tls_key_unavailable"
//   - pin mismatch / cert failure      -> "tinfoil_tls_pin_mismatch"
//   - runtime cannot observe TLS       -> "tinfoil_tls_observation_unsupported"
//
// RUNTIME. Importing `@anonrouter/confidential` stays browser-safe: the Node
// builtins are reached through non-literal dynamic specifiers, so nothing here
// is statically resolved. CALLING this function is Node-only, because no browser
// can inspect a peer certificate. In a browser it fails closed on
// `tinfoil_tls_observation_unsupported` rather than degrading to an unpinned
// check, and callers who need in-browser assurance should use an E2EE route.

import { failedResult } from "./verify/checks.js";
import {
  TinfoilTeeVerifier,
  TINFOIL_ENDPOINT_IDENTITY,
  type TinfoilVerificationDocument
} from "./verify/tinfoil.js";
import { buildExpectations } from "./verify/index.js";
import {
  TinfoilTlsUnavailableError,
  observeTinfoilTlsSpki,
  type TinfoilTlsProbeOptions
} from "./tinfoil-tls.js";
import { toNormalizedVerdict, type NormalizedVerdict } from "./verify/types.js";

/** The exact surface of Tinfoil's official verifier this wrapper uses. */
export interface TinfoilSdkVerifier {
  verify(): Promise<unknown>;
  getVerificationDocument?(): unknown;
}

/**
 * Test and advanced-integration seams. Supplying either of these REPLACES the
 * thing that makes this function independent, so production callers should pass
 * neither: `verifierFactory` replaces Tinfoil's own cryptographic verification,
 * and `observeTlsSpki` replaces the real connection whose key is pinned. They
 * exist so the negative tests can prove each check fails closed on its own.
 */
export interface TinfoilVerifyDependencies {
  verifierFactory?: (options: { serverURL: string; configRepo: string })
    => TinfoilSdkVerifier | Promise<TinfoilSdkVerifier>;
  observeTlsSpki?: (options: TinfoilTlsProbeOptions) => Promise<string>;
}

export interface TinfoilVerifyOptions {
  /** The Tinfoil enclave / router host to attest. Must be the supported
   *  `inference.tinfoil.sh`; any other host fails closed. */
  enclaveHost: string;
  /** The Tinfoil config repo the release measurement is pinned against, e.g.
   *  "tinfoilsh/confidential-model-router". */
  configRepo?: string;
  /** Public catalog model id (used only to fill the expectations; Tinfoil's
   *  measurement is model-agnostic per host + configRepo). */
  model?: string;
  /** Injectable clock (ms) for deterministic freshness. */
  now?: number;
  /** Deadline for the pinned TLS observation. */
  tlsTimeoutMs?: number;
  /** See `TinfoilVerifyDependencies`. Omit in production. */
  dependencies?: TinfoilVerifyDependencies;
}

const VERIFIER = new TinfoilTeeVerifier();
const TINFOIL_CONFIG_REPO = "tinfoilsh/confidential-model-router";

function endpointHost(value: string): string {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).host;
  } catch {
    return value;
  }
}

function failClosed(options: TinfoilVerifyOptions, reason: string): NormalizedVerdict {
  const expectations = buildExpectations("tinfoil", {
    upstreamModel: options.model ?? options.enclaveHost,
    nonce: "",
    endpointIdentity: endpointHost(options.enclaveHost),
    privacyModality: "tee",
    now: options.now
  });
  return toNormalizedVerdict(failedResult(expectations, reason, VERIFIER.verifierVersion, { hardwareType: "amd-sev-snp" }));
}

/** Dynamically import the optional `tinfoil` SDK. Returns null when it is not
 *  installed (a non-literal specifier keeps it out of static module resolution so a
 *  browser/Node build that omits the optional dep still compiles). */
async function loadTinfoilSdk(): Promise<Record<string, unknown> | null> {
  const specifier = "tinfoil";
  try {
    return (await import(specifier)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Construct the official verifier with the options the current `tinfoil`
 *  package documents (`{ serverURL, configRepo }`). */
async function officialVerifier(
  sdk: Record<string, unknown>,
  options: { serverURL: string; configRepo: string }
): Promise<TinfoilSdkVerifier | null> {
  const VerifierCtor = sdk.Verifier as
    | (new (value: { serverURL: string; configRepo: string }) => TinfoilSdkVerifier)
    | undefined;
  if (typeof VerifierCtor !== "function") return null;
  return new VerifierCtor(options);
}

/** Run the official verifier and return its document, or null if either failed. */
async function obtainVerificationDocument(
  verifier: TinfoilSdkVerifier
): Promise<TinfoilVerificationDocument | null> {
  try {
    const verifyResult = await verifier.verify();
    const doc = typeof verifier.getVerificationDocument === "function"
      ? await verifier.getVerificationDocument()
      : verifyResult;
    return doc && typeof doc === "object" ? (doc as TinfoilVerificationDocument) : null;
  } catch {
    return null;
  }
}

/**
 * Verify a Tinfoil enclave yourself, without trusting AnonRouter for any part of
 * it, and return the normalized verdict.
 *
 * Two independent steps, both required. Tinfoil's official verifier authenticates
 * the signed tagged release, the AMD SEV-SNP report, and equality between the
 * signed code and the live enclave. This function then opens its own pinned TLS
 * connection to the enclave and records the peer SPKI it actually observes, so
 * the attested key is bound to a connection rather than to a second copy of
 * itself. `sdk-verified` is reported only when both hold and every required
 * check passes.
 *
 * The request sent is one HEAD with no credential, no body and no account
 * identity, and the response is discarded unread. Nothing is billed and no
 * inference is performed.
 *
 * Node.js only. See the runtime note at the top of this file.
 */
export async function verifyTinfoilEnclave(options: TinfoilVerifyOptions): Promise<NormalizedVerdict> {
  if (options.configRepo && options.configRepo !== TINFOIL_CONFIG_REPO) {
    return failClosed(options, "tinfoil_config_repo_not_supported");
  }
  if (endpointHost(options.enclaveHost) !== TINFOIL_ENDPOINT_IDENTITY) {
    return failClosed(options, "tinfoil_enclave_host_not_supported");
  }
  const configRepo = options.configRepo ?? TINFOIL_CONFIG_REPO;
  const serverURL = `https://${TINFOIL_ENDPOINT_IDENTITY}`;
  const dependencies = options.dependencies ?? {};

  let verifier: TinfoilSdkVerifier | null = null;
  let sdkMissing = false;
  try {
    if (dependencies.verifierFactory) {
      verifier = await dependencies.verifierFactory({ serverURL, configRepo });
    } else {
      const sdk = await loadTinfoilSdk();
      sdkMissing = !sdk;
      if (sdk) verifier = await officialVerifier(sdk, { serverURL, configRepo });
    }
  } catch {
    // A constructor that throws is a verifier we do not have. Fail closed like
    // any other missing verification rather than propagating to the caller.
    verifier = null;
  }
  if (sdkMissing) return failClosed(options, "tinfoil_sdk_not_installed");
  if (!verifier) return failClosed(options, "tinfoil_sdk_verification_unavailable");

  const doc = await obtainVerificationDocument(verifier);
  if (!doc) return failClosed(options, "tinfoil_sdk_verification_unavailable");

  // Pin against the key in the VERIFIED report, never against whatever the peer
  // happens to present. A document without one cannot be bound to a connection
  // at all, so it fails here rather than later with a vaguer reason.
  const attestedTlsSpki = doc.enclaveMeasurement?.tlsPublicKeyFingerprint;
  if (doc.securityVerified !== true || !/^[0-9a-f]{64}$/i.test(attestedTlsSpki ?? "")) {
    return failClosed(options, "tinfoil_attested_tls_key_unavailable");
  }

  const observe = dependencies.observeTlsSpki ?? observeTinfoilTlsSpki;
  let observedTlsSpki: string;
  try {
    observedTlsSpki = await observe({
      origin: serverURL,
      expectedTlsSpki: attestedTlsSpki!,
      timeoutMs: options.tlsTimeoutMs
    });
  } catch (error) {
    return failClosed(
      options,
      error instanceof TinfoilTlsUnavailableError
        ? "tinfoil_tls_observation_unsupported"
        : "tinfoil_tls_pin_mismatch"
    );
  }

  const expectations = buildExpectations("tinfoil", {
    upstreamModel: options.model ?? options.enclaveHost,
    nonce: "",
    endpointIdentity: TINFOIL_ENDPOINT_IDENTITY,
    privacyModality: "tee",
    now: options.now
  });
  // Attach the observation to a COPY. The verifier is pure and must grade the
  // document plus the binding this process actually made, with no chance of the
  // SDK's own object being mutated underneath a later caller.
  const bound: TinfoilVerificationDocument = {
    ...doc,
    transportBinding: {
      mode: "tls-pinned",
      endpointIdentity: TINFOIL_ENDPOINT_IDENTITY,
      observedTlsSpki,
      verified: true
    }
  };
  return toNormalizedVerdict(VERIFIER.verifyAttestation(bound, expectations));
}
