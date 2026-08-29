// Optional-dependency wrapper for Tinfoil verification. Tinfoil is TEE-only (not
// client-opaque E2EE): its own SDK (`tinfoil` on npm, an OPTIONAL dependency) does
// the hard cryptographic work (AMD SEV-SNP + NVIDIA CC hardware attestation, a
// Sigstore-transparency-log code measurement, TLS/HPKE key binding) and refuses to
// connect if any check fails. This wrapper runs that SDK's Verifier against the
// enclave host, then maps its verification DOCUMENT through the ported
// TinfoilTeeVerifier so the result is one normalized verdict shape across providers.
//
// If `tinfoil` is not installed, this fails CLOSED: status "failed", reason
// "tinfoil_sdk_not_installed". It never fabricates a passing verdict.

import { failedResult } from "./verify/checks.js";
import { TinfoilTeeVerifier, type TinfoilVerificationDocument } from "./verify/tinfoil.js";
import { buildExpectations } from "./verify/index.js";
import { toNormalizedVerdict, type NormalizedVerdict } from "./verify/types.js";

export interface TinfoilVerifyOptions {
  /** The Tinfoil enclave / router host to attest, e.g. "inference.tinfoil.sh". */
  enclaveHost: string;
  /** The Tinfoil config repo the release measurement is pinned against, e.g.
   *  "tinfoilsh/confidential-model-router". */
  configRepo?: string;
  /** Public catalog model id (used only to fill the expectations; Tinfoil's
   *  measurement is model-agnostic per host + configRepo). */
  model?: string;
  /** Injectable clock (ms) for deterministic freshness. */
  now?: number;
}

const VERIFIER = new TinfoilTeeVerifier();

function failClosed(options: TinfoilVerifyOptions, reason: string): NormalizedVerdict {
  const expectations = buildExpectations("tinfoil", {
    upstreamModel: options.model ?? options.enclaveHost,
    nonce: "",
    endpointIdentity: options.enclaveHost,
    privacyModality: "tee",
    now: options.now
  });
  return toNormalizedVerdict(failedResult(expectations, reason, VERIFIER.verifierVersion, { hardwareType: "amd-sev-snp+nvidia-cc" }));
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

/** Best-effort extraction of a verification document from whatever surface the
 *  installed Tinfoil SDK exposes. Returns null when no document can be obtained. */
async function obtainVerificationDocument(
  sdk: Record<string, unknown>,
  options: TinfoilVerifyOptions
): Promise<TinfoilVerificationDocument | null> {
  const VerifierCtor = (sdk.Verifier ?? sdk.SecureClient ?? sdk.default) as
    | (new (...args: unknown[]) => Record<string, unknown>)
    | undefined;
  if (typeof VerifierCtor !== "function") return null;
  try {
    const args = options.configRepo ? [options.enclaveHost, options.configRepo] : [options.enclaveHost];
    const verifier = new VerifierCtor(...args) as Record<string, unknown>;
    const verifyFn = verifier.verify as ((...a: unknown[]) => Promise<unknown>) | undefined;
    const verifyResult = typeof verifyFn === "function" ? await verifyFn.call(verifier) : undefined;
    const getDocFn = verifier.getVerificationDocument as ((...a: unknown[]) => unknown) | undefined;
    const doc = typeof getDocFn === "function" ? await getDocFn.call(verifier) : verifyResult;
    return (doc && typeof doc === "object" ? (doc as TinfoilVerificationDocument) : null);
  } catch {
    return null;
  }
}

/**
 * Verify a Tinfoil enclave with the official Tinfoil SDK and return the normalized
 * verdict (`sdk-verified` when the SDK confirmed security and the code fingerprint
 * is on the operator-reviewed allowlist). Fails closed when the SDK is missing or
 * its verification did not pass.
 */
export async function verifyTinfoilEnclave(options: TinfoilVerifyOptions): Promise<NormalizedVerdict> {
  const sdk = await loadTinfoilSdk();
  if (!sdk) return failClosed(options, "tinfoil_sdk_not_installed");

  const doc = await obtainVerificationDocument(sdk, options);
  if (!doc) return failClosed(options, "tinfoil_sdk_verification_unavailable");

  const expectations = buildExpectations("tinfoil", {
    upstreamModel: options.model ?? options.enclaveHost,
    nonce: "",
    endpointIdentity: options.enclaveHost,
    privacyModality: "tee",
    now: options.now
  });
  return toNormalizedVerdict(VERIFIER.verifyAttestation(doc, expectations));
}
