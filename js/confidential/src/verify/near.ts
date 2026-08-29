// NEAR AI verifier. NEAR runs inference in Intel-TDX Confidential VMs and, for a
// direct route ({slug}.completions.near.ai), terminates TLS INSIDE the enclave. We
// verify (all fail-closed):
//   - the caller nonce is bound in report_data[32:64];
//   - the attested TLS SPKI is bound in report_data[0:32] == sha256(signing_addr ‖
//     tls_cert_fingerprint) (this is what proves TLS terminates in the TEE);
//   - the attested model_name equals the route's upstream model;
//   - mr_config_id binds the pinned app_compose document (== "01" + sha256(compose));
//   - boot measurements match NEAR's reviewed allowlist (incl. composeSha256);
//   - TD debug is disabled and NVIDIA GPU evidence is present.
// The raw TDX/NRAS chains are not cryptographically chained to vendor roots here, so
// the honest ceiling is `provider-attested`.

import { assembleResult, check, freshnessCheck, hexEqual, nonceBindingCheck, readEnvelope } from "./checks.js";
import { fromHex, sha256Hex } from "./crypto.js";
import { matchMeasurementAllowlist, parseTdxQuote, TDX_TEE_TYPE, type TdxMeasurementEntry } from "./tdx.js";
import { concatBytes } from "../bytes.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  TeeVerifier
} from "./types.js";

const ALL_ZERO_MR_CONFIG = "00".repeat(48);

interface NearAttestationPayload {
  intel_quote?: unknown;
  nvidia_payload?: unknown;
  tls_cert_fingerprint?: unknown;
  model_name?: unknown;
  signing_address?: unknown;
  signing_algo?: unknown;
  signing_public_key?: unknown;
  app_compose?: unknown;
  compose_hash?: unknown;
  info?: { tcb_info?: { app_compose?: { docker_compose_file?: unknown } } };
}

export interface NearVerifierOptions {
  verifierVersion?: string;
}

export class NearTeeVerifier implements TeeVerifier {
  readonly provider = "near-ai";
  readonly verifierVersion: string;

  constructor(opts: NearVerifierOptions = {}) {
    this.verifierVersion = opts.verifierVersion ?? "near-tdx/1";
  }

  supportsClientOpaqueE2ee(): boolean {
    return true;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const payload = envelope.payload as NearAttestationPayload | undefined;
    const checks: AttestationCheck[] = [];

    const quoteRaw = payload?.intel_quote;
    const hasQuote = typeof quoteRaw === "string" && quoteRaw.length > 0;
    checks.push(check("evidence_present", hasQuote, true, hasQuote ? undefined : "no intel_quote in report"));
    const parsed = hasQuote ? parseTdxQuote(quoteRaw) : null;
    checks.push(check("quote_parsed", parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));

    const measurements: Record<string, string> = {};
    const tlsFingerprint = typeof payload?.tls_cert_fingerprint === "string" ? payload.tls_cert_fingerprint : null;
    const signingAddress = typeof payload?.signing_address === "string" ? payload.signing_address : null;
    const modelName = typeof payload?.model_name === "string" ? payload.model_name : null;
    const appCompose = typeof payload?.app_compose === "string"
      ? payload.app_compose
      : typeof payload?.info?.tcb_info?.app_compose?.docker_compose_file === "string"
        ? (payload.info.tcb_info.app_compose.docker_compose_file as string)
        : null;
    let matchedPolicy = false;

    if (parsed) {
      measurements.mrtd = parsed.mrTd;
      measurements.rtmr0 = parsed.rtmr0;
      measurements.rtmr1 = parsed.rtmr1;
      measurements.rtmr2 = parsed.rtmr2;
      measurements.rtmr3 = parsed.rtmr3;
      measurements.mr_config_id = parsed.mrConfigId;

      checks.push(check("expected_tee_type", parsed.teeType === TDX_TEE_TYPE, true,
        parsed.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
      checks.push(check("debug_disabled", !parsed.debugEnabled, true, parsed.debugEnabled ? "TD debug mode enabled" : undefined));

      // report_data layout: [0:32] = sha256(signing_address ‖ tls_fingerprint);
      // [32:64] = nonce.
      const reportFirst = parsed.reportData.slice(0, 64);
      const reportSecond = parsed.reportData.slice(64, 128);
      checks.push(nonceBindingCheck(expectations.nonce, reportSecond));

      if (tlsFingerprint && signingAddress) {
        let expectedFirst: string | null = null;
        try {
          expectedFirst = sha256Hex(concatBytes(fromHex(signingAddress), fromHex(tlsFingerprint)));
        } catch {
          expectedFirst = null;
        }
        checks.push(check("tls_spki_binding", hexEqual(reportFirst, expectedFirst), true,
          expectedFirst ? undefined : "malformed signing_address/tls fingerprint"));
      } else {
        checks.push(check("tls_spki_binding", false, true, "attestation did not bind a TLS SPKI"));
      }

      // mr_config_id binds the exact app_compose document.
      const composeSha256 = appCompose ? sha256Hex(appCompose) : null;
      if (composeSha256 && parsed.mrConfigId !== ALL_ZERO_MR_CONFIG) {
        const expectedConfig = ("01" + composeSha256).padEnd(96, "0");
        const reportedComposeHash = typeof payload?.compose_hash === "string" ? payload.compose_hash : null;
        checks.push(check("compose_binding", hexEqual(parsed.mrConfigId, expectedConfig), true, undefined));
        checks.push(check("reported_compose_hash", hexEqual(reportedComposeHash, composeSha256), true,
          reportedComposeHash ? undefined : "report did not include compose hash"));
      } else if (parsed.mrConfigId === ALL_ZERO_MR_CONFIG) {
        checks.push(check("compose_binding", false, true, "mr_config_id is all-zero and does not bind the compose"));
      } else {
        checks.push(check("compose_binding", false, true, "no app_compose provided to bind"));
      }

      const allowlist = (expectations.measurementPolicy?.accepted as Array<TdxMeasurementEntry & { composeSha256?: string }> | undefined) ?? [];
      if (allowlist.length > 0) {
        const matchedName = matchMeasurementAllowlist(parsed, allowlist);
        const matchedEntry = matchedName ? allowlist.find((entry) => entry.name === matchedName) : undefined;
        matchedPolicy = Boolean(matchedEntry)
          && typeof matchedEntry?.composeSha256 === "string"
          && hexEqual(matchedEntry.composeSha256, composeSha256);
        checks.push(check("measurement_allowlist", matchedPolicy, true, matchedPolicy ? undefined : "measurements not in accepted allowlist"));
      } else {
        checks.push(check("measurement_allowlist", false, true, "no accepted-measurement policy pinned"));
      }
    }

    checks.push(check("model_binding", modelName === expectations.upstreamModel, true, modelName ? undefined : "attestation did not name a model"));

    const gpuOk = typeof payload?.nvidia_payload === "string" && (payload.nvidia_payload as string).length > 0;
    checks.push(check("gpu_evidence_present", gpuOk, true, gpuOk ? undefined : "no NVIDIA GPU evidence"));

    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    const boundNonce = parsed ? parsed.reportData.slice(64, 128) : null;
    return assembleResult({
      expectations,
      hardwareType: "intel-tdx+nvidia-cc",
      // Ceiling is provider-attested: the DCAP/NRAS chain is deliberately not wired.
      requestedLevel: "provider-attested",
      privacyModality: expectations.privacyModality,
      measurementIdentities: measurements,
      modelWeightIdentity: null,
      attestedTlsSpki: tlsFingerprint,
      attestedEncryptionKey: typeof payload?.signing_public_key === "string" ? payload.signing_public_key : null,
      attestedSigningKey: signingAddress,
      boundNonce: parsed && hexEqual(expectations.nonce, boundNonce) ? expectations.nonce : boundNonce,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: true,
      checks
    });
  }
}
