// Venice TEE/E2EE verifier. Venice returns an Intel TDX quote, NVIDIA evidence, a
// nonce, and a secp256k1 signing/encryption key. We validate the structural quote
// bindings: the signing address derives from the attested key (keccak256 Ethereum
// address), the address is bound in report_data[0:32], the caller nonce is bound in
// report_data[64:128], the model matches, the key is in the attested workload
// keyset, and the nested attestation report_data matches the quote. Full
// Intel/NVIDIA vendor-root verification is deliberately not inferred, so the honest
// ceiling is `provider-attested`.

import { assembleResult, check, freshnessCheck, hexEqual, readEnvelope } from "./checks.js";
import { secp256k1AddressFromPublicKey } from "./crypto.js";
import { parseTdxQuote, TDX_TEE_TYPE } from "./tdx.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  TeeVerifier
} from "./types.js";

interface VeniceAttestationPayload {
  intel_quote?: unknown;
  nvidia_payload?: unknown;
  nonce?: unknown;
  model?: unknown;
  signing_address?: unknown;
  signing_public_key?: unknown;
  signing_key?: unknown;
  signing_algo?: unknown;
  attestation?: {
    report_data?: unknown;
    workload_keyset?: { e2ee_public_keys?: Array<{ algo?: unknown; public_key?: unknown }> };
    evidence?: { quote_report_data?: unknown };
  };
}

export interface VeniceVerifierOptions {
  verifierVersion?: string;
}

export class VeniceTeeVerifier implements TeeVerifier {
  readonly provider = "venice";
  readonly verifierVersion: string;

  constructor(opts: VeniceVerifierOptions = {}) {
    this.verifierVersion = opts.verifierVersion ?? "venice-tdx-receipt/2";
  }

  supportsClientOpaqueE2ee(): boolean {
    return true;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const payload = envelope.payload as VeniceAttestationPayload | undefined;
    const checks: AttestationCheck[] = [];
    const quoteRaw = typeof payload?.intel_quote === "string" ? payload.intel_quote : null;
    const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
    const nonce = typeof payload?.nonce === "string" ? payload.nonce : null;
    const model = typeof payload?.model === "string" ? payload.model : null;
    const signingAddress = typeof payload?.signing_address === "string" ? payload.signing_address.toLowerCase() : null;
    const signingPublicKey = typeof payload?.signing_public_key === "string"
      ? payload.signing_public_key
      : typeof payload?.signing_key === "string" ? payload.signing_key : null;
    const derivedAddress = signingPublicKey ? secp256k1AddressFromPublicKey(signingPublicKey) : null;

    checks.push(check("evidence_present", Boolean(payload && quoteRaw), true, quoteRaw ? undefined : "no Intel quote"));
    checks.push(check("quote_parsed", parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));
    checks.push(check("expected_tee_type", parsed?.teeType === TDX_TEE_TYPE, true,
      parsed?.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
    checks.push(check("debug_disabled", parsed !== null && !parsed.debugEnabled, true,
      parsed?.debugEnabled ? "TD debug mode enabled" : undefined));
    checks.push(check("nonce_binding", Boolean(parsed && nonce && hexEqual(nonce, expectations.nonce)
      && hexEqual(parsed.reportData.slice(64, 128), expectations.nonce)), true,
    nonce ? undefined : "attestation did not carry the caller nonce"));
    checks.push(check("model_binding", model === expectations.upstreamModel, true,
      model ? undefined : "attestation did not name the route model"));
    checks.push(check("signing_algorithm", payload?.signing_algo === "ecdsa", true,
      payload?.signing_algo === "ecdsa" ? undefined : "unsupported attested signing algorithm"));
    checks.push(check("signing_key_address", Boolean(derivedAddress && signingAddress && hexEqual(derivedAddress, signingAddress)), true,
      derivedAddress ? undefined : "attested secp256k1 key was missing or malformed"));

    const addressReportPrefix = signingAddress && /^0x[0-9a-f]{40}$/.test(signingAddress)
      ? signingAddress.slice(2).padEnd(64, "0")
      : null;
    checks.push(check("signing_address_quote_binding", Boolean(parsed && addressReportPrefix
      && hexEqual(parsed.reportData.slice(0, 64), addressReportPrefix)), true,
    addressReportPrefix ? undefined : "attested signing address was malformed"));

    const reportedReportData = typeof payload?.attestation?.report_data === "string" ? payload.attestation.report_data : null;
    const evidenceReportData = typeof payload?.attestation?.evidence?.quote_report_data === "string"
      ? payload.attestation.evidence.quote_report_data : null;
    const reportedQuoteBound = Boolean(parsed
      && hexEqual(reportedReportData, parsed.reportData)
      && hexEqual(evidenceReportData, parsed.reportData));
    checks.push(check("reported_quote_binding", reportedQuoteBound, true,
      reportedQuoteBound ? undefined : "nested attestation report_data did not match the quote"));

    const keysetKeys = payload?.attestation?.workload_keyset?.e2ee_public_keys;
    const keyInWorkload = Array.isArray(keysetKeys) && keysetKeys.some((entry) =>
      entry?.algo === "secp256k1-aes-256-gcm-hkdf-sha256"
      && typeof entry.public_key === "string"
      && signingPublicKey !== null
      && hexEqual(entry.public_key, signingPublicKey)
    );
    checks.push(check("workload_keyset_binding", keyInWorkload, true,
      keyInWorkload ? undefined : "signing key was not in the attested workload keyset"));

    const gpuPresent = typeof payload?.nvidia_payload === "string" && payload.nvidia_payload.length > 0;
    checks.push(check("gpu_evidence_present", gpuPresent, true, gpuPresent ? undefined : "no NVIDIA GPU evidence"));
    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    const measurements: Record<string, string> = parsed ? {
      mrtd: parsed.mrTd,
      mr_config_id: parsed.mrConfigId,
      rtmr0: parsed.rtmr0,
      rtmr1: parsed.rtmr1,
      rtmr2: parsed.rtmr2,
      rtmr3: parsed.rtmr3
    } : {};
    return assembleResult({
      expectations,
      hardwareType: "intel-tdx+nvidia-cc",
      requestedLevel: "provider-attested",
      privacyModality: expectations.privacyModality,
      measurementIdentities: measurements,
      modelWeightIdentity: null,
      attestedTlsSpki: null,
      attestedEncryptionKey: signingPublicKey,
      attestedSigningKey: signingAddress,
      boundNonce: parsed && nonce && hexEqual(nonce, expectations.nonce) ? expectations.nonce : nonce,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: true,
      checks
    });
  }
}
