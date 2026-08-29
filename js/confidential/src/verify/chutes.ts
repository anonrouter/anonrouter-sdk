// Chutes TEE evidence verifier. Validates every instance the provider returned and
// the protocol-level bindings Chutes documents: Intel TDX + debug-off, the reviewed
// measurement allowlist, and the ML-KEM key/nonce binding
// report_data[0:32] == sha256(nonce ‖ ML-KEM pubkey).
//
// The certificate-possession check (report_data[64:128] == sha256(cert SPKI) plus an
// RSA signature over the attested body) needs an X.509/ASN.1 parser. It is performed
// with node:crypto when available (verifyCertPossession); in a pure browser build
// where node:crypto is absent, ONLY that sub-check degrades to advisory (required:
// false) while the ML-KEM key/nonce/measurement bindings remain required. Ceiling is
// `provider-attested` (the DCAP/NRAS chain is not wired).

import { assembleResult, check, freshnessCheck, hexEqual, readEnvelope } from "./checks.js";
import { sha256Hex, verifyCertPossession } from "./crypto.js";
import { matchMeasurementAllowlist, parseTdxQuote, TDX_TEE_TYPE, type TdxMeasurementEntry } from "./tdx.js";
import { base64ToBytes, isCanonicalBase64, utf8Decode } from "../bytes.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  TeeVerifier
} from "./types.js";

interface ChutesInstanceEvidence {
  quote?: unknown;
  gpu_evidence?: unknown;
  instance_id?: unknown;
  certificate?: unknown;
  signature?: unknown;
  attested_body?: unknown;
}

interface ChutesEvidencePayload {
  evidence?: ChutesInstanceEvidence[];
  failed_instance_ids?: unknown;
  e2e_pubkeys?: Record<string, unknown>;
}

interface ChutesAttestedBody {
  nonce?: unknown;
  evidence?: { tdx_quote?: unknown; nvtrust_evidence?: unknown };
}

export interface ChutesVerifierOptions {
  verifierVersion?: string;
}

export class ChutesTeeVerifier implements TeeVerifier {
  readonly provider = "chutes";
  readonly verifierVersion: string;

  constructor(opts: ChutesVerifierOptions = {}) {
    this.verifierVersion = opts.verifierVersion ?? "chutes-tdx/2";
  }

  supportsClientOpaqueE2ee(): boolean {
    return true;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const payload = envelope.payload as ChutesEvidencePayload | undefined;
    const instances = Array.isArray(payload?.evidence) ? payload.evidence : [];
    const checks: AttestationCheck[] = [];
    const failedIds = Array.isArray(payload?.failed_instance_ids) ? payload.failed_instance_ids : [];
    const pubkeys = payload?.e2e_pubkeys && typeof payload.e2e_pubkeys === "object" ? payload.e2e_pubkeys : {};

    checks.push(check("evidence_present", instances.length > 0, true, instances.length > 0 ? undefined : "no instance evidence"));
    checks.push(check("all_instances_returned", failedIds.length === 0, true,
      failedIds.length === 0 ? undefined : "evidence retrieval failed for one or more instances"));

    const allowlist = (expectations.measurementPolicy?.accepted as TdxMeasurementEntry[] | undefined) ?? [];
    checks.push(check("measurement_policy_pinned", allowlist.length > 0, true,
      allowlist.length > 0 ? undefined : "no accepted-measurement policy pinned"));

    let firstMeasurements: Record<string, string> = {};
    let firstBoundNonce: string | null = null;
    let everyEncryptionKeyBound = instances.length > 0;

    for (let index = 0; index < instances.length; index += 1) {
      const instance = instances[index];
      const label = `instance_${index}`;
      const instanceId = typeof instance.instance_id === "string" ? instance.instance_id : null;
      const quoteRaw = typeof instance.quote === "string" ? instance.quote : null;
      const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
      checks.push(check(`${label}_identity`, Boolean(instanceId), true, instanceId ? undefined : "instance id missing"));
      checks.push(check(`${label}_quote_parsed`, parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));
      if (!parsed || !quoteRaw) continue;

      const measurements = {
        mrtd: parsed.mrTd,
        rtmr0: parsed.rtmr0,
        rtmr1: parsed.rtmr1,
        rtmr2: parsed.rtmr2,
        rtmr3: parsed.rtmr3
      };
      if (index === 0) firstMeasurements = measurements;
      checks.push(check(`${label}_expected_tee_type`, parsed.teeType === TDX_TEE_TYPE, true,
        parsed.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
      checks.push(check(`${label}_debug_disabled`, !parsed.debugEnabled, true,
        parsed.debugEnabled ? "TD debug mode enabled" : undefined));
      const measurementsAccepted = matchMeasurementAllowlist(parsed, allowlist) !== null;
      checks.push(check(`${label}_measurement_allowlist`, measurementsAccepted, true,
        measurementsAccepted ? undefined : "measurements not in accepted allowlist"));

      const e2ePubkey = instanceId && typeof pubkeys[instanceId] === "string" ? pubkeys[instanceId] as string : null;
      const expectedNonceKey = e2ePubkey ? sha256Hex(expectations.nonce + e2ePubkey) : null;
      const reportNonceKey = parsed.reportData.slice(0, 64);
      const nonceKeyBound = hexEqual(reportNonceKey, expectedNonceKey);
      checks.push(check(`${label}_nonce_key_binding`, nonceKeyBound, true,
        e2ePubkey ? undefined : "no discovered ML-KEM public key for instance"));
      everyEncryptionKeyBound &&= nonceKeyBound;
      if (index === 0 && nonceKeyBound) firstBoundNonce = expectations.nonce;

      // Certificate possession: requires an X.509/ASN.1 parser. Verified with
      // node:crypto when available; degraded to advisory in a pure browser build.
      const certificate = decodeBase64(instance.certificate);
      const attestedBody = decodeBase64(instance.attested_body);
      const signature = decodeBase64(instance.signature);
      const at = expectations.now ?? Date.now();
      const cert = certificate && attestedBody && signature
        ? verifyCertPossession(certificate, attestedBody, signature, at)
        : { available: true, spkiHash: null, possessionVerified: false, certificateFresh: false };
      // When node:crypto is unavailable these three checks are advisory; the caller
      // is told exactly which capability was not exercised.
      const certRequired = cert.available;
      const degradeDetail = "node:crypto unavailable: certificate possession not checked in this runtime";
      checks.push(check(`${label}_certificate_spki_binding`, hexEqual(parsed.reportData.slice(64, 128), cert.spkiHash), certRequired,
        cert.available ? (cert.spkiHash ? undefined : "certificate could not be parsed") : degradeDetail));
      checks.push(check(`${label}_certificate_freshness`, cert.certificateFresh, certRequired,
        cert.available ? (cert.certificateFresh ? undefined : "instance certificate is outside its validity window") : degradeDetail));
      checks.push(check(`${label}_key_possession`, cert.possessionVerified, certRequired,
        cert.available ? (cert.possessionVerified ? undefined : "RSA signature over attested_body did not verify") : degradeDetail));

      const body = parseAttestedBody(attestedBody);
      const gpu = Array.isArray(instance.gpu_evidence) ? instance.gpu_evidence : [];
      const innerGpu = parseJson(body?.evidence?.nvtrust_evidence);
      checks.push(check(`${label}_attested_nonce`, body?.nonce === expectations.nonce, certRequired,
        cert.available ? (body?.nonce === expectations.nonce ? undefined : "signed body nonce mismatch") : degradeDetail));
      checks.push(check(`${label}_attested_quote`, body?.evidence?.tdx_quote === quoteRaw, certRequired,
        cert.available ? (body?.evidence?.tdx_quote === quoteRaw ? undefined : "signed body quote mismatch") : degradeDetail));
      const gpuEvidenceSigned = Array.isArray(innerGpu) && jsonEqual(innerGpu, gpu);
      checks.push(check(`${label}_attested_gpu_evidence`, gpuEvidenceSigned, certRequired,
        cert.available ? (gpuEvidenceSigned ? undefined : "signed body GPU evidence mismatch") : degradeDetail));
      const gpuShapeOk = gpu.length > 0 && gpu.every((item) => item !== null && typeof item === "object"
        && typeof (item as Record<string, unknown>).certificate === "string"
        && typeof (item as Record<string, unknown>).evidence === "string");
      checks.push(check(`${label}_gpu_evidence_present`, gpuShapeOk, true,
        gpuShapeOk ? undefined : "no complete NVIDIA GPU evidence"));
    }

    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));
    return assembleResult({
      expectations,
      hardwareType: "intel-tdx+nvidia-cc",
      // Ceiling is provider-attested: the DCAP/NRAS chain is deliberately not wired.
      requestedLevel: "provider-attested",
      privacyModality: expectations.privacyModality,
      measurementIdentities: firstMeasurements,
      modelWeightIdentity: null,
      attestedTlsSpki: null,
      attestedEncryptionKey: Object.keys(pubkeys).length === 1
        ? String(pubkeys[Object.keys(pubkeys)[0]])
        : null,
      attestedSigningKey: null,
      boundNonce: firstBoundNonce,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: expectations.privacyModality === "e2ee" && everyEncryptionKeyBound,
      checks
    });
  }
}

function decodeBase64(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0 || !isCanonicalBase64(value)) return null;
  try {
    const decoded = base64ToBytes(value);
    return decoded.length > 0 ? decoded : null;
  } catch {
    return null;
  }
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return null;
  try { return JSON.parse(value); } catch { return null; }
}

function parseAttestedBody(value: Uint8Array | null): ChutesAttestedBody | null {
  if (!value) return null;
  try { return JSON.parse(utf8Decode(value)) as ChutesAttestedBody; } catch { return null; }
}

function jsonEqual(a: unknown, b: unknown): boolean {
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
}
