// Generator for shared/vectors/attestation.json, the cross-language verifier
// parity contract.
//
// Each case pins a complete verdict for one raw-evidence input: status,
// verification level, failure reason, and the exact set of required checks that
// failed. The JS and Python test suites both load this file and must agree on
// every field, so a verifier change that lands in only one language fails CI.
//
// The expectations are not hand-written. Every case is run through the real
// verifier here and whatever it returns is recorded, so the file always describes
// actual behavior. Review the diff when you regenerate: a changed expectation is a
// changed security decision.
//
// Evidence is synthetic and self-consistent. The TDX quotes are byte-exact at the
// offsets the parser reads but are NOT signed by Intel, which is fine precisely
// because the SDK never verifies the DCAP chain. The Chutes case needs a real
// X.509 certificate, so one throwaway self-signed RSA key is minted with openssl.
//
// Run (from js/confidential):  npm run gen:attestation-vectors
// Requires: openssl on PATH.

import { execFileSync } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { bytesToBase64, bytesToHex, hexToBytes } from "../src/bytes.js";
import { pinnedMeasurementPolicyFor } from "../src/measurements.js";
import { sha256Hex } from "../src/verify/crypto.js";
import type { TdxMeasurementEntry } from "../src/verify/tdx.js";
import { verifyRawEvidence, type VerifiableProvider } from "../src/verify/index.js";
import { enableNodeCrypto } from "../src/verify/crypto.js";

// A fixed clock so freshness is deterministic forever. Evidence with no envelope
// inherits this instant as its fetch time, so the freshness window always passes.
const NOW_MS = 1_760_000_000_000; // 2025-10-09T07:33:20.000Z

const VENICE_MODEL = "venice-uncensored";
const CHUTES_MODEL = "z-ai/glm-5.2";
const NEAR_MODEL = "openai/gpt-oss-120b";

// Two distinct 32-byte caller nonces (64 hex chars each).
const NONCE_A = "3f1c8e5b9a2d47f0c6b3e81a5d94f27c0e6a83b15d2f49c7a08e365b1d4c7f92";
const NONCE_B = "b9e4a1c07d3f28b56e0a9c4d17f3b28e5a6c09d4b1f7e3a25c8d06b9f4e1a3c7";

// ---- TDX quote fixture -------------------------------------------------------

interface QuoteFields {
  mrTd: string;
  mrConfigId?: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  reportData: string;
  debug?: boolean;
}

function buildQuote(fields: QuoteFields): Uint8Array {
  const buf = new Uint8Array(632);
  const view = new DataView(buf.buffer);
  view.setUint16(0, 4, true); // quote version
  view.setUint32(4, 0x00000081, true); // tee_type: Intel TDX
  if (fields.debug) buf[168] = 0x01; // td_attributes bit 0 = TUD.DEBUG
  const put = (off: number, hex: string, len: number) => {
    const bytes = hexToBytes(hex);
    if (bytes.length !== len) throw new Error(`field at ${off} must be ${len} bytes, got ${bytes.length}`);
    buf.set(bytes, off);
  };
  put(184, fields.mrTd, 48);
  put(232, fields.mrConfigId ?? "00".repeat(48), 48);
  put(376, fields.rtmr0, 48);
  put(424, fields.rtmr1, 48);
  put(472, fields.rtmr2, 48);
  put(520, fields.rtmr3, 48);
  put(568, fields.reportData, 64);
  return buf;
}

// ---- Venice evidence ---------------------------------------------------------

function ethAddress(pubHex: string): string {
  return "0x" + bytesToHex(keccak_256(hexToBytes(pubHex).subarray(1)).subarray(12, 32));
}

function veniceEvidence(nonce: string, model: string): Record<string, unknown> {
  // A fixed secret keeps the vector stable across regenerations.
  const secret = hexToBytes("11".repeat(31) + "37");
  const pubHex = bytesToHex(secp256k1.getPublicKey(secret, false));
  const address = ethAddress(pubHex);
  // report_data[0:32] = 20-byte address padded to 32; [32:64] = the caller nonce.
  const reportData = address.slice(2).padEnd(64, "0") + nonce;
  const quote = bytesToHex(buildQuote({
    mrTd: "11".repeat(48),
    rtmr0: "22".repeat(48),
    rtmr1: "33".repeat(48),
    rtmr2: "44".repeat(48),
    rtmr3: "55".repeat(48),
    reportData
  }));
  return {
    intel_quote: quote,
    nvidia_payload: "nvidia-gpu-evidence-blob",
    nonce,
    model,
    signing_algo: "ecdsa",
    signing_address: address,
    signing_public_key: pubHex,
    attestation: {
      report_data: reportData,
      evidence: { quote_report_data: reportData },
      workload_keyset: {
        e2ee_public_keys: [{ algo: "secp256k1-aes-256-gcm-hkdf-sha256", public_key: pubHex }]
      }
    }
  };
}

// ---- Chutes evidence ---------------------------------------------------------

/** Mint a throwaway self-signed RSA certificate. Chutes binds the SHA-256 of the
 *  certificate's DER SubjectPublicKeyInfo into report_data and signs the attested
 *  body with the matching key, so the vector needs a real, parseable X.509. */
function mintCertificate(): { certDer: Uint8Array; privateKeyPem: string } {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const dir = mkdtempSync(join(tmpdir(), "anonrouter-vectors-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.der");
  writeFileSync(keyPath, privateKeyPem);
  execFileSync("openssl", [
    "req", "-new", "-x509",
    "-key", keyPath,
    "-out", certPath,
    "-outform", "DER",
    // An explicit window bracketing NOW_MS, not "-days N from today". The vector
    // pins a fixed instant, so a certificate minted valid-from-today would be
    // not-yet-valid at that instant and the freshness check would fail.
    "-not_before", "20200101000000Z",
    "-not_after", "21000101000000Z",
    "-subj", "/CN=anonrouter-sdk-test-vector"
  ]);
  return { certDer: new Uint8Array(readFileSync(certPath)), privateKeyPem };
}

function chutesEvidence(nonce: string, opts: { bindWrongKey?: boolean } = {}): Record<string, unknown> {
  const pin = (pinnedMeasurementPolicyFor("chutes", CHUTES_MODEL)?.accepted as TdxMeasurementEntry[])[0];
  const instanceId = "2f8c1d90-4b63-4a71-9e05-7c1a8f2b63d4";

  // Deterministic ML-KEM instance key from a fixed seed.
  const seedLen = ml_kem768.lengths.seed ?? 64;
  const keys = ml_kem768.keygen(new Uint8Array(seedLen).fill(0x2b));
  const pubB64 = bytesToBase64(keys.publicKey);
  // The "served" key the report_data binds. A tampered case binds a different key.
  const boundB64 = opts.bindWrongKey
    ? bytesToBase64(ml_kem768.keygen(new Uint8Array(seedLen).fill(0x5c)).publicKey)
    : pubB64;

  const { certDer, privateKeyPem } = mintCertificate();
  // Node exports SPKI from the certificate's public key; recompute the same bytes.
  const spkiDer = execFileSync("openssl", ["x509", "-inform", "DER", "-pubkey", "-noout"], { input: Buffer.from(certDer) });
  const spkiBody = Buffer.from(
    spkiDer.toString().replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, ""),
    "base64"
  );
  const spkiHash = sha256Hex(new Uint8Array(spkiBody));

  const reportData = sha256Hex(nonce + boundB64) + spkiHash;
  const quoteB64 = bytesToBase64(buildQuote({
    mrTd: pin.mrTd,
    rtmr0: pin.rtmr0,
    rtmr1: pin.rtmr1,
    rtmr2: pin.rtmr2,
    rtmr3: pin.rtmr3,
    reportData
  }));

  const gpuEvidence = [{ certificate: "nvidia-cert-chain-pem", evidence: "nvidia-attestation-blob" }];
  const attestedBody = JSON.stringify({
    nonce,
    evidence: { tdx_quote: quoteB64, nvtrust_evidence: JSON.stringify(gpuEvidence) }
  });
  const signer = createSign("sha256");
  signer.update(Buffer.from(attestedBody, "utf8"));
  const signature = signer.sign(privateKeyPem);

  return {
    e2e_instances: [{ instance_id: instanceId, e2e_pubkey: pubB64, nonces: [nonce] }],
    e2e_pubkeys: { [instanceId]: pubB64 },
    failed_instance_ids: [],
    evidence: [{
      instance_id: instanceId,
      quote: quoteB64,
      certificate: Buffer.from(certDer).toString("base64"),
      attested_body: Buffer.from(attestedBody, "utf8").toString("base64"),
      signature: signature.toString("base64"),
      gpu_evidence: gpuEvidence
    }]
  };
}

// ---- NEAR evidence -----------------------------------------------------------

/** NEAR evidence that is structurally complete but whose compose document is not
 *  the reviewed one. A passing NEAR case would need the exact app_compose preimage
 *  behind the pinned composeSha256, which is not distributed with the pins. */
function nearEvidenceUnreviewedCompose(nonce: string): Record<string, unknown> {
  const signingAddress = "0x" + "ab".repeat(20);
  const tlsFingerprint = "cd".repeat(32);
  const appCompose = "services:\n  app:\n    image: example/not-the-reviewed-compose\n";
  const composeSha = sha256Hex(appCompose);
  const first = sha256Hex(hexToBytes(signingAddress.slice(2) + tlsFingerprint));
  const reportData = first + nonce;
  const quote = bytesToHex(buildQuote({
    mrTd: "66".repeat(48),
    mrConfigId: ("01" + composeSha).padEnd(96, "0"),
    rtmr0: "77".repeat(48),
    rtmr1: "88".repeat(48),
    rtmr2: "99".repeat(48),
    rtmr3: "aa".repeat(48),
    reportData
  }));
  return {
    intel_quote: quote,
    nvidia_payload: "nvidia-gpu-evidence-blob",
    model_name: NEAR_MODEL,
    signing_address: signingAddress,
    signing_algo: "ed25519",
    tls_cert_fingerprint: tlsFingerprint,
    app_compose: appCompose,
    compose_hash: composeSha
  };
}

// ---- Tinfoil evidence --------------------------------------------------------

/** A Tinfoil verification document, shaped like the one Tinfoil's own verifier
 *  emits, plus the transport binding whoever opened the serving connection
 *  recorded. `steps` must all read "success": that is the official verifier
 *  reporting it completed the hard cryptography (AMD SEV-SNP attestation, the
 *  transparency-log measurement, the enclave key binding). No NVIDIA GPU
 *  evidence is involved on this route and none is implied here.
 *
 *  `transportBinding` is the half the document cannot supply about itself. The
 *  two attested TLS fields below are copies of ONE AMD-report field, so a
 *  verifier comparing them to each other passes every document ever written.
 *  The cases built from `over` exercise that distinction directly. */
const TINFOIL_TLS_FP = "3d".repeat(32);

function tinfoilDocument(opts: { failStep?: boolean; over?: Record<string, unknown> } = {}): Record<string, unknown> {
  const steps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"];
  const fingerprint = "5c".repeat(48);
  return {
    schemaVersion: 1,
    configRepo: "tinfoilsh/confidential-model-router",
    enclaveHost: "inference.tinfoil.sh",
    selectedRouterEndpoint: "https://inference.tinfoil.sh",
    releaseTag: "v9.9.9",
    releaseDigest: "d8".repeat(32),
    codeFingerprint: fingerprint,
    enclaveFingerprint: fingerprint,
    tlsPublicKey: TINFOIL_TLS_FP,
    enclaveMeasurement: { tlsPublicKeyFingerprint: TINFOIL_TLS_FP },
    transportBinding: {
      mode: "tls-pinned",
      endpointIdentity: "inference.tinfoil.sh",
      observedTlsSpki: TINFOIL_TLS_FP,
      verified: true
    },
    securityVerified: true,
    verifier: { name: "@tinfoilsh/verifier", version: "1.2.1" },
    steps: Object.fromEntries(
      steps.map((name, i) => [
        name,
        { status: opts.failStep && i === 2 ? "failed" : "success" }
      ])
    ),
    ...opts.over
  };
}

// ---- Case assembly -----------------------------------------------------------

interface CaseInput {
  name: string;
  why: string;
  provider: string;
  upstreamModel: string;
  endpointIdentity: string;
  privacyModality: "e2ee" | "tee";
  nonce: string;
  rawEvidence: unknown;
}

const inputs: CaseInput[] = [
  {
    name: "venice valid evidence",
    why: "A self-consistent Venice attestation verifies to the honest ceiling, never higher.",
    provider: "venice",
    upstreamModel: VENICE_MODEL,
    endpointIdentity: "venice",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: veniceEvidence(NONCE_A, VENICE_MODEL)
  },
  {
    name: "venice nonce not the one the evidence bound",
    why: "Anti-replay: evidence bound to another nonce must fail closed.",
    provider: "venice",
    upstreamModel: VENICE_MODEL,
    endpointIdentity: "venice",
    privacyModality: "e2ee",
    nonce: NONCE_B,
    rawEvidence: veniceEvidence(NONCE_A, VENICE_MODEL)
  },
  {
    name: "venice evidence attests a different model",
    why: "Route binding: evidence for another model must not satisfy this route.",
    provider: "venice",
    upstreamModel: "some-other-model",
    endpointIdentity: "venice",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: veniceEvidence(NONCE_A, VENICE_MODEL)
  },
  {
    name: "chutes valid evidence",
    why: "Full Chutes instance evidence: reviewed measurements, ML-KEM key binding, certificate possession, and GPU evidence.",
    provider: "chutes",
    upstreamModel: CHUTES_MODEL,
    endpointIdentity: "chutes",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: chutesEvidence(NONCE_A)
  },
  {
    name: "chutes report_data binds a key other than the served one",
    why: "A relay that attests one ML-KEM key while serving another must fail closed, so no request is ever sealed to an unverified key.",
    provider: "chutes",
    upstreamModel: CHUTES_MODEL,
    endpointIdentity: "chutes",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: chutesEvidence(NONCE_A, { bindWrongKey: true })
  },
  {
    name: "near compose document is not the reviewed one",
    why: "Structurally complete NEAR evidence still fails when the compose document is outside the reviewed allowlist.",
    provider: "near-ai",
    upstreamModel: NEAR_MODEL,
    endpointIdentity: "gpt-oss-120b.completions.near.ai",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: nearEvidenceUnreviewedCompose(NONCE_A)
  },
  {
    name: "near empty evidence",
    why: "Absent evidence is never treated as absent-and-fine.",
    provider: "near-ai",
    upstreamModel: NEAR_MODEL,
    endpointIdentity: "gpt-oss-120b.completions.near.ai",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: {}
  },
  {
    name: "tinfoil valid verification document",
    why: "A document reporting a successful official-verifier run for the supported repository, with the serving key observed on a pinned connection, reaches sdk-verified and no higher. No release fingerprint is pinned here; the release is authenticated by the provider's verifier.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument()
  },
  {
    name: "tinfoil document with a failed verification step",
    why: "If Tinfoil's own verifier did not complete every cryptographic step, the document must not be accepted.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({ failStep: true })
  },
  {
    name: "tinfoil document whose TLS key was never observed on a connection",
    why: "THE REGRESSION THIS SET EXISTS FOR. Both attested TLS fields are copies of one AMD-report field, so a document that merely agrees with itself proves nothing about the serving connection. With no independently observed transport binding it must fail, however well formed the rest is.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({ over: { transportBinding: undefined } })
  },
  {
    name: "tinfoil transport binding observing a different key",
    why: "A TLS-key substitution: the report attests one key, the connection served another. The two must be equal or the attested key binds nothing.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({
      over: {
        transportBinding: {
          mode: "tls-pinned",
          endpointIdentity: "inference.tinfoil.sh",
          observedTlsSpki: "7e".repeat(32),
          verified: true
        }
      }
    })
  },
  {
    name: "tinfoil transport binding that was not verified",
    why: "`verified: false` is an observation that failed its pin. Recording the key it saw must not be mistaken for accepting it.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({
      over: {
        transportBinding: {
          mode: "tls-pinned",
          endpointIdentity: "inference.tinfoil.sh",
          observedTlsSpki: TINFOIL_TLS_FP,
          verified: false
        }
      }
    })
  },
  {
    name: "tinfoil transport binding recorded against another endpoint",
    why: "A pinned connection to somewhere else is not evidence about this enclave, even when the key matches.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({
      over: {
        transportBinding: {
          mode: "tls-pinned",
          endpointIdentity: "inference.attacker.example",
          observedTlsSpki: TINFOIL_TLS_FP,
          verified: true
        }
      }
    })
  },
  {
    name: "tinfoil document naming another enclave host",
    why: "Endpoint substitution. The document carries TWO endpoint identities; checking only the selected router left the other free to name anywhere.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({ over: { enclaveHost: "inference.attacker.example" } })
  },
  {
    name: "tinfoil document bound to another GitHub repository",
    why: "The repository is the one authority field this SDK re-derives from the evidence. A different repository is a different codebase and fails closed.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({ over: { configRepo: "attacker/confidential-model-router" } })
  },
  {
    name: "tinfoil live enclave not running the signed release",
    why: "The signed code measurement and the live enclave measurement must be equal, or the signature covers something other than what is serving.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({ over: { enclaveFingerprint: "a1".repeat(48) } })
  },
  {
    name: "tinfoil document from an unofficial verifier",
    why: "Anything can emit `securityVerified: true`. The document must name the official verifier, or the aggregate boolean is just an assertion.",
    provider: "tinfoil",
    upstreamModel: "llama3-3-70b",
    endpointIdentity: "inference.tinfoil.sh",
    privacyModality: "tee",
    nonce: NONCE_A,
    rawEvidence: tinfoilDocument({ over: { verifier: { name: "lookalike-verifier", version: "1.2.1" } } })
  },
  {
    name: "unknown provider",
    why: "A provider with no verifier is not verifiable, and must not be reported as verified.",
    provider: "acme-inference",
    upstreamModel: "acme/model",
    endpointIdentity: "acme-inference",
    privacyModality: "e2ee",
    nonce: NONCE_A,
    rawEvidence: {}
  }
];

// Belt and braces: the loader picks node:crypto up synchronously on Node 22.3+,
// but the vectors must always record the FULL-strength verdict, never one whose
// certificate checks quietly degraded to advisory.
if (!(await enableNodeCrypto())) {
  throw new Error("node:crypto is required to generate vectors at full verification strength");
}

const cases = inputs.map((input) => {
  const verdict = verifyRawEvidence(input.provider as VerifiableProvider, input.rawEvidence, {
    upstreamModel: input.upstreamModel,
    nonce: input.nonce,
    endpointIdentity: input.endpointIdentity,
    privacyModality: input.privacyModality,
    now: NOW_MS
  });
  return {
    name: input.name,
    why: input.why,
    provider: input.provider,
    upstreamModel: input.upstreamModel,
    endpointIdentity: input.endpointIdentity,
    privacyModality: input.privacyModality,
    nonce: input.nonce,
    nowMs: NOW_MS,
    rawEvidence: input.rawEvidence,
    expected: {
      status: verdict.status,
      verificationLevel: verdict.verification_level,
      reason: verdict.reason,
      supportsClientOpaqueE2ee: verdict.supports_client_opaque_e2ee,
      failedRequiredChecks: verdict.checks.filter((c) => c.required && !c.passed).map((c) => c.name),
      // Advisory failures are pinned too. They do not change the status, which
      // is exactly why they need a gate: a named gap that silently stopped being
      // reported would look identical to a route that never had one, and the
      // only reader who notices is the one who trusted the verdict.
      failedAdvisoryChecks: verdict.checks.filter((c) => !c.required && !c.passed).map((c) => c.name)
    }
  };
});

const outPath = fileURLToPath(new URL("../../../shared/vectors/attestation.json", import.meta.url));
const doc = {
  note: [
    "Known-answer verdict vectors for the provider-neutral verifier. Both the JS and",
    "Python test suites load this file and must produce identical verdicts, so a",
    "verifier change that lands in only one language fails CI.",
    "Evidence is synthetic and self-consistent: the TDX quotes are byte-exact at the",
    "offsets the parser reads but carry no Intel signature, which is exactly why they",
    "suffice here (the SDK never verifies the DCAP chain, and says so).",
    "nowMs is a fixed clock so freshness is deterministic. Pass it as the verifier's",
    "injectable now.",
    "measurementPolicy is NOT stored here: each language resolves it from its own",
    "copy of the pins, so these vectors also prove both copies gate identically.",
    "Regenerate with: npm run gen:attestation-vectors (from js/confidential).",
    "No passing NEAR case is included: it would need the exact app_compose preimage",
    "behind the pinned composeSha256, which the pins do not distribute."
  ].join(" "),
  cases
};
writeFileSync(outPath, JSON.stringify(doc, null, 2) + "\n");

console.log(`wrote ${cases.length} cases -> ${outPath}`);
for (const c of cases) {
  const failed = c.expected.failedRequiredChecks;
  console.log(
    `  ${c.name.padEnd(50)} ${c.expected.status.padEnd(7)} ${String(c.expected.verificationLevel).padEnd(18)}` +
    ` reason=${String(c.expected.reason)}${failed.length ? ` failed=${failed.length}` : ""}`
  );
}
