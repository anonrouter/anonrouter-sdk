// Mock TEE enclaves for E2EE round-trip tests. Each mirrors the provider's
// enclave-side crypto so a test can round-trip a real encrypt -> relay(ciphertext)
// -> enclave-decrypt -> enclave-encrypt -> client-decrypt flow with NO live
// provider. gzip uses node:zlib here (test env only); it is wire-compatible with the
// Compression Streams gzip the transport uses.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8Decode,
  utf8Encode
} from "../../src/bytes.js";
import { sha256Hex } from "../../src/verify/crypto.js";
import { pinnedMeasurementPolicyFor } from "../../src/measurements.js";
import type { NormalizedVerdict } from "../../src/verify/types.js";
import type { TdxMeasurementEntry } from "../../src/verify/tdx.js";
import { buildTdxQuoteBase64, buildTdxQuoteHex } from "./tdx-fixtures.js";

function okView(overrides: Partial<NormalizedVerdict>): NormalizedVerdict {
  return {
    status: "ok",
    verification_level: "provider-attested",
    privacy_modality: "e2ee",
    hardware_type: "intel-tdx+nvidia-cc",
    measurement_identities: {},
    model_weight_identity: null,
    attested_tls_spki: null,
    attested_encryption_key: null,
    attested_signing_key: null,
    nonce: null,
    verified_at: new Date(0).toISOString(),
    expires_at: new Date(0).toISOString(),
    policy_source: null,
    verifier_version: "mock/1",
    supports_client_opaque_e2ee: true,
    reason: null,
    checks: [],
    ...overrides
  };
}

function sseResponse(text: string): Response {
  return new Response(text, { status: 200, headers: { "content-type": "text/event-stream" } });
}

// ---- Venice mock enclave -----------------------------------------------------

function veniceDeriveKey(priv: Uint8Array, peerPub: Uint8Array): Uint8Array {
  const shared = secp256k1.getSharedSecret(priv, peerPub, true).slice(1);
  return hkdf(sha256, shared, undefined, utf8Encode("ecdsa_encryption"), 32);
}
function veniceEncrypt(plaintext: string, recipientPubHex: string, senderPriv: Uint8Array, senderPub: Uint8Array): string {
  const key = veniceDeriveKey(senderPriv, hexToBytes(recipientPubHex));
  const nonce = randomBytes(12);
  const ct = gcm(key, nonce).encrypt(utf8Encode(plaintext));
  return bytesToHex(concatBytes(senderPub, nonce, ct));
}
function veniceDecrypt(hex: string, recipientPriv: Uint8Array): string {
  const blob = hexToBytes(hex);
  const peerPub = blob.subarray(0, 65);
  const nonce = blob.subarray(65, 77);
  const ct = blob.subarray(77);
  return utf8Decode(gcm(veniceDeriveKey(recipientPriv, peerPub), nonce).decrypt(ct));
}
function ethAddress(pubHex: string): string {
  const key = hexToBytes(pubHex);
  return "0x" + bytesToHex(keccak_256(key.subarray(1)).subarray(12, 32));
}

export interface VeniceMockEnclave {
  enclavePubHex: string;
  address: string;
  attestationResponse(nonce: string): { evidence: Record<string, unknown>; provider: string; model: string; upstream_model: string; privacy_class: string; protocol: string; attestation: NormalizedVerdict };
  evidence(nonce: string): Record<string, unknown>;
  /** Decrypt request messages and produce an encrypted SSE reply. */
  handleInference(init: RequestInit, replyDeltas?: string[]): { decrypted: string[]; reply: string; response: Response };
}

/**
 * @param upstreamModel the provider-native model the enclave loaded.
 * @param catalogModel  the AnonRouter catalog id the ticket was minted for.
 *   These are DIFFERENT identifiers and the relay echoes both. Defaulting the
 *   second to the first is only correct where a test does not care which one it
 *   is looking at; any test about the `requested_model` binding must pass both,
 *   or it compares a value against itself and can never fail.
 */
export function createVeniceMockEnclave(
  upstreamModel: string,
  catalogModel: string = upstreamModel
): VeniceMockEnclave {
  const enclaveSec = secp256k1.utils.randomSecretKey();
  const enclavePub = secp256k1.getPublicKey(enclaveSec, false);
  const enclavePubHex = bytesToHex(enclavePub);
  const address = ethAddress(enclavePubHex);

  function evidence(nonce: string) {
    const reportData = address.slice(2).padEnd(64, "0") + nonce;
    const quote = buildTdxQuoteHex({
      mrTd: "11".repeat(48),
      rtmr0: "22".repeat(48),
      rtmr1: "33".repeat(48),
      rtmr2: "44".repeat(48),
      rtmr3: "55".repeat(48),
      reportData
    });
    return {
      intel_quote: quote,
      nvidia_payload: "gpu-evidence",
      nonce,
      model: upstreamModel,
      signing_address: address,
      signing_algo: "ecdsa",
      signing_public_key: enclavePubHex,
      attestation: {
        report_data: reportData,
        workload_keyset: { e2ee_public_keys: [{ algo: "secp256k1-aes-256-gcm-hkdf-sha256", public_key: enclavePubHex }] },
        evidence: { quote_report_data: reportData }
      }
    };
  }

  return {
    enclavePubHex,
    address,
    evidence,
    attestationResponse(nonce: string) {
      return {
        evidence: evidence(nonce),
        provider: "venice",
        // The deployed relay echoes the FULL route binding the ticket carries:
        // catalog model, upstream model and privacy class, all bound at mint
        // time. The fixture says so too, because a client's route cross-binding
        // can only be exercised against a response that carries the fields.
        //
        // `model` is the CATALOG id and `upstream_model` is the provider-native
        // one. This used to put the upstream id in both, which made the mock
        // gateway reject every call naming a catalog id — the self-test included.
        model: catalogModel,
        upstream_model: upstreamModel,
        privacy_class: "e2ee",
        protocol: "venice-legacy",
        attestation: okView({ attested_encryption_key: enclavePubHex, attested_signing_key: address, nonce })
      };
    },
    handleInference(init, replyDeltas = ["Hello ", "E2EE"]) {
      const body = JSON.parse(String(init.body)) as { messages: Array<{ content: string }> };
      const headers = new Headers(init.headers);
      const clientPubHex = headers.get("x-venice-tee-client-pub-key") ?? "";
      const decrypted = body.messages.map((message) => veniceDecrypt(message.content, enclaveSec));
      const frames = replyDeltas
        .map((delta) => `data: ${JSON.stringify({ choices: [{ delta: { content: veniceEncrypt(delta, clientPubHex, enclaveSec, enclavePub) } }] })}\n\n`)
        .join("");
      const tail = `data: ${JSON.stringify({ choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 } })}\n\ndata: [DONE]\n\n`;
      return { decrypted, reply: replyDeltas.join(""), response: sseResponse(frames + tail) };
    }
  };
}

// ---- Chutes mock enclave -----------------------------------------------------

function chutesKey(sharedSecret: Uint8Array, mlkemCiphertext: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, sharedSecret, mlkemCiphertext.subarray(0, 16), utf8Encode(info), 32);
}

export interface ChutesMockEnclave {
  instanceId: string;
  instancePubB64: string;
  nonce: string;
  attestationResponse(callerNonceHex: string): { evidence: Record<string, unknown>; provider: string; model: string; upstream_model: string; privacy_class: string; protocol: string; attestation: NormalizedVerdict };
  /** Decrypt the request body and produce an encrypted octet-stream reply. */
  handleInference(bodyBytes: Uint8Array, reply?: Record<string, unknown>): { decrypted: Record<string, unknown>; response: Response };
}

/**
 * @param upstreamModel the provider-native model the enclave loaded.
 * @param catalogModel  the AnonRouter catalog id the ticket was minted for.
 *   See `createVeniceMockEnclave` for why these must be separable.
 */
export function createChutesMockEnclave(
  upstreamModel: string,
  catalogModel: string = upstreamModel
): ChutesMockEnclave {
  const instanceKeys = ml_kem768.keygen(randomBytes(ml_kem768.lengths.seed ?? 64));
  const instancePubB64 = bytesToBase64(instanceKeys.publicKey);
  const instanceId = "12345678-1234-1234-1234-123456789abc";
  const nonce = "chutesNonce_abcdef01";
  const pin = (pinnedMeasurementPolicyFor("chutes", "")?.accepted as TdxMeasurementEntry[])[0];

  function evidence(callerNonceHex: string) {
    const reportData = sha256Hex(callerNonceHex + instancePubB64) + "00".repeat(32);
    const quote = buildTdxQuoteBase64({
      mrTd: pin.mrTd,
      rtmr0: pin.rtmr0,
      rtmr1: pin.rtmr1,
      rtmr2: pin.rtmr2,
      rtmr3: pin.rtmr3,
      reportData
    });
    return {
      e2e_instances: [{ instance_id: instanceId, e2e_pubkey: instancePubB64, nonces: [nonce] }],
      e2e_pubkeys: { [instanceId]: instancePubB64 },
      evidence: [{ instance_id: instanceId, quote }],
      failed_instance_ids: []
    };
  }

  return {
    instanceId,
    instancePubB64,
    nonce,
    attestationResponse(callerNonceHex: string) {
      return {
        evidence: evidence(callerNonceHex),
        provider: "chutes",
        // Catalog id, then provider-native id. Not the same string.
        model: catalogModel,
        upstream_model: upstreamModel,
        privacy_class: "e2ee",
        protocol: "chutes-mlkem-v1",
        attestation: okView({ attested_encryption_key: instancePubB64, nonce: callerNonceHex })
      };
    },
    handleInference(bodyBytes, reply) {
      const mlkemCt = bodyBytes.subarray(0, 1088);
      const reqNonce = bodyBytes.subarray(1088, 1100);
      const enc = bodyBytes.subarray(1100);
      const shared = ml_kem768.decapsulate(mlkemCt, instanceKeys.secretKey);
      const reqKey = chutesKey(shared, mlkemCt, "e2e-req-v1");
      const compressed = chacha20poly1305(reqKey, reqNonce).decrypt(enc);
      const decrypted = JSON.parse(gunzipSync(compressed).toString("utf8")) as Record<string, unknown>;
      const clientRespPk = base64ToBytes(String(decrypted.e2e_response_pk));
      const replyObj = reply ?? {
        choices: [{ message: { content: "Hello E2EE from Chutes" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 }
      };
      const replyGz = new Uint8Array(gzipSync(Buffer.from(JSON.stringify(replyObj))));
      const respKem = ml_kem768.encapsulate(clientRespPk, randomBytes(ml_kem768.lengths.msgRand ?? 32));
      const respNonce = randomBytes(12);
      const respKey = chutesKey(respKem.sharedSecret, respKem.cipherText, "e2e-resp-v1");
      const encResp = chacha20poly1305(respKey, respNonce).encrypt(replyGz);
      const blob = concatBytes(respKem.cipherText, respNonce, encResp);
      return {
        decrypted,
        response: new Response(blob as Uint8Array<ArrayBuffer>, { status: 200, headers: { "content-type": "application/octet-stream" } })
      };
    }
  };
}

/** Read a fetch call's body as bytes (Uint8Array/ArrayBuffer/string). */
export function readRequestBytes(body: BodyInit | null | undefined): Uint8Array {
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (typeof body === "string") return utf8Encode(body);
  throw new Error("unsupported mock request body");
}
