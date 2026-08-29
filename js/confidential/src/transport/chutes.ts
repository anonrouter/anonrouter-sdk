// Chutes ML-KEM-768 transport.
//
// Protocol (verified against Chutes' live enclave endpoints):
//   - select an attested e2e_instances entry (instance UUID, ML-KEM-768 pubkey,
//     one single-use nonce)
//   - embed an ephemeral client response ML-KEM public key inside the JSON
//   - gzip the JSON
//   - ML-KEM-768 encapsulation to the instance key
//   - HKDF-SHA256 with request/response info strings and the ML-KEM ciphertext
//     prefix (first 16 bytes) as salt
//   - ChaCha20-Poly1305
//   - request wire: [1088 ML-KEM ct][12 nonce][ChaCha20-Poly1305(gzip(json))]
//   - POST application/octet-stream to /v1/e2ee/chat/completions with the ticket,
//     x-anonrouter-e2ee-provider: chutes, x-chutes-instance-id, x-chutes-e2e-nonce
//   - response: [1088 ML-KEM ct][12 nonce][ChaCha20-Poly1305(gzip(json))],
//     decapsulated with the client's ephemeral response secret key
//
// Chutes is NON-STREAMING (usage is inside the encrypted response).

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  asBufferSource,
  base64ToBytes,
  bytesToBase64,
  concatBytes,
  isCanonicalBase64,
  randomBytes,
  utf8Decode,
  utf8Encode,
  zeroize
} from "../bytes.js";
import { ConfidentialError } from "../errors.js";
import { gunzip, gzip } from "../gzip.js";
import { pinnedMeasurementPolicyFor } from "../measurements.js";
import { hexEqual, sha256Hex } from "../verify/crypto.js";
import { matchMeasurementAllowlist, parseTdxQuote, TDX_TEE_TYPE, type TdxMeasurementEntry } from "../verify/tdx.js";
import {
  joinUrl,
  parseRelayError,
  type CompleteOptions,
  type CreateSessionInput,
  type E2eeChatRequest,
  type E2eeCompletion,
  type E2eeSession,
  type E2eeTransport
} from "./types.js";

const MLKEM_CIPHERTEXT_BYTES = 1088;
const MLKEM_PUBLICKEY_BYTES = 1184;
const RESPONSE_NONCE_OFFSET = MLKEM_CIPHERTEXT_BYTES; // 1088
const RESPONSE_BODY_OFFSET = MLKEM_CIPHERTEXT_BYTES + 12; // 1100
const MIN_RESPONSE_BYTES = 1_116;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024;

interface ChutesInstanceEntry {
  instance_id?: unknown;
  e2e_pubkey?: unknown;
  nonces?: unknown;
}
interface ChutesEvidencePayload {
  evidence?: Array<{ instance_id?: unknown; quote?: unknown }>;
  e2e_instances?: ChutesInstanceEntry[];
  e2e_pubkeys?: Record<string, unknown>;
  failed_instance_ids?: unknown;
}

class ChutesSession implements E2eeSession {
  readonly provider = "chutes" as const;
  readonly protocol = "chutes-mlkem-v1" as const;
  disposed = false;
  constructor(
    readonly upstreamModel: string,
    readonly instanceId: string,
    readonly instanceNonce: string,
    /** Instance ML-KEM-768 public key (1184 bytes) the request is sealed to. */
    readonly instancePublicKey: Uint8Array
  ) {}
}

/** HKDF-SHA256 with the ML-KEM ciphertext's first 16 bytes as salt. */
function chutesKey(sharedSecret: Uint8Array, mlkemCiphertext: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, sharedSecret, mlkemCiphertext.subarray(0, 16), utf8Encode(info), 32);
}

function decodeInstanceKey(value: unknown): Uint8Array {
  if (typeof value !== "string" || !isCanonicalBase64(value)) {
    throw new ConfidentialError("key_binding_failed", "The enclave key encoding was invalid.");
  }
  const bytes = base64ToBytes(value);
  if (bytes.length !== MLKEM_PUBLICKEY_BYTES) {
    throw new ConfidentialError("key_binding_failed", "The enclave ML-KEM key was the wrong size.");
  }
  return bytes;
}

function chutesAllowlist(): TdxMeasurementEntry[] {
  const accepted = pinnedMeasurementPolicyFor("chutes", "")?.accepted;
  return Array.isArray(accepted) ? (accepted as TdxMeasurementEntry[]) : [];
}

/** Independently re-verify the SELECTED Chutes instance's raw evidence: Intel TDX,
 *  debug-off, reviewed measurement identity, and the ML-KEM key/nonce binding
 *  report_data[0:32] == sha256(nonce ‖ pubkey). The X.509 certificate-possession
 *  checks are part of the full verifyRawEvidence verdict (and the gateway verdict),
 *  which the caller also requires; here we bind the key we will encrypt to. */
function verifyChutesEvidence(input: CreateSessionInput): ChutesSession {
  const payload = input.rawEvidence as ChutesEvidencePayload | undefined;
  const instances = Array.isArray(payload?.e2e_instances) ? payload.e2e_instances : [];
  const failed = Array.isArray(payload?.failed_instance_ids) ? payload.failed_instance_ids : [];
  if (failed.length > 0) throw new ConfidentialError("attestation_untrusted", "Some enclave instances failed attestation.");

  const entry = instances.find((candidate) =>
    typeof candidate.instance_id === "string"
    && typeof candidate.e2e_pubkey === "string"
    && Array.isArray(candidate.nonces)
    && candidate.nonces.some((value) => typeof value === "string"));
  if (!entry || typeof entry.instance_id !== "string" || typeof entry.e2e_pubkey !== "string"
    || !Array.isArray(entry.nonces)) {
    throw new ConfidentialError("evidence_invalid", "No usable enclave instance was returned.");
  }
  const instanceId = entry.instance_id;
  const e2ePubkey = entry.e2e_pubkey;
  const instanceNonce = entry.nonces.find((value): value is string => typeof value === "string");
  if (!instanceNonce || !/^[A-Za-z0-9_-]{16,128}$/.test(instanceNonce)) {
    throw new ConfidentialError("evidence_invalid", "The enclave instance nonce was invalid.");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(instanceId)) {
    throw new ConfidentialError("evidence_invalid", "The enclave instance id was invalid.");
  }

  const pubkeys = payload?.e2e_pubkeys && typeof payload.e2e_pubkeys === "object" ? payload.e2e_pubkeys : {};
  const recordKey = typeof pubkeys[instanceId] === "string" ? (pubkeys[instanceId] as string) : null;
  if (recordKey !== null && recordKey !== e2ePubkey) {
    throw new ConfidentialError("key_binding_failed", "The enclave key records disagree.");
  }

  const evidenceInstances = Array.isArray(payload?.evidence) ? payload.evidence : [];
  const instanceEvidence = evidenceInstances.find((candidate) => candidate.instance_id === instanceId)
    ?? evidenceInstances[0];
  const quoteRaw = typeof instanceEvidence?.quote === "string" ? instanceEvidence.quote : null;
  const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
  if (!parsed) throw new ConfidentialError("evidence_invalid", "The enclave quote could not be parsed.");
  if (parsed.teeType !== TDX_TEE_TYPE) throw new ConfidentialError("attestation_untrusted", "The enclave is not Intel TDX.");
  if (parsed.debugEnabled) throw new ConfidentialError("attestation_untrusted", "The enclave is in debug mode.");
  if (matchMeasurementAllowlist(parsed, chutesAllowlist()) === null) {
    throw new ConfidentialError("measurement_untrusted", "The enclave measurements are not on the reviewed allowlist.");
  }
  const expected = sha256Hex(input.nonce + e2ePubkey);
  if (!hexEqual(parsed.reportData.slice(0, 64), expected)) {
    throw new ConfidentialError("key_binding_failed", "The enclave key is not bound to this request's nonce.");
  }

  const instanceKey = decodeInstanceKey(e2ePubkey);
  return new ChutesSession(input.upstreamModel, instanceId, instanceNonce, instanceKey);
}

export const chutesTransport: E2eeTransport = {
  provider: "chutes",
  protocol: "chutes-mlkem-v1",
  streaming: false,

  createSession(input: CreateSessionInput): E2eeSession {
    return verifyChutesEvidence(input);
  },

  async complete(session: E2eeSession, request: E2eeChatRequest, options: CompleteOptions): Promise<E2eeCompletion> {
    if (!(session instanceof ChutesSession) || session.disposed) {
      throw new ConfidentialError("transport_failed", "The encrypted session is not usable.");
    }
    // Fresh per-request response keypair; its secret never leaves this function.
    const responseKeys = ml_kem768.keygen(randomBytes(ml_kem768.lengths.seed ?? 64));
    const requestKem = ml_kem768.encapsulate(session.instancePublicKey, randomBytes(ml_kem768.lengths.msgRand ?? 32));
    const requestNonce = randomBytes(12);
    const json = JSON.stringify({
      // Chutes' enclave reads the upstream model id from the encrypted body.
      model: request.upstreamModel,
      messages: request.messages,
      max_tokens: request.maxOutputTokens,
      stream: false,
      e2e_response_pk: bytesToBase64(responseKeys.publicKey)
    });
    let blob: Uint8Array;
    const requestKey = chutesKey(requestKem.sharedSecret, requestKem.cipherText, "e2e-req-v1");
    try {
      const compressed = await gzip(utf8Encode(json));
      const encrypted = chacha20poly1305(requestKey, requestNonce).encrypt(compressed);
      blob = concatBytes(requestKem.cipherText, requestNonce, encrypted);
    } catch (error) {
      zeroize(responseKeys.secretKey, requestKem.sharedSecret, requestKey);
      if (error instanceof ConfidentialError) throw error;
      throw new ConfidentialError("encrypt_failed", "Failed to encrypt the request.");
    }
    zeroize(requestKem.sharedSecret, requestKey);

    let response: Response;
    try {
      response = await options.http.fetchImpl(joinUrl(options.http.baseUrl, "/v1/e2ee/chat/completions"), {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        headers: {
          "content-type": "application/octet-stream",
          accept: "application/octet-stream",
          "x-anonrouter-ticket": options.ticket,
          "x-anonrouter-e2ee-provider": "chutes",
          "x-chutes-instance-id": session.instanceId,
          "x-chutes-e2e-nonce": session.instanceNonce
        },
        body: asBufferSource(blob),
        signal: options.signal
      });
    } catch {
      zeroize(responseKeys.secretKey);
      if (options.signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError("transport_failed", "The encrypted request could not be sent.");
    }
    if (!response.ok) {
      zeroize(responseKeys.secretKey);
      throw new ConfidentialError("transport_failed", await parseRelayError(response));
    }

    const lengthHeader = response.headers.get("content-length");
    if (lengthHeader && Number(lengthHeader) > MAX_RESPONSE_BYTES) {
      zeroize(responseKeys.secretKey);
      throw new ConfidentialError("response_too_large", "The encrypted response was too large.");
    }
    const responseBytes = new Uint8Array(await response.arrayBuffer());
    if (responseBytes.length > MAX_RESPONSE_BYTES) {
      zeroize(responseKeys.secretKey);
      throw new ConfidentialError("response_too_large", "The encrypted response was too large.");
    }

    const completion = await decryptChutesResponse(responseBytes, responseKeys.secretKey);
    zeroize(responseKeys.secretKey);
    options.onDelta?.({ content: completion.content });
    return completion;
  },

  dispose(session: E2eeSession): void {
    if (session instanceof ChutesSession && !session.disposed) {
      zeroize(session.instancePublicKey);
      session.disposed = true;
    }
  }
};

/** Decrypt a Chutes ML-KEM whole-body response and return the RAW decrypted JSON
 *  object (the exact upstream completion body). Exported low-level: this is the
 *  primitive the shared KAT vectors exercise. */
export async function chutesDecryptResponseJson(
  responseBytes: Uint8Array,
  responseSecretKey: Uint8Array
): Promise<unknown> {
  if (responseBytes.length < MIN_RESPONSE_BYTES) {
    throw new ConfidentialError("response_invalid", "The encrypted response was too short.");
  }
  const mlkemCiphertext = responseBytes.subarray(0, MLKEM_CIPHERTEXT_BYTES);
  const nonce = responseBytes.subarray(RESPONSE_NONCE_OFFSET, RESPONSE_BODY_OFFSET);
  const encrypted = responseBytes.subarray(RESPONSE_BODY_OFFSET);
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = ml_kem768.decapsulate(mlkemCiphertext, responseSecretKey);
  } catch {
    throw new ConfidentialError("decrypt_failed", "The encrypted response key exchange failed.");
  }
  const responseKey = chutesKey(sharedSecret, mlkemCiphertext, "e2e-resp-v1");
  let json: string;
  try {
    const compressed = chacha20poly1305(responseKey, nonce).decrypt(encrypted);
    json = utf8Decode(await gunzip(compressed, MAX_DECOMPRESSED_BYTES));
  } catch (error) {
    zeroize(sharedSecret, responseKey);
    if (error instanceof ConfidentialError) throw error;
    throw new ConfidentialError("decrypt_failed", "The encrypted response failed authentication.");
  }
  zeroize(sharedSecret, responseKey);
  try {
    return JSON.parse(json);
  } catch {
    throw new ConfidentialError("response_invalid", "The decrypted response was not valid JSON.");
  }
}

/** Decrypt + normalize a Chutes ML-KEM whole-body response to an E2eeCompletion. */
export async function decryptChutesResponse(
  responseBytes: Uint8Array,
  responseSecretKey: Uint8Array
): Promise<E2eeCompletion> {
  return normalizeChutesCompletion(await chutesDecryptResponseJson(responseBytes, responseSecretKey));
}

function normalizeChutesCompletion(parsed: unknown): E2eeCompletion {
  const choice = (parsed as {
    choices?: Array<{ message?: { content?: unknown; reasoning_content?: unknown }; finish_reason?: unknown }>;
  })?.choices?.[0];
  const message = choice?.message;
  const content = typeof message?.content === "string" ? message.content : "";
  const reasoning = typeof message?.reasoning_content === "string" ? message.reasoning_content : undefined;
  const usageRaw = (parsed as { usage?: Record<string, unknown> })?.usage;
  const usage = usageRaw && typeof usageRaw === "object" ? {
    promptTokens: typeof usageRaw.prompt_tokens === "number" ? usageRaw.prompt_tokens : undefined,
    completionTokens: typeof usageRaw.completion_tokens === "number" ? usageRaw.completion_tokens : undefined,
    totalTokens: typeof usageRaw.total_tokens === "number" ? usageRaw.total_tokens : undefined
  } : undefined;
  return {
    content,
    reasoningContent: reasoning,
    usage,
    finishReason: typeof choice?.finish_reason === "string" ? choice.finish_reason : undefined
  };
}
