// Venice transport.
//
// Protocol (verified against the official veniceai/venice-cli example):
//   - ECDH on secp256k1
//   - HKDF-SHA256, info "ecdsa_encryption"
//   - AES-256-GCM, 12-byte nonce, 16-byte tag
//   - wire: [65-byte uncompressed ephemeral pub][12-byte nonce][ciphertext+tag], hex
//   - one session client keypair; each encrypted field embeds that client pubkey
//   - headers: x-anonrouter-e2ee-provider: venice, x-venice-tee-client-pub-key,
//     x-venice-tee-model-pub-key, x-venice-tee-signing-algo: ecdsa
//   - responses: decrypt content and reasoning deltas client-side

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, concatBytes, hexToBytes, isHex, randomBytes, utf8DecodeLossy, utf8Encode, zeroize } from "../bytes.js";
import { ConfidentialError } from "../errors.js";
import { secp256k1AddressFromPublicKey } from "../verify/crypto.js";
import { hexEqual } from "../verify/crypto.js";
import { parseTdxQuote, TDX_TEE_TYPE } from "../verify/tdx.js";
import { extractOpenAiDelta, extractStreamError, parseSseStream } from "../sse.js";
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

const VENICE_INFO = utf8Encode("ecdsa_encryption");
const EPHEMERAL_PUBKEY_BYTES = 65;
const GCM_NONCE_BYTES = 12;
const MIN_CIPHERTEXT_BYTES = EPHEMERAL_PUBKEY_BYTES + GCM_NONCE_BYTES + 16; // 93
const VENICE_KEYSET_ALGO = "secp256k1-aes-256-gcm-hkdf-sha256";

interface VenicePayload {
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

class VeniceSession implements E2eeSession {
  readonly provider = "venice" as const;
  readonly protocol = "venice-legacy" as const;
  disposed = false;
  constructor(
    readonly upstreamModel: string,
    readonly clientPrivate: Uint8Array,
    readonly clientPublic: Uint8Array,
    readonly clientPublicHex: string,
    readonly modelPublic: Uint8Array,
    readonly modelPublicHex: string
  ) {}
}

function normalizeHex(value: unknown): string {
  if (typeof value !== "string") throw new ConfidentialError("evidence_invalid", "Expected hex in the evidence.");
  const clean = value.toLowerCase().replace(/^0x/, "");
  if (!isHex(clean) || clean.length === 0) throw new ConfidentialError("evidence_invalid", "Malformed hex in the evidence.");
  return clean;
}

function requireUncompressedKey(hexKey: string): Uint8Array {
  const bytes = hexToBytes(hexKey);
  if (bytes.length !== EPHEMERAL_PUBKEY_BYTES || bytes[0] !== 0x04 || !secp256k1.utils.isValidPublicKey(bytes, false)) {
    throw new ConfidentialError("key_binding_failed", "The enclave key is not a valid secp256k1 point.");
  }
  return bytes;
}

/** ECDH(secp256k1) -> HKDF-SHA256("ecdsa_encryption") -> 32-byte AES key. Uses the
 *  shared point's 32-byte X coordinate, matching the Venice protocol. */
function deriveAesKey(privateKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  let sharedPoint: Uint8Array;
  try {
    sharedPoint = secp256k1.getSharedSecret(privateKey, peerPublic, true);
  } catch {
    throw new ConfidentialError("encrypt_failed", "ECDH key agreement failed.");
  }
  if (sharedPoint.length !== 33 || (sharedPoint[0] !== 0x02 && sharedPoint[0] !== 0x03)) {
    throw new ConfidentialError("encrypt_failed", "ECDH returned an invalid shared point.");
  }
  const sharedX = sharedPoint.slice(1);
  const key = hkdf(sha256, sharedX, undefined, VENICE_INFO, 32);
  zeroize(sharedX, sharedPoint);
  return key;
}

/** Encrypt one field to `recipientPubHex`, embedding the sender's public key.
 *  Exported low-level (the enclave and the client share this exact primitive). */
export function veniceEncrypt(
  plaintext: string,
  recipientPubHex: string,
  senderPrivate: Uint8Array,
  senderPublic: Uint8Array
): string {
  const key = deriveAesKey(senderPrivate, hexToBytes(recipientPubHex.toLowerCase().replace(/^0x/, "")));
  const nonce = randomBytes(GCM_NONCE_BYTES);
  try {
    const ciphertext = gcm(key, nonce).encrypt(utf8Encode(plaintext));
    return bytesToHex(concatBytes(senderPublic, nonce, ciphertext));
  } catch {
    throw new ConfidentialError("encrypt_failed", "Failed to encrypt a message.");
  } finally {
    zeroize(key);
  }
}

/** Decrypt one field with the recipient's private key (the peer public key is
 *  embedded in the wire prefix). Exported low-level. */
export function veniceDecrypt(ciphertextHex: string, recipientPrivate: Uint8Array): string {
  const clean = ciphertextHex.toLowerCase().replace(/^0x/, "");
  if (!isHex(clean)) throw new ConfidentialError("decrypt_failed", "The encrypted response field was malformed.");
  const blob = hexToBytes(clean);
  if (blob.length < MIN_CIPHERTEXT_BYTES) throw new ConfidentialError("decrypt_failed", "The encrypted response field was too short.");
  const peerPub = blob.subarray(0, EPHEMERAL_PUBKEY_BYTES);
  const nonce = blob.subarray(EPHEMERAL_PUBKEY_BYTES, EPHEMERAL_PUBKEY_BYTES + GCM_NONCE_BYTES);
  const ciphertext = blob.subarray(EPHEMERAL_PUBKEY_BYTES + GCM_NONCE_BYTES);
  const key = deriveAesKey(recipientPrivate, peerPub);
  try {
    return utf8DecodeLossy(gcm(key, nonce).decrypt(ciphertext));
  } catch {
    throw new ConfidentialError("decrypt_failed", "The encrypted response failed authentication.");
  } finally {
    zeroize(key);
  }
}

/** Independently re-verify Venice raw evidence. Venice has no pinned measurement
 *  policy; the enclave is bound via the signing key + workload keyset + report_data.
 *  Returns the trusted enclave encryption key (uncompressed secp256k1). */
function verifyVeniceEvidence(input: CreateSessionInput): Uint8Array {
  const payload = input.rawEvidence as VenicePayload | undefined;
  const quoteRaw = typeof payload?.intel_quote === "string" ? payload.intel_quote : null;
  const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
  if (!parsed) throw new ConfidentialError("evidence_invalid", "The enclave quote could not be parsed.");
  if (parsed.teeType !== TDX_TEE_TYPE) throw new ConfidentialError("attestation_untrusted", "The enclave is not Intel TDX.");
  if (parsed.debugEnabled) throw new ConfidentialError("attestation_untrusted", "The enclave is in debug mode.");

  const nonce = typeof payload?.nonce === "string" ? payload.nonce : null;
  if (!nonce || !hexEqual(nonce, input.nonce) || !hexEqual(parsed.reportData.slice(64, 128), input.nonce)) {
    throw new ConfidentialError("nonce_mismatch", "The enclave quote is not bound to this request's nonce.");
  }

  const model = typeof payload?.model === "string" ? payload.model : null;
  if (model !== input.upstreamModel) throw new ConfidentialError("model_mismatch", "The enclave attested a different model.");

  if (payload?.signing_algo !== "ecdsa") throw new ConfidentialError("attestation_untrusted", "Unsupported enclave signing algorithm.");

  const signingPublicKeyRaw = typeof payload?.signing_public_key === "string"
    ? payload.signing_public_key
    : typeof payload?.signing_key === "string" ? payload.signing_key : null;
  if (!signingPublicKeyRaw) throw new ConfidentialError("key_binding_failed", "The enclave encryption key is missing.");
  const signingPublicKey = normalizeHex(signingPublicKeyRaw);
  const signingAddress = typeof payload?.signing_address === "string" ? payload.signing_address.toLowerCase() : null;
  const derivedAddress = secp256k1AddressFromPublicKey(signingPublicKey);
  if (!signingAddress || !derivedAddress || !hexEqual(derivedAddress, signingAddress)) {
    throw new ConfidentialError("key_binding_failed", "The enclave signing address did not derive from its key.");
  }
  const addressReportPrefix = /^0x[0-9a-f]{40}$/.test(signingAddress) ? signingAddress.slice(2).padEnd(64, "0") : null;
  if (!addressReportPrefix || !hexEqual(parsed.reportData.slice(0, 64), addressReportPrefix)) {
    throw new ConfidentialError("key_binding_failed", "The enclave signing address is not bound into the quote.");
  }

  const reportedReportData = typeof payload?.attestation?.report_data === "string" ? payload.attestation.report_data : null;
  const evidenceReportData = typeof payload?.attestation?.evidence?.quote_report_data === "string"
    ? payload.attestation.evidence.quote_report_data : null;
  if (!hexEqual(reportedReportData, parsed.reportData) || !hexEqual(evidenceReportData, parsed.reportData)) {
    throw new ConfidentialError("attestation_untrusted", "The nested attestation report data did not match the quote.");
  }

  const keysetKeys = payload?.attestation?.workload_keyset?.e2ee_public_keys;
  const keyInWorkload = Array.isArray(keysetKeys) && keysetKeys.some((entry) =>
    entry?.algo === VENICE_KEYSET_ALGO
    && typeof entry.public_key === "string"
    && hexEqual(normalizeHex(entry.public_key), signingPublicKey));
  if (!keyInWorkload) throw new ConfidentialError("key_binding_failed", "The enclave key is not in the attested workload keyset.");

  const gpuOk = typeof payload?.nvidia_payload === "string" && payload.nvidia_payload.length > 0;
  if (!gpuOk) throw new ConfidentialError("attestation_untrusted", "The enclave GPU evidence is missing.");

  if (input.normalized && !hexEqual(input.normalized.attested_encryption_key, signingPublicKey)) {
    throw new ConfidentialError("key_binding_failed", "The enclave key disagrees with the gateway verdict.");
  }
  return requireUncompressedKey(signingPublicKey);
}

export const veniceTransport: E2eeTransport = {
  provider: "venice",
  protocol: "venice-legacy",
  streaming: true,

  createSession(input: CreateSessionInput): E2eeSession {
    const modelPublic = verifyVeniceEvidence(input);
    const clientPrivate = secp256k1.utils.randomSecretKey();
    const clientPublic = secp256k1.getPublicKey(clientPrivate, false);
    return new VeniceSession(
      input.upstreamModel,
      clientPrivate,
      clientPublic,
      bytesToHex(clientPublic),
      modelPublic,
      bytesToHex(modelPublic)
    );
  },

  async complete(session: E2eeSession, request: E2eeChatRequest, options: CompleteOptions): Promise<E2eeCompletion> {
    if (!(session instanceof VeniceSession) || session.disposed) {
      throw new ConfidentialError("transport_failed", "The encrypted session is not usable.");
    }
    const encryptedMessages = request.messages.map((message) => ({
      role: message.role,
      content: veniceEncrypt(message.content, session.modelPublicHex, session.clientPrivate, session.clientPublic)
    }));
    const body = JSON.stringify({
      model: request.model,
      provider: session.provider,
      messages: encryptedMessages,
      max_tokens: request.maxOutputTokens,
      stream: true
    });

    let response: Response;
    try {
      response = await options.http.fetchImpl(joinUrl(options.http.baseUrl, "/v1/chat/completions"), {
        method: "POST",
        credentials: "omit",
        cache: "no-store",
        headers: {
          "content-type": "application/json",
          accept: "text/event-stream",
          "x-anonrouter-ticket": options.ticket,
          "x-anonrouter-e2ee-provider": "venice",
          "x-venice-tee-client-pub-key": session.clientPublicHex,
          "x-venice-tee-model-pub-key": session.modelPublicHex,
          "x-venice-tee-signing-algo": "ecdsa"
        },
        body,
        signal: options.signal
      });
    } catch {
      if (options.signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      throw new ConfidentialError("transport_failed", "The encrypted request could not be sent.");
    }
    if (!response.ok) throw new ConfidentialError("transport_failed", await parseRelayError(response));

    let content = "";
    let reasoning = "";
    let usage: E2eeCompletion["usage"];
    let finishReason: string | undefined;
    for await (const frame of parseSseStream(response, options.signal)) {
      const streamError = extractStreamError(frame);
      if (streamError) throw new ConfidentialError("transport_failed", streamError);
      const delta = extractOpenAiDelta(frame);
      if (delta.content) {
        const text = veniceDecrypt(delta.content, session.clientPrivate);
        content += text;
        options.onDelta?.({ content: text });
      }
      if (delta.reasoning) {
        const text = veniceDecrypt(delta.reasoning, session.clientPrivate);
        reasoning += text;
        options.onDelta?.({ reasoning: text });
      }
      if (delta.usage) usage = delta.usage;
      if (delta.finishReason) finishReason = delta.finishReason;
    }
    return { content, reasoningContent: reasoning || undefined, usage, finishReason };
  },

  dispose(session: E2eeSession): void {
    if (session instanceof VeniceSession && !session.disposed) {
      zeroize(session.clientPrivate, session.clientPublic, session.modelPublic);
      session.disposed = true;
    }
  }
};
