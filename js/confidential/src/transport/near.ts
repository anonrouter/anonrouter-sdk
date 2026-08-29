// NEAR AI v2 transport.
//
// Protocol (verified against NEAR AI's live enclave endpoints):
//   - fresh Ed25519 client key; converted to X25519 for ECDH
//   - per-field ephemeral X25519 key
//   - HKDF-SHA256, info "ed25519_encryption"
//   - XChaCha20-Poly1305
//   - wire: [32-byte X25519 ephemeral pub][24-byte nonce][ciphertext+tag], lowercase hex
//   - headers: x-anonrouter-e2ee-provider: near-ai, x-signing-algo: ed25519,
//     x-client-pub-key: <64 hex>, x-encryption-version: 2
//   - ticketed POST /v1/chat/completions with per-field encrypted content
//   - responses: decrypt content and reasoning_content SSE fields client-side

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, edwardsToMontgomeryPriv, edwardsToMontgomeryPub, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  isHex,
  randomBytes,
  utf8DecodeLossy,
  utf8Encode,
  zeroize
} from "../bytes.js";
import { ConfidentialError } from "../errors.js";
import { pinnedMeasurementPolicyFor } from "../measurements.js";
import { hexEqual, sha256Hex } from "../verify/crypto.js";
import { matchMeasurementAllowlist, parseTdxQuote, TDX_TEE_TYPE, type TdxMeasurementEntry } from "../verify/tdx.js";
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

const NEAR_INFO = utf8Encode("ed25519_encryption");
const ALL_ZERO_MR_CONFIG = "00".repeat(48);
/** Minimum NEAR ciphertext blob: 32 + 24 + 16 bytes = 144 hex chars. */
const MIN_NEAR_CIPHERTEXT_HEX = (32 + 24 + 16) * 2;

interface NearPinnedMeasurement extends TdxMeasurementEntry {
  composeSha256?: string;
}

interface NearPayload {
  intel_quote?: unknown;
  nvidia_payload?: unknown;
  tls_cert_fingerprint?: unknown;
  model_name?: unknown;
  signing_address?: unknown;
  signing_public_key?: unknown;
  app_compose?: unknown;
  compose_hash?: unknown;
  info?: { tcb_info?: { app_compose?: { docker_compose_file?: unknown } } };
}

class NearSession implements E2eeSession {
  readonly provider = "near-ai" as const;
  readonly protocol = "near-v2" as const;
  disposed = false;
  constructor(
    readonly upstreamModel: string,
    /** Enclave Ed25519 public key (32 bytes) content is encrypted to. */
    readonly modelEd25519Key: Uint8Array,
    /** Fresh client Ed25519 secret key (32 bytes). Kept in memory only. */
    readonly clientSecret: Uint8Array,
    /** Client Ed25519 public key, lowercase hex (sent in x-client-pub-key). */
    readonly clientPublicHex: string
  ) {}
}

function hexToBytesLoose(value: unknown): Uint8Array {
  if (typeof value !== "string") throw new ConfidentialError("evidence_invalid", "Expected hex in the evidence.");
  const clean = value.toLowerCase().replace(/^0x/, "");
  if (!isHex(clean) || clean.length === 0) throw new ConfidentialError("evidence_invalid", "Malformed hex in the evidence.");
  return hexToBytes(clean);
}

/** ECDH(X25519) -> HKDF-SHA256("ed25519_encryption") -> 32-byte key. */
function deriveKey(x25519Private: Uint8Array, peerX25519Public: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(x25519Private, peerX25519Public);
  const key = hkdf(sha256, shared, undefined, NEAR_INFO, 32);
  zeroize(shared);
  return key;
}

/** Encrypt one field to the enclave's Ed25519 public key. Exported low-level. */
export function encryptField(plaintext: string, modelEd25519Key: Uint8Array): string {
  const ephemeralSecret = x25519.utils.randomSecretKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
  const nonce = randomBytes(24);
  const montPub = edwardsToMontgomeryPub(modelEd25519Key);
  const key = deriveKey(ephemeralSecret, montPub);
  try {
    const ciphertext = xchacha20poly1305(key, nonce).encrypt(utf8Encode(plaintext));
    return bytesToHex(concatBytes(ephemeralPublic, nonce, ciphertext));
  } catch {
    throw new ConfidentialError("encrypt_failed", "Failed to encrypt a message.");
  } finally {
    zeroize(ephemeralSecret, key);
  }
}

/** Decrypt one field with the client's Ed25519 secret key. Exported low-level. */
export function decryptField(ciphertextHex: string, clientSecret: Uint8Array): string {
  if (!isHex(ciphertextHex) || ciphertextHex.length < MIN_NEAR_CIPHERTEXT_HEX) {
    throw new ConfidentialError("decrypt_failed", "The encrypted response field was malformed.");
  }
  const wire = hexToBytes(ciphertextHex);
  if (wire.length < 72) throw new ConfidentialError("decrypt_failed", "The encrypted response field was too short.");
  const ephemeralPublic = wire.subarray(0, 32);
  const nonce = wire.subarray(32, 56);
  const ciphertext = wire.subarray(56);
  const montPriv = edwardsToMontgomeryPriv(clientSecret);
  const key = deriveKey(montPriv, ephemeralPublic);
  try {
    return utf8DecodeLossy(xchacha20poly1305(key, nonce).decrypt(ciphertext));
  } catch {
    throw new ConfidentialError("decrypt_failed", "The encrypted response failed authentication.");
  } finally {
    zeroize(montPriv, key);
  }
}

function measurementsFor(upstreamModel: string): NearPinnedMeasurement[] {
  const accepted = pinnedMeasurementPolicyFor("near-ai", upstreamModel)?.accepted;
  return Array.isArray(accepted) ? (accepted as NearPinnedMeasurement[]) : [];
}

/** Independently re-verify NEAR raw evidence (the client never trusts the gateway
 *  verdict alone). Throws on any required failure. Returns the trusted enclave
 *  Ed25519 encryption key. */
function verifyNearEvidence(input: CreateSessionInput): Uint8Array {
  const payload = input.rawEvidence as NearPayload | undefined;
  const quoteRaw = typeof payload?.intel_quote === "string" ? payload.intel_quote : null;
  const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
  if (!parsed) throw new ConfidentialError("evidence_invalid", "The enclave quote could not be parsed.");
  if (parsed.teeType !== TDX_TEE_TYPE) throw new ConfidentialError("attestation_untrusted", "The enclave is not Intel TDX.");
  if (parsed.debugEnabled) throw new ConfidentialError("attestation_untrusted", "The enclave is in debug mode.");

  if (!hexEqual(parsed.reportData.slice(64, 128), input.nonce)) {
    throw new ConfidentialError("nonce_mismatch", "The enclave quote is not bound to this request's nonce.");
  }

  const modelName = typeof payload?.model_name === "string" ? payload.model_name : null;
  if (modelName !== input.upstreamModel) {
    throw new ConfidentialError("model_mismatch", "The enclave attested a different model.");
  }

  const signingAddress = typeof payload?.signing_address === "string" ? payload.signing_address : null;
  const tlsFingerprint = typeof payload?.tls_cert_fingerprint === "string" ? payload.tls_cert_fingerprint : null;
  if (!signingAddress || !tlsFingerprint) {
    throw new ConfidentialError("attestation_untrusted", "The enclave did not bind its TLS identity.");
  }
  const expectedFirst = sha256Hex(concatBytes(hexToBytesLoose(signingAddress), hexToBytesLoose(tlsFingerprint)));
  if (!hexEqual(parsed.reportData.slice(0, 64), expectedFirst)) {
    throw new ConfidentialError("key_binding_failed", "The enclave TLS binding did not verify.");
  }

  const appCompose = typeof payload?.app_compose === "string"
    ? payload.app_compose
    : typeof payload?.info?.tcb_info?.app_compose?.docker_compose_file === "string"
      ? (payload.info.tcb_info.app_compose.docker_compose_file as string)
      : null;
  if (!appCompose || parsed.mrConfigId === ALL_ZERO_MR_CONFIG) {
    throw new ConfidentialError("measurement_untrusted", "The enclave did not bind its compose document.");
  }
  const composeSha256 = sha256Hex(appCompose);
  if (!hexEqual(parsed.mrConfigId, ("01" + composeSha256).padEnd(96, "0"))) {
    throw new ConfidentialError("measurement_untrusted", "The enclave compose binding did not verify.");
  }
  const reportedComposeHash = typeof payload?.compose_hash === "string" ? payload.compose_hash : null;
  if (!hexEqual(reportedComposeHash, composeSha256)) {
    throw new ConfidentialError("measurement_untrusted", "The enclave compose hash did not match.");
  }

  const allowlist = measurementsFor(input.upstreamModel);
  const matchedName = matchMeasurementAllowlist(parsed, allowlist);
  const matchedEntry = matchedName ? allowlist.find((entry) => entry.name === matchedName) : undefined;
  if (!matchedEntry || !hexEqual(matchedEntry.composeSha256, composeSha256)) {
    throw new ConfidentialError("measurement_untrusted", "The enclave measurements are not on the reviewed allowlist.");
  }

  const gpuOk = typeof payload?.nvidia_payload === "string" && (payload.nvidia_payload as string).length > 0;
  if (!gpuOk) throw new ConfidentialError("attestation_untrusted", "The enclave GPU evidence is missing.");

  const signingPublicKey = typeof payload?.signing_public_key === "string" ? payload.signing_public_key : null;
  if (!signingPublicKey || !/^[0-9a-f]{64}$/i.test(signingPublicKey)) {
    throw new ConfidentialError("key_binding_failed", "The enclave encryption key is missing or malformed.");
  }
  if (input.normalized && !hexEqual(input.normalized.attested_encryption_key, signingPublicKey)) {
    throw new ConfidentialError("key_binding_failed", "The enclave key disagrees with the gateway verdict.");
  }
  return hexToBytes(signingPublicKey);
}

export const nearTransport: E2eeTransport = {
  provider: "near-ai",
  protocol: "near-v2",
  streaming: true,

  createSession(input: CreateSessionInput): E2eeSession {
    const modelKey = verifyNearEvidence(input);
    const clientSecret = ed25519.utils.randomSecretKey();
    const clientPublic = ed25519.getPublicKey(clientSecret);
    return new NearSession(input.upstreamModel, modelKey, clientSecret, bytesToHex(clientPublic));
  },

  async complete(session: E2eeSession, request: E2eeChatRequest, options: CompleteOptions): Promise<E2eeCompletion> {
    if (!(session instanceof NearSession) || session.disposed) {
      throw new ConfidentialError("transport_failed", "The encrypted session is not usable.");
    }
    const encryptedMessages = request.messages.map((message) => ({
      role: message.role,
      content: encryptField(message.content, session.modelEd25519Key)
    }));
    const body = JSON.stringify({
      model: request.model,
      // The relay re-derives the provider-policy digest from the body and requires
      // it to equal the one bound into the ticket at issuance.
      provider: session.provider,
      messages: encryptedMessages,
      max_tokens: request.maxOutputTokens,
      stream: true
    });

    let response: Response;
    try {
      response = await options.http.fetchImpl(joinUrl(options.http.baseUrl, "/v1/chat/completions"), {
        method: "POST",
        // Credential-isolated relay: never attach a session cookie.
        credentials: "omit",
        cache: "no-store",
        headers: {
          "content-type": "application/json",
          accept: "text/event-stream",
          "x-anonrouter-ticket": options.ticket,
          "x-anonrouter-e2ee-provider": "near-ai",
          "x-signing-algo": "ed25519",
          "x-client-pub-key": session.clientPublicHex,
          "x-encryption-version": "2"
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
        const text = decryptField(delta.content, session.clientSecret);
        content += text;
        options.onDelta?.({ content: text });
      }
      if (delta.reasoning) {
        const text = decryptField(delta.reasoning, session.clientSecret);
        reasoning += text;
        options.onDelta?.({ reasoning: text });
      }
      if (delta.usage) usage = delta.usage;
      if (delta.finishReason) finishReason = delta.finishReason;
    }
    return { content, reasoningContent: reasoning || undefined, usage, finishReason };
  },

  dispose(session: E2eeSession): void {
    if (session instanceof NearSession && !session.disposed) {
      zeroize(session.clientSecret, session.modelEd25519Key);
      session.disposed = true;
    }
  }
};
