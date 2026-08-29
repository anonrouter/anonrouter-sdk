// Types for the client-opaque E2EE transports (near-ai, venice, chutes). The
// transport owns its provider crypto AND its independent, browser-side re-check of
// the raw evidence before it will encrypt. It is decoupled from any framework: it
// takes an explicit HTTP context (baseUrl + a fetch implementation) and builds
// every URL from that baseUrl.

import type { NormalizedVerdict } from "../verify/types.js";

/** A fetch implementation. Defaults to globalThis.fetch. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Where and how to reach the AnonRouter relay for the encrypted request. */
export interface HttpContext {
  /** AnonRouter API origin, e.g. "https://api.anonrouter.ai". No trailing slash
   *  required; paths are joined safely. */
  baseUrl: string;
  fetchImpl: FetchLike;
}

/** The three providers with a currently-callable client-opaque E2EE route. */
export type E2eeProviderId = "near-ai" | "venice" | "chutes";

/** The wire protocol each provider speaks. */
export type E2eeProtocol = "near-v2" | "venice-legacy" | "chutes-mlkem-v1";

/** The only message roles the E2EE launch surface accepts. */
export type E2eeRole = "user" | "system" | "assistant";

export interface E2eeChatMessage {
  role: E2eeRole;
  content: string;
}

/** A validated chat request (text-only, multi-turn). */
export interface E2eeChatRequest {
  /** Public catalog model id (the plaintext `model` field for NEAR/Venice, and the
   *  id used to mint the ticket). */
  model: string;
  /** Provider-native (upstream) model id (used inside the Chutes encrypted body). */
  upstreamModel: string;
  messages: E2eeChatMessage[];
  /** Explicit, bounded output-token ceiling. Required for every E2EE request. */
  maxOutputTokens: number;
}

/** Normalized, sanitized completion. */
export interface E2eeCompletion {
  content: string;
  reasoningContent?: string;
  usage?: { promptTokens?: number; completionTokens?: number; totalTokens?: number };
  finishReason?: string;
}

/** Inputs to a transport's independent, client-side attestation gate. */
export interface CreateSessionInput {
  /** Bound upstream model id from the attestation response. */
  upstreamModel: string;
  /** The exact fresh nonce the client generated and sent. */
  nonce: string;
  /** The gateway's normalized verdict, used only as an optional cross-check. The
   *  transport never trusts it in place of its own raw-evidence checks. */
  normalized?: NormalizedVerdict;
  /** Raw provider evidence for the client's own binding checks. */
  rawEvidence: unknown;
}

/** An opaque, disposable session carrying (private) key material. */
export interface E2eeSession {
  readonly provider: E2eeProviderId;
  readonly protocol: E2eeProtocol;
  readonly upstreamModel: string;
}

export interface CompleteOptions {
  http: HttpContext;
  /** The single-use inference ticket (paid). */
  ticket: string;
  signal?: AbortSignal;
  /** Incremental decrypted deltas for live streaming (NEAR/Venice). Chutes is
   *  non-streaming and calls this once with the full decrypted text. */
  onDelta?: (delta: { content?: string; reasoning?: string }) => void;
}

/** Provider-neutral transport contract. */
export interface E2eeTransport {
  readonly provider: E2eeProviderId;
  readonly protocol: E2eeProtocol;
  /** False for Chutes (non-streaming whole-body ML-KEM). */
  readonly streaming: boolean;
  /** Independently verify the raw evidence and set up a session with fresh client
   *  key material bound to the attested enclave key. Throws (fail-closed) when any
   *  required binding does not hold. */
  createSession(input: CreateSessionInput): E2eeSession;
  /** Encrypt, dispatch over the credential-isolated relay, decrypt, normalize. */
  complete(session: E2eeSession, request: E2eeChatRequest, options: CompleteOptions): Promise<E2eeCompletion>;
  /** Zeroize and release all key material held by the session. Idempotent. */
  dispose(session: E2eeSession): void;
}

/** Join a baseUrl and an API path without duplicating slashes. */
export function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

/** Content-free error message extraction from a non-ok relay response. */
export async function parseRelayError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: { message?: unknown }; message?: unknown };
    const message = (typeof body.error?.message === "string" && body.error.message)
      || (typeof body.message === "string" && body.message);
    return message || `Request failed with status ${response.status}`;
  } catch {
    return `Request failed with status ${response.status}`;
  }
}
