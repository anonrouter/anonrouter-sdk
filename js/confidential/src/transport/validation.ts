// Validation for client-encrypted confidential inference.
//
// The E2EE surface is text-only user/system/assistant messages with a bounded
// output ceiling. Multi-turn is supported: the caller re-sends the conversation
// (which it holds in plaintext) each turn and the SDK re-encrypts it fresh to the
// attested enclave, exactly like any stateless chat API. Anything outside the
// surface (tools, images, attachments) FAILS VISIBLY here rather than being
// silently downgraded to a plaintext request. The relay accepts the same
// user/system/assistant text and meters every message from ciphertext length.

import { ConfidentialError } from "../errors.js";
import type { E2eeChatMessage, E2eeChatRequest, E2eeRole } from "./types.js";

/** Per-message plaintext cap (characters). */
const MAX_MESSAGE_CHARS = 128 * 1024;
/** Whole-request plaintext cap across all messages. */
const MAX_TOTAL_CHARS = 256 * 1024;

export interface RawTurnMessage {
  role: string;
  content: unknown;
}

export interface ValidateInput {
  model: string;
  upstreamModel: string;
  messages: readonly RawTurnMessage[];
  maxOutputTokens: number;
}

/** Validate the message list (roles, text-only, size). Throws ConfidentialError on
 *  any violation. Multi-turn history (assistant turns) is accepted; tools, images,
 *  and attachments are not. */
export function validateE2eeMessages(messages: readonly RawTurnMessage[]): E2eeChatMessage[] {
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new ConfidentialError("unsupported_request", "The encrypted request has no messages.");
  }
  const out: E2eeChatMessage[] = [];
  let total = 0;
  let userCount = 0;
  for (const message of messages) {
    if (message.role === "tool") {
      throw new ConfidentialError("unsupported_request", "Encrypted requests do not support tool messages.");
    }
    if (message.role !== "user" && message.role !== "system" && message.role !== "assistant") {
      throw new ConfidentialError("unsupported_request", "Encrypted requests accept only user, system, and assistant messages.");
    }
    if (typeof message.content !== "string") {
      throw new ConfidentialError("unsupported_request", "Encrypted requests support text content only (no images or attachments).");
    }
    if (message.content.length === 0) {
      throw new ConfidentialError("unsupported_request", "Encrypted messages cannot be empty.");
    }
    if (message.content.length > MAX_MESSAGE_CHARS) {
      throw new ConfidentialError("unsupported_request", "An encrypted message is too long.");
    }
    total += message.content.length;
    if (total > MAX_TOTAL_CHARS) {
      throw new ConfidentialError("unsupported_request", "The encrypted request is too long.");
    }
    if (message.role === "user") userCount += 1;
    out.push({ role: message.role as E2eeRole, content: message.content });
  }
  if (userCount === 0) {
    throw new ConfidentialError("unsupported_request", "The encrypted request needs a user message.");
  }
  return out;
}

/** Validate + normalize a full request. Throws ConfidentialError on any violation. */
export function validateE2eeRequest(input: ValidateInput): E2eeChatRequest {
  if (typeof input.model !== "string" || input.model.length === 0
    || typeof input.upstreamModel !== "string" || input.upstreamModel.length === 0) {
    throw new ConfidentialError("unsupported_request", "The encrypted request is missing a model.");
  }
  if (!Number.isInteger(input.maxOutputTokens) || input.maxOutputTokens <= 0) {
    throw new ConfidentialError("unsupported_request", "Encrypted requests need a bounded output-token limit.");
  }
  const messages = validateE2eeMessages(input.messages);
  return {
    model: input.model,
    upstreamModel: input.upstreamModel,
    messages,
    maxOutputTokens: input.maxOutputTokens
  };
}
