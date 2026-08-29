// Minimal, bounded SSE parser for the streaming E2EE providers (NEAR + Venice).
// The SSE envelope is plaintext (only message content fields are ciphertext), so
// this parses the JSON frames and hands each to the provider, which decrypts the
// encrypted fields. Tolerates \r\n, multi-line data:, and keep-alives; caps total
// bytes to defend against an unbounded/hostile stream.

import { ConfidentialError } from "./errors.js";

/** Hard ceiling on the total bytes we will read from one E2EE SSE stream. */
const MAX_STREAM_BYTES = 16 * 1024 * 1024;

export async function* parseSseStream(
  response: Response,
  signal?: AbortSignal
): AsyncGenerator<unknown, void, unknown> {
  const body = response.body;
  if (!body) {
    throw new ConfidentialError("response_invalid", "The encrypted response had no stream body.");
  }
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let total = 0;

  const emit = function* (rawEvent: string): Generator<unknown> {
    const dataLines = rawEvent
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).replace(/^ /, ""));
    if (dataLines.length === 0) return;
    const data = dataLines.join("\n").trim();
    if (data.length === 0 || data === "[DONE]") return;
    try {
      yield JSON.parse(data);
    } catch {
      /* keep-alive / non-JSON line: ignore */
    }
  };

  try {
    for (;;) {
      if (signal?.aborted) throw new ConfidentialError("cancelled", "The request was cancelled.");
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        total += value.byteLength;
        if (total > MAX_STREAM_BYTES) {
          throw new ConfidentialError("response_too_large", "The encrypted response stream was too large.");
        }
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
      }
      let sep: number;
      while ((sep = buffer.indexOf("\n\n")) >= 0) {
        const rawEvent = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const done2 = rawEvent.includes("[DONE]");
        for (const obj of emit(rawEvent)) yield obj;
        if (done2) return;
      }
    }
    const tail = (buffer + decoder.decode()).trim();
    if (tail.length > 0) {
      for (const obj of emit(tail)) yield obj;
    }
  } finally {
    reader.releaseLock();
  }
}

export interface OpenAiDeltaFrame {
  /** Raw (possibly ciphertext) content delta. */
  content?: string;
  /** Raw (possibly ciphertext) reasoning delta. */
  reasoning?: string;
  finishReason?: string;
  usage?: { promptTokens?: number; completionTokens?: number; totalTokens?: number };
}

/** Extract the OpenAI-style delta + usage from one plaintext SSE envelope frame.
 *  Content/reasoning are returned verbatim (still ciphertext); the caller decrypts. */
export function extractOpenAiDelta(frame: unknown): OpenAiDeltaFrame {
  const out: OpenAiDeltaFrame = {};
  if (!frame || typeof frame !== "object") return out;
  const choice = (frame as {
    choices?: Array<{ delta?: { content?: unknown; reasoning_content?: unknown }; finish_reason?: unknown }>;
  }).choices?.[0];
  const content = choice?.delta?.content;
  const reasoning = choice?.delta?.reasoning_content;
  if (typeof content === "string" && content.length > 0) out.content = content;
  if (typeof reasoning === "string" && reasoning.length > 0) out.reasoning = reasoning;
  if (typeof choice?.finish_reason === "string") out.finishReason = choice.finish_reason;
  const usage = (frame as { usage?: unknown }).usage;
  if (usage && typeof usage === "object") {
    const u = usage as Record<string, unknown>;
    out.usage = {
      promptTokens: typeof u.prompt_tokens === "number" ? u.prompt_tokens : undefined,
      completionTokens: typeof u.completion_tokens === "number" ? u.completion_tokens : undefined,
      totalTokens: typeof u.total_tokens === "number" ? u.total_tokens : undefined
    };
  }
  return out;
}

/** Detect and surface a relay stream-error frame (`data: {"error": {...}}`). */
export function extractStreamError(frame: unknown): string | null {
  if (frame && typeof frame === "object" && "error" in (frame as Record<string, unknown>)) {
    const error = (frame as { error?: unknown }).error;
    if (error && typeof error === "object" && "type" in (error as Record<string, unknown>)) {
      return "The encrypted stream failed.";
    }
  }
  return null;
}
