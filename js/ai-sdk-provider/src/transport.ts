import { APICallError } from "@ai-sdk/provider";
import { EventSourceParserStream } from "eventsource-parser/stream";
import type { AnonRouterMode, AnonRouterProviderPolicy } from "./options.js";

type Operation = "chat" | "embeddings";

export function apiBaseURL(value: string): string {
  const url = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
    url.username || url.password || url.search || url.hash
  ) {
    throw new TypeError("AnonRouter base URLs must use HTTPS and contain no credentials, query, or fragment.");
  }
  const path = url.pathname.replace(/\/+$/, "");
  return url.origin + (path.endsWith("/v1") ? path : path + "/v1");
}

export interface TransportConfig {
  mode: AnonRouterMode;
  baseURL: string;
  controlBaseURL: string;
  apiKey?: string;
  fetch?: typeof fetch;
}

const readObject = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;

function ticketMetadata(
  body: Record<string, unknown>,
  operation: Operation,
  embeddingProvider?: AnonRouterProviderPolicy,
) {
  if (operation === "embeddings") return { model: body.model, operation, provider: embeddingProvider };

  const venice = readObject(body.venice_parameters);
  const search = Array.isArray(body.tools)
    ? body.tools.find((tool: unknown) => readObject(tool)?.type === "anonrouter:web_search")
    : undefined;
  return {
    model: body.model,
    operation,
    provider: body.provider,
    max_completion_tokens: body.max_tokens,
    reasoning_effort: body.reasoning_effort,
    reasoning: body.reasoning,
    venice_parameters: typeof venice?.disable_thinking === "boolean"
      ? { disable_thinking: venice.disable_thinking }
      : undefined,
    web_search: search ? { max_uses: readObject(readObject(search)?.parameters)?.max_uses ?? 3 } : undefined,
  };
}

function requestError(url: string, message: string) {
  return new APICallError({ url, message, requestBodyValues: undefined, isRetryable: false });
}

function safeIdentifier(value: unknown): string | undefined {
  return typeof value === "string" && /^[a-zA-Z0-9_-]{1,128}$/.test(value) ? value : undefined;
}

async function rejected(url: string, response: Response, phase: string) {
  const envelope = readObject(await response.json().catch(() => undefined));
  const error = readObject(envelope?.error);
  const code = safeIdentifier(error?.type) ?? safeIdentifier(error?.code);
  const requestId = safeIdentifier(error?.request_id) ?? safeIdentifier(response.headers.get("x-request-id"));
  const retryAfter = response.headers.get("retry-after");
  return new APICallError({
    url,
    message: `AnonRouter ${phase} failed (HTTP ${response.status}${code ? `, ${code}` : ""}).`,
    requestBodyValues: undefined,
    statusCode: response.status,
    responseHeaders: retryAfter ? { "retry-after": retryAfter } : undefined,
    data: code || requestId ? { error: { type: code, request_id: requestId } } : undefined,
    isRetryable: false,
  });
}

function verifySettlement(response: Response, url: string): Response {
  if (!response.body) throw requestError(url, "AnonRouter returned an empty stream.");
  let settled = false;
  const stream = response.body
    .pipeThrough(new TextDecoderStream())
    .pipeThrough(new EventSourceParserStream())
    .pipeThrough(new TransformStream({
      transform(event, controller) {
        if (settled || event.event === "anonrouter.web_search") return;
        if (event.data === "[DONE]") settled = true;
        controller.enqueue(event.data.split("\n").map((line: string) => `data: ${line}\n`).join("") + "\n");
      },
      flush() {
        if (!settled) throw requestError(url, "AnonRouter stream ended before settlement ([DONE]).");
      },
    }))
    .pipeThrough(new TextEncoderStream());

  return new Response(stream, { status: response.status, headers: response.headers });
}

export function createTransport(
  config: TransportConfig,
  embeddingProvider?: AnonRouterProviderPolicy,
): typeof fetch {
  const chatURL = config.baseURL + "/chat/completions";
  const embeddingURL = config.baseURL + "/embeddings";
  const ticketURL = config.controlBaseURL + "/inference/tickets";

  async function send(url: string, init: RequestInit, phase: string) {
    try {
      const doFetch = config.fetch ?? globalThis.fetch;
      const response = await doFetch(url, { ...init, credentials: "omit", redirect: "error" });
      if (response.redirected || (response.status >= 300 && response.status < 400)) {
        await response.body?.cancel();
        throw requestError(url, "AnonRouter requests cannot follow redirects.");
      }
      if (!response.ok) throw await rejected(url, response, phase);
      return response;
    } catch (error) {
      init.signal?.throwIfAborted();
      if (APICallError.isInstance(error)) throw error;
      throw requestError(url, `AnonRouter ${phase} could not be completed.`);
    }
  }

  return async (input, init) => {
    const url = String(input);
    if (
      (url !== chatURL && url !== embeddingURL) ||
      init?.method !== "POST" || typeof init.body !== "string"
    ) {
      throw new TypeError("Unexpected request from the AnonRouter AI SDK provider.");
    }

    if (typeof window !== "undefined") {
      throw new TypeError("Run the AnonRouter AI SDK provider on a trusted server.");
    }
    const apiKey = config.apiKey ?? process.env.ANONROUTER_API_KEY;
    if (!apiKey?.trim()) throw new TypeError("Set ANONROUTER_API_KEY or pass apiKey to createAnonRouter.");

    const body = JSON.parse(init.body) as Record<string, unknown>;
    const operation = url === chatURL ? "chat" : "embeddings";
    const headers = new Headers(init.headers);
    for (const name of [
      "authorization", "proxy-authorization", "api-key", "x-api-key",
      "x-anonrouter-api-key", "cookie", "cookie2", "x-anonrouter-ticket",
    ]) {
      headers.delete(name);
    }

    if (config.mode === "compatibility") {
      headers.set("authorization", `Bearer ${apiKey}`);
    } else {
      const response = await send(ticketURL, {
        method: "POST",
        headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
        body: JSON.stringify(ticketMetadata(body, operation, embeddingProvider)),
        signal: init.signal,
      }, "ticket request");
      const issued = readObject(await response.json().catch(() => undefined));
      init.signal?.throwIfAborted();
      if (typeof issued?.ticket !== "string" || !issued.ticket.trim() || /[\r\n]/.test(issued.ticket)) {
        throw requestError(ticketURL, "AnonRouter returned an invalid inference ticket.");
      }
      if (typeof issued.privacy_class === "string" && issued.privacy_class.toLowerCase() === "e2ee") {
        throw requestError(ticketURL, "E2EE routes require @anonrouter/confidential.");
      }
      headers.set("x-anonrouter-ticket", issued.ticket);
    }

    const response = await send(url, { ...init, headers }, "inference request");
    return body.stream === true ? verifySettlement(response, url) : response;
  };
}
