import { afterEach, describe, expect, it, vi } from "vitest";
import { AnonrouterApiError, createClient } from "../src/index.js";

interface RecordedCall {
  url: string;
  init: RequestInit | undefined;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}

function headerValue(init: RequestInit | undefined, name: string): string | null {
  return new Headers(init?.headers).get(name);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("createClient chat", () => {
  it("runs the two-request ticketed flow and never sends the API key with content", async () => {
    const calls: RecordedCall[] = [];
    const fetchStub = vi.fn(async (input: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url: input, init });
      if (input.endsWith("/v1/inference/tickets")) {
        return jsonResponse({ ticket: "tkt_live_123" });
      }
      if (input.endsWith("/v1/chat/completions")) {
        return jsonResponse({
          id: "cmpl_1",
          object: "chat.completion",
          created: 1,
          model: "openai/gpt-oss-120b",
          choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }]
        });
      }
      throw new Error(`unexpected url ${input}`);
    });
    vi.stubGlobal("fetch", fetchStub);

    const client = createClient({ baseUrl: "https://api.anonrouter.ai/", apiKey: "sk-test" });
    const completion = await client.chat({
      model: "openai/gpt-oss-120b",
      provider: "near-ai",
      maxTokens: 256,
      reasoningEffort: "low",
      messages: [{ role: "user", content: "hello" }]
    });

    // Exactly two requests, in order: ticket then content.
    expect(calls).toHaveLength(2);

    // 1) Ticket request: Bearer API key + control-plane body (max_completion_tokens).
    const ticketCall = calls[0]!;
    expect(ticketCall.url).toBe("https://api.anonrouter.ai/v1/inference/tickets");
    expect(ticketCall.init?.method).toBe("POST");
    expect(headerValue(ticketCall.init, "authorization")).toBe("Bearer sk-test");
    expect(JSON.parse(String(ticketCall.init?.body))).toEqual({
      model: "openai/gpt-oss-120b",
      provider: "near-ai",
      max_completion_tokens: 256,
      reasoning_effort: "low"
    });

    // 2) Content request: ticket header, NO Authorization, OpenAI-style body.
    const contentCall = calls[1]!;
    expect(contentCall.url).toBe("https://api.anonrouter.ai/v1/chat/completions");
    expect(contentCall.init?.method).toBe("POST");
    expect(headerValue(contentCall.init, "x-anonrouter-ticket")).toBe("tkt_live_123");
    expect(headerValue(contentCall.init, "authorization")).toBeNull();
    expect(JSON.parse(String(contentCall.init?.body))).toMatchObject({
      model: "openai/gpt-oss-120b",
      provider: "near-ai",
      max_tokens: 256,
      reasoning_effort: "low",
      stream: false,
      messages: [{ role: "user", content: "hello" }]
    });

    expect(completion).toMatchObject({ choices: [{ message: { content: "hi" } }] });
  });

  it("returns the raw Response when streaming", async () => {
    const fetchStub = vi.fn(async (input: string): Promise<Response> => {
      if (input.endsWith("/v1/inference/tickets")) {
        return jsonResponse({ ticket: "tkt_stream" });
      }
      return new Response("data: {}\n\ndata: [DONE]\n\n", {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      });
    });
    vi.stubGlobal("fetch", fetchStub);

    const client = createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: "sk-stream" });
    const response = await client.chat({
      model: "openai/gpt-oss-120b",
      messages: [{ role: "user", content: "stream please" }],
      stream: true
    });

    expect(response).toBeInstanceOf(Response);
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    expect(await response.text()).toContain("[DONE]");
  });

  it("omits optional routing fields from the ticket when not provided", async () => {
    const calls: RecordedCall[] = [];
    const fetchStub = vi.fn(async (input: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url: input, init });
      if (input.endsWith("/v1/inference/tickets")) {
        return jsonResponse({ ticket: "tkt_min" });
      }
      return jsonResponse({ id: "c", object: "chat.completion", created: 1, model: "m", choices: [] });
    });
    vi.stubGlobal("fetch", fetchStub);

    const client = createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: "sk" });
    await client.chat({ model: "m", messages: [{ role: "user", content: "hi" }] });

    expect(JSON.parse(String(calls[0]!.init?.body))).toEqual({ model: "m" });
  });
});

describe("createClient models", () => {
  it("GETs /v1/models with the Bearer key and parses the list", async () => {
    const calls: RecordedCall[] = [];
    const fetchStub = vi.fn(async (input: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url: input, init });
      return jsonResponse({ object: "list", data: [{ id: "openai/gpt-oss-120b" }] });
    });
    vi.stubGlobal("fetch", fetchStub);

    const client = createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: "sk-abc" });
    const models = await client.models();

    expect(calls[0]!.url).toBe("https://api.anonrouter.ai/v1/models");
    expect(calls[0]!.init?.method).toBe("GET");
    expect(headerValue(calls[0]!.init, "authorization")).toBe("Bearer sk-abc");
    expect(models.data[0]!.id).toBe("openai/gpt-oss-120b");
  });
});

describe("createClient errors", () => {
  it("throws AnonrouterApiError carrying the status and message on non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ error: { message: "insufficient credit", request_id: "req_9" } }, 402))
    );
    const client = createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: "sk" });

    const error = await client.models().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AnonrouterApiError);
    expect((error as AnonrouterApiError).status).toBe(402);
    expect((error as AnonrouterApiError).message).toBe("insufficient credit");
    expect((error as AnonrouterApiError).requestId).toBe("req_9");
  });

  it("validates required options", () => {
    expect(() => createClient({ baseUrl: "", apiKey: "sk" })).toThrow(/baseUrl/);
    expect(() => createClient({ baseUrl: "https://x", apiKey: "" })).toThrow(/apiKey/);
  });
});
