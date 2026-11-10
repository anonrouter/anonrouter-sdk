import { createServer, type RequestListener } from "node:http";
import { APICallError, embed, generateText, stepCountIs, streamText, tool } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { anonrouter, createAnonRouter } from "../src/index.js";

const API_KEY = "ar_test_key";
const CONTENT_URL = "https://api.example.test";
const CONTROL_URL = "https://control.example.test";
const TICKETS = CONTROL_URL + "/v1/inference/tickets";
const CHAT = CONTENT_URL + "/v1/chat/completions";
const EMBEDDINGS = CONTENT_URL + "/v1/embeddings";
const CHAT_MODEL = "openai/gpt-oss-120b:private";
const EMBEDDING_MODEL = "google/embeddinggemma-300m";
const USAGE = { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7, cost: 0.002 };
const SEARCH_SUMMARY = {
  searches: 1,
  model_calls: 2,
  cost: 0.006,
  model_cost: 0.001,
  results: [{ title: "Example result", url: "https://example.test/result", description: "Result excerpt" }]
};
const ROUTING_HEADERS = {
  "x-anonrouter-selected-model": "venice/openai/gpt-oss-120b",
  "x-anonrouter-provider": "venice",
  "x-anonrouter-routing": "exact",
  "x-anonrouter-provider-attempts": "2",
  "x-anonrouter-provider-fallback": "true",
  "x-anonrouter-privacy-class": "private"
};

const ROUTING_METADATA = {
  selectedModel: "venice/openai/gpt-oss-120b",
  provider: "venice",
  routing: "exact",
  providerAttempts: 2,
  providerFallback: true,
  privacyClass: "private"
};

interface Call {
  request: Request;
  body: Record<string, unknown>;
}

function recordFetch(respond: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const body = await request.json() as Record<string, unknown>;
    const call = { request, body };
    calls.push(call);
    return respond(call);
  };
  return { calls, fetch };
}

function providerWith(fetch: typeof globalThis.fetch, options: Parameters<typeof createAnonRouter>[0] = {}) {
  return createAnonRouter({
    apiKey: API_KEY,
    baseURL: CONTENT_URL,
    controlBaseURL: CONTROL_URL + "/v1/",
    fetch,
    ...options
  });
}

function completion(): Response {
  return Response.json({
    id: "cmpl_test",
    object: "chat.completion",
    created: 123,
    model: "openai/gpt-oss-120b",
    choices: [{ index: 0, message: { role: "assistant", content: "Hello from AnonRouter" }, finish_reason: "stop" }],
    usage: USAGE
  }, { headers: ROUTING_HEADERS });
}

function streamingCompletion(
  deltas: Record<string, unknown>[],
  finishReason: "stop" | "tool_calls",
  { progress = "", done = true, webSearch }: { progress?: string; done?: boolean; webSearch?: typeof SEARCH_SUMMARY } = {}
): Response {
  const chunk = {
    id: "cmpl_stream_test",
    object: "chat.completion.chunk",
    created: 124,
    model: "openai/gpt-oss-120b"
  };
  const parts = [
    ...deltas.map(delta => ({
      ...chunk,
      choices: [{ index: 0, delta, finish_reason: null }]
    })),
    { ...chunk, choices: [{ index: 0, delta: {}, finish_reason: finishReason }], web_search: webSearch },
    { ...chunk, choices: [], usage: webSearch ? { ...USAGE, cost: 0.007 } : USAGE }
  ];
  const events = parts.map(part => "data: " + JSON.stringify(part) + "\n\n").join("");
  const bytes = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes.encode(progress + events));
      if (done) {
        controller.enqueue(bytes.encode("data: [DO"));
        controller.enqueue(bytes.encode("NE]\n\n"));
      }
      controller.close();
    }
  });
  return new Response(body, {
    headers: { ...ROUTING_HEADERS, "content-type": "text/event-stream" }
  });
}

function expectTicketCall(call: Call, expectedFields: Record<string, unknown>, operation: "chat" | "embeddings" = "chat") {
  expect(call.request.url).toBe(TICKETS);
  expect(call.request.method).toBe("POST");
  expect(call.request.redirect).toBe("error");
  expect(call.request.headers.get("authorization")).toBe("Bearer " + API_KEY);
  expect(call.request.headers.get("cookie")).toBeNull();
  expect(call.request.headers.get("x-anonrouter-ticket")).toBeNull();

  const { operation: ticketOperation, ...body } = call.body;
  if (operation === "chat") {
    expect(ticketOperation ?? "chat").toBe("chat");
  } else {
    expect(ticketOperation).toBe("embeddings");
  }
  expect(body).toEqual(expectedFields);
}

function expectPrivateContent(call: Call, url: string, ticket: string) {
  expect(call.request.url).toBe(url);
  expect(call.request.method).toBe("POST");
  expect(call.request.redirect).toBe("error");
  expect(call.request.credentials).toBe("omit");
  expect(call.request.headers.get("x-anonrouter-ticket")).toBe(ticket);
  expect(call.request.headers.get("authorization")).toBeNull();
  expect(call.request.headers.get("cookie")).toBeNull();
  expect(JSON.stringify(call.body)).not.toContain(API_KEY);
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("AnonRouter provider", () => {
  it("exposes callable, chat, and embedding entry points", () => {
    expect(anonrouter(CHAT_MODEL).modelId).toBe(CHAT_MODEL);
    for (const model of [anonrouter.chat, anonrouter.chatModel, anonrouter.languageModel]) {
      expect(model(CHAT_MODEL).modelId).toBe(CHAT_MODEL);
    }
    for (const model of [anonrouter.embedding, anonrouter.embeddingModel, anonrouter.textEmbeddingModel]) {
      expect(model(EMBEDDING_MODEL).modelId).toBe(EMBEDDING_MODEL);
    }
  });

  it("uses the environment key and separates authorization from generated text", async () => {
    vi.stubEnv("ANONROUTER_API_KEY", API_KEY);
    const { fetch, calls } = recordFetch(({ request }) =>
      request.url === TICKETS ? Response.json({ ticket: "ticket_chat" }) : completion()
    );
    const provider = providerWith(fetch, {
      apiKey: undefined,
      headers: {
        Authorization: "Bearer override",
        Cookie: "session=override",
        "X-Api-Key": API_KEY,
        "X-AnonRouter-Ticket": "override-ticket",
        "X-App-Name": "app-test"
      }
    });
    const policy = { only: ["venice"], minimum_privacy: "private", allow_fallbacks: false };
    const routing = { strategy: "balanced", max_cost_usd: 0.02 };
    const result = await generateText({
      model: provider(CHAT_MODEL, { provider: "openai", reasoning_effort: "high" }),
      prompt: "private chat prompt",
      maxOutputTokens: 42,
      maxRetries: 0,
      headers: { "Proxy-Authorization": "Basic override", cookie2: "session=override" },
      providerOptions: {
        openaiCompatible: { reasoningEffort: "unrelated provider option" },
        anonrouter: { provider: policy, routing, reasoning_effort: "low" },
      }
    });

    expect(result.text).toBe("Hello from AnonRouter");
    expect(result.usage).toMatchObject({ inputTokens: 5, outputTokens: 2 });
    expect(result.providerMetadata?.anonrouter).toMatchObject({ ...ROUTING_METADATA, cost: 0.002 });
    expect(result.response.headers?.["x-anonrouter-privacy-class"]).toBe("private");
    expect(calls).toHaveLength(2);
    expectTicketCall(calls[0]!, {
      model: CHAT_MODEL,
      provider: policy,
      reasoning_effort: "low",
      max_completion_tokens: 42
    });
    expectPrivateContent(calls[1]!, CHAT, "ticket_chat");
    expect(calls[1]!.request.headers.get("x-app-name")).toBe("app-test");
    expect(calls[1]!.request.headers.get("proxy-authorization")).toBeNull();
    expect(calls[1]!.request.headers.get("cookie2")).toBeNull();
    expect(calls[1]!.request.headers.get("x-api-key")).toBeNull();
    expect(calls[1]!.body).toMatchObject({
      model: CHAT_MODEL,
      provider: policy,
      routing,
      reasoning_effort: "low",
      messages: [{ role: "user", content: "private chat prompt" }]
    });
    expect(calls[1]!.body.max_completion_tokens ?? calls[1]!.body.max_tokens).toBe(42);
  });

  it("streams a fragmented tool call and issues a new ticket for its result turn", async () => {
    let sequence = 0;
    const { fetch, calls } = recordFetch(({ request }) => {
      if (request.url === TICKETS) return Response.json({ ticket: "ticket_" + ++sequence });
      if (sequence === 1) {
        return streamingCompletion([
          { role: "assistant", tool_calls: [{
            index: 0, id: "call_weather", type: "function", function: { name: "weather", arguments: '{"city":"' }
          }] },
          { tool_calls: [{ index: 0, function: { arguments: 'Lisbon"}' } }] }
        ], "tool_calls");
      }
      return streamingCompletion([{ content: "Sunny " }, { content: "in Lisbon." }], "stop");
    });
    const execute = vi.fn(async ({ city }: { city: string }) => ({ city, forecast: "sunny" }));
    const result = streamText({
      model: providerWith(fetch).chat(CHAT_MODEL),
      prompt: "What is the weather in Lisbon?",
      tools: { weather: tool({ inputSchema: z.object({ city: z.string() }), execute }) },
      stopWhen: stepCountIs(2),
      maxRetries: 0
    });
    const text: string[] = [];
    for await (const delta of result.textStream) text.push(delta);

    expect(text.join("")).toBe("Sunny in Lisbon.");
    expect(execute).toHaveBeenCalledExactlyOnceWith({ city: "Lisbon" }, expect.any(Object));
    expect((await result.steps)).toHaveLength(2);
    expect((await result.providerMetadata)?.anonrouter).toMatchObject(ROUTING_METADATA);
    expect(calls).toHaveLength(4);
    expectTicketCall(calls[0]!, { model: CHAT_MODEL });
    expectTicketCall(calls[2]!, { model: CHAT_MODEL });
    expectPrivateContent(calls[1]!, CHAT, "ticket_1");
    expectPrivateContent(calls[3]!, CHAT, "ticket_2");
    expect(calls[1]!.body).toMatchObject({
      stream: true,
      tools: [{ type: "function", function: { name: "weather" } }]
    });
    expect(calls[3]!.body.messages).toEqual(expect.arrayContaining([
      expect.objectContaining({ role: "tool", tool_call_id: "call_weather", content: expect.stringContaining("sunny") })
    ]));
  });

  it("reserves managed web searches without sending search content to control", async () => {
    const progress = 'event: anonrouter.web_search\ndata: {"id":"cmpl_test","status":"started","index":1}\n\n';
    const { fetch, calls } = recordFetch(({ request }) =>
      request.url === TICKETS
        ? Response.json({ ticket: "ticket_search" })
        : streamingCompletion([{ content: "Search answer" }], "stop", { progress, webSearch: SEARCH_SUMMARY })
    );
    const result = streamText({
      model: providerWith(fetch)(CHAT_MODEL),
      prompt: "Search for the latest example",
      maxOutputTokens: 42,
      maxRetries: 0,
      providerOptions: { anonrouter: { webSearch: { maxUses: 2, maxResults: 4, maxTotalResults: 8 } } }
    });
    const errors: unknown[] = [];
    for await (const part of result.fullStream) {
      if (part.type === "error") errors.push(part.error);
    }

    expect(errors).toEqual([]);
    expect(await result.text).toBe("Search answer");
    expect(await result.finishReason).toBe("stop");
    expect((await result.providerMetadata)?.anonrouter).toMatchObject({
      ...ROUTING_METADATA,
      cost: 0.007,
      webSearch: SEARCH_SUMMARY
    });
    expect(calls).toHaveLength(2);
    expectTicketCall(calls[0]!, {
      model: CHAT_MODEL,
      max_completion_tokens: 42,
      web_search: { max_uses: 2 }
    });
    expectPrivateContent(calls[1]!, CHAT, "ticket_search");
    expect(calls[1]!.body.tools).toMatchObject([{
      type: "anonrouter:web_search",
      parameters: { max_uses: 2, max_results: 4, max_total_results: 8 }
    }]);
  });

  it("surfaces an incomplete stream even when a stop reason arrived before the missing settlement marker", async () => {
    const { fetch, calls } = recordFetch(({ request }) =>
      request.url === TICKETS
        ? Response.json({ ticket: "ticket_incomplete" })
        : streamingCompletion([{ content: "Potentially billable partial answer" }], "stop", { done: false })
    );
    const result = streamText({ model: providerWith(fetch)(CHAT_MODEL), prompt: "Test settlement" });
    const errors: unknown[] = [];
    try {
      for await (const part of result.fullStream) {
        if (part.type === "error") errors.push(part.error);
      }
    } catch (error) {
      errors.push(error);
    }

    expect(errors).toHaveLength(1);
    expect(calls.map(call => call.request.url)).toEqual([TICKETS, CHAT]);
  });

  it("mints an embeddings ticket without exposing the embedding input or sending the provider pin to the relay", async () => {
    const { fetch, calls } = recordFetch(({ request }) =>
      request.url === TICKETS
        ? Response.json({ ticket: "ticket_embed" })
        : Response.json({
          object: "list",
          model: EMBEDDING_MODEL,
          data: [{ object: "embedding", index: 0, embedding: [0.25, -0.5] }],
          usage: { prompt_tokens: 4, total_tokens: 4 }
        })
    );
    const result = await embed({
      model: providerWith(fetch).embeddingModel(EMBEDDING_MODEL),
      value: "private embedding input",
      maxRetries: 0,
      providerOptions: { anonrouter: { provider: "tinfoil" } }
    });

    expect(result.embedding).toEqual([0.25, -0.5]);
    expect(result.usage.tokens).toBe(4);
    expect(calls).toHaveLength(2);
    expectTicketCall(calls[0]!, { model: EMBEDDING_MODEL, provider: "tinfoil" }, "embeddings");
    expectPrivateContent(calls[1]!, EMBEDDINGS, "ticket_embed");
    expect(calls[1]!.body).toMatchObject({ model: EMBEDDING_MODEL, input: ["private embedding input"] });
    expect(calls[1]!.body).not.toHaveProperty("provider");
  });

  it("issues independent single-use tickets for concurrent calls to the same model", async () => {
    let sequence = 0;
    const { fetch, calls } = recordFetch(({ request }) =>
      request.url === TICKETS ? Response.json({ ticket: "ticket_" + ++sequence }) : completion()
    );
    const model = providerWith(fetch)(CHAT_MODEL);
    await Promise.all([
      generateText({ model, prompt: "First request", maxOutputTokens: 11, maxRetries: 0 }),
      generateText({ model, prompt: "Second request", maxOutputTokens: 12, maxRetries: 0 })
    ]);
    const tickets = calls.filter(call => call.request.url === TICKETS);
    const content = calls.filter(call => call.request.url === CHAT);
    expect(tickets).toHaveLength(2);
    expect(content).toHaveLength(2);
    expect(tickets.map(call => call.body.max_completion_tokens).sort()).toEqual([11, 12]);
    expect(content.map(call => call.request.headers.get("x-anonrouter-ticket")).sort()).toEqual(["ticket_1", "ticket_2"]);
    for (const [index, ticket] of tickets.entries()) {
      const matching = content.find(call => call.request.headers.get("x-anonrouter-ticket") === "ticket_" + (index + 1));
      expect(matching?.body.max_completion_tokens ?? matching?.body.max_tokens).toBe(ticket.body.max_completion_tokens);
    }
  });

  it("uses one bearer-authenticated content request only when compatibility mode is explicit", async () => {
    const { fetch, calls } = recordFetch(() => completion());
    const model = providerWith(fetch, { mode: "compatibility" }).languageModel(CHAT_MODEL);
    await generateText({ model, prompt: "compatibility prompt", maxRetries: 0 });

    expect(calls).toHaveLength(1);
    const { request, body } = calls[0]!;
    expect(request.url).toBe(CHAT);
    expect(request.redirect).toBe("error");
    expect(request.headers.get("authorization")).toBe("Bearer " + API_KEY);
    expect(request.headers.get("x-anonrouter-ticket")).toBeNull();
    expect(body.messages).toMatchObject([{ role: "user", content: "compatibility prompt" }]);
  });

  it("supports model fallback explicitly in compatibility mode", async () => {
    const { fetch, calls } = recordFetch(() => completion());
    const provider = providerWith(fetch, { mode: "compatibility" });
    const models = ["openai/gpt-oss-120b", "openai/gpt-oss-20b"];
    await generateText({
      model: provider(models[0]!),
      prompt: "Use an alternate model only if necessary",
      maxRetries: 0,
      providerOptions: { anonrouter: { models } }
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toMatchObject({ model: models[0], models });
  });

  it.each([
    { modelId: CHAT_MODEL, options: { models: ["openai/gpt-oss-20b"] } },
    { modelId: "openai/gpt-oss-120b:e2ee", options: {} },
    { modelId: CHAT_MODEL, options: { provider: { minimum_privacy: "e2ee" } } },
    { modelId: "/auto", options: { routing: { privacy_classes: ["e2ee"] } } },
    { modelId: CHAT_MODEL, options: { provider: { order: ["venice"], prompt: "private data" } } },
  ])("rejects incompatible private request policy before any fetch", async ({ modelId, options }) => {
    const { fetch, calls } = recordFetch(() => Response.json({ ticket: "must_not_mint" }));
    const provider = providerWith(fetch);

    await expect(generateText({
      model: provider(modelId),
      prompt: "Must not be sent",
      maxRetries: 0,
      providerOptions: { anonrouter: options }
    })).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it("surfaces a failed ticket as an API error without fallback or exposing ticket material", async () => {
    const { fetch, calls } = recordFetch(() =>
      Response.json({
        error: { type: "permission_error", message: "Ticket cannot be minted", request_id: "req_test" },
        ticket: "ticket_must_not_leak"
      }, { status: 403 })
    );
    const model = providerWith(fetch)(CHAT_MODEL);
    const error = await generateText({ model, prompt: "must not reach content" }).catch((cause: unknown) => cause);

    expect(APICallError.isInstance(error)).toBe(true);
    expect(error).toMatchObject({ statusCode: 403, isRetryable: false });
    expect(JSON.stringify(error)).not.toContain("ticket_must_not_leak");
    expect(JSON.stringify(error)).not.toContain(API_KEY);
    expect(calls).toHaveLength(1);
    expectTicketCall(calls[0]!, { model: CHAT_MODEL });
  });

  it("propagates cancellation through the ticket request and skips content", async () => {
    const controller = new AbortController();
    const { fetch, calls } = recordFetch(({ request }) => {
      controller.abort();
      expect(request.signal.aborted).toBe(true);
      return Response.json({ ticket: "ticket_cancelled" });
    });
    const model = providerWith(fetch)(CHAT_MODEL);
    await expect(generateText({
      model,
      prompt: "Cancel before content",
      abortSignal: controller.signal,
      maxRetries: 0
    })).rejects.toMatchObject({ name: "AbortError" });

    expect(calls).toHaveLength(1);
    expectTicketCall(calls[0]!, { model: CHAT_MODEL });
  });

  it("stops before content when a ticket unexpectedly selects an E2EE route", async () => {
    const { fetch, calls } = recordFetch(() => Response.json({ ticket: "ticket_e2ee", privacy_class: "E2EE" }));
    const model = providerWith(fetch)(CHAT_MODEL);
    await expect(generateText({ model, prompt: "must not be sent in plaintext", maxRetries: 0 })).rejects.toThrow(/E2EE/);

    expect(calls).toHaveLength(1);
    expectTicketCall(calls[0]!, { model: CHAT_MODEL });
  });

  it("stops on a successful mint response that does not contain a ticket", async () => {
    const { fetch, calls } = recordFetch(() => Response.json({ unrelated: "success" }));
    const model = providerWith(fetch)(CHAT_MODEL);
    await expect(generateText({ model, prompt: "must not reach content", maxRetries: 0 })).rejects.toThrow();

    expect(calls).toHaveLength(1);
    expectTicketCall(calls[0]!, { model: CHAT_MODEL });
  });

  it.each(["private", "compatibility"] as const)("does not retry an ambiguous content error in %s mode", async mode => {
    const { fetch, calls } = recordFetch(({ request }) =>
      request.url === TICKETS
        ? Response.json({ ticket: "ticket_charge" })
        : Response.json({ error: { message: "Upstream disconnected" } }, { status: 502 })
    );
    const model = providerWith(fetch, { mode })(CHAT_MODEL);
    const error = await generateText({ model, prompt: "Potentially billable" }).catch((cause: unknown) => cause);

    expect(error).toMatchObject({ statusCode: 502, isRetryable: false });
    expect(calls.map(call => call.request.url)).toEqual(mode === "private" ? [TICKETS, CHAT] : [CHAT]);
  });
});

async function withServer(listener: RequestListener, run: (baseURL: string) => Promise<void>) {
  const server = createServer(listener);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("Expected a loopback HTTP server");
    await run("http://127.0.0.1:" + address.port);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error === undefined ? resolve() : reject(error));
    });
  }
}

describe("redirect protection with native fetch", () => {
  it.each(["control", "content"] as const)("does not follow a cross-origin 307 from the %s hop", async redirectFrom => {
    const redirected = vi.fn<RequestListener>((request, response) => {
      request.resume();
      response.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
    await withServer(redirected, async foreignOrigin => {
      const content = vi.fn<RequestListener>((request, response) => {
        request.resume();
        response.writeHead(307, { location: foreignOrigin + "/redirected" }).end();
      });
      await withServer(content, async contentOrigin => {
        const control = vi.fn<RequestListener>((request, response) => {
          request.resume();
          if (redirectFrom === "control") {
            response.writeHead(307, { location: foreignOrigin + "/redirected" }).end();
            return;
          }
          response.writeHead(200, { "content-type": "application/json" }).end('{"ticket":"ticket_native"}');
        });
        await withServer(control, async controlOrigin => {
          const model = createAnonRouter({ apiKey: API_KEY, baseURL: contentOrigin, controlBaseURL: controlOrigin })(CHAT_MODEL);
          await expect(generateText({ model, prompt: "Never send me to a redirect", maxRetries: 0 })).rejects.toThrow();

          expect(control).toHaveBeenCalledTimes(1);
          expect(content).toHaveBeenCalledTimes(redirectFrom === "content" ? 1 : 0);
          expect(redirected).not.toHaveBeenCalled();
        });
      });
    });
  });
});
