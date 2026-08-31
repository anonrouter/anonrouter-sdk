// Ticketed media: the exact wire contract, and the negatives that must stay red.
//
// This suite is arranged around the property the two-origin split exists to
// create: the control origin learns WHO and WHAT SHAPE, the inference origin
// learns WHAT WAS SAID, and neither learns both. Most of these tests are
// deliberately planted to fail on a specific regression rather than to describe
// a feature:
//
//   - a prompt or speech input reaching the control origin
//   - the API key reaching the relay
//   - a ticket bound to different facts than were requested
//   - a ticket used twice
//   - a POST retried, which would be a second billable generation
//   - a malformed media payload accepted and handed to the caller
//
// The request shapes themselves come from shared/vectors/media-contract.json,
// which the Python suite replays too, so a change made in one language and not
// the other fails in both.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createClient } from "../src/client.js";
import { ConfidentialError } from "../src/errors.js";
import { MediaError, redactHeaders, utf16Length, canonicalImageSize } from "../src/media.js";
import type { FetchLike } from "../src/transport/types.js";

const VECTORS = JSON.parse(
  readFileSync(new URL("../../../shared/vectors/media-contract.json", import.meta.url), "utf8")
) as MediaVectors;

interface VectorRequest {
  method: string;
  origin: "control" | "inference";
  path: string;
  headers_present: string[];
  headers_absent: string[];
  body: Record<string, unknown>;
}

interface MediaVectors {
  control_origin: string;
  inference_origin: string;
  api_key: string;
  ticket_header: string;
  cases: Array<{
    name: string;
    api: "images.generate" | "audio.speech.create";
    args: Record<string, unknown>;
    probe: string;
    expected_input_chars?: number;
    expected_code_points?: number;
    mint: VectorRequest;
    ticket_response: Record<string, unknown>;
    content: VectorRequest;
  }>;
  refusals: Array<{
    name: string;
    api: "images.generate" | "audio.speech.create";
    args: Record<string, unknown>;
    code: string;
  }>;
}

const CONTROL = VECTORS.control_origin;
const INFERENCE = VECTORS.inference_origin;
const API_KEY = VECTORS.api_key;

/** One captured request, kept in the exact form the client produced it. */
interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  raw: string;
  credentials?: string;
}

interface Recorder {
  fetch: FetchLike;
  calls: Captured[];
  /** Only the requests that went to the control (API-key) origin. */
  control(): Captured[];
  /** Only the requests that went to the confidential inference origin. */
  inference(): Captured[];
}

/**
 * A recording fetch driven by a queue of responses.
 *
 * It records the FULL request, including the raw serialized body, so a test can
 * assert on what was on the wire rather than on what the client meant to send.
 */
function recorder(handler: (captured: Captured, index: number) => Response): Recorder {
  const calls: Captured[] = [];
  const fetch: FetchLike = async (url, init) => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[k.toLowerCase()] = v;
    }
    const raw = typeof init?.body === "string" ? init.body : "";
    const captured: Captured = {
      url,
      method: init?.method ?? "GET",
      headers,
      body: raw ? JSON.parse(raw) : undefined,
      raw,
      credentials: init?.credentials
    };
    calls.push(captured);
    if (init?.signal?.aborted) throw Object.assign(new Error("aborted"), { name: "AbortError" });
    return handler(captured, calls.length - 1);
  };
  return {
    fetch,
    calls,
    control: () => calls.filter((c) => c.url.startsWith(CONTROL)),
    inference: () => calls.filter((c) => c.url.startsWith(INFERENCE))
  };
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init
  });
}

/** A one-pixel PNG, so a successful image case decodes to real bytes. */
const PNG_B64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const MP3_BYTES = new Uint8Array([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x11]);

function imageOk(headers: Record<string, string> = {}): Response {
  return jsonResponse(
    { created: 1_700_000_000, model: "venice/flux-dev", data: [{ b64_json: PNG_B64, mime_type: "image/png" }] },
    { headers: { "content-type": "application/json", ...headers } }
  );
}

function speechOk(headers: Record<string, string> = {}): Response {
  return new Response(MP3_BYTES, {
    status: 200,
    headers: { "content-type": "audio/mpeg", ...headers }
  });
}

function errorResponse(status: number, type: string, requestId = "req_test"): Response {
  return jsonResponse(
    { error: { message: "refused", type, request_id: requestId } },
    { status, headers: { "content-type": "application/json" } }
  );
}

function client(fetchImpl: FetchLike, overrides: Record<string, unknown> = {}) {
  return createClient({
    inferenceBaseUrl: INFERENCE,
    controlBaseUrl: CONTROL,
    apiKey: API_KEY,
    fetch: fetchImpl,
    ...overrides
  });
}

/** Invoke a vector case against a client, by its declared accessor path. */
function invoke(
  c: ReturnType<typeof client>,
  api: "images.generate" | "audio.speech.create",
  args: Record<string, unknown>
): Promise<unknown> {
  return api === "images.generate"
    ? c.images.generate(args as never)
    : c.audio.speech.create(args as never);
}

// ---- The shared wire contract -------------------------------------------------

describe("the media wire contract (shared/vectors/media-contract.json)", () => {
  for (const testCase of VECTORS.cases) {
    it(testCase.name, async () => {
      const rec = recorder((captured, index) =>
        index === 0
          ? jsonResponse(testCase.ticket_response)
          : testCase.api === "images.generate"
            ? imageOk()
            : speechOk()
      );
      await invoke(client(rec.fetch), testCase.api, testCase.args);

      // Exactly two requests: one mint, one content. Nothing else, in either
      // direction, for either operation.
      expect(rec.calls).toHaveLength(2);

      for (const [captured, expected] of [
        [rec.calls[0], testCase.mint],
        [rec.calls[1], testCase.content]
      ] as const) {
        const origin = expected.origin === "control" ? CONTROL : INFERENCE;
        expect(captured.url).toBe(`${origin}${expected.path}`);
        expect(captured.method).toBe(expected.method);
        // EXACT body equality, key for key. The server schemas are strict, so an
        // extra key is a 400 and a missing one is an unbound fact.
        expect(captured.body).toEqual(expected.body);
        for (const header of expected.headers_present) {
          expect(Object.keys(captured.headers), `${expected.path} must send ${header}`)
            .toContain(header);
        }
        for (const header of expected.headers_absent) {
          expect(Object.keys(captured.headers), `${expected.path} must NOT send ${header}`)
            .not.toContain(header);
        }
        // A browser must not be able to attach an ambient cookie to either half.
        expect(captured.credentials).toBe("omit");
      }

      // The ticket the mint issued is the one presented, verbatim.
      expect(rec.calls[1].headers[VECTORS.ticket_header]).toBe(testCase.ticket_response.ticket);
      if (testCase.expected_input_chars !== undefined) {
        expect(rec.calls[0].body).toMatchObject({ input_chars: testCase.expected_input_chars });
      }
    });
  }

  for (const refusal of VECTORS.refusals) {
    it(`refuses: ${refusal.name}`, async () => {
      const rec = recorder(() => jsonResponse({ ticket: "should-never-be-minted" }));
      await expect(invoke(client(rec.fetch), refusal.api, refusal.args)).rejects.toMatchObject({
        code: refusal.code
      });
      // A refusal must happen BEFORE any network call: an unsatisfiable request
      // that mints first would burn a single-use ticket for nothing.
      expect(rec.calls).toHaveLength(0);
    });
  }
});

// ---- PLANTED NEGATIVE: content must never reach the control origin ------------

describe("the control origin never sees content", () => {
  for (const testCase of VECTORS.cases) {
    it(`${testCase.api}: the ${testCase.api === "images.generate" ? "prompt" : "input"} is absent from the entire ticket request`, async () => {
      const rec = recorder((captured, index) =>
        index === 0
          ? jsonResponse(testCase.ticket_response)
          : testCase.api === "images.generate"
            ? imageOk()
            : speechOk()
      );
      await invoke(client(rec.fetch), testCase.api, testCase.args);

      const mint = rec.calls[0];
      // Scan the WHOLE request, not just the body: a probe string in the URL, a
      // header, or a stray field would be just as much of a leak.
      const everything = `${mint.url}\n${JSON.stringify(mint.headers)}\n${mint.raw}`;
      expect(everything).not.toContain(testCase.probe);
      const content = testCase.api === "images.generate" ? testCase.args.prompt : testCase.args.input;
      expect(everything).not.toContain(content as string);
      // And the field names themselves are absent, so a future refactor cannot
      // add an empty `prompt: ""` and satisfy a substring check.
      expect(Object.keys(mint.body as object)).not.toContain("prompt");
      expect(Object.keys(mint.body as object)).not.toContain("input");
    });
  }

  it("a mint failure never reaches the content request at all", async () => {
    const rec = recorder(() => errorResponse(402, "insufficient_balance"));
    await expect(
      client(rec.fetch).images.generate({ model: "m", prompt: "SECRET-PROMPT" })
    ).rejects.toMatchObject({ code: "media_ticket_failed" });
    expect(rec.inference()).toHaveLength(0);
    expect(rec.calls).toHaveLength(1);
  });
});

// ---- PLANTED NEGATIVE: the API key must never reach the relay ------------------

describe("the inference origin never sees the API key", () => {
  it("sends no authorization, cookie, or key material on the content request", async () => {
    const rec = recorder((_c, index) => (index === 0 ? jsonResponse({ ticket: "tkt" }) : imageOk()));
    await client(rec.fetch).images.generate({ model: "m", prompt: "a boat" });

    const content = rec.inference()[0];
    expect(content.headers.authorization).toBeUndefined();
    expect(content.headers.cookie).toBeUndefined();
    // The key must not appear ANYWHERE in the relay request, under any header
    // name or inside the body.
    const everything = `${content.url}\n${JSON.stringify(content.headers)}\n${content.raw}`;
    expect(everything).not.toContain(API_KEY);
  });

  it("sends the API key on the mint and only there", async () => {
    const rec = recorder((_c, index) => (index === 0 ? jsonResponse({ ticket: "tkt" }) : speechOk()));
    await client(rec.fetch).audio.speech.create({ model: "m", input: "hello" });

    expect(rec.control()[0].headers.authorization).toBe(`Bearer ${API_KEY}`);
    expect(rec.inference()[0].headers.authorization).toBeUndefined();
  });
});

// ---- PLANTED NEGATIVE: ticket facts must not drift -----------------------------

describe("a ticket that binds different facts is refused before content is sent", () => {
  const drifts: Array<{ what: string; echo: Record<string, unknown>; call: () => Record<string, unknown> }> = [
    {
      what: "operation",
      echo: { ticket: "t", operation: "chat", model: "m", size: "1024x1024", response_format: "b64_json" },
      call: () => ({ model: "m", prompt: "p" })
    },
    {
      what: "model",
      echo: { ticket: "t", operation: "image", model: "other-model", size: "1024x1024", response_format: "b64_json" },
      call: () => ({ model: "m", prompt: "p" })
    },
    {
      what: "size",
      echo: { ticket: "t", operation: "image", model: "m", size: "512x512", response_format: "b64_json" },
      call: () => ({ model: "m", prompt: "p", size: "1024x1024" })
    },
    {
      what: "response_format",
      echo: { ticket: "t", operation: "image", model: "m", size: "1024x1024", response_format: "url" },
      call: () => ({ model: "m", prompt: "p" })
    }
  ];

  for (const drift of drifts) {
    it(`image: a drifting ${drift.what} stops the exchange`, async () => {
      const rec = recorder(() => jsonResponse(drift.echo));
      await expect(client(rec.fetch).images.generate(drift.call() as never)).rejects.toMatchObject({
        code: "ticket_binding_mismatch"
      });
      // THE POINT: the prompt was never sent anywhere.
      expect(rec.inference()).toHaveLength(0);
      expect(rec.calls).toHaveLength(1);
    });
  }

  it("speech: a drifting character count stops the exchange", async () => {
    const rec = recorder(() =>
      jsonResponse({ ticket: "t", operation: "speech", model: "m", input_chars: 999, response_format: "mp3" })
    );
    await expect(
      client(rec.fetch).audio.speech.create({ model: "m", input: "hello" })
    ).rejects.toMatchObject({ code: "ticket_binding_mismatch" });
    expect(rec.inference()).toHaveLength(0);
  });

  it("speech: a drifting voice stops the exchange", async () => {
    const rec = recorder(() =>
      jsonResponse({ ticket: "t", operation: "speech", model: "m", input_chars: 5, response_format: "mp3", voice: "other" })
    );
    await expect(
      client(rec.fetch).audio.speech.create({ model: "m", input: "hello", voice: "af_sky" })
    ).rejects.toMatchObject({ code: "ticket_binding_mismatch" });
    expect(rec.inference()).toHaveLength(0);
  });

  it("speech: a voice we did NOT ask for is drift too", async () => {
    // The relay compares (bound voice ?? null) with (body voice ?? null), so a
    // ticket carrying a voice would be redeemed against a body with none.
    const rec = recorder(() =>
      jsonResponse({ ticket: "t", operation: "speech", model: "m", input_chars: 5, response_format: "mp3", voice: "af_sky" })
    );
    await expect(
      client(rec.fetch).audio.speech.create({ model: "m", input: "hello" })
    ).rejects.toMatchObject({ code: "ticket_binding_mismatch" });
    expect(rec.inference()).toHaveLength(0);
  });

  it("a missing echo is tolerated: an older gateway is not proof of drift", async () => {
    const rec = recorder((_c, index) => (index === 0 ? jsonResponse({ ticket: "tkt" }) : imageOk()));
    await expect(client(rec.fetch).images.generate({ model: "m", prompt: "p" })).resolves.toBeTruthy();
  });

  it("a mint that returns no usable ticket never reaches the relay", async () => {
    for (const bad of [{}, { ticket: "" }, { ticket: 42 }, { ticket: null }]) {
      const rec = recorder(() => jsonResponse(bad));
      await expect(client(rec.fetch).images.generate({ model: "m", prompt: "p" })).rejects.toMatchObject({
        code: "media_ticket_failed"
      });
      expect(rec.inference()).toHaveLength(0);
    }
  });
});

// ---- PLANTED NEGATIVE: single use, and no retry --------------------------------

describe("tickets are single-use and POSTs are never retried", () => {
  it("mints a fresh ticket for every call and never replays one", async () => {
    let minted = 0;
    const rec = recorder((captured) => {
      if (captured.url.startsWith(CONTROL)) {
        minted += 1;
        return jsonResponse({ ticket: `tkt_${minted}` });
      }
      return imageOk();
    });
    const c = client(rec.fetch);
    await c.images.generate({ model: "m", prompt: "one" });
    await c.images.generate({ model: "m", prompt: "two" });

    expect(rec.control()).toHaveLength(2);
    const presented = rec.inference().map((call) => call.headers[VECTORS.ticket_header]);
    expect(presented).toEqual(["tkt_1", "tkt_2"]);
    // A reused ticket would show up as the same value twice.
    expect(new Set(presented).size).toBe(2);
  });

  it("does NOT retry a failed content POST, which would be a second generation", async () => {
    // 500 is the case a naive HTTP client would retry. A media generation is
    // billed on the provider attempt, so a transparent retry is a duplicate
    // charge for a caller who made one call.
    for (const status of [500, 502, 503, 429, 408]) {
      const rec = recorder((captured) =>
        captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt" }) : errorResponse(status, "upstream_error")
      );
      await expect(
        client(rec.fetch).images.generate({ model: "m", prompt: "p" })
      ).rejects.toBeInstanceOf(MediaError);
      expect(rec.inference(), `status ${status} must not be retried`).toHaveLength(1);
    }
  });

  it("does NOT retry a failed mint either", async () => {
    const rec = recorder(() => errorResponse(500, "internal"));
    await expect(client(rec.fetch).images.generate({ model: "m", prompt: "p" })).rejects.toMatchObject({
      code: "media_ticket_failed"
    });
    expect(rec.control()).toHaveLength(1);
  });

  it("does not retry a transport failure, which may have reached the provider", async () => {
    let attempts = 0;
    const fetchImpl: FetchLike = async (url) => {
      attempts += 1;
      if (url.startsWith(CONTROL)) return jsonResponse({ ticket: "tkt" });
      throw new Error("socket hang up");
    };
    await expect(
      client(fetchImpl).images.generate({ model: "m", prompt: "p" })
    ).rejects.toMatchObject({ code: "transport_failed" });
    expect(attempts).toBe(2);
  });
});

// ---- Typed errors --------------------------------------------------------------

describe("typed errors distinguish what was charged from what was not", () => {
  const cases: Array<{ status: number; type: string; code: string }> = [
    { status: 401, type: "ticket_required", code: "relay_refused" },
    { status: 401, type: "invalid_ticket", code: "ticket_rejected" },
    { status: 409, type: "ticket_model_mismatch", code: "ticket_rejected" },
    { status: 409, type: "ticket_input_length_mismatch", code: "ticket_rejected" },
    { status: 503, type: "media_disabled", code: "relay_refused" },
    { status: 402, type: "insufficient_balance", code: "relay_refused" },
    { status: 429, type: "rate_limited", code: "relay_refused" },
    { status: 500, type: "provider_error", code: "provider_failed" },
    { status: 502, type: "provider_unavailable", code: "provider_failed" }
  ];

  for (const { status, type, code } of cases) {
    it(`relay ${status} ${type} -> ${code}`, async () => {
      const rec = recorder((captured) =>
        captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt" }) : errorResponse(status, type)
      );
      await expect(client(rec.fetch).images.generate({ model: "m", prompt: "p" })).rejects.toMatchObject({
        code,
        diagnostics: { status, error_type: type }
      });
    });
  }

  it("reports a cancelled request as cancelled, not as a failure", async () => {
    const controller = new AbortController();
    controller.abort();
    const rec = recorder(() => jsonResponse({ ticket: "tkt" }));
    await expect(
      client(rec.fetch).images.generate({ model: "m", prompt: "p", signal: controller.signal })
    ).rejects.toMatchObject({ code: "cancelled" });
  });

  it("reports a deadline as timeout, which is not the same event as a cancel", async () => {
    const fetchImpl: FetchLike = async () => {
      throw Object.assign(new Error("timed out"), { name: "TimeoutError" });
    };
    await expect(
      client(fetchImpl).images.generate({ model: "m", prompt: "p" })
    ).rejects.toMatchObject({ code: "timeout" });
  });

  it("every media error is also a ConfidentialError, so existing handlers keep working", async () => {
    const rec = recorder(() => errorResponse(503, "media_disabled"));
    const error = await client(rec.fetch)
      .images.generate({ model: "m", prompt: "p" })
      .catch((e) => e);
    expect(error).toBeInstanceOf(MediaError);
    expect(error).toBeInstanceOf(ConfidentialError);
  });
});

// ---- PLANTED NEGATIVE: secrets and prompts stay out of errors ------------------

describe("errors carry no secrets, no prompts, and no header values", () => {
  it("never puts the prompt, the key, or the ticket into a message", async () => {
    const PROMPT = "SECRET-PROMPT-DO-NOT-LEAK";
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL)
        ? jsonResponse({ ticket: "SECRET-TICKET-DO-NOT-LEAK" })
        : // An error body that quotes the prompt back is exactly the shape that
          // leaks it into a log if the client passes the body through.
          jsonResponse(
            { error: { message: `rejected prompt: ${PROMPT}`, type: "content_policy" } },
            { status: 400 }
          )
    );
    const error = await client(rec.fetch)
      .images.generate({ model: "m", prompt: PROMPT })
      .catch((e) => e);

    const serialized = `${error.message}\n${JSON.stringify(error.diagnostics)}`;
    expect(serialized).not.toContain(PROMPT);
    expect(serialized).not.toContain(API_KEY);
    expect(serialized).not.toContain("SECRET-TICKET-DO-NOT-LEAK");
    // The machine-readable type IS kept: it is content-free and it is what a
    // caller branches on.
    expect(error.diagnostics.error_type).toBe("content_policy");
  });

  it("redacts every credential header while keeping the names visible", () => {
    const redacted = redactHeaders({
      authorization: "Bearer ar-secret",
      Cookie: "session=abc",
      "x-anonrouter-ticket": "tkt-secret",
      "content-type": "application/json"
    });
    expect(redacted).toEqual({
      authorization: "<redacted>",
      Cookie: "<redacted>",
      "x-anonrouter-ticket": "<redacted>",
      "content-type": "application/json"
    });
  });

  it("puts only redacted headers into diagnostics", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt-secret" }) : errorResponse(401, "invalid_ticket")
    );
    const error = await client(rec.fetch)
      .images.generate({ model: "m", prompt: "p" })
      .catch((e) => e);
    expect(error.diagnostics.headers["x-anonrouter-ticket"]).toBe("<redacted>");
    expect(JSON.stringify(error.diagnostics)).not.toContain("tkt-secret");
    // The origin IS reported, because a misconfiguration is the likeliest cause
    // and naming it is not a leak.
    expect(error.diagnostics.origin).toBe(INFERENCE);
  });
});

// ---- PLANTED NEGATIVE: malformed media must not be accepted --------------------

describe("malformed media is refused, not handed to the caller", () => {
  const badImages: Array<{ what: string; body: unknown }> = [
    { what: "a non-object envelope", body: [] },
    { what: "no data array", body: { created: 1, model: "m" } },
    { what: "an empty data array", body: { created: 1, model: "m", data: [] } },
    { what: "an entry that is not an object", body: { data: ["nope"] } },
    { what: "a missing b64_json", body: { data: [{ mime_type: "image/png" }] } },
    { what: "an empty b64_json", body: { data: [{ b64_json: "", mime_type: "image/png" }] } },
    { what: "a non-string b64_json", body: { data: [{ b64_json: 5, mime_type: "image/png" }] } },
    { what: "base64 with illegal characters", body: { data: [{ b64_json: "!!!not base64!!!", mime_type: "image/png" }] } },
    { what: "base64 of the wrong length", body: { data: [{ b64_json: "abcde", mime_type: "image/png" }] } },
    { what: "a missing mime type", body: { data: [{ b64_json: PNG_B64 }] } },
    { what: "a mime type that is not an image", body: { data: [{ b64_json: PNG_B64, mime_type: "text/html" }] } },
    { what: "base64 that decodes to nothing", body: { data: [{ b64_json: "", mime_type: "image/png" }] } }
  ];

  for (const { what, body } of badImages) {
    it(`image: rejects ${what}`, async () => {
      const rec = recorder((captured) =>
        captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt" }) : jsonResponse(body)
      );
      await expect(client(rec.fetch).images.generate({ model: "m", prompt: "p" })).rejects.toMatchObject({
        code: "response_invalid"
      });
    });
  }

  it("image: rejects a body that is not JSON at all", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL)
        ? jsonResponse({ ticket: "tkt" })
        : new Response("<html>gateway error</html>", {
            status: 200,
            headers: { "content-type": "text/html" }
          })
    );
    await expect(client(rec.fetch).images.generate({ model: "m", prompt: "p" })).rejects.toMatchObject({
      code: "response_invalid"
    });
  });

  it("speech: rejects a non-audio content type", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL)
        ? jsonResponse({ ticket: "tkt" })
        : jsonResponse({ not: "audio" })
    );
    await expect(client(rec.fetch).audio.speech.create({ model: "m", input: "x" })).rejects.toMatchObject({
      code: "response_invalid"
    });
  });

  it("speech: rejects an empty audio body", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL)
        ? jsonResponse({ ticket: "tkt" })
        : new Response(new Uint8Array(), { status: 200, headers: { "content-type": "audio/mpeg" } })
    );
    await expect(client(rec.fetch).audio.speech.create({ model: "m", input: "x" })).rejects.toMatchObject({
      code: "response_invalid"
    });
  });

  it("image: accepts a well-formed payload and decodes it", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt" }) : imageOk()
    );
    const result = await client(rec.fetch).images.generate({ model: "m", prompt: "p" });
    expect(result.data[0].b64_json).toBe(PNG_B64);
    expect(result.data[0].mime_type).toBe("image/png");
    expect(result.data[0].bytes.length).toBeGreaterThan(0);
    // A real PNG signature, so the decode is not merely non-empty.
    expect(Array.from(result.data[0].bytes.slice(0, 4))).toEqual([0x89, 0x50, 0x4e, 0x47]);
  });
});

// ---- Response metadata ---------------------------------------------------------

describe("meaningful response headers are preserved", () => {
  it("image: keeps the selected model, routing, safety flags and rate limits", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL)
        ? jsonResponse({ ticket: "tkt" })
        : imageOk({
            "x-anonrouter-selected-model": "venice/flux-dev",
            "x-anonrouter-routing": "exact",
            "x-anonrouter-provider-blurred": "false",
            "x-anonrouter-provider-content-violation": "true",
            "x-ratelimit-limit-requests": "100",
            "x-ratelimit-remaining-requests": "99",
            "x-ratelimit-reset-requests": "60"
          })
    );
    const result = await client(rec.fetch).images.generate({ model: "m", prompt: "p" });
    expect(result.selected_model).toBe("venice/flux-dev");
    expect(result.routing).toBe("exact");
    expect(result.provider_blurred).toBe(false);
    expect(result.provider_content_violation).toBe(true);
    expect(result.rate_limit).toMatchObject({
      limit_requests: 100,
      remaining_requests: 99,
      reset_requests: 60
    });
    expect(result.created).toBe(1_700_000_000);
    expect(result.model).toBe("venice/flux-dev");
  });

  it("speech: returns the bytes plus the content type and selected model", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL)
        ? jsonResponse({ ticket: "tkt" })
        : speechOk({ "x-anonrouter-selected-model": "venice/tts-kokoro", "x-anonrouter-routing": "exact" })
    );
    const result = await client(rec.fetch).audio.speech.create({ model: "m", input: "x" });
    expect(Array.from(result.audio)).toEqual(Array.from(MP3_BYTES));
    expect(result.content_type).toBe("audio/mpeg");
    expect(result.selected_model).toBe("venice/tts-kokoro");
  });

  it("omits metadata a deployment did not report rather than inventing it", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt" }) : imageOk()
    );
    const result = await client(rec.fetch).images.generate({ model: "m", prompt: "p" });
    expect(result.selected_model).toBeUndefined();
    expect(result.rate_limit).toBeUndefined();
    expect(result.provider_blurred).toBeUndefined();
  });
});

// ---- Configuration: the boundary cannot be collapsed ---------------------------

describe("a configuration that would collapse the privacy boundary is refused", () => {
  it("refuses media when both roles are the same remote origin", async () => {
    const rec = recorder(() => jsonResponse({ ticket: "tkt" }));
    const c = createClient({ baseUrl: INFERENCE, apiKey: API_KEY, fetch: rec.fetch });
    for (const call of [
      () => c.images.generate({ model: "m", prompt: "p" }),
      () => c.audio.speech.create({ model: "m", input: "x" })
    ]) {
      await expect(call()).rejects.toMatchObject({ code: "unsupported_request" });
    }
    // Refused before anything was sent.
    expect(rec.calls).toHaveLength(0);
  });

  it("still allows verification and chat on a single-origin client (no breaking change)", () => {
    const c = createClient({ baseUrl: INFERENCE, apiKey: API_KEY, fetch: recorder(() => new Response()).fetch });
    expect(typeof c.verifyRoute).toBe("function");
    expect(typeof c.chat).toBe("function");
  });

  it("allows a single loopback origin under the documented local-test override", async () => {
    // The same loopback-only escape hatch the package already documents for
    // plaintext http. There is no privacy boundary to collapse on one machine.
    const rec = recorder((captured, index) =>
      index === 0 ? jsonResponse({ ticket: "tkt" }) : imageOk()
    );
    const c = createClient({
      baseUrl: "http://127.0.0.1:8080",
      apiKey: API_KEY,
      fetch: rec.fetch,
      allowInsecureHttp: true
    });
    await expect(c.images.generate({ model: "m", prompt: "p" })).resolves.toBeTruthy();
  });

  it("refuses baseUrl and inferenceBaseUrl that disagree, rather than picking one", () => {
    expect(() =>
      createClient({
        baseUrl: "https://one.invalid",
        inferenceBaseUrl: "https://two.invalid",
        apiKey: API_KEY
      })
    ).toThrow(/must not disagree/);
  });

  it("defaults to the production pair when nothing is configured", async () => {
    const rec = recorder((_c, index) => (index === 0 ? jsonResponse({ ticket: "tkt" }) : imageOk()));
    const c = createClient({ apiKey: API_KEY, fetch: rec.fetch });
    await c.images.generate({ model: "m", prompt: "p" });
    expect(rec.calls[0].url).toBe("https://api.anonrouter.ai/v1/inference/tickets");
    expect(rec.calls[1].url).toBe("https://api.private.anonrouter.ai/v1/images/generations");
  });

  it("keeps controlBaseUrl defaulting to baseUrl for an existing single-origin caller", () => {
    // Preserving this is what makes the change non-breaking: a caller who set
    // only baseUrl must not suddenly start sending their key somewhere else.
    const rec = recorder(() => new Response());
    const c = createClient({ baseUrl: "https://solo.invalid", apiKey: API_KEY, fetch: rec.fetch });
    expect(c).toBeTruthy();
  });
});

// ---- Input validation ----------------------------------------------------------

describe("input validation refuses before spending a ticket", () => {
  const rejects: Array<{ what: string; run: (c: ReturnType<typeof client>) => Promise<unknown> }> = [
    { what: "an unknown image key", run: (c) => c.images.generate({ model: "m", prompt: "p", quality: "hd" } as never) },
    { what: "an unknown speech key", run: (c) => c.audio.speech.create({ model: "m", input: "x", format: "ogg" } as never) },
    { what: "a missing model", run: (c) => c.images.generate({ prompt: "p" } as never) },
    { what: "a non-string prompt", run: (c) => c.images.generate({ model: "m", prompt: 5 } as never) },
    { what: "a size below the floor", run: (c) => c.images.generate({ model: "m", prompt: "p", size: "100x100" }) },
    { what: "an over-long prompt", run: (c) => c.images.generate({ model: "m", prompt: "x".repeat(10_001) }) },
    { what: "an over-long speech input", run: (c) => c.audio.speech.create({ model: "m", input: "x".repeat(20_001) }) },
    { what: "an over-long voice", run: (c) => c.audio.speech.create({ model: "m", input: "x", voice: "v".repeat(65) }) },
    { what: "an empty voice", run: (c) => c.audio.speech.create({ model: "m", input: "x", voice: "" }) }
  ];

  for (const { what, run } of rejects) {
    it(`rejects ${what} without any network call`, async () => {
      const rec = recorder(() => jsonResponse({ ticket: "should-never-be-minted" }));
      await expect(run(client(rec.fetch))).rejects.toMatchObject({ code: "unsupported_request" });
      expect(rec.calls).toHaveLength(0);
    });
  }

  it("accepts the exact bounds the server accepts", async () => {
    const rec = recorder((captured) =>
      captured.url.startsWith(CONTROL) ? jsonResponse({ ticket: "tkt" }) : imageOk()
    );
    const c = client(rec.fetch);
    await expect(c.images.generate({ model: "m", prompt: "p", size: "128x128" })).resolves.toBeTruthy();
    await expect(c.images.generate({ model: "m", prompt: "p", size: "2048x2048" })).resolves.toBeTruthy();
  });
});

// ---- The character-count trap --------------------------------------------------

describe("the priced unit is UTF-16 code units", () => {
  it("counts astral characters the way the server does", () => {
    expect(utf16Length("Hi 😀")).toBe(5);
    expect(utf16Length("plain")).toBe(5);
    // The count the server would compute, not the number of user-visible glyphs.
    expect(utf16Length("😀😀")).toBe(4);
  });

  it("binds the same count it sends", async () => {
    const text = "emoji 😀 and more 🎧";
    const rec = recorder((_c, index) =>
      index === 0
        ? jsonResponse({ ticket: "tkt", operation: "speech", input_chars: utf16Length(text) })
        : speechOk()
    );
    await client(rec.fetch).audio.speech.create({ model: "m", input: text });
    const minted = (rec.control()[0].body as { input_chars: number }).input_chars;
    const sent = (rec.inference()[0].body as { input: string }).input;
    expect(minted).toBe(sent.length);
    expect(minted).toBe(utf16Length(text));
  });
});

describe("canonicalImageSize", () => {
  it("normalizes to the form the mint echoes", () => {
    expect(canonicalImageSize("1024x1024")).toBe("1024x1024");
    expect(canonicalImageSize("0512x0512")).toBe("512x512");
  });

  it("refuses what the server would refuse", () => {
    for (const bad of ["big", "12x12", "4096x4096", "1024", "1024x", "100x100"]) {
      expect(() => canonicalImageSize(bad), bad).toThrow();
    }
  });
});
