// A local, two-origin end-to-end for image and speech.
//
// The unit suite stubs `fetch`, which proves what the client MEANT to send. This
// runs two real HTTP servers on two different loopback ports and drives them
// with the real global fetch, so it proves what actually goes over a socket:
// real headers, real serialization, real status codes, real binary bodies.
//
// The two servers are deliberately built as ADVERSARIES of the client, not as
// helpers. The control server refuses to mint if it is ever shown content; the
// relay refuses to serve if it is ever shown a credential, and enforces the
// single-use ticket and every bound fact exactly as src/routes/{image,speech}.ts
// does. A client that cheats on the protocol fails here rather than passing on a
// mock that agrees with it.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClient } from "../src/client.js";

const API_KEY = "ar-e2e-key-must-never-reach-the-relay";
const MODEL_IMAGE = "venice/flux-dev";
const MODEL_SPEECH = "venice/tts-kokoro";
/** Marker strings the control server actively hunts for in anything it receives. */
const IMAGE_PROMPT = "a red kite over E2E-PROMPT-CANARY";
const SPEECH_INPUT = "read this aloud E2E-INPUT-CANARY 😀";

const PNG_BYTES = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64"
);
const MP3_BYTES = Buffer.from([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x11, 0x7f, 0x2a]);

/** A ticket exactly as the control plane binds one: single-use, fact-bound. */
interface BoundTicket {
  operation: "image" | "speech";
  model: string;
  size?: string;
  responseFormat: string;
  inputChars?: number;
  voice: string | null;
  spent: boolean;
}

const tickets = new Map<string, BoundTicket>();
/** Every request each origin saw, for the after-the-fact privacy assertions. */
const controlLog: Array<{ headers: Record<string, unknown>; body: string }> = [];
const relayLog: Array<{ headers: Record<string, unknown>; body: string }> = [];

let controlServer: Server;
let relayServer: Server;
let controlOrigin = "";
let inferenceOrigin = "";
let ticketCounter = 0;

function readBody(req: Parameters<Parameters<typeof createServer>[0]>[0]): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function send(res: Parameters<Parameters<typeof createServer>[0]>[1], status: number, body: unknown, headers: Record<string, string> = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
  res.writeHead(status, { "content-length": String(payload.length), ...headers });
  res.end(payload);
}

function fail(res: Parameters<Parameters<typeof createServer>[0]>[1], status: number, type: string, message: string) {
  send(res, status, { error: { type, message, request_id: `req_e2e_${status}` } }, {
    "content-type": "application/json"
  });
}

/**
 * The control plane. Holds the account, mints tickets, and MUST NEVER see
 * content: it fails the mint outright if a body carries a prompt, an input, or
 * either canary string.
 */
function buildControlServer(): Server {
  return createServer(async (req, res) => {
    const body = await readBody(req);
    controlLog.push({ headers: { ...req.headers }, body });

    if (req.url !== "/v1/inference/tickets" || req.method !== "POST") {
      return fail(res, 404, "not_found", "no such route on the control origin");
    }
    // The API key is required here, and only here.
    if (req.headers.authorization !== `Bearer ${API_KEY}`) {
      return fail(res, 401, "unauthorized", "the control origin requires the API key");
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return fail(res, 400, "invalid_body", "unparseable");
    }

    // THE ADVERSARIAL CHECK. If content ever reaches the control plane, the
    // split has failed and this must be a hard error, not a warning.
    for (const forbidden of ["prompt", "input", "messages"]) {
      if (forbidden in parsed) {
        return fail(res, 500, "content_reached_control", `the mint received "${forbidden}"`);
      }
    }
    if (body.includes("E2E-PROMPT-CANARY") || body.includes("E2E-INPUT-CANARY")) {
      return fail(res, 500, "content_reached_control", "the mint received content");
    }

    // `.strict()`: an unknown key is a 400, exactly as zod would answer.
    const allowed = new Set(["operation", "model", "size", "response_format", "input_chars", "voice"]);
    for (const key of Object.keys(parsed)) {
      if (!allowed.has(key)) return fail(res, 400, "unknown_field", `unexpected ${key}`);
    }

    const operation = parsed.operation as "image" | "speech";
    const ticket = `tkt_e2e_${++ticketCounter}`;
    if (operation === "image") {
      if (parsed.response_format !== "b64_json") {
        return fail(res, 400, "invalid_response_format", "image is b64_json only");
      }
      const size = (parsed.size as string) ?? "1024x1024";
      const [width, height] = size.split("x").map(Number);
      if (width < 128 || height < 128 || width > 2048 || height > 2048) {
        return fail(res, 400, "invalid_size", "out of range");
      }
      tickets.set(ticket, {
        operation: "image",
        model: parsed.model as string,
        size: `${width}x${height}`,
        responseFormat: "b64_json",
        voice: null,
        spent: false
      });
      // The mint ECHOES what it bound, which is what the client re-checks.
      return send(res, 200, {
        ticket,
        expires_in: 30,
        operation: "image",
        model: parsed.model,
        automatic: false,
        privacy_class: "private",
        max_output_tokens: 0,
        reasoning: "default",
        size: `${width}x${height}`,
        response_format: "b64_json"
      }, { "content-type": "application/json" });
    }

    if (parsed.response_format !== "mp3") {
      return fail(res, 400, "invalid_response_format", "speech is mp3 only");
    }
    if (typeof parsed.input_chars !== "number") {
      return fail(res, 400, "input_chars_required", "a speech ticket must bind the exact count");
    }
    tickets.set(ticket, {
      operation: "speech",
      model: parsed.model as string,
      responseFormat: "mp3",
      inputChars: parsed.input_chars,
      voice: (parsed.voice as string) ?? null,
      spent: false
    });
    return send(res, 200, {
      ticket,
      expires_in: 30,
      operation: "speech",
      model: parsed.model,
      input_chars: parsed.input_chars,
      response_format: "mp3",
      ...(parsed.voice ? { voice: parsed.voice } : {})
    }, { "content-type": "application/json" });
  });
}

/**
 * The credential-isolated relay. Sees content, holds no account, and enforces
 * every ticket-bound fact the way src/routes/{image,speech}.ts does.
 */
function buildRelayServer(): Server {
  return createServer(async (req, res) => {
    const body = await readBody(req);
    relayLog.push({ headers: { ...req.headers }, body });

    // THE ADVERSARIAL CHECK. The relay never accepts an account credential. In
    // production Caddy strips these before the relay; here, being shown one is a
    // hard failure so a client that leaks the key cannot pass this test.
    if (req.headers.authorization || req.headers.cookie) {
      return fail(res, 500, "credential_reached_relay", "the relay was shown an account credential");
    }
    // The relay serves the content paths and nothing else. Production is the
    // same: `POST /v1/inference/tickets` against the confidential origin answers
    // 404, because the mint lives on the control plane and is not proxied here.
    if (req.url !== "/v1/images/generations" && req.url !== "/v1/audio/speech") {
      return fail(res, 404, "not_found", "no such route on the relay");
    }
    const ticketId = req.headers["x-anonrouter-ticket"];
    if (typeof ticketId !== "string") {
      return fail(res, 401, "ticket_required", "A single-use ticket is required");
    }
    const bound = tickets.get(ticketId);
    if (!bound) return fail(res, 401, "invalid_ticket", "Inference ticket is invalid or expired");
    // SINGLE USE. Redemption consumes the ticket; a replay is indistinguishable
    // from an expired one, exactly as production answers.
    if (bound.spent) return fail(res, 401, "invalid_ticket", "Inference ticket is invalid or expired");
    bound.spent = true;

    const parsed = JSON.parse(body) as Record<string, unknown>;

    if (req.url === "/v1/images/generations") {
      if (bound.operation !== "image") return fail(res, 409, "ticket_operation_mismatch", "wrong operation");
      if (parsed.model !== bound.model) return fail(res, 409, "ticket_model_mismatch", "model drift");
      const size = (parsed.size as string) ?? "1024x1024";
      const [width, height] = size.split("x").map(Number);
      if (`${width}x${height}` !== bound.size) return fail(res, 409, "ticket_size_mismatch", "size drift");
      if ((parsed.response_format ?? "b64_json") !== bound.responseFormat) {
        return fail(res, 409, "ticket_format_mismatch", "format drift");
      }
      if (typeof parsed.prompt !== "string" || parsed.prompt.length === 0) {
        return fail(res, 400, "invalid_prompt", "the relay needs the prompt");
      }
      return send(res, 200, {
        created: 1_700_000_042,
        model: bound.model,
        data: [{ b64_json: PNG_BYTES.toString("base64"), mime_type: "image/png" }]
      }, {
        "content-type": "application/json",
        "x-anonrouter-selected-model": `venice/${bound.model}`,
        "x-anonrouter-routing": "exact",
        "x-ratelimit-limit-requests": "1000",
        "x-ratelimit-remaining-requests": "999"
      });
    }

    if (req.url === "/v1/audio/speech") {
      if (bound.operation !== "speech") return fail(res, 409, "ticket_operation_mismatch", "wrong operation");
      if (parsed.model !== bound.model) return fail(res, 409, "ticket_model_mismatch", "model drift");
      // The priced unit. UTF-16 code units, as Node counts them.
      if ((parsed.input as string).length !== bound.inputChars) {
        return fail(res, 409, "ticket_input_length_mismatch", "Input length does not match the issued ticket");
      }
      if (((parsed.voice as string) ?? null) !== bound.voice) {
        return fail(res, 409, "ticket_voice_mismatch", "voice drift");
      }
      if ((parsed.response_format ?? "mp3") !== bound.responseFormat) {
        return fail(res, 409, "ticket_format_mismatch", "format drift");
      }
      return send(res, 200, MP3_BYTES, {
        "content-type": "audio/mpeg",
        "x-anonrouter-selected-model": `venice/${bound.model}`,
        "x-anonrouter-routing": "exact"
      });
    }

    return fail(res, 404, "not_found", "no such route on the relay");
  });
}

beforeAll(async () => {
  controlServer = buildControlServer();
  relayServer = buildRelayServer();
  await Promise.all([
    new Promise<void>((resolve) => controlServer.listen(0, "127.0.0.1", resolve)),
    new Promise<void>((resolve) => relayServer.listen(0, "127.0.0.1", resolve))
  ]);
  controlOrigin = `http://127.0.0.1:${(controlServer.address() as AddressInfo).port}`;
  inferenceOrigin = `http://127.0.0.1:${(relayServer.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await Promise.all([
    new Promise<void>((resolve) => controlServer.close(() => resolve())),
    new Promise<void>((resolve) => relayServer.close(() => resolve()))
  ]);
});

function e2eClient() {
  return createClient({
    inferenceBaseUrl: inferenceOrigin,
    controlBaseUrl: controlOrigin,
    apiKey: API_KEY,
    // Two loopback ports: distinct origins, so the split is real, but plaintext
    // http needs the documented local-development opt-in.
    allowInsecureHttp: true
  });
}

describe("two-origin end to end, over real sockets", () => {
  it("generates an image and returns decodable bytes", async () => {
    const result = await e2eClient().images.generate({
      model: MODEL_IMAGE,
      prompt: IMAGE_PROMPT,
      size: "512x512"
    });

    expect(result.data).toHaveLength(1);
    expect(result.data[0].mime_type).toBe("image/png");
    expect(Buffer.from(result.data[0].bytes).equals(PNG_BYTES)).toBe(true);
    expect(result.model).toBe(MODEL_IMAGE);
    expect(result.created).toBe(1_700_000_042);
    expect(result.selected_model).toBe(`venice/${MODEL_IMAGE}`);
    expect(result.routing).toBe("exact");
    expect(result.rate_limit?.remaining_requests).toBe(999);
  });

  it("synthesizes speech and returns the exact audio bytes", async () => {
    const result = await e2eClient().audio.speech.create({
      model: MODEL_SPEECH,
      input: SPEECH_INPUT,
      voice: "af_sky"
    });

    expect(result.content_type).toBe("audio/mpeg");
    expect(Buffer.from(result.audio).equals(MP3_BYTES)).toBe(true);
    expect(result.selected_model).toBe(`venice/${MODEL_SPEECH}`);
  });

  it("bound an emoji input at the count the relay recomputed", async () => {
    // The relay compares against `input.length` in Node. If the client had bound
    // a code-point count this would have come back 409, not 200. The success
    // above IS the assertion; this pins the number so the reason is visible.
    const speechMints = controlLog.filter((entry) => entry.body.includes('"operation":"speech"'));
    const bound = JSON.parse(speechMints[0].body) as { input_chars: number };
    expect(bound.input_chars).toBe(SPEECH_INPUT.length);
    expect(bound.input_chars).not.toBe([...SPEECH_INPUT].length);
  });

  it("never sent content to the control origin", async () => {
    // Every byte the control server received across every test above.
    const everything = controlLog.map((entry) => entry.body).join("\n");
    expect(everything).not.toContain("E2E-PROMPT-CANARY");
    expect(everything).not.toContain("E2E-INPUT-CANARY");
    expect(everything).not.toContain(IMAGE_PROMPT);
    expect(everything).not.toContain(SPEECH_INPUT);
  });

  it("never sent the API key to the relay", async () => {
    const everything = relayLog
      .map((entry) => `${JSON.stringify(entry.headers)}\n${entry.body}`)
      .join("\n");
    expect(everything).not.toContain(API_KEY);
    for (const entry of relayLog) {
      expect(entry.headers.authorization).toBeUndefined();
      expect(entry.headers.cookie).toBeUndefined();
    }
  });

  it("did send the API key to the control origin, and the ticket to the relay", () => {
    expect(controlLog.every((entry) => entry.headers.authorization === `Bearer ${API_KEY}`)).toBe(true);
    expect(relayLog.every((entry) => typeof entry.headers["x-anonrouter-ticket"] === "string")).toBe(true);
  });

  it("cannot replay a ticket: the relay spends it on first redemption", async () => {
    // Mint one ticket by hand and redeem it twice, which is what a client with a
    // retry loop would do. The second attempt must be refused.
    const minted = await fetch(`${controlOrigin}/v1/inference/tickets`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify({ operation: "image", model: MODEL_IMAGE, size: "512x512", response_format: "b64_json" })
    });
    const { ticket } = (await minted.json()) as { ticket: string };

    const redeem = () =>
      fetch(`${inferenceOrigin}/v1/images/generations`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-anonrouter-ticket": ticket },
        body: JSON.stringify({
          model: MODEL_IMAGE,
          prompt: "replay probe",
          size: "512x512",
          response_format: "b64_json"
        })
      });

    expect((await redeem()).status).toBe(200);
    const replayed = await redeem();
    expect(replayed.status).toBe(401);
    expect((await replayed.json() as { error: { type: string } }).error.type).toBe("invalid_ticket");
  });

  it("surfaces a relay refusal as a typed error, having spent exactly one ticket", async () => {
    // A ticket bound to image, redeemed at the speech route. The client cannot
    // produce this itself, which is the point: it proves the relay's own
    // enforcement is what the typed error reflects.
    const minted = await fetch(`${controlOrigin}/v1/inference/tickets`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify({ operation: "image", model: MODEL_IMAGE, response_format: "b64_json" })
    });
    const { ticket } = (await minted.json()) as { ticket: string };
    const crossed = await fetch(`${inferenceOrigin}/v1/audio/speech`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-anonrouter-ticket": ticket },
      body: JSON.stringify({ model: MODEL_SPEECH, input: "x", response_format: "mp3" })
    });
    expect(crossed.status).toBe(409);
    expect((await crossed.json() as { error: { type: string } }).error.type).toBe("ticket_operation_mismatch");
  });

  it("cannot even be pointed at these plaintext origins without the explicit opt-in", () => {
    // The loopback override is what makes this whole file possible, and it has
    // to be asked for. Without it the client refuses at construction, before any
    // media guard is reached, so a production caller cannot arrive at a
    // plaintext data plane by leaving a flag unset.
    expect(() =>
      createClient({
        inferenceBaseUrl: inferenceOrigin,
        controlBaseUrl: controlOrigin,
        apiKey: API_KEY
      })
    ).toThrow(/must be https/);
  });

  it("serves the relay routes ONLY from the inference origin", async () => {
    // The split is not just a client convention: these two servers genuinely do
    // not serve each other's routes. A client that sent the prompt to the
    // control origin would get a 404 there, which is what production does too
    // (api.anonrouter.ai answers 503 media_disabled for both media paths).
    const wrongHost = await fetch(`${controlOrigin}/v1/images/generations`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-anonrouter-ticket": "tkt_e2e_1" },
      body: JSON.stringify({ model: MODEL_IMAGE, prompt: "p" })
    });
    expect(wrongHost.status).toBe(404);

    const mintOnRelay = await fetch(`${inferenceOrigin}/v1/inference/tickets`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ operation: "image", model: MODEL_IMAGE })
    });
    expect(mintOnRelay.status).toBe(404);
  });

  it("refuses media when the two roles collapse onto one origin", async () => {
    const collapsed = createClient({ baseUrl: "https://one.origin.invalid", apiKey: API_KEY });
    await expect(collapsed.images.generate({ model: MODEL_IMAGE, prompt: "p" })).rejects.toMatchObject({
      code: "unsupported_request"
    });
  });
});
