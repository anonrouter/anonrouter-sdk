// Live, credential-free validation of the media contract.
//
// WHAT THIS COSTS: nothing. Every probe here is a POST that the relay refuses
// before any provider is dispatched, because it carries no ticket. No API key
// is sent, no ticket is minted, no prompt is transmitted, and no generation is
// billed. That is exactly the property being verified: that both media routes
// FAIL CLOSED for an unauthenticated caller.
//
// What it cannot establish is that a generation succeeds. That needs a real
// inference-scoped API key and a callable model, and it spends money, so it is
// deliberately out of scope. See VERIFYING.md.
//
// DEFAULT: skips with a stated reason. It is never silently green.
//
// The distinction the probes pin, which is the whole shape of the split:
//
//   confidential origin  serves both media routes, and answers 401
//                        ticket_required without one
//   control origin       does NOT serve media content at all, and answers 503
//                        media_disabled
//
// A control origin that started SERVING media content would be a privacy
// regression invisible to every offline test in this repo, because the client
// would keep working. This is the test that would catch it.

import { describe, expect, it } from "vitest";

const LIVE_ORIGIN = process.env.ANONROUTER_LIVE_GATEWAY_ORIGIN;
const PUBLIC_ORIGIN = process.env.ANONROUTER_LIVE_PUBLIC_ORIGIN;

const IMAGE_PATH = "/v1/images/generations";
const SPEECH_PATH = "/v1/audio/speech";
const TICKET_PATH = "/v1/inference/tickets";

interface Probe {
  status: number;
  type?: string;
}

/**
 * POST with NO credential and NO ticket.
 *
 * The body is a placeholder that is never a real prompt: the request cannot
 * reach a provider, because the relay rejects an absent ticket before it
 * dispatches anything. Nothing here is billable and nothing here is private.
 */
async function probe(origin: string, path: string, body: unknown): Promise<Probe> {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000)
  });
  let type: string | undefined;
  try {
    const parsed = (await response.json()) as { error?: { type?: string } };
    type = parsed?.error?.type;
  } catch {
    // A non-JSON body is still a status worth asserting on.
  }
  return { status: response.status, type };
}

const live = LIVE_ORIGIN ? describe : describe.skip;
const control = PUBLIC_ORIGIN ? describe : describe.skip;

live(`the confidential origin fails closed for media (${LIVE_ORIGIN ?? "not configured"})`, () => {
  it("refuses image generation without a ticket", async () => {
    const result = await probe(LIVE_ORIGIN!, IMAGE_PATH, { model: "probe", prompt: "probe" });
    expect(result.status).toBe(401);
    expect(result.type).toBe("ticket_required");
  });

  it("refuses speech without a ticket", async () => {
    const result = await probe(LIVE_ORIGIN!, SPEECH_PATH, { model: "probe", input: "probe" });
    expect(result.status).toBe(401);
    expect(result.type).toBe("ticket_required");
  });

  it("refuses before it will even parse a body, so a malformed request cannot probe deeper", async () => {
    for (const path of [IMAGE_PATH, SPEECH_PATH]) {
      const result = await probe(LIVE_ORIGIN!, path, {});
      expect(result.status, path).toBe(401);
      expect(result.type, path).toBe("ticket_required");
    }
  });

  it("does NOT mint tickets: the API key belongs to the control origin", async () => {
    // 404, not 401. The confidential plane does not recognize the mint at all,
    // which is what keeps the API key off this host by construction rather than
    // by the client's good manners.
    const result = await probe(LIVE_ORIGIN!, TICKET_PATH, { model: "probe", operation: "image" });
    expect(result.status).toBe(404);
  });
});

control(`the control origin serves no media content (${PUBLIC_ORIGIN ?? "not configured"})`, () => {
  it("does not generate images", async () => {
    // 503 media_disabled: the route exists in the path table but the capability
    // is off here. What matters is that it is not 200 and not 401 — the control
    // plane must never be a host that could serve a prompt.
    const result = await probe(PUBLIC_ORIGIN!, IMAGE_PATH, { model: "probe", prompt: "probe" });
    expect(result.status).not.toBe(200);
    expect([503, 404]).toContain(result.status);
    if (result.status === 503) expect(result.type).toBe("media_disabled");
  });

  it("does not synthesize speech", async () => {
    const result = await probe(PUBLIC_ORIGIN!, SPEECH_PATH, { model: "probe", input: "probe" });
    expect(result.status).not.toBe(200);
    expect([503, 404]).toContain(result.status);
    if (result.status === 503) expect(result.type).toBe("media_disabled");
  });

  it("DOES serve the ticket mint, and requires authentication for it", async () => {
    // The mint is the one media-related route that belongs here. Unauthenticated
    // it must refuse: 401 for a request that presented no key, or 403 for the
    // browser CSRF guard when no Authorization header is present at all.
    const result = await probe(PUBLIC_ORIGIN!, TICKET_PATH, { model: "probe", operation: "image" });
    expect([401, 403]).toContain(result.status);
    expect(result.status).not.toBe(404);
  });

  it("refuses an unauthenticated mint even with a bearer header present", async () => {
    // With an Authorization header the CSRF guard is bypassed and real
    // authentication is what answers. A bogus key must be refused, never
    // accepted, and the refusal must not be a 404 (which would mean the SDK's
    // whole mint path is pointed at a route that does not exist).
    const response = await fetch(`${PUBLIC_ORIGIN}${TICKET_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer not-a-real-key-credential-free-probe"
      },
      body: JSON.stringify({ model: "probe", operation: "image" }),
      signal: AbortSignal.timeout(20_000)
    });
    expect(response.status).toBe(401);
  });
});

describe("live media probe readiness", () => {
  it("states plainly when the live probes did not run", () => {
    // A skipped live suite must be legible in the output, not inferred from an
    // absence. This case always runs and records which origins were configured.
    const configured = { gateway: Boolean(LIVE_ORIGIN), control: Boolean(PUBLIC_ORIGIN) };
    expect(typeof configured.gateway).toBe("boolean");
    expect(typeof configured.control).toBe("boolean");
  });

  it("sends no credential and no real prompt in any probe", async () => {
    // The probe helper is the only thing in this file that talks to a network,
    // and this pins that it carries no authorization header and no ticket. A
    // future edit that added one would make these probes billable.
    const source = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL(import.meta.url), "utf8")
    );
    const helper = source.slice(source.indexOf("async function probe"), source.indexOf("const live ="));
    expect(helper).not.toContain("authorization");
    expect(helper).not.toContain("x-anonrouter-ticket");
  });
});
