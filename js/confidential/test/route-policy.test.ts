// The seven routes AnonRouter withheld, refused here before anything is sent.
//
// WHAT THIS IS AND IS NOT. The shipped route policy is a CONVENIENCE: it turns
// "your ticket request failed" into a sentence naming the route and the reason,
// before a ticket is spent or a byte is encrypted. It is not what protects the
// caller — a withheld route that somehow reached the wire would still have to
// produce evidence that verifies, and would still be refused if it did not.
//
// So the assertions come in pairs. Each withheld route is refused AND nothing
// reaches the network; each allowed route is not refused, so the gate cannot be
// passing by refusing everything.

import { describe, expect, it, vi } from "vitest";
import { createClient } from "../src/client.js";
import {
  isRouteWithheldByService,
  withheldRouteClassification,
  withheldRouteMessage,
  OFFERED_CONFIDENTIAL_ROUTES,
  WITHHELD_CONFIDENTIAL_ROUTES
} from "../src/routePolicy.js";
import type { FetchLike } from "../src/transport/types.js";

const PRODUCTION = "https://api.anonrouter.ai";
const CONTROL = "https://control.anonrouter.ai";

/** The owner's decision, written out independently of the file under test. */
const WITHHELD = [
  ["venice", "deepseek/deepseek-v4-flash"],
  ["venice", "qwen/qwen-3.6-35b-a3b-fp8"],
  ["venice", "z-ai/glm-5.1"],
  ["venice", "google/gemma-3-27b"],
  ["venice", "openai/gpt-oss-120b"],
  ["chutes", "z-ai/glm-5.2"],
  ["chutes", "moonshotai/kimi-k2.6"]
] as const;

const ALLOWED = [
  ["venice", "google/gemma-4-26b-a4b-uncensored"],
  ["venice", "openai/gpt-oss-20b"],
  ["venice", "qwen/qwen-2.5-7b"],
  ["venice", "z-ai/glm-5.2"],
  ["chutes", "deepseek/deepseek-v3.2"],
  ["chutes", "qwen/qwen3-32b"]
] as const;

describe("the shipped policy matches the decision", () => {
  it("withholds exactly the seven reviewed e2ee routes", () => {
    expect(WITHHELD_CONFIDENTIAL_ROUTES.map((r) => `${r.provider}:${r.model}`).sort())
      .toEqual(WITHHELD.map(([provider, model]) => `${provider}:${model}`).sort());
    for (const r of WITHHELD_CONFIDENTIAL_ROUTES) expect(r.privacyClass).toBe("e2ee");
  });

  it("offers exactly the six measured-working and admissible ones", () => {
    expect(OFFERED_CONFIDENTIAL_ROUTES.map((r) => `${r.provider}:${r.model}`).sort())
      .toEqual(ALLOWED.map(([provider, model]) => `${provider}:${model}`).sort());
  });
});

describe("the predicate is per route", () => {
  it("withholds each of the seven", () => {
    for (const [provider, model] of WITHHELD) {
      expect(isRouteWithheldByService(provider, model, "e2ee"), `${provider}:${model}`).toBe(true);
    }
  });

  it("allows each of the six", () => {
    for (const [provider, model] of ALLOWED) {
      expect(isRouteWithheldByService(provider, model, "e2ee"), `${provider}:${model}`).toBe(false);
    }
  });

  it("leaves the same models' other routes alone", () => {
    // Venice serves `z-ai/glm-5.1` as both `e2ee` and `private`, and Tinfoil
    // serves `openai/gpt-oss-120b` as `tee`. A model-keyed rule would take both
    // down while trying to withhold an encrypted route.
    expect(isRouteWithheldByService("venice", "z-ai/glm-5.1", "private")).toBe(false);
    expect(isRouteWithheldByService("tinfoil", "openai/gpt-oss-120b", "tee")).toBe(false);
    expect(isRouteWithheldByService("deepinfra", "z-ai/glm-5.1", "private")).toBe(false);
  });

  it("withholds unknown governed e2ee routes, and no ungoverned provider's", () => {
    expect(isRouteWithheldByService("venice", "someone/new", "e2ee")).toBe(true);
    expect(isRouteWithheldByService("chutes", "someone/new", "e2ee")).toBe(true);
    for (const provider of ["near-ai", "tinfoil"]) {
      expect(isRouteWithheldByService(provider, "someone/new", "e2ee"), provider).toBe(false);
    }
  });

  it("names a classification for each withheld route", () => {
    for (const [provider, model] of WITHHELD) {
      expect(withheldRouteClassification(provider, model, "e2ee"), `${provider}:${model}`).toBeTruthy();
    }
  });

  it("refuses in a message that does not invite a retry", () => {
    const message = withheldRouteMessage("venice", "z-ai/glm-5.1", "e2ee");
    expect(message).toContain("z-ai/glm-5.1");
    expect(message).toContain("Nothing was sent");
    expect(message).toMatch(/retrying will not change it/);
  });
});

/** A client whose fetch records every call, so "nothing was sent" is measured. */
function watchedClient(baseUrl: string) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (url: string) => {
    calls.push(new URL(url).pathname);
    return new Response(JSON.stringify({ ticket: "att" }), { status: 200 });
  }) as unknown as FetchLike;
  return {
    calls,
    client: createClient({
      inferenceBaseUrl: baseUrl,
      controlBaseUrl: CONTROL,
      apiKey: "ar_test",
      fetch: fetchImpl
    })
  };
}

describe("chat() against production", () => {
  const CANARY = "withheld-route-canary-do-not-send";

  it.each(WITHHELD)("refuses %s:%s before any network call", async (provider, model) => {
    const { client, calls } = watchedClient(PRODUCTION);
    await expect(client.chat({
      model,
      provider,
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 16
    })).rejects.toMatchObject({ code: "provider_unsupported" });

    // Refused BEFORE the first authenticated call: no ticket spent, no model
    // named to the service, and the content never left the process.
    expect(calls).toEqual([]);
  });

  it.each(ALLOWED)("does not refuse %s:%s on policy grounds", async (provider, model) => {
    // THE POSITIVE CONTROL. The stub answers every path with a ticket shape, so
    // this call fails LATER, on evidence — never with the policy refusal. A gate
    // that refused everything would pass the block above and fail here.
    const { client } = watchedClient(PRODUCTION);
    const error = await client.chat({
      model,
      provider,
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 16
    }).catch((e: unknown) => e);
    expect(error).toBeTruthy();
    const message = (error as Error).message ?? "";
    expect(message, model).not.toContain("not currently offering");
  });
});

describe("the policy is scoped to AnonRouter's production origins", () => {
  it("does not refuse a withheld model on a self-hosted origin", async () => {
    // The policy describes AnonRouter's service. Applying it to somebody else's
    // deployment would be this SDK inventing policy for a catalog it has never
    // seen, and would make a private deployment unusable for no reason.
    const { client } = watchedClient("https://confidential.example");
    const error = await client.chat({
      model: "z-ai/glm-5.1",
      provider: "venice",
      messages: [{ role: "user", content: "x" }],
      maxOutputTokens: 16
    }).catch((e: unknown) => e);
    expect((error as Error).message).not.toContain("not currently offering");
  });
});
