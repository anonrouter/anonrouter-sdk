// The five routes AnonRouter withheld, refused here before anything is sent.
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
  "deepseek/deepseek-v4-flash",
  "qwen/qwen-3.6-35b-a3b-fp8",
  "z-ai/glm-5.1",
  "google/gemma-3-27b",
  "openai/gpt-oss-120b"
] as const;

const ALLOWED = [
  "google/gemma-4-26b-a4b-uncensored",
  "openai/gpt-oss-20b",
  "qwen/qwen-2.5-7b",
  "z-ai/glm-5.2"
] as const;

describe("the shipped policy matches the decision", () => {
  it("withholds exactly the five Venice e2ee routes", () => {
    expect(WITHHELD_CONFIDENTIAL_ROUTES.map((r) => r.model).sort()).toEqual([...WITHHELD].sort());
    for (const r of WITHHELD_CONFIDENTIAL_ROUTES) {
      expect(r.provider).toBe("venice");
      expect(r.privacyClass).toBe("e2ee");
    }
  });

  it("offers exactly the four measured-working ones", () => {
    expect(OFFERED_CONFIDENTIAL_ROUTES.map((r) => r.model).sort()).toEqual([...ALLOWED].sort());
  });
});

describe("the predicate is per route", () => {
  it("withholds each of the five", () => {
    for (const model of WITHHELD) {
      expect(isRouteWithheldByService("venice", model, "e2ee"), model).toBe(true);
    }
  });

  it("allows each of the four", () => {
    for (const model of ALLOWED) {
      expect(isRouteWithheldByService("venice", model, "e2ee"), model).toBe(false);
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

  it("withholds an unknown Venice e2ee route, and no other provider's", () => {
    expect(isRouteWithheldByService("venice", "someone/new", "e2ee")).toBe(true);
    for (const provider of ["chutes", "near-ai", "tinfoil"]) {
      expect(isRouteWithheldByService(provider, "someone/new", "e2ee"), provider).toBe(false);
    }
  });

  it("names a classification for each withheld route", () => {
    for (const model of WITHHELD) {
      expect(withheldRouteClassification("venice", model, "e2ee"), model).toBeTruthy();
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

  it.each(WITHHELD)("refuses %s before any network call", async (model) => {
    const { client, calls } = watchedClient(PRODUCTION);
    await expect(client.chat({
      model,
      provider: "venice",
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 16
    })).rejects.toMatchObject({ code: "provider_unsupported" });

    // Refused BEFORE the first authenticated call: no ticket spent, no model
    // named to the service, and the content never left the process.
    expect(calls).toEqual([]);
  });

  it.each(ALLOWED)("does not refuse %s on policy grounds", async (model) => {
    // THE POSITIVE CONTROL. The stub answers every path with a ticket shape, so
    // this call fails LATER, on evidence — never with the policy refusal. A gate
    // that refused everything would pass the block above and fail here.
    const { client } = watchedClient(PRODUCTION);
    const error = await client.chat({
      model,
      provider: "venice",
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
