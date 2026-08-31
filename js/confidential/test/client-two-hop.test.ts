// Client-level tests for the two-hop verification API.
//
// The point of these is not the crypto (gateway-verify.test.ts covers that) but
// the WIRING: that hop 1 and hop 2 stay distinct, that a report never implies it
// covered a hop it skipped, that chat() refuses to send anything when a required
// hop fails, and that a client cannot be pointed at an origin whose attestation
// could not mean anything.

import { describe, expect, it } from "vitest";
import { createClient } from "../src/client.js";
import { ConfidentialError } from "../src/errors.js";
import {
  gatewayBindingHash,
  GATEWAY_BINDING_VERSION,
  type GatewayAttestationBinding
} from "../src/gateway/binding.js";
import { loadGatewayPolicy, type GatewayMeasurementPolicy } from "../src/gateway/policy.js";
import type { FetchLike } from "../src/transport/types.js";
import {
  buildAppCompose,
  buildSyntheticEventLog,
  buildSyntheticTdxQuote,
  buildVmConfig
} from "./helpers/gateway-fixtures.js";
import { createVeniceMockEnclave } from "./helpers/mock-enclaves.js";

const ORIGIN = "https://gateway.test.invalid";
const APP_ID = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98";
const RELEASE_ID = "anonrouter-tee@test";
const MODEL = "venice-uncensored";
const CANARY = "two-hop-canary-do-not-leak";

const compose = buildAppCompose();

function testPolicy(overrides: Partial<GatewayMeasurementPolicy> = {}): GatewayMeasurementPolicy {
  return {
    ...loadGatewayPolicy({
      source: "test-suite",
      version: "1",
      origins: [ORIGIN],
      appIds: [APP_ID],
      composeHashes: [compose.hash],
      releaseIds: [RELEASE_ID],
      requireInTeeTls: false,
      requirePrivateLogs: true,
      requireDigestPinnedImages: true,
      requireHardwareVerified: false,
      acceptableTcbStatuses: ["UpToDate"],
      requireEvidenceExpiry: false,
      maxEvidenceAgeMs: 300_000
    }),
    ...overrides
  };
}

/** Build a gateway document bound to whatever nonce the client actually sent. */
function gatewayDocumentFor(nonce: string, overrides: Partial<GatewayAttestationBinding> = {}) {
  const binding: GatewayAttestationBinding = {
    v: GATEWAY_BINDING_VERSION,
    nonce,
    app_id: APP_ID,
    instance_id: INSTANCE_ID,
    compose_hash: compose.hash,
    release_id: RELEASE_ID,
    origin: ORIGIN,
    key_alg: "x25519",
    public_key: "ab".repeat(32),
    transport: "gateway-tls",
    tls_spki_sha256: null,
    ...overrides
  };
  const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: binding.compose_hash, instanceId: INSTANCE_ID });
  return {
    binding,
    binding_hash: gatewayBindingHash(binding),
    quote: buildSyntheticTdxQuote({
      reportDataHex: gatewayBindingHash(binding),
      rtmr0: log.rtmr0,
      rtmr1: log.rtmr1,
      rtmr2: log.rtmr2,
      rtmr3: log.rtmr3
    }),
    event_log: JSON.stringify(log.events),
    app_compose: compose.manifest,
    vm_config: buildVmConfig(),
    issued_at_ms: Date.now()
  };
}

interface StubOptions {
  /** How the gateway attestation route behaves. */
  gateway?: "ok" | "unavailable" | "wrong-release";
  enclave?: ReturnType<typeof createVeniceMockEnclave>;
}

/** A stub AnonRouter serving both hops, recording every path it was asked for. */
function stubGateway(options: StubOptions = {}) {
  const enclave = options.enclave ?? createVeniceMockEnclave(MODEL);
  const paths: string[] = [];
  const bodies: string[] = [];

  const fetchImpl: FetchLike = async (url, init) => {
    const parsed = new URL(url);
    paths.push(parsed.pathname);
    if (init?.body) bodies.push(String(init.body));

    if (parsed.pathname === "/v1/gateway/attestation") {
      if (options.gateway === "unavailable") {
        return new Response(JSON.stringify({ error: { type: "gateway_attestation_unavailable" } }), { status: 503 });
      }
      const nonce = parsed.searchParams.get("nonce") ?? "";
      const doc = gatewayDocumentFor(
        nonce,
        options.gateway === "wrong-release" ? { release_id: "anonrouter-tee@unreviewed" } : {}
      );
      return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (parsed.pathname === "/v1/inference/attestation-tickets") {
      return new Response(JSON.stringify({ ticket: "att-ticket", expires_in: 30 }), { status: 200 });
    }
    if (parsed.pathname === "/v1/inference/tickets") {
      return new Response(JSON.stringify({ ticket: "inf-ticket" }), { status: 200 });
    }
    if (parsed.pathname === "/v1/tee/attestation") {
      const nonce = init?.body
        ? (JSON.parse(String(init.body)) as { nonce: string }).nonce
        : parsed.searchParams.get("nonce") ?? "";
      return new Response(JSON.stringify(enclave.attestationResponse(nonce)), { status: 200 });
    }
    if (parsed.pathname === "/v1/chat/completions") {
      return enclave.handleInference(init ?? {}).response;
    }
    return new Response("not found", { status: 404 });
  };

  return { fetchImpl, paths, bodies, enclave };
}

function client(options: StubOptions = {}) {
  const stub = stubGateway(options);
  return {
    stub,
    client: createClient({ baseUrl: ORIGIN, apiKey: "ar_test", fetch: stub.fetchImpl })
  };
}

describe("createClient origin validation", () => {
  it("accepts a bare https origin and tolerates a trailing slash", () => {
    expect(() => createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: "ar_k" })).not.toThrow();
    expect(() => createClient({ baseUrl: "https://api.anonrouter.ai/", apiKey: "ar_k" })).not.toThrow();
  });

  it("refuses plaintext http against a remote host", () => {
    // Over plaintext the API key travels in the clear and the origin a quote binds
    // proves nothing about who answered, so an attested route would be decorative.
    expect(() => createClient({ baseUrl: "http://api.anonrouter.ai", apiKey: "ar_k" }))
      .toThrow(/must be https/);
    expect(() => createClient({ baseUrl: "http://api.anonrouter.ai", apiKey: "ar_k", allowInsecureHttp: true }))
      .toThrow(/loopback/);
  });

  it("permits plaintext http against loopback only with an explicit opt-in", () => {
    expect(() => createClient({ baseUrl: "http://localhost:8080", apiKey: "ar_k" })).toThrow(/must be https/);
    expect(() => createClient({ baseUrl: "http://localhost:8080", apiKey: "ar_k", allowInsecureHttp: true }))
      .not.toThrow();
  });

  it("refuses a baseUrl carrying a path, query, or credentials", () => {
    expect(() => createClient({ baseUrl: "https://api.anonrouter.ai/v1", apiKey: "ar_k" })).toThrow(/no path/);
    expect(() => createClient({ baseUrl: "https://api.anonrouter.ai?x=1", apiKey: "ar_k" })).toThrow(/bare origin/);
    expect(() => createClient({ baseUrl: "https://u:p@api.anonrouter.ai", apiKey: "ar_k" })).toThrow(/bare origin/);
  });

  it("uses a distinct control origin only for authenticated ticket operations", async () => {
    const inferenceOrigin = "https://confidential.example";
    const controlOrigin = "https://control.example";
    const seen: Array<{ origin: string; path: string }> = [];
    const enclave = createVeniceMockEnclave(MODEL);
    const fetchImpl: FetchLike = async (url, init) => {
      const parsed = new URL(url);
      seen.push({ origin: parsed.origin, path: parsed.pathname });
      if (parsed.pathname === "/v1/inference/attestation-tickets") {
        return new Response(JSON.stringify({ ticket: "att-ticket" }), { status: 200 });
      }
      if (parsed.pathname === "/v1/tee/attestation") {
        const nonce = (JSON.parse(String(init?.body)) as { nonce: string }).nonce;
        return new Response(JSON.stringify(enclave.attestationResponse(nonce)), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };
    const c = createClient({
      baseUrl: inferenceOrigin,
      controlBaseUrl: controlOrigin,
      apiKey: "ar_test",
      fetch: fetchImpl
    });

    const result = await c.verifyAttestation({ model: MODEL, provider: "venice" });
    expect(result.verdict.status).toBe("ok");
    expect(seen).toEqual([
      { origin: controlOrigin, path: "/v1/inference/attestation-tickets" },
      { origin: inferenceOrigin, path: "/v1/tee/attestation" }
    ]);
  });

  it("never sends the API key to a split confidential origin when ticket minting fails", async () => {
    const inferenceOrigin = "https://confidential.example";
    const controlOrigin = "https://control.example";
    const seen: Array<{ origin: string; authorization: string | null }> = [];
    const fetchImpl: FetchLike = async (url, init) => {
      const parsed = new URL(url);
      const headers = new Headers(init?.headers);
      seen.push({ origin: parsed.origin, authorization: headers.get("authorization") });
      return new Response(JSON.stringify({ error: "route unavailable" }), { status: 404 });
    };
    const c = createClient({
      baseUrl: inferenceOrigin,
      controlBaseUrl: controlOrigin,
      apiKey: "ar_secret_canary",
      fetch: fetchImpl
    });

    await expect(c.verifyAttestation({ model: MODEL, provider: "venice" }))
      .rejects.toThrow(/ticket/i);
    expect(seen).toEqual([{ origin: controlOrigin, authorization: "Bearer ar_secret_canary" }]);
  });

  it("fails closed on a malformed split-origin ticket response", async () => {
    const seen: string[] = [];
    const c = createClient({
      baseUrl: "https://confidential.example",
      controlBaseUrl: "https://control.example",
      apiKey: "ar_secret_canary",
      fetch: async (url) => {
        seen.push(new URL(url).origin);
        return new Response(JSON.stringify({ ticket: "" }), { status: 200 });
      }
    });

    await expect(c.verifyAttestation({ model: MODEL, provider: "venice" }))
      .rejects.toThrow(/invalid attestation ticket/i);
    expect(seen).toEqual(["https://control.example"]);
  });

  it("validates the control origin as strictly as the confidential origin", () => {
    expect(() => createClient({
      baseUrl: "https://api.private.anonrouter.ai",
      controlBaseUrl: "http://api.anonrouter.ai",
      apiKey: "ar_k"
    })).toThrow(/must be https/);
    expect(() => createClient({
      baseUrl: "https://api.private.anonrouter.ai",
      controlBaseUrl: "https://api.anonrouter.ai/v1",
      apiKey: "ar_k"
    })).toThrow(/no path/);
  });
});

describe("verifyGateway (hop 1)", () => {
  it("verifies the plane against a caller-supplied policy", async () => {
    const { client: c } = client();
    const result = await c.verifyGateway({ policy: testPolicy() });
    expect(result.verdict.reason).toBeNull();
    expect(result.verdict.status).toBe("ok");
    expect(result.verdict.verificationLevel).toBe("provider-attested");
    expect(result.origin).toBe(ORIGIN);
    expect(result.policy.origin).toBe("caller-supplied");
    expect(result.verdict.binding?.origin).toBe(ORIGIN);
  });

  it("binds the quote to a nonce the client generated, not one the server chose", async () => {
    const { client: c, stub } = client();
    const first = await c.verifyGateway({ policy: testPolicy() });
    const second = await c.verifyGateway({ policy: testPolicy() });
    expect(first.verdict.binding?.nonce).not.toBe(second.verdict.binding?.nonce);
    expect(stub.paths.filter((p) => p === "/v1/gateway/attestation")).toHaveLength(2);
  });

  it("fails closed when no policy is pinned for the origin", async () => {
    const { client: c } = client();
    // No caller policy and nothing shipped for this test origin: there is nothing
    // to check the evidence against, so reporting what it says would be reading
    // the server's own claim back to the caller.
    await expect(c.verifyGateway()).rejects.toMatchObject({ code: "measurement_untrusted" });
  });

  it("fails closed when the deployment does not expose gateway attestation", async () => {
    const { client: c } = client({ gateway: "unavailable" });
    await expect(c.verifyGateway({ policy: testPolicy() }))
      .rejects.toThrow(/does not expose gateway attestation/);
  });

  it("reports a failed verdict for a release the client did not review", async () => {
    const { client: c } = client({ gateway: "wrong-release" });
    const result = await c.verifyGateway({ policy: testPolicy() });
    expect(result.verdict.status).toBe("failed");
    expect(result.verdict.reason).toBe("release_pinned");
  });

  it("refuses a nonce that is not exactly 32 bytes", async () => {
    const { client: c } = client();
    await expect(c.verifyGateway({ nonce: "ab".repeat(8), policy: testPolicy() }))
      .rejects.toThrow(/exactly 64 hex characters/);
  });

  it("never sends the API key to the credential-free attestation route", async () => {
    const seen: Array<Record<string, string>> = [];
    const stub = stubGateway();
    const recording: FetchLike = async (url, init) => {
      if (new URL(url).pathname === "/v1/gateway/attestation") {
        const headers = new Headers(init?.headers as HeadersInit);
        const captured: Record<string, string> = {};
        headers.forEach((value, key) => { captured[key] = value; });
        seen.push(captured);
      }
      return stub.fetchImpl(url, init);
    };
    const c = createClient({ baseUrl: ORIGIN, apiKey: "ar_secret_key", fetch: recording });
    await c.verifyGateway({ policy: testPolicy() });
    expect(seen).toHaveLength(1);
    expect(JSON.stringify(seen[0])).not.toContain("ar_secret_key");
    expect(seen[0].authorization).toBeUndefined();
  });
});

describe("verify (both hops)", () => {
  it("skips hop 1 by default and says so, rather than implying it passed", async () => {
    const { client: c, stub } = client();
    const report = await c.verify({ model: MODEL, provider: "venice" });
    expect(report.gateway.requested).toBe(false);
    expect(report.gateway.status).toBe("not-requested");
    expect(report.gateway.verificationLevel).toBeNull();
    expect(report.provider.status).toBe("ok");
    // trusted covers only what was asked for, and gateway.requested says so.
    expect(report.trusted).toBe(true);
    expect(stub.paths).not.toContain("/v1/gateway/attestation");
  });

  it("establishes both hops when asked", async () => {
    const { client: c, stub } = client();
    const report = await c.verify({
      model: MODEL,
      provider: "venice",
      gateway: { policy: testPolicy() }
    });
    expect(report.gateway.requested).toBe(true);
    expect(report.gateway.status).toBe("ok");
    expect(report.provider.status).toBe("ok");
    expect(report.trusted).toBe(true);
    expect(report.reason).toBeNull();
    expect(stub.paths).toContain("/v1/gateway/attestation");
  });

  it("is untrusted when hop 1 fails, even though hop 2 verified", async () => {
    const { client: c } = client({ gateway: "wrong-release" });
    const report = await c.verify({
      model: MODEL,
      provider: "venice",
      gateway: { policy: testPolicy() }
    });
    expect(report.provider.status).toBe("ok");
    expect(report.gateway.status).toBe("failed");
    expect(report.trusted).toBe(false);
    expect(report.reason).toContain("gateway");
    expect(report.reason).toContain("release_pinned");
  });

  it("is untrusted when hop 1 cannot be established at all", async () => {
    const { client: c } = client({ gateway: "unavailable" });
    const report = await c.verify({
      model: MODEL,
      provider: "venice",
      gateway: { policy: testPolicy() }
    });
    expect(report.gateway.status).toBe("unavailable");
    expect(report.trusted).toBe(false);
  });

  it("is untrusted when hop 1 was asked for but nothing is pinned for the origin", async () => {
    const { client: c } = client();
    const report = await c.verify({ model: MODEL, provider: "venice", gateway: true });
    expect(report.gateway.status).toBe("unpinned");
    expect(report.trusted).toBe(false);
  });

  it("states plainly whether AnonRouter can read the content on this route", async () => {
    const { client: c } = client();
    const report = await c.verify({ model: MODEL, provider: "venice" });
    expect(report.route.privacyModality).toBe("e2ee");
    expect(report.route.contentVisibleToAnonRouter).toBe(false);
  });
});

describe("chat with a required gateway hop", () => {
  it("sends nothing when AnonRouter's own plane does not verify", async () => {
    const { client: c, stub } = client({ gateway: "wrong-release" });
    await expect(c.chat({
      model: MODEL,
      provider: "venice",
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 32,
      requireGateway: { policy: testPolicy() }
    })).rejects.toMatchObject({ code: "attestation_untrusted" });

    // The gate runs BEFORE the first authenticated call, so no ticket was spent,
    // no model was named, and the canary never reached the wire.
    expect(stub.paths).toEqual(["/v1/gateway/attestation"]);
    expect(stub.bodies.join("")).not.toContain(CANARY);
  });

  it("sends nothing when the deployment cannot attest its own plane", async () => {
    const { client: c, stub } = client({ gateway: "unavailable" });
    await expect(c.chat({
      model: MODEL,
      provider: "venice",
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 32,
      requireGateway: { policy: testPolicy() }
    })).rejects.toThrow(/did not verify/);
    expect(stub.paths).toEqual(["/v1/gateway/attestation"]);
    expect(stub.bodies.join("")).not.toContain(CANARY);
  });

  it("proceeds and keeps content opaque once both hops hold", async () => {
    const { client: c, stub } = client();
    const result = await c.chat({
      model: MODEL,
      provider: "venice",
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 32,
      requireGateway: { policy: testPolicy() }
    });
    expect(result.content).toBe("Hello E2EE");
    expect(stub.paths).toContain("/v1/gateway/attestation");
    expect(stub.paths).toContain("/v1/chat/completions");
    // Every body that crossed the wire carried ciphertext only.
    expect(stub.bodies.join("")).not.toContain(CANARY);
  });

  it("still runs without a gateway requirement, unchanged", async () => {
    const { client: c, stub } = client();
    const result = await c.chat({
      model: MODEL,
      provider: "venice",
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 32
    });
    expect(result.content).toBe("Hello E2EE");
    expect(stub.paths).not.toContain("/v1/gateway/attestation");
  });
});

describe("provider-hop route binding", () => {
  it("refuses evidence the gateway bound to a different provider", async () => {
    const enclave = createVeniceMockEnclave(MODEL);
    const stub = stubGateway({ enclave });
    const swapping: FetchLike = async (url, init) => {
      const response = await stub.fetchImpl(url, init);
      if (new URL(url).pathname !== "/v1/tee/attestation") return response;
      const body = await response.json() as Record<string, unknown>;
      return new Response(JSON.stringify({ ...body, provider: "chutes" }), { status: 200 });
    };
    const c = createClient({ baseUrl: ORIGIN, apiKey: "ar_test", fetch: swapping });
    await expect(c.verifyAttestation({ model: MODEL, provider: "venice" }))
      .rejects.toMatchObject({ code: "attestation_untrusted" });
  });

  it("refuses a route the gateway itself labels as plaintext-visible tee", async () => {
    const enclave = createVeniceMockEnclave(MODEL);
    const stub = stubGateway({ enclave });
    const downgrading: FetchLike = async (url, init) => {
      const response = await stub.fetchImpl(url, init);
      if (new URL(url).pathname !== "/v1/tee/attestation") return response;
      const body = await response.json() as Record<string, unknown>;
      return new Response(JSON.stringify({ ...body, privacy_class: "tee" }), { status: 200 });
    };
    const c = createClient({ baseUrl: ORIGIN, apiKey: "ar_test", fetch: downgrading });
    const error = await c.verifyAttestation({ model: MODEL, provider: "venice" }).catch((e) => e);
    expect(error).toBeInstanceOf(ConfidentialError);
    expect((error as ConfidentialError).code).toBe("attestation_untrusted");
  });
});
