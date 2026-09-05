// End-to-end SELF-TEST with NO API key, NO network, and NO spend.
//
// It runs the SDK's full flow (verify attestation + E2EE chat) against an
// in-process mock gateway backed by mock enclaves that speak the real provider
// crypto. If this passes, the client orchestration, the E2EE transports, and the
// verifier are wired together correctly. The real-gateway examples
// (verify-tee.ts, chat-e2ee.ts) then prove the same code against production
// evidence with your API key.
//
// Run: npm run example:selftest   (from js/confidential)
//
// A real external app would `import { createClient } from "@anonrouter/confidential"`;
// here we import from ../src so the example runs without a build step.

import assert from "node:assert/strict";
import { createClient, type FetchLike } from "../src/index.js";
import {
  createChutesMockEnclave,
  createVeniceMockEnclave,
  readRequestBytes
} from "../test/helpers/mock-enclaves.js";

/**
 * HTTPS even though nothing is dialled.
 *
 * The client refuses a non-loopback `http://` origin, because over plaintext the
 * API key travels in the clear and the origin a gateway quote binds cannot mean
 * anything. This self-test replaces `fetch` entirely, so no connection is made
 * either way, and using `https` keeps it on the same code path a real application
 * takes rather than the `allowInsecureHttp` escape hatch. Using `http` here is
 * what silently broke this gate when that check landed.
 */
const BASE = "https://mock.local";

function json(obj: unknown): Response {
  return new Response(JSON.stringify(obj), { status: 200, headers: { "content-type": "application/json" } });
}

interface Enclave {
  attestationResponse(nonce: string): unknown;
  handleInference(arg: RequestInit | Uint8Array): { response: Response };
}

/** A fetch that behaves like the AnonRouter gateway for one provider's enclave.
 *  It also records the exact bytes sent to the relay so we can prove ciphertext-only. */
function makeMockGateway(enclave: Enclave, relayPath: string): { fetch: FetchLike; lastRelayBody(): string } {
  let lastRelayBody = "";
  const fetchImpl: FetchLike = async (url, init = {}) => {
    const u = new URL(String(url));
    const path = u.pathname;
    const method = (init.method ?? "GET").toUpperCase();
    if (path.endsWith("/v1/inference/attestation-tickets")) return json({ ticket: "att-mock" });
    if (path.endsWith("/v1/inference/tickets")) return json({ ticket: "inf-mock" });
    if (path.endsWith("/v1/models")) {
      // The catalog the SDK reads to reserve a whole-body opaque route's full
      // output ceiling (Chutes). Streaming providers never hit this path.
      return json({
        object: "list",
        data: [{ id: "qwen/qwen3-32b", max_output_tokens: 2048, provider_routes: [{ provider: "chutes", max_output_tokens: 2048 }] }]
      });
    }
    if (path.endsWith("/v1/tee/attestation")) {
      const nonce = method === "GET"
        ? (u.searchParams.get("nonce") ?? "")
        : (JSON.parse(String(init.body)).nonce as string);
      return json(enclave.attestationResponse(nonce));
    }
    if (path.endsWith(relayPath)) {
      if (relayPath.includes("e2ee")) {
        const bytes = readRequestBytes(init.body as BodyInit);
        lastRelayBody = Buffer.from(bytes).toString("hex");
        return enclave.handleInference(bytes).response;
      }
      lastRelayBody = String(init.body);
      return enclave.handleInference(init).response;
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch: fetchImpl, lastRelayBody: () => lastRelayBody };
}

async function run(): Promise<void> {
  const canary = "CANARY-" + Math.random().toString(36).slice(2);

  // Venice: streaming E2EE over /v1/chat/completions. Exercises verify + chat.
  {
    // Two identifiers, deliberately different: the catalog id the caller names
    // and the provider-native model the enclave loaded. A mock that used one
    // string for both could not exercise the route cross-binding at all.
    const enclave = createVeniceMockEnclave("e2ee-gpt-oss-20b-p", "venice/e2ee-gpt-oss-20b-p");
    const gw = makeMockGateway(enclave, "/v1/chat/completions");
    const client = createClient({ baseUrl: BASE, apiKey: "mock", fetch: gw.fetch });

    const verified = await client.verifyAttestation({ model: "venice/e2ee-gpt-oss-20b-p", provider: "venice" });
    assert.equal(verified.verdict.status, "ok", "venice: independent verdict should be ok");
    assert.equal(verified.verdict.verification_level, "provider-attested", "venice: level");

    const chat = await client.chat({
      model: "venice/e2ee-gpt-oss-20b-p",
      provider: "venice",
      messages: [{ role: "user", content: canary }],
      maxOutputTokens: 16
    });
    assert.equal(chat.content, "Hello E2EE", "venice: decrypted reply");
    assert.ok(!gw.lastRelayBody().includes(canary), "venice: the canary must NOT appear in the relay body");
    console.log(`venice   PASS   verify=ok/provider-attested   chat="${chat.content}"   relay saw ciphertext only`);
  }

  // Chutes: non-streaming ML-KEM E2EE over /v1/e2ee/chat/completions. Exercises chat
  // (its whole-body transport gate). A full chutes verifyAttestation additionally
  // requires the X.509 cert-possession evidence a real enclave returns, which this
  // minimal mock does not synthesize, so we prove the chat round-trip here.
  {
    const enclave = createChutesMockEnclave("Qwen/Qwen3-32B-TEE", "qwen/qwen3-32b");
    const gw = makeMockGateway(enclave, "/v1/e2ee/chat/completions");
    const client = createClient({ baseUrl: BASE, apiKey: "mock", fetch: gw.fetch });

    const chat = await client.chat({
      model: "qwen/qwen3-32b",
      provider: "chutes",
      messages: [{ role: "user", content: canary }],
      maxOutputTokens: 16
    });
    assert.equal(chat.content, "Hello E2EE from Chutes", "chutes: decrypted reply");
    const canaryHex = Buffer.from(canary).toString("hex");
    assert.ok(!gw.lastRelayBody().includes(canaryHex), "chutes: the canary must NOT appear in the relay body");
    console.log(`chutes   PASS   chat="${chat.content}"   relay saw ciphertext only`);
  }

  console.log("\nSELF-TEST PASSED: verify + E2EE chat round-trip works end to end (mock gateway, no key, no spend).");
}

run().catch((error) => {
  console.error("SELF-TEST FAILED:", error);
  process.exit(1);
});
