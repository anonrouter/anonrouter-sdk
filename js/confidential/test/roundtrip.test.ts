// End-to-end E2EE round-trip against mock enclaves (no live provider). For Venice
// and Chutes we: build valid evidence, gate + create a session, then run the real
// transport against a stubbed fetch that decrypts as the enclave and returns an
// encrypted reply. We assert the decrypted content round-trips AND that the
// plaintext canary never appears anywhere in the relay request body.

import { describe, expect, it } from "vitest";
import { bytesToHex, randomBytes } from "../src/bytes.js";
import { transportFor } from "../src/index.js";
import type { E2eeChatRequest, FetchLike, HttpContext } from "../src/index.js";
import { createChutesMockEnclave, createVeniceMockEnclave, readRequestBytes } from "./helpers/mock-enclaves.js";

const CANARY = "top-secret-canary-a1b2c3-do-not-leak";
const BASE_URL = "https://relay.test.invalid";

describe("Venice E2EE round-trip", () => {
  it("round-trips content and never leaks the plaintext to the relay", async () => {
    const model = "venice-uncensored";
    const nonce = bytesToHex(randomBytes(32));
    const enclave = createVeniceMockEnclave(model);
    const att = enclave.attestationResponse(nonce);

    const transport = transportFor("venice");
    const session = transport.createSession({
      upstreamModel: model,
      nonce,
      normalized: att.attestation,
      rawEvidence: att.evidence
    });

    let capturedBody = "";
    let enclaveDecrypted: string[] = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      capturedBody = String(init?.body ?? "");
      const result = enclave.handleInference(init ?? {});
      enclaveDecrypted = result.decrypted;
      return result.response;
    };
    const http: HttpContext = { baseUrl: BASE_URL, fetchImpl };

    const request: E2eeChatRequest = {
      model,
      upstreamModel: model,
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 64
    };
    const completion = await transport.complete(session, request, { http, ticket: "ticket-abc" });
    transport.dispose(session);

    // The enclave saw the plaintext (proving the round-trip decrypts correctly)...
    expect(enclaveDecrypted).toEqual([CANARY]);
    // ...but the relay request body carried only ciphertext.
    expect(capturedBody.length).toBeGreaterThan(0);
    expect(capturedBody).not.toContain(CANARY);
    // And the encrypted reply decrypted back to the enclave's plaintext.
    expect(completion.content).toBe("Hello E2EE");
    expect(completion.usage?.totalTokens).toBe(7);
  });
});

describe("Chutes E2EE round-trip", () => {
  it("round-trips content and never leaks the plaintext to the relay", async () => {
    const model = "chutes/some-model";
    const nonce = bytesToHex(randomBytes(32));
    const enclave = createChutesMockEnclave(model);
    const att = enclave.attestationResponse(nonce);

    const transport = transportFor("chutes");
    const session = transport.createSession({
      upstreamModel: model,
      nonce,
      normalized: att.attestation,
      rawEvidence: att.evidence
    });

    let capturedBytes = new Uint8Array(0);
    let enclaveDecrypted: Record<string, unknown> = {};
    const fetchImpl: FetchLike = async (_url, init) => {
      capturedBytes = readRequestBytes(init?.body ?? null);
      const result = enclave.handleInference(capturedBytes);
      enclaveDecrypted = result.decrypted;
      return result.response;
    };
    const http: HttpContext = { baseUrl: BASE_URL, fetchImpl };

    const request: E2eeChatRequest = {
      model,
      upstreamModel: model,
      messages: [{ role: "user", content: CANARY }],
      maxOutputTokens: 64
    };
    const completion = await transport.complete(session, request, { http, ticket: "ticket-xyz" });
    transport.dispose(session);

    const decryptedMessages = enclaveDecrypted.messages as Array<{ content: string }>;
    expect(decryptedMessages[0].content).toBe(CANARY);
    // The relay request body is opaque ciphertext: the canary appears nowhere in it.
    const asLatin1 = Buffer.from(capturedBytes).toString("latin1");
    expect(capturedBytes.length).toBeGreaterThan(1100);
    expect(asLatin1).not.toContain(CANARY);
    expect(completion.content).toBe("Hello E2EE from Chutes");
    expect(completion.usage?.totalTokens).toBe(8);
  });
});
