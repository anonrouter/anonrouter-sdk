// Route-binding negative controls, one per field the ticket binds.
//
// AnonRouter's attestation ticket is minted against exactly one catalog row and
// binds five things: the provider, the requested (catalog) model, the upstream
// (provider-native) model, the privacy class, and — through the redemption — a
// single use with a short expiry. The client's fresh nonce binds the sixth.
//
// A hop verifier can check NONE of that. It is handed one enclave's evidence and
// asked whether that enclave is sound; an enclave that is perfectly sound is
// still the wrong enclave if the caller asked for a different route. So every
// one of those bindings has to be checked where both sides are visible, and each
// gets a test here that FAILS when the check is removed.
//
// The suite deliberately drives the real client through a stub gateway rather
// than calling `assembleRouteVerdict` directly: a binding rule that is only
// exercised by hand-built inputs cannot tell a wired-up check from a dead one.
// Two of the defects below were invisible to the existing route-contract suite
// for exactly that reason.

import { describe, expect, it } from "vitest";
import { createClient } from "../src/client.js";
import type { FetchLike } from "../src/transport/types.js";
import { createVeniceMockEnclave } from "./helpers/mock-enclaves.js";

const ORIGIN = "https://confidential.test.invalid";
const CONTROL = "https://control.test.invalid";
const CATALOG_MODEL = "openai/gpt-oss-20b";
const UPSTREAM_MODEL = "e2ee-gpt-oss-20b-p";

const TINFOIL_FP = "6d".repeat(48);

/** The document Tinfoil's official verifier produces for a signed release. */
function tinfoilDocument() {
  const tlsFingerprint = "19".repeat(32);
  return {
    schemaVersion: 1,
    securityVerified: true,
    enclaveHost: "inference.tinfoil.sh",
    selectedRouterEndpoint: "inference.tinfoil.sh",
    configRepo: "tinfoilsh/confidential-model-router",
    releaseTag: "v99.0.0",
    releaseDigest: "7d".repeat(32),
    codeFingerprint: TINFOIL_FP,
    enclaveFingerprint: TINFOIL_FP,
    enclaveMeasurement: { tlsPublicKeyFingerprint: tlsFingerprint },
    tlsPublicKey: tlsFingerprint,
    verifier: { name: "@tinfoilsh/verifier", version: "1.2.1" },
    steps: {
      fetchDigest: { status: "success" },
      verifyCode: { status: "success" },
      verifyEnclave: { status: "success" },
      compareMeasurements: { status: "success" },
      verifyCertificate: { status: "success" }
    }
  };
}

interface GatewayShape {
  /** What the redemption response claims about the route it served. */
  provider?: string;
  model?: string | null;
  upstream_model?: string;
  privacy_class?: string | null;
  protocol?: string | null;
  /** Serve Tinfoil TEE evidence instead of the Venice E2EE enclave. */
  tee?: boolean;
  /** Refuse the ticket mint with this error type (as production does today). */
  mintError?: { status: number; type: string };
}

/**
 * A stub AnonRouter serving the two-origin production shape: the ticket is minted
 * at the control origin with the key, and the evidence is redeemed at the
 * confidential origin with the ticket alone.
 */
function stub(shape: GatewayShape = {}) {
  const enclave = createVeniceMockEnclave(shape.upstream_model ?? UPSTREAM_MODEL);
  const seen: Array<{ origin: string; path: string; authorization: string | null; ticket: string | null }> = [];

  const fetchImpl: FetchLike = async (url, init) => {
    const parsed = new URL(url);
    const headers = new Headers(init?.headers);
    seen.push({
      origin: parsed.origin,
      path: parsed.pathname,
      authorization: headers.get("authorization"),
      ticket: headers.get("x-anonrouter-ticket")
    });

    if (parsed.pathname === "/v1/inference/attestation-tickets") {
      if (shape.mintError) {
        return new Response(
          JSON.stringify({ error: { type: shape.mintError.type, message: "refused" } }),
          { status: shape.mintError.status, headers: { "content-type": "application/json" } }
        );
      }
      return new Response(JSON.stringify({ ticket: "att-ticket", expires_in: 60 }), { status: 200 });
    }

    if (parsed.pathname === "/v1/tee/attestation") {
      const nonce = (JSON.parse(String(init?.body)) as { nonce: string }).nonce;
      const base = shape.tee
        ? { evidence: tinfoilDocument(), provider: "tinfoil", upstream_model: shape.upstream_model ?? "nomic-embed-text" }
        : enclave.attestationResponse(nonce);
      // The deployed relay echoes the ticket's full route binding. Every field
      // here is a catalog fact bound at mint time, not something the relay
      // derives, which is why disagreeing with it is a routing substitution.
      // `null` in the shape means the field is ABSENT, which a client must treat
      // differently from present-and-wrong.
      const body: Record<string, unknown> = {
        ...base,
        model: CATALOG_MODEL,
        privacy_class: shape.tee ? "tee" : "e2ee"
      };
      const apply = (key: string, value: string | null | undefined) => {
        if (value === undefined) return;
        if (value === null) delete body[key];
        else body[key] = value;
      };
      apply("provider", shape.provider);
      apply("model", shape.model);
      apply("privacy_class", shape.privacy_class);
      apply("protocol", shape.protocol);
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("not found", { status: 404 });
  };

  return {
    seen,
    client: createClient({ baseUrl: ORIGIN, controlBaseUrl: CONTROL, apiKey: "ar_canary_key", fetch: fetchImpl })
  };
}

describe("the requested-model binding", () => {
  it("refuses a route whose attested catalog model is not the one asked for", async () => {
    // THE SUBSTITUTION THIS CATCHES. Both hops can be flawless and the enclave
    // genuinely sound, while the gateway quietly served a cheaper or less
    // private model than the caller named. The provider matches, the evidence
    // verifies, and the upstream id is whatever that other model's enclave
    // reports — so nothing but the catalog-model echo can see it.
    const { client } = stub({ model: "deepseek/deepseek-v4-flash", upstream_model: "e2ee-deepseek-v4-flash" });
    const verdict = await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });

    expect(verdict.trusted).toBe(false);
    expect(verdict.overallState).toBe("untrusted");
    expect(verdict.bindingMismatches).toContainEqual({
      field: "requested_model",
      expected: CATALOG_MODEL,
      observed: "deepseek/deepseek-v4-flash",
      source: "gateway"
    });
  });

  it("accepts the route it was asked for", async () => {
    const { client } = stub();
    const verdict = await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });
    expect(verdict.bindingMismatches).toEqual([]);
    expect(verdict.trusted).toBe(true);
  });

  it("does not invent a mismatch against a gateway too old to echo the model", async () => {
    const { client } = stub({ model: null });
    const verdict = await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });
    expect(verdict.bindingMismatches).toEqual([]);
  });
});

describe("the upstream-model binding", () => {
  it("refuses evidence attesting an upstream model the caller did not pin", async () => {
    const { client } = stub({ upstream_model: "e2ee-some-other-model" });
    const verdict = await client.verifyRoute({
      model: CATALOG_MODEL, provider: "venice", upstreamModel: UPSTREAM_MODEL
    });
    expect(verdict.trusted).toBe(false);
    expect(verdict.bindingMismatches[0]).toMatchObject({ field: "model", source: "provider-evidence" });
  });
});

describe("the provider binding", () => {
  it("refuses a gateway that served a different provider than the one asked for", async () => {
    const { client } = stub({ provider: "chutes" });
    const verdict = await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });
    expect(verdict.trusted).toBe(false);
    expect(verdict.bindingMismatches.some((m) => m.field === "provider")).toBe(true);
  });
});

describe("the privacy-modality binding", () => {
  it("is read from the ROUTE, not guessed from the provider name", async () => {
    // The modality is a per-row catalog fact. Venice publishes `private` and
    // `e2ee` rows today and could publish a `tee` row tomorrow with no code
    // change anywhere; Tinfoil is `tee` on seven routes and could add an E2EE
    // one. A client that derives the modality from the provider NAME reports a
    // privacy property it never established, and gets it wrong the first time a
    // provider serves two classes.
    const { client } = stub({ tee: true, provider: "venice", privacy_class: "tee", upstream_model: UPSTREAM_MODEL });
    const verdict = await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });

    expect(verdict.route.privacyModality).toBe("tee");
    expect(verdict.route.privacyModalitySource).toBe("gateway-attested");
    expect(verdict.contentVisibleToAnonRouter).toBe(true);
    expect(verdict.bindingMismatches).toEqual([]);
  });

  it("refuses a route served under a different class than the caller pinned", async () => {
    // A silent e2ee -> tee downgrade is the one substitution that changes who is
    // in the trust set without changing a single measurement.
    const { client } = stub({ tee: true, provider: "venice", privacy_class: "tee", upstream_model: UPSTREAM_MODEL });
    const verdict = await client.verifyRoute({
      model: CATALOG_MODEL, provider: "venice", privacyClass: "e2ee"
    });

    expect(verdict.trusted).toBe(false);
    expect(verdict.bindingMismatches).toContainEqual({
      field: "privacy_modality", expected: "e2ee", observed: "tee", source: "gateway"
    });
  });

  it("never claims content is hidden from AnonRouter on a route whose class was not established", async () => {
    // A gateway that says nothing about the class has established nothing. The
    // honest report is the WEAKER claim: assume AnonRouter's build is in the
    // trust set until something proves it is not.
    const { client } = stub({ privacy_class: null });
    const verdict = await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });

    expect(verdict.route.privacyModalitySource).toBe("unestablished");
    expect(verdict.contentVisibleToAnonRouter).toBe(true);
  });

  it("lets the caller pin the class they reviewed", async () => {
    const { client } = stub({ privacy_class: null });
    const verdict = await client.verifyRoute({
      model: CATALOG_MODEL, provider: "venice", privacyClass: "e2ee"
    });
    expect(verdict.route.privacyModalitySource).toBe("caller-pinned");
    expect(verdict.contentVisibleToAnonRouter).toBe(false);
  });
});

describe("a TEE route is verifiable, not an unsupported case", () => {
  it("verifies a ticketed TEE route end to end", async () => {
    // The SDK used to tell callers that "a TEE-only route cannot be verified
    // against this host", because AnonRouter's mint refused every non-E2EE
    // route. The mint now issues for any callable tee/e2ee route with a
    // registered verifier, so the statement is false and the path must work.
    const { client, seen } = stub({
      tee: true, provider: "tinfoil", privacy_class: "tee", upstream_model: "nomic-embed-text"
    });
    const verdict = await client.verifyRoute({ model: "nomic-ai/nomic-embed-text", provider: "tinfoil" });

    expect(verdict.provider.state).not.toBe("unavailable");
    expect(verdict.provider.failedChecks).toEqual([]);
    expect(verdict.route.privacyModality).toBe("tee");
    // And the key never left the control origin.
    expect(seen.filter((s) => s.origin === ORIGIN).every((s) => s.authorization === null)).toBe(true);
    expect(seen.find((s) => s.path === "/v1/tee/attestation")?.ticket).toBe("att-ticket");
  });

  it("names the mint's own refusal rather than asserting a rule about TEE routes", async () => {
    const { client } = stub({ mintError: { status: 400, type: "model_not_e2ee" } });
    const verdict = await client.verifyRoute({ model: "nomic-ai/nomic-embed-text", provider: "tinfoil" });

    expect(verdict.trusted).toBe(false);
    expect(verdict.provider.reason).toContain("attestation_ticket_failed");
  });
});

describe("credential isolation holds on every path", () => {
  it("never sends the API key or a cookie to the confidential origin", async () => {
    const { client, seen } = stub();
    await client.verifyRoute({ model: CATALOG_MODEL, provider: "venice" });

    const toContent = seen.filter((s) => s.origin === ORIGIN);
    expect(toContent.length).toBeGreaterThan(0);
    for (const call of toContent) expect(call.authorization).toBeNull();
    const toControl = seen.filter((s) => s.origin === CONTROL);
    for (const call of toControl) expect(call.authorization).toBe("Bearer ar_canary_key");
  });
});
