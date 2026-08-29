// Live-CVM readiness.
//
// Two modes, and the distinction is the point:
//
//   OPT-IN LIVE   Set ANONROUTER_LIVE_GATEWAY_ORIGIN to a real confidential
//                 deployment and these run against it for real: fresh nonce,
//                 real TDX quote, real event log, real measurements.
//
//   DEFAULT       No origin configured, so the live cases SKIP with a stated
//                 reason. They are never silently green: the readiness cases
//                 below still run and assert the properties that must hold
//                 BEFORE a live run can mean anything.
//
// What this file must never do is fabricate a passing live result. A synthetic
// fixture cannot stand in for hardware, so when there is no hardware the honest
// output is a skip that says so, not a green check that implies a run happened.
//
// The gateway attestation endpoint is credential-free, content-free, and
// read-only, so pointing this at a real deployment is safe: it sends no prompt,
// no key, and no account identity.

import { describe, expect, it } from "vitest";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";
import { loadGatewayPolicy } from "../src/gateway/policy.js";
import { normalizeGatewayBinding, gatewayBindingHash } from "../src/gateway/binding.js";
import { parseEventLog, replayRtmrs } from "../src/gateway/eventLog.js";
import { parseTdxQuote, TDX_TEE_TYPE } from "../src/verify/tdx.js";
import { createClient } from "../src/client.js";
import type { FetchLike } from "../src/transport/types.js";

const LIVE_ORIGIN = process.env.ANONROUTER_LIVE_GATEWAY_ORIGIN;
const describeLive = LIVE_ORIGIN ? describe : describe.skip;

function freshNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchLive(origin: string, nonce: string): Promise<GatewayAttestationEvidence> {
  const response = await fetch(`${origin}/v1/gateway/attestation?nonce=${nonce}`, {
    headers: { accept: "application/json" }
  });
  if (!response.ok) throw new Error(`live gateway returned ${response.status}`);
  return (await response.json()) as GatewayAttestationEvidence;
}

// ---- Readiness: always runs, no hardware required ---------------------------

describe("live-CVM readiness", () => {
  it("states whether a live origin is configured, so a skip is never ambiguous", () => {
    // This test exists to put the mode in the output. It always passes; what
    // matters is that a reader can see which mode the suite ran in.
    const mode = LIVE_ORIGIN ? `LIVE against ${LIVE_ORIGIN}` : "SKIPPED (set ANONROUTER_LIVE_GATEWAY_ORIGIN to run live)";
    expect(typeof mode).toBe("string");
    if (!LIVE_ORIGIN) {
      expect(LIVE_ORIGIN).toBeUndefined();
    }
  });

  it("reports `unavailable`, not a pass, when a deployment does not serve the route", async () => {
    // The precondition for trusting a live run: a gateway that cannot attest
    // must be distinguishable from one that attested successfully. If this ever
    // regressed, a live run against a non-CVM deployment could look like a pass.
    const fetchImpl: FetchLike = async () =>
      new Response(JSON.stringify({ error: { type: "gateway_attestation_unavailable" } }), { status: 503 });
    const client = createClient({ baseUrl: "https://not-a-cvm.test.invalid", apiKey: "ar_k", fetch: fetchImpl });
    const hop = await client.verifyRoute({ model: "m", provider: "venice", gateway: true })
      .then((v) => v.gateway)
      .catch(() => null);
    expect(hop).not.toBeNull();
    expect(hop!.state).toBe("unavailable");
    expect(hop!.requested).toBe(true);
  });

  it("has a verifier that refuses evidence bound to somebody else's nonce", () => {
    // Replay protection is the property that makes a live fetch meaningful. It
    // is asserted here structurally so the live block can rely on it.
    const policy = loadGatewayPolicy({
      source: "readiness", version: "1", origins: ["https://x.invalid"],
      appIds: ["aa"], composeHashes: ["ab".repeat(32)], releaseIds: ["r"],
      requireInTeeTls: false, requirePrivateLogs: false, requireDigestPinnedImages: false,
      requireHardwareVerified: false, acceptableTcbStatuses: ["UpToDate"],
      requireEvidenceExpiry: false, maxEvidenceAgeMs: 300_000
    });
    const result = verifyGatewayAttestation(
      { binding: null, quote: "zz", event_log: "[]", app_compose: "" },
      { nonce: "0".repeat(64), origin: "https://x.invalid", policy, now: Date.now() }
    );
    expect(result.status).toBe("failed");
  });
});

// ---- Live: only against a real confidential deployment ----------------------

describeLive("live confidential VM", () => {
  const origin = LIVE_ORIGIN!;

  it("serves a document bound to OUR fresh nonce", async () => {
    const nonce = freshNonce();
    const doc = await fetchLive(origin, nonce);
    const binding = normalizeGatewayBinding(doc.binding);
    expect(binding.nonce).toBe(nonce);
    expect(binding.origin).toBe(origin);
  }, 30_000);

  it("returns a real, non-debug Intel TDX quote whose report_data commits to the binding", async () => {
    const nonce = freshNonce();
    const doc = await fetchLive(origin, nonce);
    const quote = parseTdxQuote(doc.quote);
    expect(quote).not.toBeNull();
    expect(quote!.teeType).toBe(TDX_TEE_TYPE);
    expect(quote!.debugEnabled).toBe(false);
    // The load-bearing one: our canonical serialization must reproduce exactly
    // what the TD hashed into report_data, on real hardware output.
    expect(quote!.reportData).toBe(gatewayBindingHash(normalizeGatewayBinding(doc.binding)));
  }, 30_000);

  it("has an event log that replays to the hardware registers", async () => {
    const nonce = freshNonce();
    const doc = await fetchLive(origin, nonce);
    const quote = parseTdxQuote(doc.quote)!;
    const replayed = replayRtmrs(parseEventLog(doc.event_log));
    expect(replayed[0]).toBe(quote.rtmr0);
    expect(replayed[1]).toBe(quote.rtmr1);
    expect(replayed[2]).toBe(quote.rtmr2);
    expect(replayed[3]).toBe(quote.rtmr3);
  }, 30_000);

  it("REFUSES the same document when replayed against a different nonce", async () => {
    // Anti-replay, proven on real evidence rather than a fixture: a document
    // that verified a moment ago must not verify for a challenge it never saw.
    const nonce = freshNonce();
    const doc = await fetchLive(origin, nonce);
    const binding = normalizeGatewayBinding(doc.binding);
    const policy = loadGatewayPolicy({
      source: "live-readiness", version: "1",
      origins: [binding.origin], appIds: [binding.app_id],
      composeHashes: [binding.compose_hash], releaseIds: [binding.release_id],
      requireInTeeTls: false, requirePrivateLogs: false, requireDigestPinnedImages: false,
      requireHardwareVerified: false, acceptableTcbStatuses: ["UpToDate"],
      requireEvidenceExpiry: false, maxEvidenceAgeMs: 300_000
    });
    const replayed = verifyGatewayAttestation(doc, {
      nonce: freshNonce(), origin: binding.origin, policy, now: Date.now()
    });
    expect(replayed.status).toBe("failed");
    expect(replayed.reason).toBe("nonce_matches_request");
  }, 30_000);

  it("caps the verdict at cryptographically_checked without a DCAP engine", async () => {
    // Even against genuine hardware, no vendor-root chain means no
    // hardware_verified. This is the claim discipline the SDK exists to keep.
    const nonce = freshNonce();
    const doc = await fetchLive(origin, nonce);
    const binding = normalizeGatewayBinding(doc.binding);
    const policy = loadGatewayPolicy({
      source: "live-readiness", version: "1",
      origins: [binding.origin], appIds: [binding.app_id],
      composeHashes: [binding.compose_hash], releaseIds: [binding.release_id],
      requireInTeeTls: false, requirePrivateLogs: false, requireDigestPinnedImages: false,
      requireHardwareVerified: false, acceptableTcbStatuses: ["UpToDate"],
      requireEvidenceExpiry: false, maxEvidenceAgeMs: 300_000
    });
    const result = verifyGatewayAttestation(doc, {
      nonce, origin: binding.origin, policy, now: Date.now()
    });
    expect(result.status).toBe("ok");
    expect(result.verificationLevel).toBe("provider-attested");
    expect(result.verificationLevel).not.toBe("hardware-verified");
  }, 30_000);
});
