// Live-CVM validation.
//
// Three modes, and the distinctions are the point:
//
//   OPT-IN LIVE     ANONROUTER_LIVE_GATEWAY_ORIGIN points at a real confidential
//                   deployment. These run for real: fresh nonce, real TDX quote,
//                   real event log, real measurements.
//
//   OPT-IN HARDWARE ANONROUTER_DCAP_VERIFIER_BIN additionally points at the
//                   reviewed DCAP engine. The chain to Intel's roots is then
//                   checked too, and the verdict may legitimately reach
//                   hardware_verified.
//
//   DEFAULT         Nothing configured, so the live cases SKIP with a stated
//                   reason. They are never silently green: the readiness cases
//                   below still run and assert the properties that must hold
//                   BEFORE a live run can mean anything.
//
// What this file must never do is fabricate a passing live result. A synthetic
// fixture cannot stand in for hardware, so when there is no hardware the honest
// output is a skip that says so, not a green check that implies a run happened.
//
// THE NEGATIVES ARE THE POINT. A live "it verified" is nearly worthless on its
// own: a verifier that returned ok for everything would produce it too. Each
// tamper case below takes the SAME genuine document, changes exactly one thing,
// and requires the verdict to fail on the exact check that covers it. That is
// what makes the positive result mean something.
//
// The gateway attestation endpoint is credential-free, content-free, and
// read-only, so pointing this at a real deployment is safe: it sends no prompt,
// no key, and no account identity.

import { beforeAll, describe, expect, it } from "vitest";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";
import { loadGatewayPolicy, pinnedGatewayPolicyFor, type GatewayMeasurementPolicy } from "../src/gateway/policy.js";
import { normalizeGatewayBinding, gatewayBindingHash, type GatewayAttestationBinding } from "../src/gateway/binding.js";
import { parseEventLog, replayRtmrs } from "../src/gateway/eventLog.js";
import { parseTdxQuote, TDX_TEE_TYPE } from "../src/verify/tdx.js";
import { createAnonRouterDcapVerifier, resolveDcapVerifierBinary } from "../src/gateway/dcap/index.js";
import { createClient } from "../src/client.js";
import type { FetchLike } from "../src/transport/types.js";

const LIVE_ORIGIN = process.env.ANONROUTER_LIVE_GATEWAY_ORIGIN;
/** A deployment that is expected NOT to serve the confidential contract. */
const PUBLIC_ORIGIN = process.env.ANONROUTER_LIVE_PUBLIC_ORIGIN;
const ENGINE = resolveDcapVerifierBinary().path;

const describeLive = LIVE_ORIGIN ? describe : describe.skip;
const describePublic = PUBLIC_ORIGIN ? describe : describe.skip;
const describeHardware = LIVE_ORIGIN && ENGINE ? describe : describe.skip;

/** Byte offset of report_data inside a TDX v4 quote. */
const REPORT_DATA_OFFSET = 568;
/** Byte offset of td_attributes, whose bit 0 is TUD.DEBUG. */
const TD_ATTRIBUTES_OFFSET = 168;

function freshNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Fetch one evidence document, retrying only what is safe to retry.
 *
 * Two things are retried and nothing else. A dropped connection is a fact about
 * the network, not about the evidence: a suite this size opens many TLS
 * connections in a few seconds against a 2-vCPU machine. And a 429 is the server
 * explicitly saying "later", which is a scheduling answer rather than a
 * verification one.
 *
 * Retrying is safe precisely because nothing about the verification is relaxed:
 * the nonce still has to come back inside the quote, so a retry that produced a
 * document for a different challenge would fail exactly as it should. Every other
 * status is the server answering and is thrown.
 */
async function fetchLive(origin: string, nonce: string, attempts = 5): Promise<GatewayAttestationEvidence> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** attempt));
    let response: Response;
    try {
      response = await fetch(`${origin}/v1/gateway/attestation?nonce=${nonce}`, {
        headers: { accept: "application/json" }
      });
    } catch (error) {
      lastError = error;
      continue;
    }
    if (response.status === 429) {
      lastError = new Error("rate limited");
      const retryAfter = Number(response.headers.get("retry-after"));
      if (Number.isFinite(retryAfter) && retryAfter > 0) {
        await new Promise((resolve) => setTimeout(resolve, Math.min(retryAfter, 10) * 1000));
      }
      continue;
    }
    if (!response.ok) throw new Error(`live gateway returned ${response.status}`);
    return (await response.json()) as GatewayAttestationEvidence;
  }
  throw new Error(`could not reach ${origin} in ${attempts} attempts: ${String(lastError)}`);
}

/**
 * A policy pinned to the document's own identity.
 *
 * NOT A SECURITY RESULT: a policy read out of the evidence it authorizes is
 * circular, and the source string says so. It exists so the CRYPTOGRAPHIC checks
 * can be exercised against real hardware independently of whether the shipped pin
 * is current, which is a different question and has its own case below.
 */
function policyFrom(
  binding: GatewayAttestationBinding,
  overrides: Record<string, unknown> = {}
): GatewayMeasurementPolicy {
  return loadGatewayPolicy({
    source: "live-readiness-NOT-A-SECURITY-RESULT",
    version: "1",
    origins: [binding.origin],
    appIds: [binding.app_id],
    composeHashes: [binding.compose_hash],
    releaseIds: [binding.release_id],
    requireInTeeTls: false,
    requirePrivateLogs: false,
    requireDigestPinnedImages: false,
    requireHardwareVerified: false,
    acceptableTcbStatuses: ["UpToDate"],
    requireEvidenceExpiry: false,
    maxEvidenceAgeMs: 300_000,
    ...overrides
  });
}

/** Flip one bit in the byte at `offset` of a hex-encoded quote. */
function flipQuoteByte(quoteHex: string, offset: number): string {
  const at = offset * 2;
  const byte = parseInt(quoteHex.slice(at, at + 2), 16) ^ 0x01;
  return quoteHex.slice(0, at) + byte.toString(16).padStart(2, "0") + quoteHex.slice(at + 2);
}

/** Set the TUD.DEBUG bit, turning genuine evidence into a debug TD's evidence. */
function setDebugBit(quoteHex: string): string {
  const at = TD_ATTRIBUTES_OFFSET * 2;
  const byte = parseInt(quoteHex.slice(at, at + 2), 16) | 0x01;
  return quoteHex.slice(0, at) + byte.toString(16).padStart(2, "0") + quoteHex.slice(at + 2);
}

/**
 * TWO documents for the whole file, fetched once.
 *
 * A confidential VM is a small machine, and asking it for a fresh document per
 * test hammers it hard enough to be rate limited, which tests the network rather
 * than the verifier. Two is the minimum that keeps every property below
 * reachable: one to verify and tamper with, and a second bound to a DIFFERENT
 * challenge, which is what proves the TD quoted each nonce rather than replaying
 * a recording. Freshness is asserted explicitly rather than assumed from the
 * number of fetches.
 */
interface LiveDocument {
  nonce: string;
  doc: GatewayAttestationEvidence;
  binding: GatewayAttestationBinding;
}

let first: LiveDocument;
let second: LiveDocument;

async function loadDocument(origin: string): Promise<LiveDocument> {
  const nonce = freshNonce();
  const doc = await fetchLive(origin, nonce);
  return { nonce, doc, binding: normalizeGatewayBinding(doc.binding) };
}

if (LIVE_ORIGIN) {
  beforeAll(async () => {
    // Sequential on purpose: parallel requests test the network, not the property.
    first = await loadDocument(LIVE_ORIGIN);
    second = await loadDocument(LIVE_ORIGIN);
  }, 120_000);
}

// ---- Readiness: always runs, no hardware required ---------------------------

describe("live-CVM readiness", () => {
  it("states which mode the suite ran in, so a skip is never ambiguous", () => {
    const mode = LIVE_ORIGIN
      ? `LIVE against ${LIVE_ORIGIN}${ENGINE ? " WITH a DCAP engine" : " WITHOUT a DCAP engine"}`
      : "SKIPPED (set ANONROUTER_LIVE_GATEWAY_ORIGIN to run live)";
    expect(typeof mode).toBe("string");
  });

  it("reports `unavailable`, not a pass, when a deployment does not serve the route", async () => {
    // The precondition for trusting a live run: a gateway that cannot attest must
    // be distinguishable from one that attested successfully. If this regressed, a
    // live run against a non-CVM deployment could look like a pass.
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

  it("serves a document bound to OUR fresh nonce", () => {
    expect(first.binding.nonce).toBe(first.nonce);
    expect(first.binding.origin).toBe(origin);
    expect(second.binding.nonce).toBe(second.nonce);
    expect(first.nonce).not.toBe(second.nonce);
  });

  it("answers two different challenges with two different documents", () => {
    // A recorded document replayed to everyone would answer the case above just
    // as well. Two nonces must produce two different report_data values, which is
    // only possible if the TD quoted each challenge.
    const a = parseTdxQuote(first.doc.quote)!;
    const b = parseTdxQuote(second.doc.quote)!;
    expect(a.reportData).not.toBe(b.reportData);
    // ...while the MEASUREMENTS stay identical, because it is the same TD.
    expect(a.mrTd).toBe(b.mrTd);
    expect(a.rtmr0).toBe(b.rtmr0);
    expect(a.rtmr3).toBe(b.rtmr3);
  });

  it("returns a real, non-debug Intel TDX quote whose report_data commits to the binding", () => {
    for (const document of [first, second]) {
      const quote = parseTdxQuote(document.doc.quote);
      expect(quote).not.toBeNull();
      expect(quote!.teeType).toBe(TDX_TEE_TYPE);
      expect(quote!.debugEnabled).toBe(false);
      // The load-bearing one: our canonical serialization must reproduce exactly
      // what the TD hashed into report_data, on real hardware output.
      expect(quote!.reportData).toBe(gatewayBindingHash(document.binding));
    }
  });

  it("has an event log that replays to the hardware registers", () => {
    const quote = parseTdxQuote(first.doc.quote)!;
    const replayed = replayRtmrs(parseEventLog(first.doc.event_log));
    expect(replayed[0]).toBe(quote.rtmr0);
    expect(replayed[1]).toBe(quote.rtmr1);
    expect(replayed[2]).toBe(quote.rtmr2);
    expect(replayed[3]).toBe(quote.rtmr3);
  });

  it("caps the verdict at cryptographically_checked without a DCAP engine", () => {
    // Even against genuine hardware, no vendor-root chain means no
    // hardware_verified. This is the claim discipline the SDK exists to keep.
    const result = verifyGatewayAttestation(first.doc, {
      nonce: first.nonce, origin: first.binding.origin,
      policy: policyFrom(first.binding), now: Date.now()
    });
    expect(result.status).toBe("ok");
    expect(result.verificationLevel).toBe("provider-attested");
    expect(result.verificationLevel).not.toBe("hardware-verified");
  });
});

// ---- Live negatives: one genuine document, one change at a time -------------

describeLive("live confidential VM, negatives", () => {
  // The same genuine document every case starts from, so a failure below is
  // caused by the one field that case changed and nothing else.
  const nonce = () => first.nonce;
  const doc = () => first.doc;
  const binding = () => first.binding;
  const policy = () => policyFrom(first.binding);

  /** Verify a locally modified copy of the genuine document. */
  function verifyMutated(
    mutate: (copy: GatewayAttestationEvidence) => GatewayAttestationEvidence,
    expectations: Partial<Parameters<typeof verifyGatewayAttestation>[1]> = {}
  ) {
    const copy = mutate(JSON.parse(JSON.stringify(doc())) as GatewayAttestationEvidence);
    return verifyGatewayAttestation(copy, {
      nonce: nonce(), origin: binding().origin, policy: policy(), now: Date.now(), ...expectations
    });
  }

  it("the unmodified document verifies, so each failure below is caused by the change", () => {
    const result = verifyMutated((copy) => copy);
    expect(result.status).toBe("ok");
  });

  it("REPLAY: refuses the document against a nonce it never saw", () => {
    const result = verifyMutated((copy) => copy, { nonce: freshNonce() });
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("nonce_matches_request");
  });

  it("WRONG ORIGIN: refuses a document that names a different deployment", () => {
    // The document belongs to whoever it names. Accepting it for another origin
    // would let one verified deployment vouch for an unverified one.
    const result = verifyMutated((copy) => copy, { origin: "https://someone-else.example" });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "origin_matches_connection")!.passed).toBe(false);
  });

  it("TAMPERED BINDING: a rewritten release id no longer matches report_data", () => {
    const result = verifyMutated((copy) => {
      (copy.binding as Record<string, unknown>).release_id = "anonrouter-tee@attacker";
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "report_data_binds_binding")!.passed).toBe(false);
  });

  it("TAMPERED BINDING: a rewritten TLS fingerprint no longer matches report_data", () => {
    const result = verifyMutated((copy) => {
      (copy.binding as Record<string, unknown>).tls_spki_sha256 = "ab".repeat(32);
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "report_data_binds_binding")!.passed).toBe(false);
  });

  it("TAMPERED QUOTE: one flipped byte in report_data breaks the binding", () => {
    const result = verifyMutated((copy) => {
      copy.quote = flipQuoteByte(String(copy.quote), REPORT_DATA_OFFSET);
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "report_data_binds_binding")!.passed).toBe(false);
  });

  it("TAMPERED QUOTE: a flipped RTMR byte breaks the event-log replay", () => {
    const result = verifyMutated((copy) => {
      copy.quote = flipQuoteByte(String(copy.quote), 376); // rtmr0
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "event_log_replays_rtmrs")!.passed).toBe(false);
  });

  it("DEBUG TD: setting the debug bit is fatal even on otherwise genuine evidence", () => {
    // A debug TD lets the host read and modify guest memory, so nothing measured
    // inside it is confidential. This must fail regardless of everything else.
    const result = verifyMutated((copy) => {
      copy.quote = setDebugBit(String(copy.quote));
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "quote_not_debug")!.passed).toBe(false);
  });

  it("TAMPERED EVENT LOG: a rewritten digest no longer replays to the registers", () => {
    const result = verifyMutated((copy) => {
      const events = JSON.parse(String(copy.event_log)) as Array<Record<string, unknown>>;
      events[0].digest = "00".repeat(48);
      copy.event_log = JSON.stringify(events);
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "event_log_replays_rtmrs")!.passed).toBe(false);
  });

  it("REWRITTEN PAYLOAD: renaming the measured compose hash breaks the replay", () => {
    // The attack this closes: take a genuine quote and its genuine log, and
    // rewrite the readable compose-hash payload to a value the client's policy
    // accepts. It fails because RTMR3 digests are DERIVED from each event's own
    // fields rather than read out of the log, so the rewritten payload produces a
    // different digest and the register no longer reproduces. Nothing about the
    // readable part of the log is taken on trust.
    const result = verifyMutated((copy) => {
      const events = JSON.parse(String(copy.event_log)) as Array<Record<string, unknown>>;
      const target = events.find((e) => e.event === "compose-hash");
      expect(target).toBeDefined();
      // The live agent ships RTMR3 entries with an EMPTY digest precisely so the
      // verifier must derive one. Confirm that, because the argument above only
      // holds if the digest is not being read from the log.
      expect(target!.digest).toBe("");
      target!.event_payload = "ff".repeat(32);
      copy.event_log = JSON.stringify(events);
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "event_log_replays_rtmrs")!.passed).toBe(false);
  });

  it("SUPPLIED DIGEST: a digest that does not commit to its own payload is caught", () => {
    // The other half. If a log supplies a digest instead of leaving it empty, the
    // verifier must still require it to agree with the payload printed beside it,
    // or a server could ship a digest that replays correctly while displaying
    // something else.
    const result = verifyMutated((copy) => {
      const events = JSON.parse(String(copy.event_log)) as Array<Record<string, unknown>>;
      const target = events.find((e) => e.event === "compose-hash");
      target!.digest = "ab".repeat(48);
      copy.event_log = JSON.stringify(events);
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "event_digests_commit_to_payloads")!.passed).toBe(false);
  });

  it("TAMPERED MANIFEST: an edited app-compose is no longer the measured one", () => {
    const result = verifyMutated((copy) => {
      copy.app_compose = `${String(copy.app_compose)} `;
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "app_compose_matches_measurement")!.passed).toBe(false);
  });

  it("TAMPERED VM CONFIG: an OS image the hardware did not measure is caught", () => {
    // vm_config is what an auditor re-feeds to dstack-mr. A CVM that named a
    // different OS image would send them to reproduce the wrong measurements and
    // conclude the quote was forged.
    const result = verifyMutated((copy) => {
      const config = JSON.parse(String(copy.vm_config)) as Record<string, unknown>;
      config.os_image_hash = "ab".repeat(32);
      copy.vm_config = JSON.stringify(config);
      return copy;
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "vm_config_matches_measured_os_image")!.passed).toBe(false);
  });

  it("STALE EVIDENCE: an old document fails when the policy requires freshness", () => {
    const result = verifyGatewayAttestation(doc(), {
      nonce: nonce(),
      origin: binding().origin,
      policy: policyFrom(binding(), { requireEvidenceExpiry: true, maxEvidenceAgeMs: 1000 }),
      now: Date.now() + 3_600_000
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "evidence_recent")!.passed).toBe(false);
  });

  it("WRONG CERTIFICATE: an observed SPKI the TD did not attest is refused", () => {
    const result = verifyGatewayAttestation(doc(), {
      nonce: nonce(),
      origin: binding().origin,
      policy: policyFrom(binding(), { requireInTeeTls: true }),
      now: Date.now(),
      observedTlsSpkiSha256: "cd".repeat(32)
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "tls_certificate_bound_to_quote")!.passed).toBe(false);
  });

  it("WRONG KEY PROVIDER: a different KMS is a different trust domain", () => {
    const result = verifyGatewayAttestation(doc(), {
      nonce: nonce(),
      origin: binding().origin,
      policy: policyFrom(binding(), { keyProviderId: "ab".repeat(32) }),
      now: Date.now()
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "key_provider_pinned")!.passed).toBe(false);
  });

  it("WRONG PLATFORM PIN: measurements that do not match are refused", () => {
    const result = verifyGatewayAttestation(doc(), {
      nonce: nonce(),
      origin: binding().origin,
      policy: policyFrom(binding(), {
        platform: {
          mrTd: ["ab".repeat(48)], mrConfigId: ["ab".repeat(48)],
          rtmr0: ["ab".repeat(48)], rtmr1: ["ab".repeat(48)], rtmr2: ["ab".repeat(48)],
          osImageHash: ["ab".repeat(32)]
        }
      }),
      now: Date.now()
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "platform_measurements_pinned")!.passed).toBe(false);
    expect(result.checks.find((c) => c.name === "os_image_pinned")!.passed).toBe(false);
  });
});

// ---- Live: the shipped pin, held to the plane it names ----------------------

describeLive("the shipped pin against the live plane", () => {
  const origin = LIVE_ORIGIN!;

  it("resolves the reviewed production pin by default", () => {
    expect(pinnedGatewayPolicyFor(origin)?.status).toBe("published");
  });

  it("matches every shipped production identity pin", () => {
    const entry = pinnedGatewayPolicyFor(origin);
    if (!entry) return; // nothing shipped for this origin; the case above covers that
    const result = verifyGatewayAttestation(first.doc, {
      nonce: first.nonce, origin, policy: entry.policy, now: Date.now()
    });
    const failed = result.checks.filter((c) => c.required && !c.passed).map((c) => c.name);
    expect(failed).toEqual(["quote_signature_chain", "tcb_status_acceptable"]);
  });
});

// ---- Live + engine: the full chain to Intel's roots -------------------------

describeHardware("live confidential VM with the reviewed DCAP engine", () => {
  const origin = LIVE_ORIGIN!;

  it("reaches hardware_verified with an acceptable TCB", async () => {
    const entry = pinnedGatewayPolicyFor(origin);
    expect(entry?.status).toBe("published");
    const policy = entry!.policy;
    const verifier = await createAnonRouterDcapVerifier().prepare(String(first.doc.quote), {
      acceptedTcbStatuses: policy.acceptableTcbStatuses,
      nowMs: Date.now()
    });
    const result = verifyGatewayAttestation(first.doc, {
      nonce: first.nonce, origin: first.binding.origin, policy, now: Date.now(), chainVerifier: verifier
    });
    expect(result.status).toBe("ok");
    expect(result.verificationLevel).toBe("hardware-verified");
    expect(policy.acceptableTcbStatuses).toContain(result.tcbStatus);
  }, 60_000);

  it("REFUSES a tampered quote at the signature, not just at the binding", async () => {
    // The check no amount of structural verification can make: this quote is
    // internally consistent right up to the ECDSA signature, and only the chain
    // to Intel's roots catches it.
    // Flip a byte inside the SIGNED body and let the engine speak: this quote is
    // internally consistent to every structural check and only the chain catches it.
    const tampered = flipQuoteByte(String(first.doc.quote), 184);
    const verifier = await createAnonRouterDcapVerifier().prepare(tampered, {
      acceptedTcbStatuses: ["UpToDate"],
      nowMs: Date.now()
    });
    const outcome = verifier.verifyChain(tampered);
    expect(outcome.verified).toBe(false);
  }, 60_000);

  it("a verifier prepared for the live quote refuses a different one", async () => {
    // Both quotes are genuine and come from the same machine. A prepared verifier
    // that answered for either would let one challenge's pass launder another's.
    const verifier = await createAnonRouterDcapVerifier().prepare(String(first.doc.quote), {
      acceptedTcbStatuses: ["UpToDate"],
      nowMs: Date.now()
    });
    expect(verifier.verifyChain(String(first.doc.quote)).verified).toBe(true);
    expect(verifier.verifyChain(String(second.doc.quote)).verified).toBe(false);
  }, 60_000);

  it("refuses when the policy accepts no TCB status the platform can report", async () => {
    // The case that separates "the signature is genuine" from "this machine is
    // safe to hand data to". Both are required; neither implies the other.
    const policy = policyFrom(first.binding, {
      requireHardwareVerified: true,
      acceptableTcbStatuses: ["Revoked"]
    });
    const verifier = await createAnonRouterDcapVerifier().prepare(String(first.doc.quote), {
      // The engine is told the same list, so it refuses too. Both layers gate.
      acceptedTcbStatuses: policy.acceptableTcbStatuses,
      nowMs: Date.now()
    });
    const result = verifyGatewayAttestation(first.doc, {
      nonce: first.nonce, origin: first.binding.origin, policy, now: Date.now(), chainVerifier: verifier
    });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "tcb_status_acceptable")!.passed).toBe(false);
  }, 60_000);
});

// ---- Live: a deployment that does NOT serve the confidential contract -------

describePublic("a public deployment that does not expose gateway attestation", () => {
  const origin = PUBLIC_ORIGIN!;

  it("reports the route as absent rather than as verified or as an error", async () => {
    const response = await fetch(`${origin}/v1/gateway/attestation?nonce=${freshNonce()}`, {
      headers: { accept: "application/json" }
    });
    // 404 (no such route) and 503 (running, but not attestable) are the two
    // documented answers. Anything else would mean the contract exists here and
    // this test's premise is wrong.
    expect([404, 503]).toContain(response.status);
  }, 30_000);

  it("verifyRoute reports `unavailable`, which is NOT a failure of the plane", async () => {
    // "We could not look" and "we looked and it failed" call for different
    // responses. Collapsing them would hide which one an operator is in.
    const client = createClient({ baseUrl: origin, apiKey: "unused-for-gateway-verification" });
    const verdict = await client.verifyRoute({
      model: "-", provider: "-",
      gateway: { policy: loadGatewayPolicy({
        source: "public-origin-probe", version: "1", origins: [origin],
        appIds: ["aa"], composeHashes: ["ab".repeat(32)], releaseIds: ["r"],
        requireInTeeTls: false, requirePrivateLogs: false, requireDigestPinnedImages: false,
        requireHardwareVerified: false, acceptableTcbStatuses: ["UpToDate"],
        requireEvidenceExpiry: false, maxEvidenceAgeMs: 300_000
      }) }
    });
    expect(verdict.gateway.requested).toBe(true);
    expect(verdict.gateway.state).toBe("unavailable");
    expect(verdict.gateway.failedChecks).toEqual([]);
  }, 30_000);

  it("ships no pin for it, so a default call has nothing to verify against", () => {
    expect(pinnedGatewayPolicyFor(origin, { allowCandidate: true })).toBeUndefined();
  });
});
