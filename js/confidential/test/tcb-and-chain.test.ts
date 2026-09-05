// TCB enforcement, evidence expiry, and the reference chain-verifier adapters.
//
// The theme is that a DCAP verdict is not a boolean. A quote can chain perfectly
// to Intel's roots while the machine holding your data has known unpatched
// vulnerabilities, so `verified: true` alone must never be enough.

import { describe, expect, it } from "vitest";
import { gatewayBindingHash, GATEWAY_BINDING_VERSION } from "../src/gateway/binding.js";
import { loadGatewayPolicy, type GatewayMeasurementPolicy } from "../src/gateway/policy.js";
import {
  verifyGatewayAttestation,
  type GatewayAttestationEvidence,
  type TdxChainVerifier
} from "../src/gateway/verify.js";
import { preparedChainVerifier, createSubprocessChainVerifier } from "../src/gateway/chain-verifiers.js";
import {
  buildAppCompose,
  buildSyntheticEventLog,
  buildSyntheticTdxQuote,
  buildVmConfig
} from "./helpers/gateway-fixtures.js";

const NONCE = "9".repeat(64);
const ORIGIN = "https://tee.anonrouter.ai";
const APP_ID = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98";
const RELEASE_ID = "anonrouter-tee@c7b32e0";
const NOW = 1_760_000_000_000;
const compose = buildAppCompose();

function policy(overrides: Record<string, unknown> = {}): GatewayMeasurementPolicy {
  return loadGatewayPolicy({
    source: "anonrouter-sdk@test",
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
    maxEvidenceAgeMs: 300_000,
    ...overrides
  });
}

/** `issuedAtMs: null` OMITS the field entirely, which is a different case from
 *  a stale timestamp and has to be reachable to be tested. */
function evidence(issuedAtMs: number | null = NOW - 500): GatewayAttestationEvidence {
  const binding = {
    v: GATEWAY_BINDING_VERSION,
    nonce: NONCE,
    app_id: APP_ID,
    instance_id: INSTANCE_ID,
    compose_hash: compose.hash,
    release_id: RELEASE_ID,
    origin: ORIGIN,
    key_alg: "x25519" as const,
    public_key: "ab".repeat(32),
    transport: "gateway-tls" as const,
    tls_spki_sha256: null
  };
  const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: compose.hash, instanceId: INSTANCE_ID });
  return {
    binding,
    quote: buildSyntheticTdxQuote({
      reportDataHex: gatewayBindingHash(binding),
      rtmr0: log.rtmr0, rtmr1: log.rtmr1, rtmr2: log.rtmr2, rtmr3: log.rtmr3
    }),
    event_log: JSON.stringify(log.events),
    app_compose: compose.manifest,
    vm_config: buildVmConfig(),
    ...(issuedAtMs === null ? {} : { issued_at_ms: issuedAtMs })
  };
}

function verify(chainVerifier?: TdxChainVerifier, policyOverrides: Record<string, unknown> = {}, issuedAt?: number) {
  return verifyGatewayAttestation(evidence(issuedAt), {
    nonce: NONCE, origin: ORIGIN, policy: policy(policyOverrides), now: NOW, chainVerifier
  });
}

function chain(verified: boolean, tcbStatus?: string): TdxChainVerifier {
  return { implementation: "test", verifyChain: () => ({ verified, ...(tcbStatus ? { tcbStatus } : {}) }) };
}

describe("TCB status enforcement", () => {
  it("accepts a verified quote whose TCB is on the accepted list", () => {
    const r = verify(chain(true, "UpToDate"));
    expect(r.status).toBe("ok");
    expect(r.verificationLevel).toBe("hardware-verified");
  });

  it("REFUSES a verified quote whose TCB is out of date", () => {
    // The whole point: the signature chained fine, but the platform holding the
    // data has known unpatched vulnerabilities. `verified: true` is not enough.
    const r = verify(chain(true, "OutOfDate"));
    expect(r.status).toBe("failed");
    expect(r.reason).toBe("tcb_status_acceptable");
    expect(r.checks.find((c) => c.name === "quote_signature_chain")?.passed).toBe(true);
  });

  it("refuses a verifier that reports no TCB status at all", () => {
    const r = verify(chain(true));
    expect(r.status).toBe("failed");
    expect(r.reason).toBe("tcb_status_acceptable");
    expect(r.checks.find((c) => c.name === "tcb_status_acceptable")?.detail).toContain("no TCB status");
  });

  it("honours a widened accepted list, since that is a written-down decision", () => {
    const r = verify(chain(true, "SWHardeningNeeded"), {
      acceptableTcbStatuses: ["UpToDate", "SWHardeningNeeded"]
    });
    expect(r.status).toBe("ok");
    expect(r.verificationLevel).toBe("hardware-verified");
  });

  it("compares TCB status case-insensitively", () => {
    expect(verify(chain(true, "uptodate")).status).toBe("ok");
  });

  it("records the TCB check even with no verifier, so verdicts stay comparable", () => {
    const r = verify(undefined);
    const entry = r.checks.find((c) => c.name === "tcb_status_acceptable");
    expect(entry).toBeDefined();
    expect(entry!.passed).toBe(false);
    expect(entry!.required).toBe(false); // requireHardwareVerified is off here
    expect(r.status).toBe("ok");
    expect(r.verificationLevel).toBe("provider-attested");
  });

  it("makes the TCB check required when hardware verification is required", () => {
    const r = verify(undefined, { requireHardwareVerified: true });
    expect(r.status).toBe("failed");
    expect(r.checks.find((c) => c.name === "tcb_status_acceptable")?.required).toBe(true);
  });
});

describe("evidence expiry", () => {
  it("is advisory by default and does not fail a fresh document", () => {
    expect(verify(undefined, {}, NOW - 500).status).toBe("ok");
  });

  it("fails a stale document when the policy requires expiry", () => {
    const r = verify(undefined, { requireEvidenceExpiry: true }, NOW - 10 * 60_000);
    expect(r.status).toBe("failed");
    expect(r.reason).toBe("evidence_recent");
  });

  it("fails a document with NO timestamp when expiry is required", () => {
    // "Cannot be aged" must not read as "fresh enough": that is how an expiry
    // check quietly stops existing.
    const r = verifyGatewayAttestation(evidence(null), {
      nonce: NONCE, origin: ORIGIN, policy: policy({ requireEvidenceExpiry: true }), now: NOW
    });
    expect(r.status).toBe("failed");
    expect(r.reason).toBe("evidence_recent");
    expect(r.checks.find((c) => c.name === "evidence_recent")?.detail).toBe("no issued_at_ms");
  });

  it("rejects a future-dated document beyond the skew allowance", () => {
    const r = verify(undefined, { requireEvidenceExpiry: true }, NOW + 10 * 60_000);
    expect(r.status).toBe("failed");
    expect(r.reason).toBe("evidence_recent");
  });
});

describe("prepared chain verifier binding", () => {
  it("refuses a quote it was not prepared for", () => {
    // Without this, a verifier prepared for quote A would report verified for
    // quote B, which is exactly the substitution the port exists to prevent.
    const v = preparedChainVerifier("aabb", { verified: true, tcbStatus: "UpToDate" }, "test");
    expect(v.verifyChain("aabb", undefined)).toEqual({ verified: true, tcbStatus: "UpToDate" });
    expect(v.verifyChain("ccdd", undefined).verified).toBe(false);
  });

  it("matches the prepared quote case-insensitively", () => {
    const v = preparedChainVerifier("AABB", { verified: true }, "test");
    expect(v.verifyChain("aabb", undefined).verified).toBe(true);
  });

  it("passes a negative verdict through rather than swallowing it", () => {
    const v = preparedChainVerifier("aabb", { verified: false, error: "bad chain" }, "test");
    expect(v.verifyChain("aabb", undefined).verified).toBe(false);
  });
});

describe("subprocess chain verifier fails closed", () => {
  const quote = "aabbccdd";

  it("treats a missing binary as not verified", async () => {
    const adapter = createSubprocessChainVerifier({ binaryPath: "/nonexistent/dcap-verifier-xyz" });
    const verifier = await adapter.prepare(quote);
    expect(verifier.verifyChain(quote, undefined).verified).toBe(false);
  });

  it("treats non-JSON output as not verified", async () => {
    const adapter = createSubprocessChainVerifier({ binaryPath: "/bin/echo", args: ["not json at all"] });
    const verifier = await adapter.prepare(quote);
    expect(verifier.verifyChain(quote, undefined).verified).toBe(false);
  });

  it("treats a non-boolean `verified` field as not verified", async () => {
    // Coercing a truthy string here would invent a pass out of noise.
    const adapter = createSubprocessChainVerifier({
      binaryPath: "/bin/echo", args: ['{"verified":"yes","tcbStatus":"UpToDate"}']
    });
    const verifier = await adapter.prepare(quote);
    expect(verifier.verifyChain(quote, undefined).verified).toBe(false);
  });

  it("refuses a malformed quote before spawning anything", async () => {
    const adapter = createSubprocessChainVerifier({ binaryPath: "/bin/echo", args: ['{"verified":true}'] });
    const verifier = await adapter.prepare("not-hex");
    expect(verifier.verifyChain("not-hex", undefined).verified).toBe(false);
  });

  it("accepts a well-formed positive verdict", async () => {
    const adapter = createSubprocessChainVerifier({
      binaryPath: "/bin/echo", args: ['{"verified":true,"tcbStatus":"UpToDate"}']
    });
    const verifier = await adapter.prepare(quote);
    expect(verifier.verifyChain(quote, undefined)).toEqual({ verified: true, tcbStatus: "UpToDate" });
  });

  it("accepts an engine that answers without draining stdin", async () => {
    // THE RACE THIS PINS. An engine that prints its verdict and exits without
    // reading stdin closes the pipe while the quote is still being written, and
    // the parent gets EPIPE. Treating that as the answer failed a correct engine
    // depending on machine speed — safe, since it failed closed, but it made
    // `hardware_verified` a matter of timing. What decides the outcome is the
    // verdict on stdout.
    //
    // Deterministic rather than lucky: the child closes fd 0 explicitly, and the
    // quote is larger than a pipe buffer, so the write cannot quietly succeed.
    const bigQuote = "ab".repeat(100_000);
    const adapter = createSubprocessChainVerifier({
      binaryPath: "/bin/sh",
      args: ["-c", `exec 0<&-; printf '%s' '{"verified":true,"tcbStatus":"UpToDate"}'`]
    });
    const verifier = await adapter.prepare(bigQuote);
    expect(verifier.verifyChain(bigQuote, undefined)).toEqual({ verified: true, tcbStatus: "UpToDate" });
  });

  it("still refuses when the engine passes but the policy rejects the TCB", async () => {
    // End to end: engine says verified/OutOfDate, policy accepts only UpToDate.
    const adapter = createSubprocessChainVerifier({
      binaryPath: "/bin/echo", args: ['{"verified":true,"tcbStatus":"OutOfDate"}']
    });
    const doc = evidence();
    const verifier = await adapter.prepare(doc.quote);
    const r = verifyGatewayAttestation(doc, {
      nonce: NONCE, origin: ORIGIN, policy: policy(), now: NOW, chainVerifier: verifier
    });
    expect(r.status).toBe("failed");
    expect(r.reason).toBe("tcb_status_acceptable");
  });
});
