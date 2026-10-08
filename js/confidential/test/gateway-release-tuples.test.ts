// Tuple-form gateway policies: explicit platform kinds, whole release tuples,
// GCP same-connection key binding and the unqualified-platform gate.
//
// The shared vectors are verified byte for byte by the Python suite as well
// (python/tests/test_gateway_release_tuples.py). Everything is synthetic: no
// value here is a Google firmware measurement or an AnonRouter production pin.

import { describe, expect, it, vi } from "vitest";
import vectors from "../../../shared/vectors/gateway-release-tuples.json" with { type: "json" };
import { createClient } from "../src/client.js";
import { ConfidentialError } from "../src/errors.js";
import { assertGatewayPolicySecurityFloor, verifySignedGatewayPolicy, type GatewayPolicyAuthority } from "../src/gateway/authority.js";
import {
  GATEWAY_PLATFORM_QUALIFIED,
  gatewayPolicyRegistry,
  loadGatewayPolicy,
  type GatewayMeasurementPolicy
} from "../src/gateway/policy.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";

type VerifyCase = (typeof vectors.verifyCases)[number];

function run(testCase: VerifyCase, policy: GatewayMeasurementPolicy = loadGatewayPolicy(testCase.policy)) {
  const e = testCase.expectations;
  const chain = testCase.chainVerifier;
  return verifyGatewayAttestation(testCase.evidence as unknown as GatewayAttestationEvidence, {
    nonce: e.nonce, origin: e.origin, policy, now: e.nowMs,
    ...(e.observedTlsSpki.supplied ? { observedTlsSpkiSha256: e.observedTlsSpki.value } : {}),
    observedOnRetainedConnection: e.observedOnRetainedConnection,
    unqualifiedPlatformPilot: e.unqualifiedPlatformPilot,
    ...(chain ? { chainVerifier: { implementation: "vector-stub", verifyChain: () => ({
      verified: chain.verified, ...(chain.tcbStatus ? { tcbStatus: chain.tcbStatus } : {}) }) } } : {})
  });
}

describe("tuple-form policy documents, from the shared vectors", () => {
  for (const testCase of vectors.loadCases) {
    it(`${testCase.accepted ? "accepts" : "refuses"}: ${testCase.name}`, () => {
      if (!testCase.accepted) {
        expect(() => loadGatewayPolicy(testCase.policy)).toThrow();
        return;
      }
      const policy = loadGatewayPolicy(testCase.policy);
      expect(() => assertGatewayPolicySecurityFloor(policy)).not.toThrow();
      expect(policy.platform).toBeUndefined();
      expect(policy.keyProviderId).toBeUndefined();
      // Derived lists are display-only unions of the tuples, never a second source.
      expect(policy.releaseIds).toEqual([...new Set(policy.releaseTuples!.map(t => t.releaseId))]);
    });
  }
});

describe("tuple-form verdicts, from the shared vectors", () => {
  for (const testCase of vectors.verifyCases) {
    it(testCase.name, () => {
      const result = run(testCase);
      expect({
        status: result.status,
        verificationLevel: result.verificationLevel,
        reason: result.reason,
        failedRequiredChecks: result.checks.filter(c => c.required && !c.passed).map(c => c.name),
        unmetAdvisoryChecks: result.checks.filter(c => !c.required && !c.passed).map(c => c.name),
        releaseTupleDetail: result.checks.find(c => c.name === "release_tuple_matched")?.detail ?? null
      }).toEqual(testCase.expected);
    });
  }

  it("a policy object mutated after loading fails its own floor at verification", () => {
    const testCase = vectors.verifyCases[0]!;
    const weakened = { ...loadGatewayPolicy(testCase.policy), requireHardwareVerified: false };
    const result = run(testCase, weakened);
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("policy_security_floor");
  });

  it("a hand-built object cannot smuggle tuples past the legacy branch", () => {
    const testCase = vectors.verifyCases[0]!;
    const { platformKind: _kind, ...withoutKind } = loadGatewayPolicy(testCase.policy);
    expect(() => assertGatewayPolicySecurityFloor(withoutKind as GatewayMeasurementPolicy)).toThrow(/explicit platformKind/);
    expect(run(testCase, withoutKind as GatewayMeasurementPolicy).reason).toBe("policy_security_floor");
  });

  it("derived identity lists cannot be widened independently of the tuples", () => {
    const testCase = vectors.verifyCases[0]!;
    const widened = loadGatewayPolicy(testCase.policy);
    widened.releaseIds = [...widened.releaseIds, "content@unreviewed"];
    expect(() => assertGatewayPolicySecurityFloor(widened)).toThrow(/derived identity/);
  });
});

describe("signed feed and packaged registry never supply an unqualified platform", () => {
  const root = vectors.signingRoot as GatewayPolicyAuthority;
  for (const testCase of vectors.signedCases) {
    it(testCase.name, () => {
      const verify = () => verifySignedGatewayPolicy(testCase.envelope, root, testCase.origin, vectors.nowMs);
      if (testCase.accepted) expect(verify().policy.platformKind).toBe("phala-dstack-kms");
      else expect(verify).toThrow(/not qualified/);
    });
  }

  it("gcp-tdx-native is not qualified by this release", () => {
    expect(GATEWAY_PLATFORM_QUALIFIED["gcp-tdx-native"]).toBe(false);
    expect(GATEWAY_PLATFORM_QUALIFIED["phala-dstack-kms"]).toBe(true);
  });

  it("the packaged registry is the unchanged legacy Phala form with one value per pin", () => {
    for (const entry of gatewayPolicyRegistry()) {
      expect("platformKind" in entry.policy).toBe(false);
      expect("releaseTuples" in entry.policy).toBe(false);
      // A legacy entry with one value per list is exactly one correlated tuple;
      // several values would reintroduce independently mixed allowlists.
      const p = entry.policy;
      for (const list of [p.appIds, p.composeHashes, p.releaseIds, p.platform!.mrTd, p.platform!.mrConfigId,
        p.platform!.rtmr0, p.platform!.rtmr1, p.platform!.rtmr2, p.platform!.osImageHash]) expect(list).toHaveLength(1);
    }
  });
});

describe("client refuses unbound or unacknowledged GCP verification before any request", () => {
  const gcp = loadGatewayPolicy(vectors.verifyCases[0]!.policy);
  const origin = vectors.verifyCases[0]!.expectations.origin;

  function unboundClient() {
    const fetchMock = vi.fn(async () => { throw new Error("no request may be made"); });
    const client = createClient({ inferenceBaseUrl: origin, controlBaseUrl: "https://control.gcp.example",
      apiKey: "synthetic-key", fetch: fetchMock as unknown as typeof fetch });
    return { client, fetchMock };
  }

  it("standalone verifyGateway on a separate connection", async () => {
    const { client, fetchMock } = unboundClient();
    const error = await client.verifyGateway({ policy: gcp, unqualifiedPlatformPilot: true }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConfidentialError);
    expect((error as ConfidentialError).code).toBe("unsupported_request");
    expect((error as Error).message).toMatch(/connection binding/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("an unbound chat gated on a GCP policy mints no ticket and sends no content", async () => {
    const { client, fetchMock } = unboundClient();
    const error = await client.chat({ model: "venice-uncensored", provider: "venice",
      messages: [{ role: "user", content: "synthetic-content-canary" }], maxOutputTokens: 8,
      requireGateway: { policy: gcp, unqualifiedPlatformPilot: true } }).catch((e: unknown) => e);
    expect((error as ConfidentialError).code).toBe("unsupported_request");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("required connection binding without the pilot opt-in", async () => {
    const client = createClient({ inferenceBaseUrl: origin, controlBaseUrl: "https://control.gcp.example",
      apiKey: "synthetic-key", gatewayConnectionBinding: { mode: "required", verification: {
        policy: gcp, chainVerifier: { implementation: "unused", verifyChain: () => ({ verified: false }) } } } });
    // verifyGateway is the separate-connection API even on a bound client.
    const error = await client.verifyGateway({ policy: gcp, unqualifiedPlatformPilot: true }).catch((e: unknown) => e);
    expect((error as ConfidentialError).code).toBe("unsupported_request");
    expect((error as Error).message).toMatch(/connection binding/);
    const chatError = await client.chat({ model: "venice-uncensored", provider: "venice",
      messages: [{ role: "user", content: "synthetic-content-canary" }], maxOutputTokens: 8 }).catch((e: unknown) => e);
    expect((chatError as ConfidentialError).code).toBe("unsupported_request");
    expect((chatError as Error).message).toMatch(/unqualifiedPlatformPilot/);
  });

  it("refuses a non-boolean pilot flag at construction", () => {
    expect(() => createClient({ inferenceBaseUrl: origin, controlBaseUrl: "https://control.gcp.example",
      apiKey: "synthetic-key", gatewayConnectionBinding: { mode: "required", verification: {
        policy: gcp, unqualifiedPlatformPilot: "yes" as unknown as boolean,
        chainVerifier: { implementation: "unused", verifyChain: () => ({ verified: false }) } } } })).toThrow();
  });
});
