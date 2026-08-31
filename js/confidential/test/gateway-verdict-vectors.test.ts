// The complete hop 1 verdict, pinned across both languages.
//
// `attestation.json` does this for hop 2. Without an equivalent here the two
// languages agreed about the binding digest and the quote parse, but nothing
// pinned the VERDICT: which checks are required, what a failure is called, and
// which single check a given tamper is supposed to fail. A change that landed in
// one language and not the other could pass both suites.
//
// Every case carries a complete evidence document (expressed as a diff from one
// base, merged here), so both languages verify the same bytes rather than each
// rebuilding a fixture and hoping the two agree.

import { describe, expect, it } from "vitest";
import vectors from "../../../shared/vectors/gateway-verdicts.json" with { type: "json" };
import { GATEWAY_BINDING_VERSION } from "../src/gateway/binding.js";
import { loadGatewayPolicy } from "../src/gateway/policy.js";
import {
  verifyGatewayAttestation,
  type GatewayAttestationEvidence,
  type TdxChainVerifier
} from "../src/gateway/verify.js";

type Record_ = Record<string, unknown>;

/**
 * The merge contract, stated in `_readme` and asserted by the generator: shallow
 * override, plus an explicit removal list because JSON cannot express "absent"
 * and a document with no `issued_at_ms` is a case that has to be reachable.
 */
function mergeOnBase(base: Record_, overrides: Record_, removed: readonly string[]): Record_ {
  const merged = { ...base, ...overrides };
  for (const key of removed) delete merged[key];
  return merged;
}

const base = vectors.base as unknown as {
  evidence: Record_;
  policy: Record_;
  expectations: Record_;
};

describe("hop 1 verdicts, from the shared vectors", () => {
  it("pins the binding version both languages serialize", () => {
    expect(vectors.bindingVersion).toBe(GATEWAY_BINDING_VERSION);
  });

  for (const testCase of vectors.cases) {
    it(testCase.name, () => {
      const evidence = mergeOnBase(
        base.evidence,
        testCase.evidence as Record_,
        testCase.evidenceRemoved
      );
      const policy = loadGatewayPolicy(
        mergeOnBase(base.policy, testCase.policy as Record_, testCase.policyRemoved)
      );
      const expectations = { ...base.expectations, ...(testCase.expectations as Record_) };

      // A verifier is code and cannot be serialized, so the vector records the
      // outcome it should produce and each language builds the stub locally. This
      // is what makes the TCB cases reachable without a DCAP engine.
      const stub: TdxChainVerifier | undefined = testCase.chainVerifier
        ? {
          implementation: "vector-stub",
          verifyChain: () => ({
            verified: testCase.chainVerifier!.verified,
            ...(testCase.chainVerifier!.tcbStatus ? { tcbStatus: testCase.chainVerifier!.tcbStatus } : {})
          })
        }
        : undefined;

      const result = verifyGatewayAttestation(evidence as unknown as GatewayAttestationEvidence, {
        nonce: expectations.nonce as string,
        origin: expectations.origin as string,
        policy,
        now: expectations.nowMs as number,
        ...(testCase.observedTlsSpki.supplied
          ? { observedTlsSpkiSha256: testCase.observedTlsSpki.value }
          : {}),
        ...(stub ? { chainVerifier: stub } : {})
      });

      expect(result.status).toBe(testCase.expected.status);
      expect(result.verificationLevel).toBe(testCase.expected.verificationLevel);
      expect(result.reason).toBe(testCase.expected.reason);
      expect(result.tcbStatus).toBe(testCase.expected.tcbStatus);
      // The exact set, in order. A check quietly relaxed from required to advisory
      // would move between these two lists rather than disappear silently.
      expect(result.checks.filter((c) => c.required && !c.passed).map((c) => c.name))
        .toEqual(testCase.expected.failedRequiredChecks);
      expect(result.checks.filter((c) => !c.required && !c.passed).map((c) => c.name))
        .toEqual(testCase.expected.unmetAdvisoryChecks);
    });
  }

  it("never reports the same check name twice in one verdict", () => {
    // A verdict carrying `event_log_replays_rtmrs` twice, once passing and once
    // failing, is worse than a plain failure: a caller looking a check up by name
    // finds the passing copy and never sees the failure. This regressed once,
    // when reading the named identities out of the log shared a catch block with
    // the replay.
    for (const testCase of vectors.cases) {
      const evidence = mergeOnBase(base.evidence, testCase.evidence as Record_, testCase.evidenceRemoved);
      const policy = loadGatewayPolicy(
        mergeOnBase(base.policy, testCase.policy as Record_, testCase.policyRemoved)
      );
      const expectations = { ...base.expectations, ...(testCase.expectations as Record_) };
      const result = verifyGatewayAttestation(evidence as unknown as GatewayAttestationEvidence, {
        nonce: expectations.nonce as string,
        origin: expectations.origin as string,
        policy,
        now: expectations.nowMs as number
      });
      const names = result.checks.map((c) => c.name);
      expect(new Set(names).size, `duplicate check names in "${testCase.name}": ${names.join(", ")}`)
        .toBe(names.length);
    }
  });

  it("covers both outcomes, so a change cannot pass by making everything fail", () => {
    const passing = vectors.cases.filter((c) => c.expected.status === "ok");
    const failing = vectors.cases.filter((c) => c.expected.status === "failed");
    expect(passing.length).toBeGreaterThan(5);
    expect(failing.length).toBeGreaterThan(20);
  });

  it("reaches hardware_verified only where a chain verifier actually passed", () => {
    for (const testCase of vectors.cases) {
      if (testCase.expected.verificationLevel !== "hardware-verified") continue;
      expect(testCase.chainVerifier?.verified).toBe(true);
      expect(testCase.chainVerifier?.tcbStatus).toBe("UpToDate");
    }
  });
});
