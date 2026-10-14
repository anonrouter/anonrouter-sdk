// Shared release policy v3 known answers (shared/vectors/release-policy-v3.json),
// loaded identically by python/tests/test_release_policy_v3.py. The backend
// section comes from the AnonRouter backend's own implementation, so this also
// pins byte compatibility with the signer, control and the nodes.
import { describe, expect, it } from "vitest";
import vectors from "../../../shared/vectors/release-policy-v3.json" with { type: "json" };
import { bytesToHex } from "../src/bytes.js";
import { releasePolicySha256 } from "../src/gateway/release-v3-canonical.js";
import {
  releaseEnvelopeV3Message, releaseOwnerRootSha256, releasePolicyV3GatewayPolicy, releaseTupleDigest, ReleasePolicyV3Error,
  verifyReleasePolicyV3, type ReleasePolicyV3Checkpoint, type ReleasePolicyV3Trust
} from "../src/gateway/release-v3.js";
import { verifyGatewayAttestation, type GatewayAttestationEvidence } from "../src/gateway/verify.js";

const trust = vectors.trust as ReleasePolicyV3Trust;
const kat = vectors.backendKat;

describe("backend known answers (independent implementation)", () => {
  const backendTrust = kat.trust as ReleasePolicyV3Trust;
  it("derives the backend owner root, tuple digests and signing messages", () => {
    expect(releaseOwnerRootSha256(backendTrust)).toBe(backendTrust.ownerRootSha256);
    for (const tuple of kat.policy.envelope.payload.tuples) {
      expect(releaseTupleDigest(tuple)).toBe((kat.tupleDigests as Record<string, string>)[tuple.tupleId]);
    }
    for (const signed of [kat.policy, kat.successor]) {
      const e = signed.envelope;
      expect(bytesToHex(releaseEnvelopeV3Message("release-policy", e.groupId, e.ownerRootSha256, e.payload))).toBe(signed.signingMessage);
    }
  });
  it("verifies the backend's signed policy and successor with their payload digests", () => {
    const first = verifyReleasePolicyV3(kat.policy.envelope, backendTrust);
    expect(first.policySha256).toBe(kat.policy.payloadSha256);
    const next = verifyReleasePolicyV3(kat.successor.envelope, backendTrust,
      { sequence: first.sequence, policySha256: first.policySha256, revokedTuples: first.revokedTuples });
    expect(next.policySha256).toBe(kat.successor.payloadSha256);
  });
  it("reproduces the backend's tcbGrace payload digest", () => {
    expect(releasePolicySha256(kat.tcbGrace.payload)).toBe(kat.tcbGrace.policySha256);
  });
});

describe("policy cases", () => {
  for (const testCase of vectors.policyCases) {
    it(testCase.name, () => {
      const caseTrust = { ...trust, minimumPolicySequence: (testCase as { minimumPolicySequence?: number }).minimumPolicySequence ?? 1 };
      const previous = (testCase as { previous?: ReleasePolicyV3Checkpoint }).previous;
      const expected = testCase.expected as { ok?: Record<string, unknown>; refusal?: string };
      if (expected.refusal) {
        let code: string | undefined;
        try { verifyReleasePolicyV3(testCase.envelope, caseTrust, previous); } catch (error) {
          if (error instanceof ReleasePolicyV3Error) code = error.code; else throw error;
        }
        expect(code).toBe(expected.refusal);
        return;
      }
      const v = verifyReleasePolicyV3(testCase.envelope, caseTrust, previous);
      expect({ sequence: v.sequence, policySha256: v.policySha256, tupleDigests: v.tuples.map((t) => t.tupleDigest),
        revokedTuples: v.revokedTuples, tcbGrace: v.tcbGrace ?? null, requireGcePzid: v.requireGcePzid ?? null }).toEqual(expected.ok);
    });
  }
});

describe("attestation cases", () => {
  const e = vectors.expectations;
  for (const testCase of vectors.attestationCases) {
    it(testCase.name, () => {
      const policy = releasePolicyV3GatewayPolicy(verifyReleasePolicyV3(testCase.envelope, trust), [e.origin]);
      const verdict = verifyGatewayAttestation(testCase.evidence as GatewayAttestationEvidence, { nonce: e.nonce, origin: e.origin,
        policy, now: e.nowMs, observedTlsSpkiSha256: e.observedTlsSpki, observedOnRetainedConnection: true,
        chainVerifier: { implementation: "vector-stub", verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" }) } });
      expect({ status: verdict.status, verificationLevel: verdict.verificationLevel, reason: verdict.reason,
        instanceIdentity: verdict.instanceIdentity, gceInstance: verdict.gceInstance,
        checks: verdict.checks.map((c) => [c.name, c.passed, c.required]) }).toEqual(testCase.expected);
    });
  }
});
