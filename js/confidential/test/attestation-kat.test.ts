// Verdict known-answer parity: run every case in shared/vectors/attestation.json
// through the verifier and assert the whole verdict, not just its status.
//
// The Python suite loads the same file and asserts the same fields, so a verifier
// change that lands in only one language fails CI. Regenerate the vectors with
// `npm run gen:attestation-vectors` and review the diff: a changed expectation is a
// changed security decision.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyRawEvidence, type VerifiableProvider } from "../src/index.js";

interface AttestationCase {
  name: string;
  provider: string;
  upstreamModel: string;
  endpointIdentity: string;
  privacyModality: "e2ee" | "tee";
  nonce: string;
  nowMs: number;
  rawEvidence: unknown;
  expected: {
    status: string;
    verificationLevel: string;
    reason: string | null;
    supportsClientOpaqueE2ee: boolean;
    failedRequiredChecks: string[];
    failedAdvisoryChecks: string[];
  };
}

const doc = JSON.parse(
  readFileSync(new URL("../../../shared/vectors/attestation.json", import.meta.url), "utf8")
) as { cases: AttestationCase[] };

describe("verifier verdict KAT parity (shared/vectors/attestation.json)", () => {
  it("ships cases for every verifiable E2EE provider", () => {
    const providers = new Set(doc.cases.map((c) => c.provider));
    expect(providers).toContain("venice");
    expect(providers).toContain("chutes");
    expect(providers).toContain("near-ai");
    expect(doc.cases.length).toBeGreaterThan(0);
  });

  for (const testCase of doc.cases) {
    it(testCase.name, () => {
      const verdict = verifyRawEvidence(testCase.provider as VerifiableProvider, testCase.rawEvidence, {
        upstreamModel: testCase.upstreamModel,
        nonce: testCase.nonce,
        endpointIdentity: testCase.endpointIdentity,
        privacyModality: testCase.privacyModality,
        now: testCase.nowMs
      });

      expect(verdict.status).toBe(testCase.expected.status);
      expect(verdict.verification_level).toBe(testCase.expected.verificationLevel);
      expect(verdict.reason).toBe(testCase.expected.reason);
      expect(verdict.supports_client_opaque_e2ee).toBe(testCase.expected.supportsClientOpaqueE2ee);
      expect(verdict.checks.filter((c) => c.required && !c.passed).map((c) => c.name))
        .toEqual(testCase.expected.failedRequiredChecks);
      // Advisory failures are pinned too. They do not change the status, which is
      // why they need a gate of their own: a named gap that quietly stopped being
      // reported looks exactly like a route that never had one.
      expect(verdict.checks.filter((c) => !c.required && !c.passed).map((c) => c.name))
        .toEqual(testCase.expected.failedAdvisoryChecks);
    });
  }

  it("never claims hardware-verified on any case", () => {
    for (const testCase of doc.cases) {
      expect(testCase.expected.verificationLevel).not.toBe("hardware-verified");
    }
  });
});
