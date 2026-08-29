// Regression guard for a silent-downgrade bug.
//
// The Chutes certificate-possession checks degrade to advisory when node:crypto is
// absent, which is correct in a browser. It is NOT correct in Node: there the
// checks must be required, or a verdict could read "ok" while certificate
// possession, certificate freshness, and the signed-body bindings went unchecked.
//
// The capability has to resolve SYNCHRONOUSLY, because verifyRawEvidence is pure
// and cannot await. These tests fail if that ever regresses to "only after an
// explicit async opt-in".

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

const chutesCase = (() => {
  const doc = JSON.parse(
    readFileSync(new URL("../../../shared/vectors/attestation.json", import.meta.url), "utf8")
  ) as { cases: Array<Record<string, any>> };
  const found = doc.cases.find((c) => c.name === "chutes valid evidence");
  if (!found) throw new Error("shared vectors are missing the chutes valid case");
  return found;
})();

describe("node:crypto capability in a Node runtime", () => {
  it("resolves without an explicit opt-in call", async () => {
    vi.resetModules();
    const { verifyCertPossession } = await import("../src/verify/crypto.js");

    // Deliberately malformed inputs. What is asserted is that the capability
    // reports itself AVAILABLE, not that this certificate verifies: an
    // unavailable capability is what silently relaxes the required checks.
    const result = verifyCertPossession(
      new Uint8Array([1, 2, 3]),
      new Uint8Array([4, 5, 6]),
      new Uint8Array([7, 8, 9]),
      Date.parse("2026-01-01T00:00:00Z")
    );

    expect(result.available).toBe(true);
    expect(result.possessionVerified).toBe(false);
  });

  it("keeps the Chutes certificate checks REQUIRED, not advisory", async () => {
    vi.resetModules();
    const { verifyRawEvidence } = await import("../src/index.js");

    const verdict = verifyRawEvidence("chutes", chutesCase.rawEvidence, {
      upstreamModel: chutesCase.upstreamModel,
      nonce: chutesCase.nonce,
      endpointIdentity: chutesCase.endpointIdentity,
      privacyModality: chutesCase.privacyModality,
      now: chutesCase.nowMs
    });

    const certChecks = verdict.checks.filter((c) =>
      c.name.endsWith("_certificate_spki_binding")
      || c.name.endsWith("_certificate_freshness")
      || c.name.endsWith("_key_possession")
    );

    expect(certChecks.length).toBeGreaterThan(0);
    for (const check of certChecks) {
      expect(check.required, `${check.name} must be required in Node`).toBe(true);
      expect(check.passed, `${check.name} must pass on valid evidence`).toBe(true);
    }
    expect(verdict.status).toBe("ok");
  });
});
