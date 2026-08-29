// Guards on the pins this package actually ships.
//
// The failure these prevent is a candidate pin being promoted to `published`
// without the review that promotion is supposed to represent. A promotion should
// be a deliberate act that also updates this file, not something that slips in
// with an unrelated edit.

import { describe, expect, it } from "vitest";
import { gatewayPolicyRegistry, pinnedGatewayPolicyFor } from "../src/gateway/policy.js";

describe("shipped gateway pins", () => {
  const registry = gatewayPolicyRegistry();

  it("parses every shipped entry under the same required-switch rules as a user policy", () => {
    // If a shipped entry could parse under looser rules than a hand-written one,
    // the strictness would be decorative.
    expect(registry.length).toBeGreaterThan(0);
    for (const entry of registry) {
      expect(entry.policy.origins.length).toBeGreaterThan(0);
      expect(entry.policy.acceptableTcbStatuses.length).toBeGreaterThan(0);
      expect(typeof entry.policy.requireEvidenceExpiry).toBe("boolean");
      expect(entry.reviewedAt).not.toBe("");
      expect(entry.notes.length).toBeGreaterThan(40);
    }
  });

  it("ships NO published pins today, so the default path resolves nothing", () => {
    // As of the 2026-08-29 review the only entry is a candidate whose refresh was
    // examined and rejected: its measurement identity is corroborated but the
    // origin is covered only by preproduction records. Promoting it must be a
    // deliberate act that updates this assertion too.
    const published = registry.filter((e) => e.status === "published");
    expect(published).toEqual([]);
    for (const entry of registry) {
      for (const origin of entry.policy.origins) {
        expect(pinnedGatewayPolicyFor(origin), `${origin} must not resolve by default`).toBeUndefined();
      }
    }
  });

  it("resolves a candidate only behind the explicit opt-in", () => {
    for (const entry of registry.filter((e) => e.status === "candidate")) {
      const origin = entry.policy.origins[0];
      expect(pinnedGatewayPolicyFor(origin)).toBeUndefined();
      expect(pinnedGatewayPolicyFor(origin, { allowCandidate: true })?.status).toBe("candidate");
    }
  });

  it("resolves nothing for an origin it does not pin, rather than falling back", () => {
    expect(pinnedGatewayPolicyFor("https://not-pinned.example", { allowCandidate: true })).toBeUndefined();
    expect(pinnedGatewayPolicyFor("not-a-url", { allowCandidate: true })).toBeUndefined();
  });
});
