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

  it("ships the manifest-bound production pin and resolves it by default", () => {
    // Pin the source digest here too, so changing the default trust anchor is
    // always a deliberate test update rather than a quiet edit to a data file.
    const published = registry.filter((e) => e.status === "published");
    expect(published).toHaveLength(1);
    expect(published[0]?.policy.source).toBe(
      "anonrouter-release-manifest-sha256:303e61fb7c89a6b7079c489a58955aa9cc76b1e09e03b777f133cdf525f34c8d"
    );
    // The pin must name the live content plane, not a superseded one. These are
    // the two values a stale refresh gets wrong first.
    expect(published[0]?.policy.composeHashes).toEqual([
      "9e369fb632fb3b98c604b0c8457448ce88a29077c1766948b87fb6673db494fb"
    ]);
    expect(published[0]?.policy.releaseIds).toEqual(["anonrouter-tee@xl-4c9b984"]);
    for (const entry of published) {
      for (const origin of entry.policy.origins) {
        expect(pinnedGatewayPolicyFor(origin)?.status, `${origin} must resolve by default`).toBe("published");
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
