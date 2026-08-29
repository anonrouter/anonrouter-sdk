// The stable verdict contract: states, ordering, and the cross-hop route binding.
//
// These are the assertions that make `verifyRoute` safe to build on. The states
// must stay ordered, a skipped hop must never read as a passing one, and two
// honestly-attested parties on the WRONG route must still come out untrusted.

import { describe, expect, it } from "vitest";
import {
  assembleRouteVerdict,
  gatewayHopVerdict,
  hopNotRequested,
  hopUnavailable,
  providerHopVerdict,
  type RouteHopVerdict
} from "../src/verify/route.js";
import {
  atLeast,
  describeState,
  isTrusted,
  stateForLevel,
  TRUSTED_STATES,
  type RouteVerificationState
} from "../src/verify/state.js";
import type { NormalizedVerdict } from "../src/verify/types.js";
import type { GatewayVerificationResult } from "../src/gateway/verify.js";

const ROUTE = { provider: "venice", model: "venice-uncensored", privacyModality: "e2ee" as const };

function hop(state: RouteVerificationState, requested = true): RouteHopVerdict {
  return { requested, state, meaning: describeState(state), reason: null, failedChecks: [], advisoryGaps: [] };
}

describe("verification states", () => {
  it("maps every internal level onto a state without inflating it", () => {
    expect(stateForLevel("hardware-verified")).toBe("hardware_verified");
    expect(stateForLevel("provider-attested")).toBe("cryptographically_checked");
    expect(stateForLevel("sdk-verified")).toBe("policy_matched");
    expect(stateForLevel("unverified")).toBe("untrusted");
    expect(stateForLevel("unsupported")).toBe("unavailable");
  });

  it("treats an unrecognized level as untrusted rather than guessing upward", () => {
    expect(stateForLevel("something-new")).toBe("untrusted");
    expect(stateForLevel("")).toBe("untrusted");
  });

  it("orders the trusted states strongest first", () => {
    expect(atLeast("hardware_verified", "cryptographically_checked")).toBe(true);
    expect(atLeast("cryptographically_checked", "policy_matched")).toBe(true);
    expect(atLeast("policy_matched", "cryptographically_checked")).toBe(false);
    expect(atLeast("hardware_verified", "hardware_verified")).toBe(true);
  });

  it("never lets a failure state satisfy a threshold, including its own", () => {
    for (const failure of ["untrusted", "unavailable"] as const) {
      for (const required of TRUSTED_STATES) {
        expect(atLeast(failure, required)).toBe(false);
      }
      // The trap this guards: `atLeast("untrusted","untrusted")` returning true
      // would make `require: "untrusted"` read as a satisfied requirement.
      expect(atLeast(failure, failure)).toBe(false);
      expect(isTrusted(failure)).toBe(false);
    }
  });

  it("gives every state a distinct, non-empty meaning", () => {
    const all: RouteVerificationState[] = [
      "hardware_verified", "cryptographically_checked", "policy_matched", "untrusted", "unavailable"
    ];
    const meanings = all.map(describeState);
    expect(new Set(meanings).size).toBe(all.length);
    for (const m of meanings) expect(m.length).toBeGreaterThan(20);
  });
});

describe("route verdict assembly", () => {
  it("takes the WEAKEST requested hop, never the strongest", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hop("hardware_verified"),
      provider: hop("policy_matched")
    });
    expect(verdict.overallState).toBe("policy_matched");
    expect(verdict.trusted).toBe(true);
  });

  it("ignores a hop nobody asked about when ranking, and says it was skipped", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hopNotRequested(),
      provider: hop("cryptographically_checked")
    });
    expect(verdict.overallState).toBe("cryptographically_checked");
    expect(verdict.gateway.requested).toBe(false);
    // trusted is true, but only because the caller never asked about hop 1.
    // gateway.requested is what stops that being misread.
    expect(verdict.trusted).toBe(true);
  });

  it("is untrusted when a requested hop is unavailable", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hopUnavailable("this deployment does not expose gateway attestation"),
      provider: hop("cryptographically_checked")
    });
    expect(verdict.overallState).toBe("unavailable");
    expect(verdict.trusted).toBe(false);
    expect(verdict.reason).toContain("gateway");
  });

  it("is unavailable when no hop was requested at all", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hopNotRequested(),
      provider: hopNotRequested()
    });
    expect(verdict.overallState).toBe("unavailable");
    expect(verdict.trusted).toBe(false);
  });

  it("states plainly whether AnonRouter can read the content", () => {
    expect(assembleRouteVerdict({
      route: ROUTE, gateway: hopNotRequested(), provider: hop("cryptographically_checked")
    }).contentVisibleToAnonRouter).toBe(false);

    expect(assembleRouteVerdict({
      route: { ...ROUTE, privacyModality: "tee" },
      gateway: hopNotRequested(),
      provider: hop("cryptographically_checked")
    }).contentVisibleToAnonRouter).toBe(true);
  });
});

describe("cross-hop route binding", () => {
  it("refuses two perfectly-attested hops that served the WRONG provider", () => {
    // This is the case neither hop verifier can see: each one only ever gets its
    // own evidence, so a gateway attesting itself honestly while routing to a
    // different provider is invisible until the hops are cross-bound.
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hop("hardware_verified"),
      provider: hop("hardware_verified"),
      gatewayEcho: { provider: "chutes" }
    });
    expect(verdict.trusted).toBe(false);
    expect(verdict.overallState).toBe("untrusted");
    expect(verdict.bindingMismatches).toHaveLength(1);
    expect(verdict.bindingMismatches[0]).toMatchObject({
      field: "provider", expected: "venice", observed: "chutes", source: "gateway"
    });
    expect(verdict.reason).toContain("route_binding_mismatch");
  });

  it("refuses a silent downgrade from e2ee to tee", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hop("hardware_verified"),
      provider: hop("hardware_verified"),
      gatewayEcho: { privacyClass: "tee" }
    });
    expect(verdict.trusted).toBe(false);
    expect(verdict.bindingMismatches[0].field).toBe("privacy_modality");
  });

  it("refuses an attested model that is not the one the caller pinned", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hopNotRequested(),
      provider: hop("cryptographically_checked"),
      expectedUpstreamModel: "e2ee-gpt-oss-20b-p",
      attestedUpstreamModel: "some-other-model"
    });
    expect(verdict.trusted).toBe(false);
    expect(verdict.bindingMismatches[0]).toMatchObject({ field: "model", source: "provider-evidence" });
  });

  it("does not invent a model mismatch when the caller pinned nothing", () => {
    // Without a caller expectation there is no disagreement to detect: the
    // gateway's mapping is the only statement of it, and flagging that would
    // make every default call fail.
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hopNotRequested(),
      provider: hop("cryptographically_checked"),
      attestedUpstreamModel: "e2ee-gpt-oss-20b-p"
    });
    expect(verdict.bindingMismatches).toHaveLength(0);
    expect(verdict.trusted).toBe(true);
  });

  it("keeps an echo that AGREES from producing a mismatch", () => {
    const verdict = assembleRouteVerdict({
      route: ROUTE,
      gateway: hop("cryptographically_checked"),
      provider: hop("cryptographically_checked"),
      gatewayEcho: { provider: "venice", privacyClass: "e2ee" },
      expectedUpstreamModel: "m", attestedUpstreamModel: "m"
    });
    expect(verdict.bindingMismatches).toHaveLength(0);
    expect(verdict.trusted).toBe(true);
  });
});

describe("hop projection", () => {
  it("projects a failed gateway result to untrusted and lists the failed checks", () => {
    const result = {
      status: "failed",
      verificationLevel: "unverified",
      reason: "release_pinned",
      checks: [
        { name: "quote_parsed", passed: true, required: true },
        { name: "release_pinned", passed: false, required: true },
        { name: "evidence_recent", passed: false, required: false }
      ],
      binding: null, appCompose: null, measurements: null, tcbStatus: null,
      policySource: "t", policyVersion: "1", verifiedAtMs: 0
    } as unknown as GatewayVerificationResult;
    const projected = gatewayHopVerdict(result);
    expect(projected.state).toBe("untrusted");
    expect(projected.failedChecks).toEqual(["release_pinned"]);
    expect(projected.advisoryGaps).toEqual(["evidence_recent"]);
  });

  it("never projects an ok status onto a state stronger than its level", () => {
    const result = {
      status: "ok", verificationLevel: "provider-attested", reason: null, checks: []
    } as unknown as GatewayVerificationResult;
    expect(gatewayHopVerdict(result).state).toBe("cryptographically_checked");
  });

  it("projects a provider verdict the same way", () => {
    const verdict = {
      status: "ok", verification_level: "sdk-verified", reason: null, checks: []
    } as unknown as NormalizedVerdict;
    expect(providerHopVerdict(verdict).state).toBe("policy_matched");
  });
});
