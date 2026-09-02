// verifyRoute(): the stable two-hop verdict.
//
// This is the API most callers should use, and the one whose shape this SDK
// promises to keep. It answers a single question honestly:
//
//   "For the route I asked for, what did I actually establish about the party
//    that ROUTED my request, and about the party that RAN it?"
//
// Three things make this more than a wrapper around the two hop verifiers.
//
// 1. It CROSS-BINDS the hops to one route. Each hop verifier is only ever handed
//    the evidence for its own side, so neither can notice that the gateway
//    attested itself honestly while serving a different provider, model, or
//    privacy class than the caller asked for. That disagreement is invisible to
//    both hops individually and is exactly what a routing substitution looks
//    like, so it is checked here and nowhere else.
//
// 2. It reports STATES, not levels. See verify/state.ts: the states say what was
//    established rather than who asserted it, and they are ordered so a caller
//    can set a threshold that keeps meaning the same thing over time.
//
// 3. It never collapses "did not check" into "checked and passed". A hop that
//    was not requested, or that could not be reached, is `unavailable`, which is
//    a different fact from `untrusted`, and `overallState` is only ever as strong
//    as the WEAKEST hop the caller asked for.

import type { NormalizedVerdict } from "./types.js";
import {
  atLeast,
  describeState,
  isTrusted,
  stateForLevel,
  type RouteVerificationState
} from "./state.js";
import type { GatewayVerificationResult } from "../gateway/verify.js";

/**
 * How the route's privacy modality was established.
 *
 * It is a PER-ROUTE catalog fact, not a property of the provider: AnonRouter
 * publishes `private`, `e2ee` and `tee` rows for the same provider, and the same
 * model id can be served by one provider as `tee` and another as `e2ee`. So the
 * modality has to come from the route that was actually served, and the client
 * has to be able to say which of the three ways it learned it.
 */
export type PrivacyModalitySource =
  /** The caller pinned it, and any disagreement is a binding mismatch. */
  | "caller-pinned"
  /** Read from the class the gateway bound into the single-use ticket at mint. */
  | "gateway-attested"
  /** Nobody stated it. The verdict must then assume the WEAKER privacy claim. */
  | "unestablished";

/** What the caller asked to be routed to. Every hop is bound back to this. */
export interface RequestedRoute {
  provider: string;
  model: string;
  /** Expected privacy modality. `e2ee` means the content must stay opaque to AnonRouter. */
  privacyModality: "tee" | "e2ee";
  /** Where `privacyModality` came from. Absent is read as `unestablished`. */
  privacyModalitySource?: PrivacyModalitySource;
}

/** One hop's outcome in the stable contract. */
export interface RouteHopVerdict {
  /** Whether this call asked to establish this hop at all. */
  requested: boolean;
  state: RouteVerificationState;
  /** Human-readable statement of what this state does and does not prove. */
  meaning: string;
  /** The first unmet requirement, or null. Sanitized and content-free. */
  reason: string | null;
  /** Names of every required check that failed, in order. */
  failedChecks: string[];
  /** Names of checks that did not pass but were advisory: known, unclosed gaps. */
  advisoryGaps: string[];
}

/** A disagreement between what was asked for and what a hop attested. */
export interface RouteBindingMismatch {
  /**
   * `requested_model` is the CATALOG id the caller named; `model` is the
   * provider-native upstream id the evidence attested. They are separate
   * bindings because a substitution can move either one on its own: serving a
   * different catalog model leaves the upstream id internally consistent, and
   * serving different weights under the same catalog id leaves the catalog id
   * intact.
   */
  field: "provider" | "requested_model" | "model" | "privacy_modality";
  expected: string;
  observed: string;
  /** Which side reported the observed value. */
  source: "gateway" | "provider-evidence";
}

export interface RouteVerdict {
  route: RequestedRoute;
  /**
   * The weakest state across every hop the caller requested, plus the route
   * binding. This is the number to gate on. It is never stronger than the
   * weakest thing you asked to establish.
   */
  overallState: RouteVerificationState;
  /** Convenience: `isTrusted(overallState)` and no binding mismatches. */
  trusted: boolean;
  /** The first reason the route is not fully established, or null. */
  reason: string | null;
  /** Hop 1: AnonRouter's own confidential routing plane. */
  gateway: RouteHopVerdict;
  /** Hop 2: the downstream provider route. */
  provider: RouteHopVerdict;
  /**
   * Disagreements between the requested route and what a hop attested. ANY entry
   * here forces `trusted: false` and `overallState: "untrusted"`, regardless of
   * how strong the individual hops were: two honestly-attested parties on the
   * wrong route is still the wrong route.
   */
  bindingMismatches: RouteBindingMismatch[];
  /**
   * True on a `tee` route: AnonRouter's relay handles your PLAINTEXT in order to
   * route and meter it. False on `e2ee`, where the relay only ever holds
   * ciphertext.
   *
   * WHAT THIS DOES AND DOES NOT MEAN. It is not "AnonRouter reads your prompts".
   * On the production confidential origin the relay runs inside an attested Intel
   * TDX CVM and terminates TLS in-enclave (the shipped policy makes
   * `transport_terminates_in_tee` and `tls_certificate_bound_to_quote` required
   * checks), so plaintext never reaches ordinary AnonRouter infrastructure and no
   * operator can read it out of a running host.
   *
   * The difference this flag marks is about the TRUST SET, not about exposure to
   * normal servers:
   *
   *   tee    the plaintext is processed by AnonRouter's relay SOFTWARE, inside
   *          the enclave. You are trusting the reviewed build. A build that
   *          changed to exfiltrate it would change the measurements, so hop 1
   *          would stop verifying -- cheating is DETECTABLE, provided you check.
   *   e2ee   the request is encrypted to the PROVIDER's attested key, so the
   *          relay holds ciphertext whatever code it is running. AnonRouter's
   *          build is not in your trust set at all.
   *
   * So `true` means "this route requires you to trust our attested build";
   * `false` means "it does not". The name predates the confidential data plane
   * and is kept for compatibility.
   *
   * WHEN THE MODALITY WAS NOT ESTABLISHED this is `true`, which is the weaker
   * privacy claim and therefore the honest one. `false` is a positive assertion
   * that AnonRouter's build is out of your trust set, and it is only ever made
   * from a caller pin or an attested route class — never from a provider name.
   * Read `route.privacyModalitySource` to tell the two apart.
   */
  contentVisibleToAnonRouter: boolean;
}

function hopFromChecks(
  requested: boolean,
  state: RouteVerificationState,
  reason: string | null,
  checks: ReadonlyArray<{ name: string; passed: boolean; required: boolean }>
): RouteHopVerdict {
  return {
    requested,
    state,
    meaning: describeState(state),
    reason,
    failedChecks: checks.filter((c) => c.required && !c.passed).map((c) => c.name),
    advisoryGaps: checks.filter((c) => !c.required && !c.passed).map((c) => c.name)
  };
}

/** A hop that was never asked about. Not a failure, and not a pass. */
export function hopNotRequested(): RouteHopVerdict {
  return {
    requested: false,
    state: "unavailable",
    meaning: describeState("unavailable"),
    reason: "not requested",
    failedChecks: [],
    advisoryGaps: []
  };
}

/** A hop that was asked about but could not be attempted (no endpoint, no pin). */
export function hopUnavailable(reason: string): RouteHopVerdict {
  return {
    requested: true,
    state: "unavailable",
    meaning: describeState("unavailable"),
    reason,
    failedChecks: [],
    advisoryGaps: []
  };
}

/** Project a gateway (hop 1) result into the stable contract. */
export function gatewayHopVerdict(result: GatewayVerificationResult): RouteHopVerdict {
  const state = result.status === "ok" ? stateForLevel(result.verificationLevel) : "untrusted";
  return hopFromChecks(true, state, result.reason, result.checks);
}

/** Project a provider (hop 2) verdict into the stable contract. */
export function providerHopVerdict(verdict: NormalizedVerdict): RouteHopVerdict {
  const state = verdict.status === "ok" ? stateForLevel(verdict.verification_level) : "untrusted";
  return hopFromChecks(true, state, verdict.reason, verdict.checks);
}

export interface AssembleRouteVerdictInput {
  route: RequestedRoute;
  gateway: RouteHopVerdict;
  provider: RouteHopVerdict;
  /**
   * What the gateway echoed about the route it served, when it said anything.
   *
   * These are the values the GATEWAY reported, never values the client derived.
   * Feeding a client-derived value back in here would make the comparison a
   * tautology that can never fire, which is the exact way a cross-binding check
   * dies quietly while still looking present.
   */
  gatewayEcho?: { provider?: string | null; model?: string | null; privacyClass?: string | null };
  /** The provider-native model the evidence attested, when known. */
  attestedUpstreamModel?: string | null;
  /** The upstream model the caller expected, when they pinned one. */
  expectedUpstreamModel?: string | null;
}

/**
 * Combine both hops and the route binding into one verdict.
 *
 * Pure and synchronous: the client fetches evidence and runs the hop verifiers,
 * then hands the results here. Keeping the combination logic free of I/O is what
 * lets the ordering rules be tested exhaustively.
 */
export function assembleRouteVerdict(input: AssembleRouteVerdictInput): RouteVerdict {
  const mismatches: RouteBindingMismatch[] = [];

  // Cross-binding. A hop verifier only sees its own evidence, so a gateway that
  // attests itself perfectly while serving a different provider is invisible to
  // both hops and visible only here.
  const echoedProvider = input.gatewayEcho?.provider;
  if (typeof echoedProvider === "string" && echoedProvider.length > 0 && echoedProvider !== input.route.provider) {
    mismatches.push({
      field: "provider",
      expected: input.route.provider,
      observed: echoedProvider,
      source: "gateway"
    });
  }
  // The catalog model. Distinct from the upstream check below: this one needs no
  // caller pin, because naming the model IS the request. A gateway that echoes a
  // different one has substituted the route, however sound the enclave is.
  const echoedModel = input.gatewayEcho?.model;
  if (typeof echoedModel === "string" && echoedModel.length > 0 && echoedModel !== input.route.model) {
    mismatches.push({
      field: "requested_model",
      expected: input.route.model,
      observed: echoedModel,
      source: "gateway"
    });
  }
  // Only bites when the caller PINNED a class: with no pin the route's modality
  // is read FROM this echo, so comparing them would be a tautology. That is not
  // a weakening — an unpinned caller has asserted nothing to contradict — and the
  // pin is how a caller says "I reviewed an e2ee route; refuse a tee one".
  const echoedClass = input.gatewayEcho?.privacyClass;
  if (typeof echoedClass === "string" && (echoedClass === "tee" || echoedClass === "e2ee")
    && echoedClass !== input.route.privacyModality) {
    mismatches.push({
      field: "privacy_modality",
      expected: input.route.privacyModality,
      observed: echoedClass,
      source: "gateway"
    });
  }
  // Only checked when the caller pinned an expectation. Without one there is no
  // disagreement to detect: the gateway's mapping IS the only statement of it.
  const expectedUpstream = input.expectedUpstreamModel;
  const attestedUpstream = input.attestedUpstreamModel;
  if (typeof expectedUpstream === "string" && expectedUpstream.length > 0
    && typeof attestedUpstream === "string" && attestedUpstream.length > 0
    && expectedUpstream !== attestedUpstream) {
    mismatches.push({
      field: "model",
      expected: expectedUpstream,
      observed: attestedUpstream,
      source: "provider-evidence"
    });
  }

  // The overall state is the weakest REQUESTED hop. A hop nobody asked about
  // cannot drag the verdict down, but it also cannot prop it up, which is why
  // `gateway.requested` stays on the result for the caller to read.
  const requestedHops = [input.gateway, input.provider].filter((hop) => hop.requested);
  const weakest = requestedHops.reduce<RouteVerificationState>((worst, hop) => {
    if (!isTrusted(hop.state)) return hop.state;
    if (!isTrusted(worst)) return worst;
    return atLeast(hop.state, worst) ? worst : hop.state;
  }, "hardware_verified");

  const overallState: RouteVerificationState = mismatches.length > 0
    ? "untrusted"
    : requestedHops.length === 0 ? "unavailable" : weakest;

  const reason = mismatches.length > 0
    ? `route_binding_mismatch: ${mismatches[0].field} expected ${mismatches[0].expected}, ${mismatches[0].source} reported ${mismatches[0].observed}`
    : !input.provider.requested && !input.gateway.requested
      ? "no hop was requested"
      : !isTrusted(input.provider.state) && input.provider.requested
        ? `provider: ${input.provider.reason ?? input.provider.state}`
        : !isTrusted(input.gateway.state) && input.gateway.requested
          ? `gateway: ${input.gateway.reason ?? input.gateway.state}`
          : null;

  return {
    route: { privacyModalitySource: "unestablished", ...input.route },
    overallState,
    trusted: isTrusted(overallState) && mismatches.length === 0,
    reason,
    gateway: input.gateway,
    provider: input.provider,
    bindingMismatches: mismatches,
    contentVisibleToAnonRouter: input.route.privacyModality === "tee"
  };
}
