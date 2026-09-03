// Which AnonRouter confidential routes are currently OFFERED.
//
// A CONVENIENCE, AND NOT A SECURITY CONTROL. This exists so a caller who names a
// route AnonRouter has withheld gets a clear answer immediately, instead of a
// ticket mint failing with something that reads like a routing bug. It is not
// what protects them: every route still fetches fresh evidence and every verdict
// is still computed from that evidence, so a route missing from this file is not
// thereby trusted and a route listed in it is not thereby verified.
//
// The distinction matters for how this file may be used. It may refuse early. It
// may NEVER be consulted to decide that something verified — that would move a
// trust decision from evidence the caller checked to a list the service shipped,
// which is the whole thing this package exists not to do.
//
// Generated from AnonRouter's `config/confidential-route-policy.json`; synced by
// `scripts/sync-shared.mjs` and gated by `scripts/check-parity.mjs`.

import policy from "./confidential-route-policy.json" with { type: "json" };

export interface OfferedRouteKey {
  provider: string;
  model: string;
  privacyClass: string;
}

interface WithheldRoute extends OfferedRouteKey {
  classification: string;
}

const doc = policy as unknown as {
  version: string;
  verified: OfferedRouteKey[];
  withheld: WithheldRoute[];
  governedProviders: Record<string, { privacyClass: string }>;
};

const key = (provider: string, model: string, privacyClass: string) =>
  `${provider} ${model} ${privacyClass}`;

const VERIFIED = new Set(doc.verified.map((r) => key(r.provider, r.model, r.privacyClass)));
const WITHHELD = new Map(doc.withheld.map((r) => [key(r.provider, r.model, r.privacyClass), r]));

export const CONFIDENTIAL_ROUTE_POLICY_VERSION = doc.version;
export const OFFERED_CONFIDENTIAL_ROUTES: readonly OfferedRouteKey[] = doc.verified;
export const WITHHELD_CONFIDENTIAL_ROUTES: readonly WithheldRoute[] = doc.withheld;

/**
 * Whether AnonRouter currently withholds this exact route.
 *
 * Keyed on provider + canonical model + privacy class, because none of the three
 * is redundant: one provider serves the same model under two classes, and one
 * model is served by several providers. A rule keyed on any two of them would
 * refuse a route nobody decided to refuse.
 *
 * Allowlist semantics within a governed (provider, class) pair, so a route the
 * service adds tomorrow is not assumed offered. Outside a governed pair this
 * answers false: the SDK does not invent policy for providers the service has
 * not spoken about.
 */
export function isRouteWithheldByService(
  provider: string,
  model: string,
  privacyClass: string
): boolean {
  const governed = doc.governedProviders[provider];
  if (!governed || governed.privacyClass !== privacyClass) return false;
  return !VERIFIED.has(key(provider, model, privacyClass));
}

/** The recorded classification, when the policy names one. */
export function withheldRouteClassification(
  provider: string,
  model: string,
  privacyClass: string
): string | null {
  return WITHHELD.get(key(provider, model, privacyClass))?.classification ?? null;
}

/** The message the SDK refuses with. Names the route, says nothing was sent, and
 *  does not suggest retrying — retrying is how a caller comes to believe a
 *  withheld route is merely flaky. */
export function withheldRouteMessage(provider: string, model: string, privacyClass: string): string {
  const classification = withheldRouteClassification(provider, model, privacyClass);
  return `AnonRouter is not currently offering the ${provider} ${privacyClass} route for ${model}`
    + (classification ? ` (${classification})` : "")
    + ". Nothing was sent. This is a service-side decision recorded in the shipped route policy, "
    + "not a transient failure, so retrying will not change it. Verify it yourself with "
    + "verifyRoute() if you want the evidence, or choose another route.";
}
