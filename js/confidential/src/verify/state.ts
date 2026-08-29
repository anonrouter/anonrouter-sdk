// The stable, public verdict contract.
//
// `VerificationLevel` (verify/types.ts) is the internal, provider-neutral level
// that mirrors what AnonRouter's gateway computes server-side. It is useful for
// comparing our verdict to theirs, but it is a poor thing to build a product on:
// "provider-attested" and "sdk-verified" say WHO attested rather than WHAT was
// actually checked, and a reader has to already know the trust model to rank them.
//
// `RouteVerificationState` is the contract this SDK promises to keep stable. Each
// state answers one question: how much did we actually establish? They are
// strictly ordered, so a caller can write `state >= "cryptographically_checked"`
// via `atLeast()` and get a decision that stays correct as new states are added
// below the one they required.

/**
 * How much a hop actually established, strongest first.
 *
 *   hardware_verified        Everything cryptographically_checked establishes,
 *                            AND the quote's signature chained to the silicon
 *                            vendor's roots with an acceptable TCB status. This
 *                            is the only state that says the evidence came from
 *                            genuine, current hardware.
 *
 *   cryptographically_checked
 *                            Every binding was recomputed and held: the caller's
 *                            nonce is inside the quote, the event log replays to
 *                            the hardware registers, each measured digest commits
 *                            to the payload printed beside it, and the identity
 *                            matched local pins. The quote's signature was NOT
 *                            chained to vendor roots, so this proves the evidence
 *                            is internally consistent and matches what you pinned,
 *                            not that any of it came from real silicon.
 *
 *   policy_matched           The evidence's CLAIMED identity matched local pins,
 *                            but the cryptographic binding of that identity to
 *                            hardware was not established in-process. This is the
 *                            honest state for a verdict that rests on a document
 *                            somebody else produced, such as a vendor SDK's
 *                            verification report relayed through the gateway.
 *
 *   untrusted                A required check failed. Never treat as partial
 *                            success: a single required failure means the whole
 *                            hop is unestablished.
 *
 *   unavailable              The hop could not be attempted at all. The endpoint
 *                            is absent, or nothing is pinned for this origin, so
 *                            there was no evidence to check. Distinct from
 *                            `untrusted` on purpose: "we could not look" and "we
 *                            looked and it failed" are different facts, and
 *                            collapsing them hides which one you are in.
 */
export type RouteVerificationState =
  | "hardware_verified"
  | "cryptographically_checked"
  | "policy_matched"
  | "untrusted"
  | "unavailable";

/**
 * Rank, strongest first. `unavailable` and `untrusted` share the bottom because
 * neither is a basis for proceeding; they are distinguished by MEANING, not by
 * strength, and no caller should ever prefer one over the other numerically.
 */
const RANK: Record<RouteVerificationState, number> = {
  hardware_verified: 4,
  cryptographically_checked: 3,
  policy_matched: 2,
  untrusted: 0,
  unavailable: 0
};

/** The states a caller may reasonably require. Excludes the two failure states. */
export const TRUSTED_STATES: readonly RouteVerificationState[] = [
  "hardware_verified",
  "cryptographically_checked",
  "policy_matched"
];

/**
 * True when `state` is at least as strong as `required`.
 *
 * Use this rather than comparing strings or reimplementing the order: it is the
 * one place the ranking lives, so a caller's threshold keeps meaning the same
 * thing if a state is ever inserted into the middle of the scale.
 */
export function atLeast(state: RouteVerificationState, required: RouteVerificationState): boolean {
  // A failure state never satisfies a threshold, including a threshold that is
  // itself a failure state. `atLeast("untrusted", "untrusted")` returning true
  // would let `require: "untrusted"` read as a satisfied requirement.
  if (RANK[required] === 0) return false;
  return RANK[state] >= RANK[required];
}

/** Whether this state means the hop was established at all. */
export function isTrusted(state: RouteVerificationState): boolean {
  return RANK[state] > 0;
}

/**
 * Project the internal `VerificationLevel` onto the public state.
 *
 * The mapping is deliberately lossy in one direction only: several internal
 * levels can collapse into one state, but no state can be reached from a weaker
 * level than it represents.
 *
 *   hardware-verified  -> hardware_verified
 *   provider-attested  -> cryptographically_checked   (bindings recomputed, no vendor chain)
 *   sdk-verified       -> policy_matched              (rests on a document we did not produce)
 *   unverified         -> untrusted                   (a required check failed)
 *   unsupported        -> unavailable                 (nothing to check)
 */
export function stateForLevel(level: string): RouteVerificationState {
  switch (level) {
    case "hardware-verified":
      return "hardware_verified";
    case "provider-attested":
      return "cryptographically_checked";
    case "sdk-verified":
      return "policy_matched";
    case "unsupported":
      return "unavailable";
    case "unverified":
      return "untrusted";
    default:
      // An unrecognized level is not a reason to guess upward.
      return "untrusted";
  }
}

/** A one-line, user-facing explanation of what a state does and does not prove. */
export function describeState(state: RouteVerificationState): string {
  switch (state) {
    case "hardware_verified":
      return "The quote's signature chained to the silicon vendor's roots with an acceptable TCB, and every binding held.";
    case "cryptographically_checked":
      return "Every binding was recomputed and held against your pins, but the quote's signature was not chained to vendor roots, so this is not proof of genuine silicon.";
    case "policy_matched":
      return "The claimed identity matched your pins, but its binding to hardware was not established in this process.";
    case "untrusted":
      return "A required check failed. Do not proceed on this route.";
    case "unavailable":
      return "This hop could not be checked at all: no endpoint, or nothing pinned for this origin.";
  }
}
