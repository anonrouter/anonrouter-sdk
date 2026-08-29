"""The stable, public verdict contract.

``VerificationLevel`` (verify/types.py) is the internal, provider-neutral level
that mirrors what AnonRouter's gateway computes server-side. It is useful for
comparing our verdict to theirs, but it is a poor thing to build a product on:
"provider-attested" and "sdk-verified" say WHO attested rather than WHAT was
actually checked, and a reader has to already know the trust model to rank them.

``RouteVerificationState`` is the contract this SDK promises to keep stable. Each
state answers one question: how much did we actually establish? They are strictly
ordered, so a caller can write ``at_least(state, "cryptographically_checked")``
and get a decision that stays correct as states are added below their threshold.

Mirrors ``js/confidential/src/verify/state.ts`` exactly, including the ordering
and the refusal to let a failure state satisfy any threshold.
"""

from __future__ import annotations

from typing import Literal

#: How much a hop actually established, strongest first.
#:
#: ``hardware_verified``
#:     Everything ``cryptographically_checked`` establishes, AND the quote's
#:     signature chained to the silicon vendor's roots with an acceptable TCB
#:     status. The only state that says the evidence came from genuine, current
#:     hardware.
#:
#: ``cryptographically_checked``
#:     Every binding was recomputed and held: the caller's nonce is inside the
#:     quote, the event log replays to the hardware registers, each measured
#:     digest commits to the payload printed beside it, and the identity matched
#:     local pins. The quote's signature was NOT chained to vendor roots, so this
#:     proves the evidence is internally consistent and matches what you pinned,
#:     not that any of it came from real silicon.
#:
#: ``policy_matched``
#:     The evidence's CLAIMED identity matched local pins, but the cryptographic
#:     binding of that identity to hardware was not established in-process. The
#:     honest state for a verdict resting on a document somebody else produced.
#:
#: ``untrusted``
#:     A required check failed. Never a partial success.
#:
#: ``unavailable``
#:     The hop could not be attempted at all. Distinct from ``untrusted`` on
#:     purpose: "we could not look" and "we looked and it failed" are different
#:     facts, and collapsing them hides which one you are in.
RouteVerificationState = Literal[
    "hardware_verified",
    "cryptographically_checked",
    "policy_matched",
    "untrusted",
    "unavailable",
]

#: Rank, strongest first. ``unavailable`` and ``untrusted`` share the bottom
#: because neither is a basis for proceeding; they are distinguished by MEANING,
#: not by strength, and no caller should prefer one over the other numerically.
_RANK: dict[str, int] = {
    "hardware_verified": 4,
    "cryptographically_checked": 3,
    "policy_matched": 2,
    "untrusted": 0,
    "unavailable": 0,
}

#: The states a caller may reasonably require. Excludes the two failure states.
TRUSTED_STATES: tuple[str, ...] = (
    "hardware_verified",
    "cryptographically_checked",
    "policy_matched",
)


def at_least(state: str, required: str) -> bool:
    """True when ``state`` is at least as strong as ``required``.

    Use this rather than comparing strings or reimplementing the order: it is the
    one place the ranking lives, so a caller's threshold keeps meaning the same
    thing if a state is ever inserted into the middle of the scale.
    """
    # A failure state never satisfies a threshold, including a threshold that is
    # itself a failure state: ``at_least("untrusted", "untrusted")`` returning
    # True would let ``require="untrusted"`` read as a satisfied requirement.
    if _RANK.get(required, 0) == 0:
        return False
    return _RANK.get(state, 0) >= _RANK[required]


def is_trusted(state: str) -> bool:
    """Whether this state means the hop was established at all."""
    return _RANK.get(state, 0) > 0


def state_for_level(level: str) -> str:
    """Project the internal ``VerificationLevel`` onto the public state.

    Lossy in one direction only: several levels can collapse into one state, but
    no state can be reached from a weaker level than it represents.
    """
    if level == "hardware-verified":
        return "hardware_verified"
    if level == "provider-attested":
        return "cryptographically_checked"
    if level == "sdk-verified":
        return "policy_matched"
    if level == "unsupported":
        return "unavailable"
    # "unverified", and anything unrecognized. An unknown level is not a reason
    # to guess upward.
    return "untrusted"


def describe_state(state: str) -> str:
    """A one-line explanation of what a state does and does not prove."""
    if state == "hardware_verified":
        return (
            "The quote's signature chained to the silicon vendor's roots with an "
            "acceptable TCB, and every binding held."
        )
    if state == "cryptographically_checked":
        return (
            "Every binding was recomputed and held against your pins, but the quote's "
            "signature was not chained to vendor roots, so this is not proof of genuine silicon."
        )
    if state == "policy_matched":
        return (
            "The claimed identity matched your pins, but its binding to hardware was "
            "not established in this process."
        )
    if state == "untrusted":
        return "A required check failed. Do not proceed on this route."
    return "This hop could not be checked at all: no endpoint, or nothing pinned for this origin."
