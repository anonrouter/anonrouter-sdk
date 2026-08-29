"""Guards on the pins this package actually ships.

Mirrors ``js/confidential/test/shipped-pins.test.ts``. The failure these prevent
is a candidate pin being promoted to ``published`` without the review that
promotion is supposed to represent.
"""

from __future__ import annotations

from anonrouter_confidential.gateway.policy import (
    gateway_policy_registry,
    pinned_gateway_policy_for,
)


def test_parses_every_shipped_entry_under_the_same_rules_as_a_user_policy() -> None:
    registry = gateway_policy_registry()
    assert len(registry) > 0
    for entry in registry:
        assert entry.policy.origins
        assert entry.policy.acceptable_tcb_statuses
        assert isinstance(entry.policy.require_evidence_expiry, bool)
        assert entry.reviewed_at != ""
        assert len(entry.notes) > 40


def test_ships_no_published_pins_so_the_default_path_resolves_nothing() -> None:
    # As of the 2026-08-29 review the only entry is a candidate whose refresh was
    # examined and rejected: measurement identity corroborated, origin covered
    # only by preproduction records. Promoting it must update this assertion too.
    registry = gateway_policy_registry()
    assert [e for e in registry if e.status == "published"] == []
    for entry in registry:
        for origin in entry.policy.origins:
            assert pinned_gateway_policy_for(origin) is None, f"{origin} must not resolve by default"


def test_resolves_a_candidate_only_behind_the_explicit_opt_in() -> None:
    for entry in (e for e in gateway_policy_registry() if e.status == "candidate"):
        origin = entry.policy.origins[0]
        assert pinned_gateway_policy_for(origin) is None
        resolved = pinned_gateway_policy_for(origin, allow_candidate=True)
        assert resolved is not None
        assert resolved.status == "candidate"


def test_resolves_nothing_for_an_unpinned_origin_rather_than_falling_back() -> None:
    assert pinned_gateway_policy_for("https://not-pinned.example", allow_candidate=True) is None
    assert pinned_gateway_policy_for("not-a-url", allow_candidate=True) is None
