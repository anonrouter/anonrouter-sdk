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


def test_ships_the_manifest_bound_production_pin_and_resolves_it_by_default() -> None:
    # Pin the source digest here so changing the default trust anchor is always a
    # deliberate test update rather than a quiet edit to a data file.
    registry = gateway_policy_registry()
    published = [entry for entry in registry if entry.status == "published"]
    assert len(published) == 1
    assert published[0].policy.source == (
        "anonrouter-release-manifest-sha256:"
        "d992b00b085d9d500d88ff926dea5c9916d29c103fe127e61273d6bde084e2a5"
    )
    # The pin must name the live content plane, not a superseded one. These are
    # the two values a stale refresh gets wrong first.
    assert published[0].policy.compose_hashes == [
        "9329f5078f9ca6fe658ec999d92a3d5d7661b7d81f60d6410ac3377ce6090f02"
    ]
    assert published[0].policy.release_ids == ["anonrouter-tee@xl-7a84989"]
    for entry in published:
        for origin in entry.policy.origins:
            resolved = pinned_gateway_policy_for(origin)
            assert resolved is not None, f"{origin} must resolve by default"
            assert resolved.status == "published"


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
