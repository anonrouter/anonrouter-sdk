"""The stable verdict contract, checked against the SHARED vectors JS also loads.

A divergence here is not cosmetic: if one language ranked the states differently,
a caller who wrote the same threshold in both would get different security
decisions from identical evidence.
"""

from __future__ import annotations

from typing import Any

from anonrouter_confidential.verify.state import (
    TRUSTED_STATES,
    at_least,
    is_trusted,
    state_for_level,
)


def test_maps_every_pinned_level_to_the_pinned_state(state_vectors: dict[str, Any]) -> None:
    for v in state_vectors["levelMapping"]:
        assert state_for_level(v["level"]) == v["state"], f"level {v['level'] or '(empty)'}"


def test_agrees_on_the_full_at_least_matrix(state_vectors: dict[str, Any]) -> None:
    # Exhaustive: 5 states x 5 thresholds, so a new state cannot be added in one
    # language without this failing in both.
    states = state_vectors["states"]
    assert len(state_vectors["atLeast"]) == len(states) * len(states)
    for v in state_vectors["atLeast"]:
        assert at_least(v["state"], v["required"]) is v["expected"], (
            f"at_least({v['state']}, {v['required']})"
        )


def test_agrees_on_exactly_which_states_are_trusted(state_vectors: dict[str, Any]) -> None:
    trusted = set(state_vectors["trustedStates"])
    for state in state_vectors["states"]:
        assert is_trusted(state) is (state in trusted), state
    assert sorted(TRUSTED_STATES) == sorted(trusted)
