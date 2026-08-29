"""The stable verdict contract: states, ordering, and the cross-hop route binding.

Mirrors ``js/confidential/test/route-contract.test.ts`` case for case. These are
the assertions that make ``verify_route`` safe to build on: the states must stay
ordered, a skipped hop must never read as a passing one, and two honestly-attested
parties on the WRONG route must still come out untrusted.
"""

from __future__ import annotations

from typing import Any

from anonrouter_confidential.verify.route import (
    RequestedRoute,
    RouteHopVerdict,
    assemble_route_verdict,
    gateway_hop_verdict,
    hop_not_requested,
    hop_unavailable,
    provider_hop_verdict,
)
from anonrouter_confidential.verify.state import (
    TRUSTED_STATES,
    at_least,
    describe_state,
    is_trusted,
    state_for_level,
)

ROUTE = RequestedRoute(provider="venice", model="venice-uncensored", privacy_modality="e2ee")

ALL_STATES = (
    "hardware_verified",
    "cryptographically_checked",
    "policy_matched",
    "untrusted",
    "unavailable",
)


def hop(state: str, requested: bool = True) -> RouteHopVerdict:
    return RouteHopVerdict(
        requested=requested, state=state, meaning=describe_state(state), reason=None
    )


# ---- states ------------------------------------------------------------------


def test_maps_every_internal_level_without_inflating_it() -> None:
    assert state_for_level("hardware-verified") == "hardware_verified"
    assert state_for_level("provider-attested") == "cryptographically_checked"
    assert state_for_level("sdk-verified") == "policy_matched"
    assert state_for_level("unverified") == "untrusted"
    assert state_for_level("unsupported") == "unavailable"


def test_unrecognized_level_is_untrusted_not_a_guess_upward() -> None:
    assert state_for_level("something-new") == "untrusted"
    assert state_for_level("") == "untrusted"


def test_states_are_ordered_strongest_first() -> None:
    assert at_least("hardware_verified", "cryptographically_checked")
    assert at_least("cryptographically_checked", "policy_matched")
    assert not at_least("policy_matched", "cryptographically_checked")
    assert at_least("hardware_verified", "hardware_verified")


def test_a_failure_state_never_satisfies_a_threshold_including_its_own() -> None:
    for failure in ("untrusted", "unavailable"):
        for required in TRUSTED_STATES:
            assert not at_least(failure, required)
        # at_least("untrusted","untrusted") returning True would let
        # require="untrusted" read as a satisfied requirement.
        assert not at_least(failure, failure)
        assert not is_trusted(failure)


def test_every_state_has_a_distinct_non_empty_meaning() -> None:
    meanings = [describe_state(s) for s in ALL_STATES]
    assert len(set(meanings)) == len(ALL_STATES)
    assert all(len(m) > 20 for m in meanings)


# ---- assembly ----------------------------------------------------------------


def test_takes_the_weakest_requested_hop_never_the_strongest() -> None:
    v = assemble_route_verdict(
        route=ROUTE, gateway=hop("hardware_verified"), provider=hop("policy_matched")
    )
    assert v.overall_state == "policy_matched"
    assert v.trusted is True


def test_ignores_a_hop_nobody_asked_about_and_says_it_was_skipped() -> None:
    v = assemble_route_verdict(
        route=ROUTE, gateway=hop_not_requested(), provider=hop("cryptographically_checked")
    )
    assert v.overall_state == "cryptographically_checked"
    assert v.gateway.requested is False
    # trusted is True, but only because hop 1 was never asked about;
    # gateway.requested is what stops that being misread.
    assert v.trusted is True


def test_is_untrusted_when_a_requested_hop_is_unavailable() -> None:
    v = assemble_route_verdict(
        route=ROUTE,
        gateway=hop_unavailable("this deployment does not expose gateway attestation"),
        provider=hop("cryptographically_checked"),
    )
    assert v.overall_state == "unavailable"
    assert v.trusted is False
    assert v.reason is not None and "gateway" in v.reason


def test_is_unavailable_when_no_hop_was_requested() -> None:
    v = assemble_route_verdict(
        route=ROUTE, gateway=hop_not_requested(), provider=hop_not_requested()
    )
    assert v.overall_state == "unavailable"
    assert v.trusted is False


def test_states_plainly_whether_anonrouter_can_read_the_content() -> None:
    e2ee = assemble_route_verdict(
        route=ROUTE, gateway=hop_not_requested(), provider=hop("cryptographically_checked")
    )
    assert e2ee.content_visible_to_anonrouter is False

    tee = assemble_route_verdict(
        route=RequestedRoute(provider="tinfoil", model="m", privacy_modality="tee"),
        gateway=hop_not_requested(),
        provider=hop("cryptographically_checked"),
    )
    assert tee.content_visible_to_anonrouter is True


# ---- cross-hop route binding -------------------------------------------------


def test_refuses_two_attested_hops_that_served_the_wrong_provider() -> None:
    # Neither hop verifier can see this: each only gets its own evidence, so a
    # gateway attesting itself honestly while routing elsewhere is invisible
    # until the hops are cross-bound.
    v = assemble_route_verdict(
        route=ROUTE,
        gateway=hop("hardware_verified"),
        provider=hop("hardware_verified"),
        gateway_echo={"provider": "chutes"},
    )
    assert v.trusted is False
    assert v.overall_state == "untrusted"
    assert len(v.binding_mismatches) == 1
    m = v.binding_mismatches[0]
    assert (m.field_name, m.expected, m.observed, m.source) == (
        "provider",
        "venice",
        "chutes",
        "gateway",
    )
    assert v.reason is not None and "route_binding_mismatch" in v.reason


def test_refuses_a_silent_downgrade_from_e2ee_to_tee() -> None:
    v = assemble_route_verdict(
        route=ROUTE,
        gateway=hop("hardware_verified"),
        provider=hop("hardware_verified"),
        gateway_echo={"privacy_class": "tee"},
    )
    assert v.trusted is False
    assert v.binding_mismatches[0].field_name == "privacy_modality"


def test_refuses_an_attested_model_the_caller_did_not_pin() -> None:
    v = assemble_route_verdict(
        route=ROUTE,
        gateway=hop_not_requested(),
        provider=hop("cryptographically_checked"),
        expected_upstream_model="e2ee-gpt-oss-20b-p",
        attested_upstream_model="some-other-model",
    )
    assert v.trusted is False
    assert v.binding_mismatches[0].field_name == "model"
    assert v.binding_mismatches[0].source == "provider-evidence"


def test_does_not_invent_a_model_mismatch_when_nothing_was_pinned() -> None:
    v = assemble_route_verdict(
        route=ROUTE,
        gateway=hop_not_requested(),
        provider=hop("cryptographically_checked"),
        attested_upstream_model="e2ee-gpt-oss-20b-p",
    )
    assert v.binding_mismatches == []
    assert v.trusted is True


def test_an_agreeing_echo_produces_no_mismatch() -> None:
    v = assemble_route_verdict(
        route=ROUTE,
        gateway=hop("cryptographically_checked"),
        provider=hop("cryptographically_checked"),
        gateway_echo={"provider": "venice", "privacy_class": "e2ee"},
        expected_upstream_model="m",
        attested_upstream_model="m",
    )
    assert v.binding_mismatches == []
    assert v.trusted is True


# ---- hop projection ----------------------------------------------------------


class _Check:
    def __init__(self, name: str, passed: bool, required: bool) -> None:
        self.name, self.passed, self.required = name, passed, required


class _Result:
    def __init__(self, status: str, level: str, reason: str | None, checks: Any) -> None:
        self.status, self.verification_level, self.reason, self.checks = (
            status,
            level,
            reason,
            checks,
        )


def test_projects_a_failed_gateway_result_and_lists_the_failed_checks() -> None:
    result = _Result(
        "failed",
        "unverified",
        "release_pinned",
        [
            _Check("quote_parsed", True, True),
            _Check("release_pinned", False, True),
            _Check("evidence_recent", False, False),
        ],
    )
    projected = gateway_hop_verdict(result)
    assert projected.state == "untrusted"
    assert projected.failed_checks == ["release_pinned"]
    assert projected.advisory_gaps == ["evidence_recent"]


def test_never_projects_ok_onto_a_state_stronger_than_its_level() -> None:
    assert gateway_hop_verdict(_Result("ok", "provider-attested", None, [])).state == (
        "cryptographically_checked"
    )


def test_projects_a_provider_verdict_the_same_way() -> None:
    assert provider_hop_verdict(_Result("ok", "sdk-verified", None, [])).state == "policy_matched"
