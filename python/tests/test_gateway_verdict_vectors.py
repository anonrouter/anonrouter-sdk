"""The complete hop 1 verdict, pinned across both languages.

``attestation.json`` does this for hop 2. Without an equivalent here the two
languages agreed about the binding digest and the quote parse, but nothing pinned
the VERDICT: which checks are required, what a failure is called, and which single
check a given tamper is supposed to fail. A change that landed in one language and
not the other could pass both suites.

Every case carries a complete evidence document (expressed as a diff from one
base, merged here), so both languages verify the same bytes rather than each
rebuilding a fixture and hoping the two agree.

Mirrors ``js/confidential/test/gateway-verdict-vectors.test.ts``.
"""

from __future__ import annotations

from typing import Any

from anonrouter_confidential.gateway.binding import GATEWAY_BINDING_VERSION
from anonrouter_confidential.gateway.policy import load_gateway_policy
from anonrouter_confidential.gateway.verify import verify_gateway_attestation


def _merge_on_base(
    base: dict[str, Any], overrides: dict[str, Any], removed: list[str]
) -> dict[str, Any]:
    """The merge contract, stated in ``_readme`` and asserted by the generator.

    Shallow override, plus an explicit removal list because JSON cannot express
    "absent" and a document with no ``issued_at_ms`` is a case that has to be
    reachable.
    """
    merged = {**base, **overrides}
    for key in removed:
        merged.pop(key, None)
    return merged


class _StubChainVerifier:
    """A verifier is code and cannot be serialized, so the vector records the
    outcome it should produce and each language builds the stub locally. This is
    what makes the TCB cases reachable without a DCAP engine."""

    implementation = "vector-stub"

    def __init__(self, verified: bool, tcb_status: str | None) -> None:
        self._verified = verified
        self._tcb_status = tcb_status

    def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, str | None]:
        return self._verified, self._tcb_status


def _run(case: dict[str, Any], base: dict[str, Any], *, with_chain: bool = True) -> Any:
    evidence = _merge_on_base(base["evidence"], case["evidence"], case["evidenceRemoved"])
    policy = load_gateway_policy(
        _merge_on_base(base["policy"], case["policy"], case["policyRemoved"])
    )
    expectations = {**base["expectations"], **case["expectations"]}
    stub = None
    if with_chain and case["chainVerifier"] is not None:
        stub = _StubChainVerifier(
            case["chainVerifier"]["verified"], case["chainVerifier"]["tcbStatus"]
        )
    observed = case["observedTlsSpki"]
    return verify_gateway_attestation(
        evidence,
        nonce=expectations["nonce"],
        origin=expectations["origin"],
        policy=policy,
        now_ms=expectations["nowMs"],
        observed_tls_spki_sha256=observed["value"] if observed["supplied"] else None,
        observed_tls_spki_supplied=bool(observed["supplied"]),
        chain_verifier=stub,
    )


def test_binding_version_matches(gateway_verdict_vectors: dict[str, Any]) -> None:
    assert gateway_verdict_vectors["bindingVersion"] == GATEWAY_BINDING_VERSION


def test_every_case_reproduces_the_pinned_verdict(
    gateway_verdict_vectors: dict[str, Any],
) -> None:
    base = gateway_verdict_vectors["base"]
    for case in gateway_verdict_vectors["cases"]:
        result = _run(case, base)
        expected = case["expected"]
        assert result.status == expected["status"], case["name"]
        assert result.verification_level == expected["verificationLevel"], case["name"]
        assert result.reason == expected["reason"], case["name"]
        assert result.tcb_status == expected["tcbStatus"], case["name"]
        # The exact set, in order. A check quietly relaxed from required to
        # advisory would move between these two lists rather than disappear.
        assert [c.name for c in result.checks if c.required and not c.passed] == expected[
            "failedRequiredChecks"
        ], case["name"]
        assert [c.name for c in result.checks if not c.required and not c.passed] == expected[
            "unmetAdvisoryChecks"
        ], case["name"]


def test_no_verdict_reports_the_same_check_twice(
    gateway_verdict_vectors: dict[str, Any],
) -> None:
    # A verdict carrying `event_log_replays_rtmrs` twice, once passing and once
    # failing, is worse than a plain failure: a caller looking a check up by name
    # finds the passing copy and never sees the failure. This regressed once, when
    # reading the named identities out of the log shared an except block with the
    # replay.
    base = gateway_verdict_vectors["base"]
    for case in gateway_verdict_vectors["cases"]:
        result = _run(case, base, with_chain=False)
        names = [c.name for c in result.checks]
        assert len(set(names)) == len(names), f"duplicate check names in {case['name']}: {names}"


def test_the_vectors_cover_both_outcomes(gateway_verdict_vectors: dict[str, Any]) -> None:
    # A change cannot pass this file by making everything fail.
    cases = gateway_verdict_vectors["cases"]
    passing = [c for c in cases if c["expected"]["status"] == "ok"]
    failing = [c for c in cases if c["expected"]["status"] == "failed"]
    assert len(passing) > 5
    assert len(failing) > 20


def test_hardware_verified_only_where_a_chain_verifier_passed(
    gateway_verdict_vectors: dict[str, Any],
) -> None:
    for case in gateway_verdict_vectors["cases"]:
        if case["expected"]["verificationLevel"] != "hardware-verified":
            continue
        assert case["chainVerifier"]["verified"] is True
        assert case["chainVerifier"]["tcbStatus"] == "UpToDate"


def test_a_two_tuple_chain_verifier_still_works(
    gateway_verdict_vectors: dict[str, Any],
) -> None:
    # The port grew an optional third element (a content-free detail) after it
    # shipped. An implementation returning the original 2-tuple must keep working,
    # or the addition would be a silent breaking change for anyone who wrote their
    # own verifier against the published Protocol.
    base = gateway_verdict_vectors["base"]
    case = next(
        c for c in gateway_verdict_vectors["cases"]
        if c["name"] == "HARDWARE VERIFICATION with a passing chain verifier"
    )
    result = _run(case, base)
    assert result.status == "ok"
    assert result.verification_level == "hardware-verified"
