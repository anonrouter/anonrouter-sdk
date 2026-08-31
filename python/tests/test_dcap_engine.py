"""The official DCAP adapter: the wire contract, engine discovery, fail-closed paths.

Loads the SAME ``shared/vectors/dcap.json`` the JavaScript suite loads. A drift in
quote parsing, collateral slicing, or the engine wire format would mean the two
languages verify different things while printing the same verdict shape, so every
vector case below has a JS twin asserting the identical expectation.

Mirrors ``js/confidential/test/dcap-engine.test.ts``.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from typing import Any

import pytest
from gateway_fixtures import build_synthetic_tdx_quote

from anonrouter_confidential.gateway.dcap import (
    DCAP_ENGINE_ENV,
    AnonRouterDcapVerifier,
    CollateralCache,
    CollateralError,
    DcapEngineVerdictV1,
    PreparedDcapVerifier,
    build_dcap_engine_request,
    create_anonrouter_dcap_verifier,
    dcap_platform_target,
    describe_dcap_installation,
    engine_report_disagreement,
    extract_fmspc,
    extract_pck_chain,
    file_sha256,
    normalize_quote_hex,
    parse_dcap_engine_verdict,
    read_next_update_ms,
    read_signed_document_signature,
    resolve_dcap_verifier_binary,
    run_dcap_engine,
    slice_signed_document,
)
from anonrouter_confidential.gateway.dcap.collateral import (
    AcquiredCollateral,
    DcapCollateral,
)


def _executable_script(body: str) -> str:
    """Write an executable shell script and return its path."""
    directory = tempfile.mkdtemp(prefix="anonrouter-dcap-")
    path = os.path.join(directory, "fake-engine")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(f"#!/bin/sh\n{body}\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _fake_engine(stdout: str, exit_code: int = 0, extra: str = "") -> str:
    """A fake engine: consumes the request on stdin and prints a fixed verdict."""
    return _executable_script(
        f"cat > /dev/null\n{extra}\ncat <<'ENGINE_EOF'\n{stdout}\nENGINE_EOF\nexit {exit_code}"
    )


def _quote() -> str:
    """The same synthetic TD the JavaScript twin builds, field for field."""
    return build_synthetic_tdx_quote(
        report_data_hex="66" * 64,
        mr_td="11" * 48,
        mr_config_id="00" * 48,
        rtmr0="22" * 48,
        rtmr1="33" * 48,
        rtmr2="44" * 48,
        rtmr3="55" * 48,
    )


# ---- shared vectors: quote -> PCK chain -> FMSPC ----------------------------


def test_quote_parsing_vectors(dcap_vectors: dict[str, Any]) -> None:
    for case in dcap_vectors["quoteParsing"]["cases"]:
        chain = extract_pck_chain(case["quote"])
        assert chain == case["expectedChain"], case["name"]
        fmspc = extract_fmspc(chain) if chain is not None else None
        assert fmspc == case["expectedFmspc"], case["name"]


def test_fmspc_ignores_the_four_byte_decoy(dcap_vectors: dict[str, Any]) -> None:
    # The fixture leaf carries the same OID twice: once with a 4-byte value and once
    # with the real 6-byte FMSPC. Taking the first match would point the whole TCB
    # lookup at a platform that does not exist.
    chain = extract_pck_chain(dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"])
    assert chain is not None
    assert extract_fmspc(chain) == "20a06f000000"


def test_pck_chain_strips_dstack_nul_padding(dcap_vectors: dict[str, Any]) -> None:
    chain = extract_pck_chain(dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"])
    assert chain is not None
    assert "\x00" not in chain
    assert chain.endswith("-----END CERTIFICATE-----")


def test_quote_normalization_accepts_hex_and_base64(dcap_vectors: dict[str, Any]) -> None:
    hex_quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    b64 = base64.b64encode(bytes.fromhex(hex_quote)).decode()
    assert normalize_quote_hex(b64) == hex_quote
    assert normalize_quote_hex(hex_quote.upper()) == hex_quote
    assert normalize_quote_hex("") is None
    assert normalize_quote_hex(42) is None


# ---- shared vectors: Intel's signed documents -------------------------------


def test_signed_document_vectors(dcap_vectors: dict[str, Any]) -> None:
    for case in dcap_vectors["signedDocuments"]:
        if case["expectedDocument"] is None:
            with pytest.raises(CollateralError):
                slice_signed_document(case["body"], case["key"])
            continue
        sliced = slice_signed_document(case["body"], case["key"])
        # The signature covers these exact bytes, so this is an identity check.
        assert sliced == case["expectedDocument"], case["name"]
        assert read_signed_document_signature(case["body"]) == case["expectedSignature"]
        if case["expectedNextUpdateMs"] is None:
            with pytest.raises(CollateralError):
                read_next_update_ms(sliced)
        else:
            assert read_next_update_ms(sliced) == case["expectedNextUpdateMs"], case["name"]


def test_next_update_is_parsed_as_utc() -> None:
    expected = datetime(2026, 9, 29, 23, 23, 57, tzinfo=timezone.utc).timestamp() * 1000
    assert read_next_update_ms('{"nextUpdate":"2026-09-29T23:23:57Z"}') == expected


# ---- shared vectors: the engine wire contract -------------------------------


def test_engine_request_vectors(dcap_vectors: dict[str, Any]) -> None:
    collateral = dcap_vectors["engineWire"]["collateral"]
    for case in dcap_vectors["engineWire"]["requests"]:
        request = build_dcap_engine_request(
            case["quote"], collateral, case["nowSecs"], case["acceptedTcbStatuses"]
        )
        assert request == case["expected"], case["name"]


def test_engine_request_floors_now_secs(dcap_vectors: dict[str, Any]) -> None:
    collateral = dcap_vectors["engineWire"]["collateral"]
    request = build_dcap_engine_request("00", collateral, int(1_788_000_000.9))
    assert request["now_secs"] == 1_788_000_000


def test_engine_request_accepts_the_typed_collateral(dcap_vectors: dict[str, Any]) -> None:
    # A DcapCollateral and its dict form must serialize identically, or a caller
    # that supplied a typed object would send a different request than one who
    # passed a dict, for the same collateral.
    raw = dcap_vectors["engineWire"]["collateral"]
    typed = DcapCollateral.from_dict(raw)
    assert build_dcap_engine_request("00", typed, 1) == build_dcap_engine_request("00", raw, 1)


def test_collateral_from_dict_rejects_a_partial_document() -> None:
    with pytest.raises(CollateralError):
        DcapCollateral.from_dict({"pck_crl": "aa"})
    with pytest.raises(CollateralError):
        DcapCollateral.from_dict("not an object")


def test_engine_verdict_vectors(dcap_vectors: dict[str, Any]) -> None:
    for case in dcap_vectors["engineWire"]["verdicts"]:
        parsed = parse_dcap_engine_verdict(case["stdout"])
        if case["expected"] is None:
            # The whole point: a malformed verdict is unusable, not a weak pass.
            assert parsed is None, case["name"]
            continue
        assert parsed is not None, case["name"]
        expected = case["expected"]
        assert parsed.verified == expected["verified"], case["name"]
        assert parsed.tcb_status == expected["tcbStatus"]
        assert parsed.qe_tcb_status == expected["qeTcbStatus"]
        assert parsed.platform_tcb_status == expected["platformTcbStatus"]
        assert parsed.advisory_ids == expected["advisoryIds"]
        assert (parsed.report is not None) == expected["hasReport"]
        assert parsed.error == expected["error"]
        assert parsed.engine == expected["engine"]


def test_oversized_verdict_is_refused() -> None:
    assert parse_dcap_engine_verdict('{"verified":true,"pad":"' + "a" * 300_000 + '"}') is None


# ---- locating the engine ----------------------------------------------------


def test_explicit_path_is_used_when_executable() -> None:
    engine = _fake_engine('{"verified":true}')
    resolved = resolve_dcap_verifier_binary(engine, env={})
    assert resolved.path == engine
    assert resolved.origin == "explicit"


def test_missing_explicit_path_resolves_to_nothing() -> None:
    # The load-bearing rule. Falling through here would run an engine the caller did
    # not name, which is exactly the substitution this component prevents.
    engine = _fake_engine('{"verified":true}')
    resolved = resolve_dcap_verifier_binary("/nonexistent/engine", env={DCAP_ENGINE_ENV: engine})
    assert resolved.path is None
    assert resolved.origin == "none"
    assert "/nonexistent/engine" in (resolved.reason or "")


def test_missing_env_path_does_not_fall_through_to_path() -> None:
    resolved = resolve_dcap_verifier_binary(
        None, env={DCAP_ENGINE_ENV: "/nonexistent/engine", "PATH": "/usr/bin"}
    )
    assert resolved.path is None
    assert DCAP_ENGINE_ENV in (resolved.reason or "")


def test_environment_resolution() -> None:
    engine = _fake_engine('{"verified":true}')
    resolved = resolve_dcap_verifier_binary(None, env={DCAP_ENGINE_ENV: engine})
    assert resolved.path == engine
    assert resolved.origin == "environment"


def test_search_path_off_resolves_nothing() -> None:
    resolved = resolve_dcap_verifier_binary(None, search_path=False, env={})
    assert resolved.path is None
    assert resolved.origin == "none"


def test_binary_digest() -> None:
    engine = _fake_engine('{"verified":true}')
    digest = file_sha256(engine)
    assert digest is not None and len(digest) == 64
    assert file_sha256("/nonexistent/engine") is None


def test_platform_targets_match_the_shared_table(dcap_vectors: dict[str, Any]) -> None:
    node_to_python = {"x64": "x86_64", "arm64": "aarch64", "ia32": "i386"}
    for entry in dcap_vectors["platformTargets"]:
        machine = node_to_python[entry["arch"]]
        assert dcap_platform_target(entry["platform"], machine) == entry["target"], entry


def test_doctor_reports_the_path_that_would_run() -> None:
    engine = _fake_engine('{"verified":true}')
    found = describe_dcap_installation(binary_path=engine)
    assert found.available is True
    assert found.binary_path == engine
    assert found.binary_sha256 is not None

    missing = describe_dcap_installation(binary_path="/nonexistent/engine")
    assert missing.available is False
    joined = " ".join(missing.instructions)
    assert "bundles no DCAP engine" in joined
    # The instructions must never imply a silent downgrade is what happens.
    assert "fails closed" in joined


# ---- running the engine -----------------------------------------------------


def test_non_zero_exit_still_yields_the_printed_verdict(dcap_vectors: dict[str, Any]) -> None:
    # The exit code is NOT the answer: the engine prints a verdict for 0 and 1 alike,
    # and treating a non-zero exit as unparseable would lose the reason.
    collateral = dcap_vectors["engineWire"]["collateral"]
    engine = _fake_engine(
        '{"verified":false,"tcb_status":"OutOfDate","error":"tcb status OutOfDate is not accepted"}',
        1,
    )
    verdict = run_dcap_engine(engine, build_dcap_engine_request(_quote(), collateral, 1))
    assert verdict.verified is False
    assert verdict.tcb_status == "OutOfDate"
    assert "OutOfDate" in (verdict.error or "")


def test_missing_binary_is_a_refusal(dcap_vectors: dict[str, Any]) -> None:
    collateral = dcap_vectors["engineWire"]["collateral"]
    verdict = run_dcap_engine(
        "/nonexistent/engine", build_dcap_engine_request(_quote(), collateral, 1)
    )
    assert verdict.verified is False
    assert verdict.engine == "unavailable"


def test_non_json_output_is_a_refusal(dcap_vectors: dict[str, Any]) -> None:
    collateral = dcap_vectors["engineWire"]["collateral"]
    engine = _fake_engine("segmentation fault", 139)
    verdict = run_dcap_engine(engine, build_dcap_engine_request(_quote(), collateral, 1))
    assert verdict.verified is False


def test_a_hung_engine_is_refused_at_the_deadline(dcap_vectors: dict[str, Any]) -> None:
    collateral = dcap_vectors["engineWire"]["collateral"]
    engine = _fake_engine('{"verified":true}', 0, "sleep 5")
    verdict = run_dcap_engine(engine, build_dcap_engine_request(_quote(), collateral, 1), 0.3)
    assert verdict.verified is False


def test_request_travels_on_stdin_not_argv(dcap_vectors: dict[str, Any]) -> None:
    # The engine refuses if it sees any argument; an empty argv proves the
    # multi-kilobyte request was not passed on the command line, where it would
    # show up in the process table.
    collateral = dcap_vectors["engineWire"]["collateral"]
    engine = _fake_engine('{"verified":true,"engine":"argv-probe"}', 0, 'test -z "$1" || exit 3')
    verdict = run_dcap_engine(engine, build_dcap_engine_request(_quote(), collateral, 1))
    assert verdict.verified is True
    assert verdict.engine == "argv-probe"


# ---- the prepared verifier is bound to one quote ----------------------------

_PASS = DcapEngineVerdictV1(
    verified=True,
    tcb_status="UpToDate",
    qe_tcb_status="UpToDate",
    platform_tcb_status="UpToDate",
    engine="test",
)


def test_prepared_verifier_answers_for_its_own_quote() -> None:
    verified, status, _ = PreparedDcapVerifier(_quote(), _PASS, "test").verify_chain(_quote())
    assert verified is True
    assert status == "UpToDate"


def test_prepared_verifier_refuses_any_other_quote() -> None:
    other = build_synthetic_tdx_quote(
        report_data_hex="44" * 64, mr_td="99" * 48, mr_config_id="00" * 48,
        rtmr0="88" * 48, rtmr1="77" * 48, rtmr2="66" * 48, rtmr3="55" * 48,
    )
    verified, _, detail = PreparedDcapVerifier(_quote(), _PASS, "test").verify_chain(other)
    assert verified is False
    assert "prepared for a different quote" in detail


def test_prepared_verifier_compares_on_bytes_not_spelling() -> None:
    as_base64 = base64.b64encode(bytes.fromhex(_quote())).decode()
    verified, _, _ = PreparedDcapVerifier(_quote(), _PASS, "test").verify_chain(as_base64)
    assert verified is True


def test_prepared_verifier_carries_the_engine_reason() -> None:
    refused = DcapEngineVerdictV1(verified=False, error="TCBInfo expired", engine="test")
    _, _, detail = PreparedDcapVerifier(_quote(), refused, "test").verify_chain(_quote())
    assert detail == "TCBInfo expired"


# ---- the engine's report is cross-checked against our parse ------------------

_AGREEING_REPORT = {
    "kind": "td10",
    "mr_td": "11" * 48,
    "mr_config_id": "00" * 48,
    "rtmr0": "22" * 48,
    "rtmr1": "33" * 48,
    "rtmr2": "44" * 48,
    "rtmr3": "55" * 48,
    "report_data": "66" * 64,
    "debug": False,
}


def test_report_agreement() -> None:
    assert engine_report_disagreement(_quote(), _AGREEING_REPORT) is None


def test_report_data_disagreement_is_fatal() -> None:
    bad = {**_AGREEING_REPORT, "report_data": "77" * 64}
    assert "report_data" in (engine_report_disagreement(_quote(), bad) or "")


def test_mr_td_disagreement_is_fatal() -> None:
    bad = {**_AGREEING_REPORT, "mr_td": "ab" * 48}
    assert "mr_td" in (engine_report_disagreement(_quote(), bad) or "")


def test_no_report_is_not_a_disagreement() -> None:
    assert engine_report_disagreement(_quote(), None) is None


# ---- the adapter fails closed on every path ---------------------------------


def test_adapter_refuses_without_an_engine(dcap_vectors: dict[str, Any]) -> None:
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    verifier = create_anonrouter_dcap_verifier(
        binary_path="/nonexistent/engine",
        collateral=dcap_vectors["engineWire"]["collateral"],
    ).prepare(quote)
    verified, _, detail = verifier.verify_chain(quote)
    assert verified is False
    assert "/nonexistent/engine" in detail


def test_adapter_refuses_a_digest_mismatch(dcap_vectors: dict[str, Any]) -> None:
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    engine = _fake_engine('{"verified":true,"tcb_status":"UpToDate"}')
    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine,
        collateral=dcap_vectors["engineWire"]["collateral"],
        expected_binary_sha256="00" * 32,
    ).prepare(quote)
    verified, _, detail = verifier.verify_chain(quote)
    assert verified is False
    assert "expected_binary_sha256" in detail


def test_adapter_accepts_a_matching_digest(dcap_vectors: dict[str, Any]) -> None:
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    engine = _fake_engine('{"verified":true,"tcb_status":"UpToDate"}')
    digest = file_sha256(engine)
    assert digest is not None
    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine,
        collateral=dcap_vectors["engineWire"]["collateral"],
        expected_binary_sha256=digest.upper(),
    ).prepare(quote)
    assert verifier.verify_chain(quote)[0] is True


def test_adapter_refuses_when_fetching_is_disabled(dcap_vectors: dict[str, Any]) -> None:
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    engine = _fake_engine('{"verified":true}')
    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine, fetch_collateral=False
    ).prepare(quote)
    assert "fetching is disabled" in verifier.verify_chain(quote)[2]


def test_adapter_refuses_when_collateral_is_unavailable(dcap_vectors: dict[str, Any]) -> None:
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    engine = _fake_engine('{"verified":true}')

    def boom(_quote_arg: str) -> Any:
        raise CollateralError("Intel PCS returned 503")

    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine, collateral_cache=CollateralCache(boom)
    ).prepare(quote)
    verified, _, detail = verifier.verify_chain(quote)
    assert verified is False
    assert "collateral unavailable" in detail


def test_adapter_refuses_a_report_describing_another_td(dcap_vectors: dict[str, Any]) -> None:
    # A pass whose measurements disagree with the quote is worse than a refusal: it
    # would report hardware_verified for evidence nobody checked.
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    engine = _fake_engine(
        json.dumps(
            {
                "verified": True,
                "tcb_status": "UpToDate",
                "report": {"mr_td": "ff" * 48, "report_data": "00" * 64},
            }
        )
    )
    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine, collateral=dcap_vectors["engineWire"]["collateral"]
    ).prepare(quote)
    verified, _, detail = verifier.verify_chain(quote)
    assert verified is False
    assert "disagree" in detail


def test_adapter_refuses_an_unparsable_quote(dcap_vectors: dict[str, Any]) -> None:
    engine = _fake_engine('{"verified":true}')
    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine, collateral=dcap_vectors["engineWire"]["collateral"]
    ).prepare("not a quote!!")
    assert verifier.verify_chain("not a quote!!")[0] is False


def test_adapter_forwards_the_accepted_statuses(dcap_vectors: dict[str, Any]) -> None:
    # Proven by having the fake engine echo what it read: if the SDK dropped the
    # field, an engine defaulting to UpToDate would refuse statuses the policy
    # allows, and a caller would be left debugging a disagreement they cannot see.
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    engine = _executable_script(
        'request=$(cat)\ncase "$request" in\n'
        '  *SWHardeningNeeded*) echo \'{"verified":true,"tcb_status":"SWHardeningNeeded"}\' ;;\n'
        '  *) echo \'{"verified":false,"error":"statuses not forwarded"}\' ;;\nesac'
    )
    verifier = create_anonrouter_dcap_verifier(
        binary_path=engine, collateral=dcap_vectors["engineWire"]["collateral"]
    ).prepare(quote, accepted_tcb_statuses=["UpToDate", "SWHardeningNeeded"])
    verified, status, _ = verifier.verify_chain(quote)
    assert verified is True
    assert status == "SWHardeningNeeded"


def test_collateral_cache_is_bounded_by_intels_signed_expiry(
    dcap_vectors: dict[str, Any],
) -> None:
    quote = dcap_vectors["quoteParsing"]["fixtures"]["quoteWithPckChain"]
    collateral = DcapCollateral.from_dict(dcap_vectors["engineWire"]["collateral"])
    fetches = 0

    def fetcher(_quote_arg: str) -> AcquiredCollateral:
        nonlocal fetches
        fetches += 1
        return AcquiredCollateral(
            collateral=collateral,
            fmspc="20a06f000000",
            next_update_ms=2_000,
            fetched_at_ms=1_000,
        )

    cache = CollateralCache(fetcher)
    cache.get(quote, 1_000)
    cache.get(quote, 1_999)
    assert fetches == 1
    # Past the signed nextUpdate the cache must not answer: the expiry comes from
    # what Intel signed, not from a policy constant we could quietly extend.
    cache.get(quote, 2_001)
    assert fetches == 2
    assert cache.peek("20a06f000000") is not None
    cache.clear()
    assert cache.peek("20a06f000000") is None


def test_verifier_class_and_factory_are_the_same_thing() -> None:
    assert isinstance(create_anonrouter_dcap_verifier(), AnonRouterDcapVerifier)
