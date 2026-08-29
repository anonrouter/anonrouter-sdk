"""TDX v4 quote parser parity: load tdx-quotes.json and assert every field."""

from __future__ import annotations

from anonrouter_confidential.tdx import TDX_TEE_TYPE, parse_tdx_quote


def test_tdx_quote_vectors(tdx_vectors: list[dict]) -> None:
    for case in tdx_vectors:
        parsed = parse_tdx_quote(case["quote"])
        assert parsed is not None, f"{case['name']} did not parse"
        expected = case["expected"]
        assert parsed.tee_type == expected["teeType"]
        assert parsed.debug_enabled == expected["debugEnabled"]
        assert parsed.mr_td == expected["mrTd"]
        # The richer fields are only asserted on the full (non-debug) fixture.
        for key, attr in (
            ("mrConfigId", "mr_config_id"),
            ("rtmr0", "rtmr0"),
            ("rtmr1", "rtmr1"),
            ("rtmr2", "rtmr2"),
            ("rtmr3", "rtmr3"),
            ("reportData", "report_data"),
        ):
            if key in expected:
                assert getattr(parsed, attr) == expected[key], f"{case['name']}:{key}"


def test_tee_type_is_intel_tdx() -> None:
    assert TDX_TEE_TYPE == 0x00000081


def test_malformed_quote_fails_closed() -> None:
    assert parse_tdx_quote("not a quote!!!") is None
    assert parse_tdx_quote("") is None
    assert parse_tdx_quote("abcd") is None  # too short
    assert parse_tdx_quote(None) is None  # type: ignore[arg-type]


def test_base64_and_hex_accepted(tdx_vectors: list[dict]) -> None:
    encodings = {case["encoding"] for case in tdx_vectors}
    assert {"hex", "base64"}.issubset(encodings)
