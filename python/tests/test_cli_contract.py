"""The anonrouter-verify command's contract.

Every case here has a JavaScript twin loading the SAME
``shared/vectors/cli-contract.json``. Two commands with the same name that
disagreed about their exit codes or their JSON shape would be worse than having
only one, because a script written against either would silently mean something
different under the other.

Mirrors ``js/confidential/test/cli-contract.test.ts``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from anonrouter_confidential.cli import (
    EXIT_MET,
    EXIT_NOT_MET,
    EXIT_USAGE,
    SCHEMA,
    CliIo,
    UsageError,
    parse_args,
    run_cli,
)


class Capture(CliIo):
    """Capture what one invocation printed."""

    def __init__(self) -> None:
        self.stdout = ""
        self.stderr = ""
        super().__init__(out=self._out, err=self._err)

    def _out(self, text: str) -> None:
        self.stdout += text

    def _err(self, text: str) -> None:
        self.stderr += text


# ---- exit codes and schema --------------------------------------------------


def test_schema_and_exit_codes_match_the_contract(cli_contract: dict[str, Any]) -> None:
    assert SCHEMA == cli_contract["schema"]
    assert EXIT_MET == cli_contract["exitCodes"]["met"]
    assert EXIT_NOT_MET == cli_contract["exitCodes"]["notMet"]
    assert EXIT_USAGE == cli_contract["exitCodes"]["usage"]


def test_not_met_and_usage_stay_distinct() -> None:
    # Load-bearing. If a mistyped command exited 1, a CI job gating on the exit
    # code would read its own typo as a verification answer.
    assert EXIT_NOT_MET != EXIT_USAGE


# ---- inputs refused before anything is contacted ----------------------------


def test_usage_cases(cli_contract: dict[str, Any]) -> None:
    for case in cli_contract["usageCases"]:
        io = Capture()
        code = run_cli(case["argv"], io)
        assert code == case["exitCode"], case["name"]
        assert case["stderrContains"] in io.stderr, case["name"]
        # Nothing was established, so nothing may be printed as though it was.
        assert io.stdout == "", case["name"]


def test_api_key_on_argv_is_refused_and_not_echoed() -> None:
    # argv is visible in the process table and lands in shell history. Silently
    # ignoring the flag would leave the key exposed AND the command unauthorized.
    io = Capture()
    code = run_cli(
        [
            "route", "--origin", "https://x.example", "--provider", "venice",
            "--model", "m", "--api-key", "ar_live_secret",
        ],
        io,
    )
    assert code == EXIT_USAGE
    assert "ar_live_secret" not in io.stderr


# ---- parsed options ---------------------------------------------------------


def test_default_assurance(cli_contract: dict[str, Any]) -> None:
    options = parse_args(["gateway", "--origin", "https://x.example"])
    assert options["require"] == cli_contract["defaultRequire"]


def test_accepts_a_separate_content_free_control_origin() -> None:
    options = parse_args([
        "route", "--origin", "https://confidential.example",
        "--control-origin", "https://control.example",
        "--provider", "venice", "--model", "model",
    ])
    assert options["control_origin"] == "https://control.example"


def test_dcap_binary_implies_dcap() -> None:
    options = parse_args(["gateway", "--origin", "https://x.example", "--dcap-binary", "/opt/engine"])
    assert options["dcap"] is True
    assert options["dcap_binary"] == "/opt/engine"


def test_every_contract_command_parses(cli_contract: dict[str, Any]) -> None:
    for command in cli_contract["commands"]:
        if command == "doctor":
            argv = [command]
        elif command == "route":
            argv = [command, "--origin", "https://x.example", "--provider", "venice", "--model", "m"]
        else:
            argv = [command, "--origin", "https://x.example"]
        assert parse_args(argv)["command"] == command


def test_parse_args_raises_rather_than_exiting() -> None:
    with pytest.raises(UsageError):
        parse_args(["nope"])


# ---- doctor -----------------------------------------------------------------


def test_doctor_document_keys(cli_contract: dict[str, Any]) -> None:
    io = Capture()
    code = run_cli(["doctor", "--compact"], io)
    assert code == EXIT_MET
    document = json.loads(io.stdout)
    assert list(document.keys()) == cli_contract["documentKeys"]["doctor"]
    for key in cli_contract["engineKeys"]:
        assert key in document["engine"]
    assert list(document["pin"].keys()) == cli_contract["pinKeys"]


def test_doctor_reports_the_reviewed_production_pin_as_published() -> None:
    io = Capture()
    run_cli(["doctor", "--origin", "https://api.private.anonrouter.ai", "--compact"], io)
    document = json.loads(io.stdout)
    assert document["pin"]["present"] is True
    assert document["pin"]["status"] == "published"
    assert document["pin"]["requiresOptIn"] is False


def test_doctor_reports_no_pin_for_an_uncovered_origin() -> None:
    io = Capture()
    run_cli(["doctor", "--origin", "https://example.invalid", "--compact"], io)
    assert json.loads(io.stdout)["pin"]["present"] is False


def test_doctor_does_not_gate() -> None:
    # doctor answering "you cannot reach hardware_verified here" is a successful
    # report. Exiting nonzero would make `doctor` unusable in a setup script.
    io = Capture()
    assert run_cli(["doctor", "--compact"], io) == EXIT_MET


# ---- an origin with no pin fails closed offline -----------------------------


def test_unpinned_origin_fails_closed(cli_contract: dict[str, Any]) -> None:
    # No network call is possible here: the policy is resolved first, and with
    # nothing pinned there is nothing to check evidence against, so fetching it
    # would only be reading the server's own claim back to the caller.
    offline = cli_contract["offlineCase"]
    io = Capture()
    code = run_cli(offline["argv"], io)
    assert code == offline["exitCode"]
    document = json.loads(io.stdout)
    assert document["outcome"]["met"] == offline["outcome"]["met"]
    assert document["outcome"]["state"] == offline["outcome"]["state"]
    assert document["gateway"]["state"] == offline["gatewayState"]
    assert document["provider"]["requested"] == offline["providerRequested"]
    assert offline["reasonContains"] in str(document["outcome"]["reason"])


def test_unpinned_origin_document_keys(cli_contract: dict[str, Any]) -> None:
    io = Capture()
    run_cli(cli_contract["offlineCase"]["argv"], io)
    document = json.loads(io.stdout)
    assert list(document.keys()) == cli_contract["documentKeys"]["verify"]
    assert list(document["requested"].keys()) == cli_contract["requestedKeys"]
    assert list(document["outcome"].keys()) == cli_contract["outcomeKeys"]
    for key in cli_contract["hopKeys"]:
        assert key in document["gateway"]
        assert key in document["provider"]


def test_nothing_credential_shaped_is_printed(cli_contract: dict[str, Any]) -> None:
    io = Capture()
    run_cli(cli_contract["offlineCase"]["argv"], io)
    for forbidden in cli_contract["neverPrinted"]:
        assert forbidden not in io.stdout


# ---- formatting -------------------------------------------------------------


def test_compact_changes_only_the_bytes() -> None:
    compact = Capture()
    run_cli(["doctor", "--compact"], compact)
    assert "\n" not in compact.stdout.rstrip("\n")

    pretty = Capture()
    run_cli(["doctor"], pretty)
    assert "\n  " in pretty.stdout
    # Same document either way: formatting must not be a semantic difference.
    assert json.loads(pretty.stdout) == json.loads(compact.stdout)
