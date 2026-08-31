"""There is no way to accidentally turn verification off.

Every SDK grows an escape hatch eventually: an ``if os.environ.get("CI")``, an
``ANONROUTER_INSECURE=1``, a "skip in tests" branch. Each one is a switch an
attacker who can set an environment variable, or a developer copying a deployment
config, can flip to make a failing verdict pass. This file asserts the absence of
that whole class, which is a property worth testing precisely because it is
invisible until somebody adds one.

The deliberate opt-ins are tested from the other direction too: each must still
require its explicit argument, and none may be reachable through the environment.

Mirrors ``js/confidential/test/no-insecure-escape-hatch.test.ts``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from anonrouter_confidential.cli import EXIT_USAGE, CliIo, run_cli
from anonrouter_confidential.client import ConfidentialError, create_client
from anonrouter_confidential.gateway.policy import (
    load_gateway_policy,
    pinned_gateway_policy_for,
)
from anonrouter_confidential.gateway.verify import verify_gateway_attestation

#: Names an escape hatch would plausibly be spelled. None of these may do anything.
HOSTILE_ENV = {
    "PYTHON_ENV": "test",
    "CI": "true",
    "PYTEST_CURRENT_TEST": "probe",
    "ANONROUTER_INSECURE": "1",
    "ANONROUTER_SKIP_VERIFY": "1",
    "ANONROUTER_SKIP_ATTESTATION": "1",
    "ANONROUTER_ALLOW_CANDIDATE": "1",
    "ANONROUTER_ALLOW_INSECURE_HTTP": "1",
    "ANONROUTER_DISABLE_TLS_CHECK": "1",
    "ANONROUTER_REQUIRE_HARDWARE": "0",
    "ANONROUTER_TRUST_GATEWAY": "1",
    "ANONROUTER_DEV": "1",
    "ANONROUTER_TEST_MODE": "1",
}


@contextmanager
def hostile_env() -> Iterator[None]:
    saved = {key: os.environ.get(key) for key in HOSTILE_ENV}
    os.environ.update(HOSTILE_ENV)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class Capture(CliIo):
    def __init__(self) -> None:
        self.stdout = ""
        self.stderr = ""
        super().__init__(out=self._out, err=self._err)

    def _out(self, text: str) -> None:
        self.stdout += text

    def _err(self, text: str) -> None:
        self.stderr += text


_PROBE_POLICY = load_gateway_policy(
    {
        "source": "escape-hatch-probe",
        "version": "1",
        "origins": ["https://x.invalid"],
        "appIds": ["aa"],
        "composeHashes": ["ab" * 32],
        "releaseIds": ["r"],
        "requireInTeeTls": True,
        "requirePrivateLogs": True,
        "requireDigestPinnedImages": True,
        "requireHardwareVerified": True,
        "acceptableTcbStatuses": ["UpToDate"],
        "requireEvidenceExpiry": True,
        "maxEvidenceAgeMs": 300_000,
    }
)


def test_garbage_evidence_fails_identically_under_a_hostile_environment() -> None:
    evidence = {"binding": None, "quote": "zz", "event_log": "[]", "app_compose": ""}
    kwargs: dict[str, Any] = {
        "nonce": "0" * 64,
        "origin": "https://x.invalid",
        "policy": _PROBE_POLICY,
        "now_ms": 1,
    }
    clean = verify_gateway_attestation(evidence, **kwargs)
    with hostile_env():
        hostile = verify_gateway_attestation(evidence, **kwargs)

    assert clean.status == "failed"
    assert hostile.status == "failed"
    # Identical, not merely both failing: a hatch that changed which checks ran
    # would be a difference worth seeing even if the outcome happened to match.
    assert json.dumps(hostile.as_dict()) == json.dumps(clean.as_dict())


def test_hardware_requirement_still_fails_closed_with_no_engine(
    gateway_verdict_vectors: dict[str, Any],
) -> None:
    # The single most tempting hatch: "it is fine, we are in CI". It is not fine.
    # This uses the shared vectors' base document, which is otherwise valid, so the
    # run actually REACHES the chain check rather than failing before it.
    base = gateway_verdict_vectors["base"]
    policy = load_gateway_policy({**base["policy"], "requireHardwareVerified": True})
    with hostile_env():
        result = verify_gateway_attestation(
            base["evidence"],
            nonce=base["expectations"]["nonce"],
            origin=base["expectations"]["origin"],
            policy=policy,
            now_ms=base["expectations"]["nowMs"],
        )
    chain = next(c for c in result.checks if c.name == "quote_signature_chain")
    assert chain.required is True
    assert chain.passed is False
    assert result.status == "failed"

    # The same document under a policy that does NOT require it still passes, so
    # the failure above is the requirement biting and not the document being bad.
    relaxed = verify_gateway_attestation(
        base["evidence"],
        nonce=base["expectations"]["nonce"],
        origin=base["expectations"]["origin"],
        policy=load_gateway_policy(base["policy"]),
        now_ms=base["expectations"]["nowMs"],
    )
    assert relaxed.status == "ok"
    assert relaxed.verification_level == "provider-attested"


def test_the_published_pin_cannot_be_changed_through_the_environment() -> None:
    origin = "https://api.private.anonrouter.ai"
    normal = pinned_gateway_policy_for(origin)
    with hostile_env():
        hostile = pinned_gateway_policy_for(origin)
    assert normal is not None
    assert normal.status == "published"
    assert hostile == normal


def test_a_plaintext_remote_origin_is_refused_however_the_environment_is_set() -> None:
    # Over plaintext the API key travels in the clear and the origin a quote binds
    # cannot mean anything, so an attested route would become decorative.
    with hostile_env():
        with pytest.raises(ConfidentialError):
            create_client("http://api.anonrouter.ai", "k")
        # Even the explicit opt-in does not extend past loopback.
        with pytest.raises(ConfidentialError):
            create_client("http://api.anonrouter.ai", "k", allow_insecure_http=True)
        # Loopback plus the explicit flag is the one accepted combination.
        create_client("http://127.0.0.1:3000", "k", allow_insecure_http=True).close()
        # ...and the flag is still required for it.
        with pytest.raises(ConfidentialError):
            create_client("http://127.0.0.1:3000", "k")


def test_the_command_still_refuses_hardware_verified_without_dcap() -> None:
    io = Capture()
    with hostile_env():
        code = run_cli(
            ["gateway", "--origin", "https://x.example", "--require", "hardware_verified"], io
        )
    assert code == EXIT_USAGE
    assert "needs --dcap" in io.stderr


def test_the_published_pin_still_fails_closed_without_the_required_dcap_engine() -> None:
    io = Capture()
    with hostile_env():
        code = run_cli(
            [
                "gateway", "--origin", "https://api.private.anonrouter.ai",
                "--compact", "--no-tls-check",
            ],
            io,
        )
    assert code != 0
    document = json.loads(io.stdout)
    assert document["outcome"]["met"] is False
    assert "quote_signature_chain" in document["gateway"]["failedChecks"]


def test_the_deciding_modules_never_read_the_environment() -> None:
    # A structural assertion, because the behavioural ones above can only cover the
    # names someone thought to try. These modules decide whether a verdict passes;
    # none has any business reading the environment.
    root = Path(__file__).resolve().parents[1] / "src" / "anonrouter_confidential"
    for relative in (
        "gateway/verify.py",
        "gateway/policy.py",
        "verify/state.py",
        "verify/route.py",
    ):
        source = (root / relative).read_text(encoding="utf-8")
        assert "os.environ" not in source, f"{relative} reads the environment"
        assert "getenv" not in source, f"{relative} reads the environment"
