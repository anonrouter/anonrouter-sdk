"""Shared test fixtures: locate the language-neutral KAT vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_VECTORS_DIR = Path(__file__).resolve().parents[2] / "shared" / "vectors"


def _load(name: str) -> Any:
    return json.loads((_VECTORS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def crypto_vectors() -> list[dict[str, Any]]:
    return _load("crypto-decrypt.json")


@pytest.fixture(scope="session")
def tdx_vectors() -> list[dict[str, Any]]:
    return _load("tdx-quotes.json")


@pytest.fixture(scope="session")
def attestation_vectors() -> dict[str, Any]:
    return _load("attestation.json")


@pytest.fixture(scope="session")
def gateway_binding_vectors() -> dict[str, Any]:
    """Hop 1's parity contract: the canonical binding serialization and digest."""
    return _load("gateway-binding.json")


@pytest.fixture(scope="session")
def state_vectors() -> Any:
    """The stable verdict contract: level mapping and the at_least matrix."""
    return _load("verification-states.json")


@pytest.fixture(scope="session")
def dcap_vectors() -> dict[str, Any]:
    """The DCAP layer's parity contract: quote parsing, collateral, engine wire."""
    return _load("dcap.json")


@pytest.fixture(scope="session")
def gateway_verdict_vectors() -> dict[str, Any]:
    """Hop 1's complete verdicts: the analogue of attestation.json for the gateway."""
    return _load("gateway-verdicts.json")


@pytest.fixture(scope="session")
def cli_contract() -> dict[str, Any]:
    """The anonrouter-verify command's contract: exit codes and document shape."""
    return _load("cli-contract.json")
