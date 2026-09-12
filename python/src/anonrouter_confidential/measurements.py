"""Load the operator-reviewed TEE/E2EE verification policy.

The pins live in the package-local ``measurements.json`` (a synced copy of
``shared/measurements.json``; DO NOT hand-edit the copy). A CI parity gate keeps
every copy byte-identical across the JS and Python SDKs. We LOAD this file at
import time via ``importlib.resources`` rather than hardcoding any pin.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

_PACKAGE = "anonrouter_confidential"
_FILENAME = "measurements.json"


@lru_cache(maxsize=1)
def load_measurements() -> dict[str, Any]:
    """Return the parsed measurements.json document (cached)."""
    text = resources.files(_PACKAGE).joinpath(_FILENAME).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("measurements.json did not decode to an object")
    return data


def tdx_tee_type() -> int:
    """The pinned Intel TDX tee_type (129 == 0x81)."""
    value = load_measurements().get("tdxTeeType", 0x00000081)
    return int(value)


def pinned_measurement_policy_for(
    provider: str, upstream_model: str
) -> dict[str, Any] | None:
    """The verification policy for a route, or None when the provider binds
    the enclave by something other than a measurement policy (Venice).

    ``accepted`` is provider-specific: normally a measurement list, and for
    Tinfoil the fixed signed-release authority and repository.
    """
    providers = load_measurements().get("providers", {})
    entry = providers.get(provider)
    if not isinstance(entry, dict):
        return None

    if provider == "near-ai":
        by_model = entry.get("byModel", {})
        model_entry = by_model.get(upstream_model)
        if not isinstance(model_entry, dict):
            return None
        return _shape_policy(model_entry.get("measurementPolicy"))

    return _shape_policy(entry.get("measurementPolicy"))


def _shape_policy(policy: Any) -> dict[str, Any] | None:
    if not isinstance(policy, dict):
        return None
    return {
        "source": policy.get("source"),
        "version": policy.get("version"),
        "kind": policy.get("kind"),
        "accepted": policy.get("accepted", []),
    }


def pinned_endpoint_identity_for(
    provider: str, upstream_model: str
) -> str | None:
    """The operator-pinned direct endpoint identity for a route, if one exists."""
    providers = load_measurements().get("providers", {})
    entry = providers.get(provider)
    if not isinstance(entry, dict):
        return None
    if provider == "near-ai":
        model_entry = entry.get("byModel", {}).get(upstream_model)
        if isinstance(model_entry, dict):
            identity = model_entry.get("endpointIdentity")
            if isinstance(identity, str):
                return identity
        return None
    # Other providers (e.g. tinfoil) carry a single reviewed endpoint identity.
    identity = entry.get("endpointIdentity")
    return identity if isinstance(identity, str) else None
