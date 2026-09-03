"""Which AnonRouter confidential routes are currently OFFERED.

A CONVENIENCE, AND NOT A SECURITY CONTROL. This exists so a caller who names a
route AnonRouter has withheld gets a clear answer immediately, instead of a
ticket mint failing with something that reads like a routing bug. It is not what
protects them: every route still fetches fresh evidence and every verdict is
still computed from that evidence, so a route missing from this file is not
thereby trusted and a route listed in it is not thereby verified.

The distinction matters for how this module may be used. It may refuse early. It
may NEVER be consulted to decide that something verified -- that would move a
trust decision from evidence the caller checked to a list the service shipped,
which is the whole thing this package exists not to do.

Generated from AnonRouter's ``config/confidential-route-policy.json``; synced by
``scripts/sync-shared.mjs`` and gated by ``scripts/check-parity.mjs``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_POLICY_PATH = Path(__file__).with_name("confidential_route_policy.json")


@lru_cache(maxsize=1)
def _policy() -> dict[str, Any]:
    return json.loads(_POLICY_PATH.read_text(encoding="utf-8"))


def _key(provider: str, model: str, privacy_class: str) -> str:
    return f"{provider} {model} {privacy_class}"


@lru_cache(maxsize=1)
def _verified() -> frozenset[str]:
    return frozenset(
        _key(r["provider"], r["model"], r["privacyClass"]) for r in _policy()["verified"]
    )


@lru_cache(maxsize=1)
def _withheld() -> dict[str, dict[str, Any]]:
    return {
        _key(r["provider"], r["model"], r["privacyClass"]): r
        for r in _policy()["withheld"]
    }


def confidential_route_policy_version() -> str:
    return str(_policy()["version"])


def offered_confidential_routes() -> list[dict[str, Any]]:
    return list(_policy()["verified"])


def withheld_confidential_routes() -> list[dict[str, Any]]:
    return list(_policy()["withheld"])


def is_route_withheld_by_service(provider: str, model: str, privacy_class: str) -> bool:
    """Whether AnonRouter currently withholds this exact route.

    Keyed on provider + canonical model + privacy class, because none of the
    three is redundant: one provider serves the same model under two classes, and
    one model is served by several providers. A rule keyed on any two of them
    would refuse a route nobody decided to refuse.

    Allowlist semantics within a governed (provider, class) pair, so a route the
    service adds tomorrow is not assumed offered. Outside a governed pair this
    returns False: the SDK does not invent policy for providers the service has
    not spoken about.
    """
    governed = _policy()["governedProviders"].get(provider)
    if governed is None or governed.get("privacyClass") != privacy_class:
        return False
    return _key(provider, model, privacy_class) not in _verified()


def withheld_route_classification(provider: str, model: str, privacy_class: str) -> str | None:
    entry = _withheld().get(_key(provider, model, privacy_class))
    return None if entry is None else str(entry.get("classification"))


def withheld_route_message(provider: str, model: str, privacy_class: str) -> str:
    """The message the SDK refuses with. Names the route, says nothing was sent,
    and does not suggest retrying -- retrying is how a caller comes to believe a
    withheld route is merely flaky."""
    classification = withheld_route_classification(provider, model, privacy_class)
    suffix = f" ({classification})" if classification else ""
    return (
        f"AnonRouter is not currently offering the {provider} {privacy_class} route "
        f"for {model}{suffix}. Nothing was sent. This is a service-side decision "
        "recorded in the shipped route policy, not a transient failure, so retrying "
        "will not change it. Verify it yourself with verify_route() if you want the "
        "evidence, or choose another route."
    )
