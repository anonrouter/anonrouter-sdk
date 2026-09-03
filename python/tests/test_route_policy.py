"""The five routes AnonRouter withheld, refused here before anything is sent.

Mirrors ``js/confidential/test/route-policy.test.ts`` case for case.

WHAT THIS IS AND IS NOT. The shipped route policy is a CONVENIENCE: it turns
"your ticket request failed" into a sentence naming the route and the reason,
before a ticket is spent or a byte is encrypted. It is not what protects the
caller -- a withheld route that somehow reached the wire would still have to
produce evidence that verifies.

So the assertions come in pairs. Each withheld route is refused AND nothing
reaches the network; each allowed route is not refused, so the gate cannot be
passing by refusing everything.
"""

from __future__ import annotations

import httpx
import pytest

from anonrouter_confidential import (
    is_route_withheld_by_service,
    offered_confidential_routes,
    withheld_confidential_routes,
    withheld_route_classification,
    withheld_route_message,
)
from anonrouter_confidential.client import ConfidentialClient, ConfidentialError

PRODUCTION = "https://api.anonrouter.ai"
CONTROL = "https://control.anonrouter.ai"

#: The owner's decision, written out independently of the file under test.
WITHHELD = [
    "deepseek/deepseek-v4-flash",
    "qwen/qwen-3.6-35b-a3b-fp8",
    "z-ai/glm-5.1",
    "google/gemma-3-27b",
    "openai/gpt-oss-120b",
]

ALLOWED = [
    "google/gemma-4-26b-a4b-uncensored",
    "openai/gpt-oss-20b",
    "qwen/qwen-2.5-7b",
    "z-ai/glm-5.2",
]


def test_shipped_policy_withholds_exactly_the_five() -> None:
    assert sorted(r["model"] for r in withheld_confidential_routes()) == sorted(WITHHELD)
    for route in withheld_confidential_routes():
        assert route["provider"] == "venice"
        assert route["privacyClass"] == "e2ee"


def test_shipped_policy_offers_exactly_the_four() -> None:
    assert sorted(r["model"] for r in offered_confidential_routes()) == sorted(ALLOWED)


@pytest.mark.parametrize("model", WITHHELD)
def test_each_withheld_route_is_withheld(model: str) -> None:
    assert is_route_withheld_by_service("venice", model, "e2ee") is True


@pytest.mark.parametrize("model", ALLOWED)
def test_each_allowed_route_is_allowed(model: str) -> None:
    assert is_route_withheld_by_service("venice", model, "e2ee") is False


def test_other_routes_for_the_same_models_are_untouched() -> None:
    # Venice serves `z-ai/glm-5.1` as both `e2ee` and `private`, and Tinfoil
    # serves `openai/gpt-oss-120b` as `tee`. A model-keyed rule would take both
    # down while trying to withhold an encrypted route.
    assert is_route_withheld_by_service("venice", "z-ai/glm-5.1", "private") is False
    assert is_route_withheld_by_service("tinfoil", "openai/gpt-oss-120b", "tee") is False
    assert is_route_withheld_by_service("deepinfra", "z-ai/glm-5.1", "private") is False


def test_unknown_venice_e2ee_route_is_withheld_by_default() -> None:
    assert is_route_withheld_by_service("venice", "someone/new", "e2ee") is True
    for provider in ("chutes", "near-ai", "tinfoil"):
        assert is_route_withheld_by_service(provider, "someone/new", "e2ee") is False


def test_message_names_the_route_and_does_not_invite_a_retry() -> None:
    message = withheld_route_message("venice", "z-ai/glm-5.1", "e2ee")
    assert "z-ai/glm-5.1" in message
    assert "Nothing was sent" in message
    assert "retrying will not change it" in message
    assert withheld_route_classification("venice", "z-ai/glm-5.1", "e2ee")


def _watched_client(base_url: str) -> tuple[ConfidentialClient, list[str]]:
    """A client whose transport records every call, so "nothing was sent" is
    measured rather than assumed."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"ticket": "att"})

    client = ConfidentialClient(
        base_url=base_url,
        control_base_url=CONTROL,
        api_key="ar_test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return client, seen


@pytest.mark.parametrize("model", WITHHELD)
def test_chat_refuses_a_withheld_route_before_any_network_call(model: str) -> None:
    client, seen = _watched_client(PRODUCTION)
    with pytest.raises(ConfidentialError, match="not currently offering"):
        client.chat(model, "venice", [{"role": "user", "content": "canary"}], 16)
    # Refused BEFORE the first authenticated call: no ticket spent, no model
    # named to the service, and the content never left the process.
    assert seen == []


@pytest.mark.parametrize("model", ALLOWED)
def test_chat_does_not_refuse_an_allowed_route_on_policy_grounds(model: str) -> None:
    # THE POSITIVE CONTROL. The stub answers every path with a ticket shape, so
    # this call fails LATER, on evidence -- never with the policy refusal. A gate
    # that refused everything would pass the block above and fail here.
    client, _ = _watched_client(PRODUCTION)
    with pytest.raises(ConfidentialError) as excinfo:
        client.chat(model, "venice", [{"role": "user", "content": "canary"}], 16)
    assert "not currently offering" not in str(excinfo.value)


def test_policy_is_scoped_to_production_origins() -> None:
    # The policy describes AnonRouter's service. Applying it to somebody else's
    # deployment would be this SDK inventing policy for a catalog it has never
    # seen, and would make a private deployment unusable for no reason.
    client, _ = _watched_client("https://confidential.example")
    with pytest.raises(ConfidentialError) as excinfo:
        client.chat("z-ai/glm-5.1", "venice", [{"role": "user", "content": "x"}], 16)
    assert "not currently offering" not in str(excinfo.value)
