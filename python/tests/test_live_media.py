"""Live, credential-free validation of the media contract.

WHAT THIS COSTS: nothing. Every probe here is a POST the relay refuses before
any provider is dispatched, because it carries no ticket. No API key is sent, no
ticket is minted, no prompt is transmitted, and no generation is billed. That is
exactly the property being verified: both media routes FAIL CLOSED for an
unauthenticated caller.

What it cannot establish is that a generation succeeds. That needs a real
inference-scoped API key and a callable model, and it spends money, so it is
deliberately out of scope. See VERIFYING.md.

DEFAULT: skips with a stated reason. It is never silently green.

Mirrors ``js/confidential/test/live-media.test.ts``.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest

LIVE_ORIGIN = os.environ.get("ANONROUTER_LIVE_GATEWAY_ORIGIN")
PUBLIC_ORIGIN = os.environ.get("ANONROUTER_LIVE_PUBLIC_ORIGIN")

IMAGE_PATH = "/v1/images/generations"
SPEECH_PATH = "/v1/audio/speech"
TICKET_PATH = "/v1/inference/tickets"

live = pytest.mark.skipif(
    not LIVE_ORIGIN, reason="ANONROUTER_LIVE_GATEWAY_ORIGIN is not set: live media probes skipped"
)
control = pytest.mark.skipif(
    not PUBLIC_ORIGIN, reason="ANONROUTER_LIVE_PUBLIC_ORIGIN is not set: live media probes skipped"
)


def probe(origin: str, path: str, body: Any) -> tuple[int, str | None]:
    """POST with NO credential and NO ticket.

    The body is a placeholder that is never a real prompt: the request cannot
    reach a provider, because the relay rejects an absent ticket before it
    dispatches anything. Nothing here is billable and nothing here is private.
    """
    response = httpx.post(
        f"{origin}{path}",
        headers={"content-type": "application/json"},
        json=body,
        timeout=20.0,
    )
    error_type = None
    try:
        parsed = response.json()
        if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
            error_type = parsed["error"].get("type")
    except ValueError:
        pass
    return response.status_code, error_type


@live
@pytest.mark.parametrize(
    ("path", "body"),
    [
        (IMAGE_PATH, {"model": "probe", "prompt": "probe"}),
        (SPEECH_PATH, {"model": "probe", "input": "probe"}),
        (IMAGE_PATH, {}),
        (SPEECH_PATH, {}),
    ],
)
def test_the_confidential_origin_fails_closed_without_a_ticket(path: str, body: Any) -> None:
    assert LIVE_ORIGIN is not None
    status, error_type = probe(LIVE_ORIGIN, path, body)
    assert status == 401
    assert error_type == "ticket_required"


@live
def test_the_confidential_origin_does_not_mint_tickets() -> None:
    # 404, not 401. The confidential plane does not recognize the mint at all,
    # which keeps the API key off this host by construction rather than by the
    # client's good manners.
    assert LIVE_ORIGIN is not None
    status, _ = probe(LIVE_ORIGIN, TICKET_PATH, {"model": "probe", "operation": "image"})
    assert status == 404


@control
@pytest.mark.parametrize(
    ("path", "body"),
    [
        (IMAGE_PATH, {"model": "probe", "prompt": "probe"}),
        (SPEECH_PATH, {"model": "probe", "input": "probe"}),
    ],
)
def test_the_control_origin_serves_no_media_content(path: str, body: Any) -> None:
    # A control origin that started SERVING media content would be a privacy
    # regression invisible to every offline test in this repo, because the client
    # would keep working. This is the check that would catch it.
    assert PUBLIC_ORIGIN is not None
    status, error_type = probe(PUBLIC_ORIGIN, path, body)
    assert status != 200
    assert status in (503, 404)
    if status == 503:
        assert error_type == "media_disabled"


@control
def test_the_control_origin_serves_the_mint_and_requires_auth() -> None:
    assert PUBLIC_ORIGIN is not None
    status, _ = probe(PUBLIC_ORIGIN, TICKET_PATH, {"model": "probe", "operation": "image"})
    # 401 for a request that presented no key, or 403 for the browser CSRF guard
    # when no Authorization header is present at all. Never 404: that would mean
    # the SDK's whole mint path points at a route that does not exist.
    assert status in (401, 403)


@control
def test_an_unauthenticated_mint_is_refused_even_with_a_bearer_header() -> None:
    # With an Authorization header the CSRF guard is bypassed and real
    # authentication answers. A bogus key must be refused, never accepted.
    response = httpx.post(
        f"{PUBLIC_ORIGIN}{TICKET_PATH}",
        headers={
            "content-type": "application/json",
            "authorization": "Bearer not-a-real-key-credential-free-probe",
        },
        json={"model": "probe", "operation": "image"},
        timeout=20.0,
    )
    assert response.status_code == 401


def test_the_probe_helper_sends_no_credential() -> None:
    # The probe helper is the only thing here that talks to a network. This pins
    # that it carries no authorization header and no ticket: a future edit adding
    # one would make these probes billable.
    import inspect

    source = inspect.getsource(probe)
    assert "authorization" not in source
    assert "x-anonrouter-ticket" not in source
