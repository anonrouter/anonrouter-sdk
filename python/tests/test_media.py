"""Ticketed media: the exact wire contract, and the negatives that must stay red.

The Python half of the media parity gate. It replays the SAME
``shared/vectors/media-contract.json`` the JavaScript suite does, so a request
shape that changes in one language and not the other fails in both.

Most of these tests are planted to fail on a specific regression rather than to
describe a feature:

  - a prompt or speech input reaching the control origin
  - the API key reaching the relay
  - a ticket bound to different facts than were requested
  - a ticket used twice
  - a POST retried, which would be a second billable generation
  - a malformed media payload accepted and handed to the caller
"""

from __future__ import annotations

import base64
import json
import pathlib
from typing import Any

import httpx
import pytest

from anonrouter_confidential import (
    ConfidentialError,
    MediaError,
    canonical_image_size,
    create_client,
    redact_headers,
    utf16_length,
)

VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "shared/vectors/media-contract.json").read_text()
)
CONTROL = VECTORS["control_origin"]
INFERENCE = VECTORS["inference_origin"]
API_KEY = VECTORS["api_key"]
TICKET_HEADER = VECTORS["ticket_header"]

PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAE"
    "hQGAhKmMIQAAAABJRU5ErkJggg=="
)
PNG_BYTES = base64.b64decode(PNG_B64)
MP3_BYTES = bytes([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x11])


class Recorder:
    """A recording httpx transport driven by a response handler.

    Records the FULL request, including the raw serialized body, so a test can
    assert on what went on the wire rather than on what the client meant to send.
    """

    def __init__(self, handler: Any) -> None:
        self.calls: list[httpx.Request] = []
        self._handler = handler

    def transport(self) -> httpx.MockTransport:
        def respond(request: httpx.Request) -> httpx.Response:
            self.calls.append(request)
            return self._handler(request, len(self.calls) - 1)

        return httpx.MockTransport(respond)

    def control(self) -> list[httpx.Request]:
        return [c for c in self.calls if str(c.url).startswith(CONTROL)]

    def inference(self) -> list[httpx.Request]:
        return [c for c in self.calls if str(c.url).startswith(INFERENCE)]


def json_response(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status, json=body, headers={"content-type": "application/json", **(headers or {})}
    )


def image_ok(headers: dict[str, str] | None = None) -> httpx.Response:
    return json_response(
        {
            "created": 1_700_000_000,
            "model": "venice/flux-dev",
            "data": [{"b64_json": PNG_B64, "mime_type": "image/png"}],
        },
        headers=headers,
    )


def speech_ok(headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        200, content=MP3_BYTES, headers={"content-type": "audio/mpeg", **(headers or {})}
    )


def error_response(status: int, error_type: str) -> httpx.Response:
    return json_response(
        {"error": {"message": "refused", "type": error_type, "request_id": "req_test"}},
        status=status,
    )


def make_client(rec: Recorder, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "inference_base_url": INFERENCE,
        "control_base_url": CONTROL,
        "api_key": API_KEY,
        "http_client": httpx.Client(transport=rec.transport()),
    }
    kwargs.update(overrides)
    return create_client(**kwargs)


def invoke(client: Any, api: str, args: dict[str, Any]) -> Any:
    """Call a vector case by its declared accessor path."""
    if api == "images.generate":
        return client.images.generate(**args)
    return client.audio.speech.create(**args)


def body_of(request: httpx.Request) -> Any:
    return json.loads(request.content.decode())


# ---- The shared wire contract -----------------------------------------------


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_media_wire_contract(case: dict[str, Any]) -> None:
    def handler(request: httpx.Request, index: int) -> httpx.Response:
        if index == 0:
            return json_response(case["ticket_response"])
        return image_ok() if case["api"] == "images.generate" else speech_ok()

    rec = Recorder(handler)
    invoke(make_client(rec), case["api"], case["args"])

    # Exactly two requests: one mint, one content. Nothing else, in either
    # direction, for either operation.
    assert len(rec.calls) == 2

    for request, expected in ((rec.calls[0], case["mint"]), (rec.calls[1], case["content"])):
        origin = CONTROL if expected["origin"] == "control" else INFERENCE
        assert str(request.url) == f"{origin}{expected['path']}"
        assert request.method == expected["method"]
        # EXACT body equality, key for key. The server schemas are strict, so an
        # extra key is a 400 and a missing one is an unbound fact.
        assert body_of(request) == expected["body"]
        for header in expected["headers_present"]:
            assert header in request.headers, f"{expected['path']} must send {header}"
        for header in expected["headers_absent"]:
            assert header not in request.headers, f"{expected['path']} must NOT send {header}"

    assert rec.calls[1].headers[TICKET_HEADER] == case["ticket_response"]["ticket"]
    if "expected_input_chars" in case:
        assert body_of(rec.calls[0])["input_chars"] == case["expected_input_chars"]


@pytest.mark.parametrize(
    "refusal", VECTORS["refusals"], ids=[r["name"] for r in VECTORS["refusals"]]
)
def test_media_refusals(refusal: dict[str, Any]) -> None:
    rec = Recorder(lambda _r, _i: json_response({"ticket": "should-never-be-minted"}))
    with pytest.raises(MediaError) as caught:
        invoke(make_client(rec), refusal["api"], refusal["args"])
    assert caught.value.code == refusal["code"]
    # A refusal must happen BEFORE any network call: an unsatisfiable request
    # that mints first would burn a single-use ticket for nothing.
    assert rec.calls == []


# ---- PLANTED NEGATIVE: content must never reach the control origin ----------


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_control_origin_never_sees_content(case: dict[str, Any]) -> None:
    def handler(request: httpx.Request, index: int) -> httpx.Response:
        if index == 0:
            return json_response(case["ticket_response"])
        return image_ok() if case["api"] == "images.generate" else speech_ok()

    rec = Recorder(handler)
    invoke(make_client(rec), case["api"], case["args"])

    mint = rec.calls[0]
    # Scan the WHOLE request, not just the body: a probe string in the URL, a
    # header, or a stray field would be just as much of a leak.
    everything = f"{mint.url}\n{dict(mint.headers)}\n{mint.content.decode()}"
    assert case["probe"] not in everything
    content = case["args"].get("prompt") or case["args"].get("input")
    assert content not in everything
    # And the field names themselves are absent, so a future refactor cannot add
    # an empty `prompt: ""` and satisfy a substring check.
    assert "prompt" not in body_of(mint)
    assert "input" not in body_of(mint)


def test_a_failed_mint_never_reaches_the_relay() -> None:
    rec = Recorder(lambda _r, _i: error_response(402, "insufficient_balance"))
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="SECRET-PROMPT")
    assert caught.value.code == "media_ticket_failed"
    assert rec.inference() == []
    assert len(rec.calls) == 1


# ---- PLANTED NEGATIVE: the API key must never reach the relay ----------------


def test_inference_origin_never_sees_the_api_key() -> None:
    rec = Recorder(
        lambda _r, i: json_response({"ticket": "tkt"}) if i == 0 else image_ok()
    )
    make_client(rec).images.generate(model="m", prompt="a boat")

    content = rec.inference()[0]
    assert "authorization" not in content.headers
    assert "cookie" not in content.headers
    everything = f"{content.url}\n{dict(content.headers)}\n{content.content.decode()}"
    assert API_KEY not in everything


def test_the_api_key_goes_to_the_mint_and_only_there() -> None:
    rec = Recorder(
        lambda _r, i: json_response({"ticket": "tkt"}) if i == 0 else speech_ok()
    )
    make_client(rec).audio.speech.create(model="m", input="hello")

    assert rec.control()[0].headers["authorization"] == f"Bearer {API_KEY}"
    assert "authorization" not in rec.inference()[0].headers


# ---- PLANTED NEGATIVE: ticket facts must not drift --------------------------


@pytest.mark.parametrize(
    ("what", "echo", "args"),
    [
        (
            "operation",
            {"ticket": "t", "operation": "chat", "model": "m", "size": "1024x1024", "response_format": "b64_json"},
            {"model": "m", "prompt": "p"},
        ),
        (
            "model",
            {"ticket": "t", "operation": "image", "model": "other", "size": "1024x1024", "response_format": "b64_json"},
            {"model": "m", "prompt": "p"},
        ),
        (
            "size",
            {"ticket": "t", "operation": "image", "model": "m", "size": "512x512", "response_format": "b64_json"},
            {"model": "m", "prompt": "p", "size": "1024x1024"},
        ),
        (
            "response_format",
            {"ticket": "t", "operation": "image", "model": "m", "size": "1024x1024", "response_format": "url"},
            {"model": "m", "prompt": "p"},
        ),
    ],
)
def test_image_ticket_drift_stops_the_exchange(
    what: str, echo: dict[str, Any], args: dict[str, Any]
) -> None:
    rec = Recorder(lambda _r, _i: json_response(echo))
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(**args)
    assert caught.value.code == "ticket_binding_mismatch", what
    # THE POINT: the prompt was never sent anywhere.
    assert rec.inference() == []
    assert len(rec.calls) == 1


def test_speech_input_length_drift_stops_the_exchange() -> None:
    rec = Recorder(
        lambda _r, _i: json_response(
            {"ticket": "t", "operation": "speech", "model": "m", "input_chars": 999, "response_format": "mp3"}
        )
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).audio.speech.create(model="m", input="hello")
    assert caught.value.code == "ticket_binding_mismatch"
    assert rec.inference() == []


def test_speech_voice_drift_stops_the_exchange() -> None:
    rec = Recorder(
        lambda _r, _i: json_response(
            {
                "ticket": "t",
                "operation": "speech",
                "model": "m",
                "input_chars": 5,
                "response_format": "mp3",
                "voice": "other",
            }
        )
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).audio.speech.create(model="m", input="hello", voice="af_sky")
    assert caught.value.code == "ticket_binding_mismatch"
    assert rec.inference() == []


def test_an_unrequested_voice_is_drift_too() -> None:
    # The relay compares (bound voice or None) with (body voice or None), so a
    # ticket carrying a voice would be redeemed against a body with none.
    rec = Recorder(
        lambda _r, _i: json_response(
            {
                "ticket": "t",
                "operation": "speech",
                "model": "m",
                "input_chars": 5,
                "response_format": "mp3",
                "voice": "af_sky",
            }
        )
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).audio.speech.create(model="m", input="hello")
    assert caught.value.code == "ticket_binding_mismatch"
    assert rec.inference() == []


def test_a_missing_echo_is_tolerated() -> None:
    # An older gateway that does not echo the binding is not proof of drift.
    rec = Recorder(lambda _r, i: json_response({"ticket": "tkt"}) if i == 0 else image_ok())
    assert make_client(rec).images.generate(model="m", prompt="p").data


@pytest.mark.parametrize("bad", [{}, {"ticket": ""}, {"ticket": 42}, {"ticket": None}])
def test_an_unusable_ticket_never_reaches_the_relay(bad: dict[str, Any]) -> None:
    rec = Recorder(lambda _r, _i: json_response(bad))
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.code == "media_ticket_failed"
    assert rec.inference() == []


# ---- PLANTED NEGATIVE: single use, and no retry ------------------------------


def test_every_call_mints_a_fresh_ticket() -> None:
    minted = 0

    def handler(request: httpx.Request, _index: int) -> httpx.Response:
        nonlocal minted
        if str(request.url).startswith(CONTROL):
            minted += 1
            return json_response({"ticket": f"tkt_{minted}"})
        return image_ok()

    rec = Recorder(handler)
    client = make_client(rec)
    client.images.generate(model="m", prompt="one")
    client.images.generate(model="m", prompt="two")

    assert len(rec.control()) == 2
    presented = [c.headers[TICKET_HEADER] for c in rec.inference()]
    assert presented == ["tkt_1", "tkt_2"]
    # A reused ticket would show up as the same value twice.
    assert len(set(presented)) == 2


@pytest.mark.parametrize("status", [500, 502, 503, 429, 408])
def test_a_failed_content_post_is_never_retried(status: int) -> None:
    # A media generation is billed on the provider attempt, so a transparent
    # retry is a duplicate charge for a caller who made one call.
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else error_response(status, "upstream_error")
    )
    with pytest.raises(MediaError):
        make_client(rec).images.generate(model="m", prompt="p")
    assert len(rec.inference()) == 1, f"status {status} must not be retried"


def test_a_failed_mint_is_never_retried() -> None:
    rec = Recorder(lambda _r, _i: error_response(500, "internal"))
    with pytest.raises(MediaError):
        make_client(rec).images.generate(model="m", prompt="p")
    assert len(rec.control()) == 1


def test_a_transport_failure_is_not_retried() -> None:
    attempts = 0

    def handler(request: httpx.Request, _index: int) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if str(request.url).startswith(CONTROL):
            return json_response({"ticket": "tkt"})
        raise httpx.ConnectError("socket hang up", request=request)

    rec = Recorder(handler)
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.code == "transport_failed"
    assert attempts == 2


# ---- Typed errors ------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "error_type", "code"),
    [
        (401, "ticket_required", "relay_refused"),
        (401, "invalid_ticket", "ticket_rejected"),
        (409, "ticket_model_mismatch", "ticket_rejected"),
        (409, "ticket_input_length_mismatch", "ticket_rejected"),
        (503, "media_disabled", "relay_refused"),
        (402, "insufficient_balance", "relay_refused"),
        (429, "rate_limited", "relay_refused"),
        (500, "provider_error", "provider_failed"),
        (502, "provider_unavailable", "provider_failed"),
    ],
)
def test_typed_errors_for_relay_statuses(status: int, error_type: str, code: str) -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else error_response(status, error_type)
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.code == code
    assert caught.value.diagnostics.status == status
    assert caught.value.diagnostics.error_type == error_type


def test_a_deadline_is_reported_as_timeout() -> None:
    def handler(request: httpx.Request, _index: int) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    rec = Recorder(handler)
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.code == "timeout"


# ---- PLANTED NEGATIVE: secrets and prompts stay out of errors ----------------


def test_errors_never_carry_the_prompt_the_key_or_the_ticket() -> None:
    prompt = "SECRET-PROMPT-DO-NOT-LEAK"

    def handler(request: httpx.Request, _index: int) -> httpx.Response:
        if str(request.url).startswith(CONTROL):
            return json_response({"ticket": "SECRET-TICKET-DO-NOT-LEAK"})
        # An error body that quotes the prompt back is exactly the shape that
        # leaks it into a log if the client passes the body through.
        return json_response(
            {"error": {"message": f"rejected prompt: {prompt}", "type": "content_policy"}},
            status=400,
        )

    rec = Recorder(handler)
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt=prompt)

    serialized = f"{caught.value}\n{caught.value.diagnostics}"
    assert prompt not in serialized
    assert API_KEY not in serialized
    assert "SECRET-TICKET-DO-NOT-LEAK" not in serialized
    # The machine-readable type IS kept: it is content-free and it is what a
    # caller branches on.
    assert caught.value.diagnostics.error_type == "content_policy"


def test_redact_headers_keeps_names_and_drops_values() -> None:
    assert redact_headers(
        {
            "authorization": "Bearer ar-secret",
            "Cookie": "session=abc",
            "x-anonrouter-ticket": "tkt-secret",
            "content-type": "application/json",
        }
    ) == {
        "authorization": "<redacted>",
        "Cookie": "<redacted>",
        "x-anonrouter-ticket": "<redacted>",
        "content-type": "application/json",
    }


def test_diagnostics_carry_only_redacted_headers() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt-secret"})
        if str(r.url).startswith(CONTROL)
        else error_response(401, "invalid_ticket")
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.diagnostics.headers["x-anonrouter-ticket"] == "<redacted>"
    assert "tkt-secret" not in str(caught.value.diagnostics)
    # The origin IS reported: a misconfiguration is the likeliest cause and
    # naming it is not a leak.
    assert caught.value.diagnostics.origin == INFERENCE


# ---- PLANTED NEGATIVE: malformed media must not be accepted ------------------


@pytest.mark.parametrize(
    ("what", "body"),
    [
        ("a non-object envelope", []),
        ("no data array", {"created": 1, "model": "m"}),
        ("an empty data array", {"created": 1, "model": "m", "data": []}),
        ("an entry that is not an object", {"data": ["nope"]}),
        ("a missing b64_json", {"data": [{"mime_type": "image/png"}]}),
        ("an empty b64_json", {"data": [{"b64_json": "", "mime_type": "image/png"}]}),
        ("a non-string b64_json", {"data": [{"b64_json": 5, "mime_type": "image/png"}]}),
        ("illegal base64 characters", {"data": [{"b64_json": "!!!nope!!!", "mime_type": "image/png"}]}),
        ("base64 of the wrong length", {"data": [{"b64_json": "abcde", "mime_type": "image/png"}]}),
        ("a missing mime type", {"data": [{"b64_json": PNG_B64}]}),
        ("a non-image mime type", {"data": [{"b64_json": PNG_B64, "mime_type": "text/html"}]}),
    ],
)
def test_malformed_image_payloads_are_refused(what: str, body: Any) -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else json_response(body)
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.code == "response_invalid", what


def test_a_non_json_image_body_is_refused() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else httpx.Response(200, content=b"<html>gateway error</html>", headers={"content-type": "text/html"})
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).images.generate(model="m", prompt="p")
    assert caught.value.code == "response_invalid"


def test_a_non_audio_speech_body_is_refused() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else json_response({"not": "audio"})
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).audio.speech.create(model="m", input="x")
    assert caught.value.code == "response_invalid"


def test_an_empty_audio_body_is_refused() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else httpx.Response(200, content=b"", headers={"content-type": "audio/mpeg"})
    )
    with pytest.raises(MediaError) as caught:
        make_client(rec).audio.speech.create(model="m", input="x")
    assert caught.value.code == "response_invalid"


def test_a_well_formed_image_decodes() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else image_ok()
    )
    result = make_client(rec).images.generate(model="m", prompt="p")
    assert result.data[0].b64_json == PNG_B64
    assert result.data[0].mime_type == "image/png"
    # A real PNG signature, so the decode is not merely non-empty.
    assert result.data[0].data[:4] == b"\x89PNG"


# ---- Response metadata -------------------------------------------------------


def test_image_metadata_is_preserved() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else image_ok(
            {
                "x-anonrouter-selected-model": "venice/flux-dev",
                "x-anonrouter-routing": "exact",
                "x-anonrouter-provider-blurred": "false",
                "x-anonrouter-provider-content-violation": "true",
                "x-ratelimit-limit-requests": "100",
                "x-ratelimit-remaining-requests": "99",
            }
        )
    )
    result = make_client(rec).images.generate(model="m", prompt="p")
    assert result.selected_model == "venice/flux-dev"
    assert result.routing == "exact"
    assert result.provider_blurred is False
    assert result.provider_content_violation is True
    assert result.rate_limit is not None
    assert result.rate_limit.limit_requests == 100
    assert result.rate_limit.remaining_requests == 99
    assert result.created == 1_700_000_000


def test_speech_returns_bytes_and_content_type(tmp_path: pathlib.Path) -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else speech_ok({"x-anonrouter-selected-model": "venice/tts-kokoro"})
    )
    result = make_client(rec).audio.speech.create(model="m", input="x")
    assert result.audio == MP3_BYTES
    assert result.content_type == "audio/mpeg"
    assert result.selected_model == "venice/tts-kokoro"
    # The stream-friendly convenience a caller actually reaches for.
    out = tmp_path / "speech.mp3"
    assert result.write_to(str(out)) == len(MP3_BYTES)
    assert out.read_bytes() == MP3_BYTES


def test_absent_metadata_is_not_invented() -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else image_ok()
    )
    result = make_client(rec).images.generate(model="m", prompt="p")
    assert result.selected_model is None
    assert result.rate_limit is None
    assert result.provider_blurred is None


# ---- Configuration: the boundary cannot be collapsed -------------------------


def test_media_is_refused_when_both_roles_share_a_remote_origin() -> None:
    rec = Recorder(lambda _r, _i: json_response({"ticket": "tkt"}))
    client = create_client(
        INFERENCE, api_key=API_KEY, http_client=httpx.Client(transport=rec.transport())
    )
    for call in (
        lambda: client.images.generate(model="m", prompt="p"),
        lambda: client.audio.speech.create(model="m", input="x"),
    ):
        with pytest.raises(ConfidentialError, match="two distinct origins"):
            call()
    # Refused before anything was sent.
    assert rec.calls == []


def test_a_single_origin_client_keeps_verification_and_chat() -> None:
    # No breaking change: only media needs the stronger configuration.
    client = create_client(INFERENCE, api_key=API_KEY)
    assert callable(client.verify_route)
    assert callable(client.chat)


def test_a_single_loopback_origin_is_allowed_under_the_documented_override() -> None:
    rec = Recorder(lambda _r, i: json_response({"ticket": "tkt"}) if i == 0 else image_ok())
    client = create_client(
        "http://127.0.0.1:8080",
        api_key=API_KEY,
        allow_insecure_http=True,
        http_client=httpx.Client(transport=rec.transport()),
    )
    assert client.images.generate(model="m", prompt="p").data


def test_disagreeing_origins_are_refused_rather_than_resolved() -> None:
    with pytest.raises(ConfidentialError, match="must not disagree"):
        create_client(
            "https://one.invalid", api_key=API_KEY, inference_base_url="https://two.invalid"
        )


def test_nothing_configured_defaults_to_the_production_pair() -> None:
    client = create_client(api_key=API_KEY)
    assert client.control_origin == "https://api.anonrouter.ai"
    assert client.origin == "https://api.private.anonrouter.ai"


def test_control_still_defaults_to_base_url_for_an_existing_caller() -> None:
    # Preserving this is what makes the change non-breaking: a caller who set
    # only base_url must not suddenly start sending their key somewhere else.
    client = create_client("https://solo.invalid", api_key=API_KEY)
    assert client.control_origin == "https://solo.invalid"
    assert client.origin == "https://solo.invalid"


# ---- Input validation --------------------------------------------------------


@pytest.mark.parametrize(
    ("what", "api", "args"),
    [
        ("a missing model", "images.generate", {"model": "", "prompt": "p"}),
        ("a non-string prompt", "images.generate", {"model": "m", "prompt": 5}),
        ("a size below the floor", "images.generate", {"model": "m", "prompt": "p", "size": "100x100"}),
        ("an over-long prompt", "images.generate", {"model": "m", "prompt": "x" * 10_001}),
        ("an over-long speech input", "audio.speech.create", {"model": "m", "input": "x" * 20_001}),
        ("an over-long voice", "audio.speech.create", {"model": "m", "input": "x", "voice": "v" * 65}),
        ("an empty voice", "audio.speech.create", {"model": "m", "input": "x", "voice": ""}),
    ],
)
def test_input_validation_refuses_before_minting(what: str, api: str, args: dict[str, Any]) -> None:
    rec = Recorder(lambda _r, _i: json_response({"ticket": "should-never-be-minted"}))
    with pytest.raises(MediaError) as caught:
        invoke(make_client(rec), api, args)
    assert caught.value.code == "unsupported_request", what
    assert rec.calls == []


def test_an_unknown_keyword_is_a_type_error_not_a_silent_drop() -> None:
    # Python's own keyword handling is the strictness here: `quality="hd"` is a
    # TypeError, so an OpenAI parameter AnonRouter does not serve can never be
    # accepted and quietly ignored.
    rec = Recorder(lambda _r, _i: json_response({"ticket": "no"}))
    with pytest.raises(TypeError):
        make_client(rec).images.generate(model="m", prompt="p", quality="hd")
    assert rec.calls == []


@pytest.mark.parametrize("size", ["128x128", "2048x2048"])
def test_the_exact_server_bounds_are_accepted(size: str) -> None:
    rec = Recorder(
        lambda r, _i: json_response({"ticket": "tkt"})
        if str(r.url).startswith(CONTROL)
        else image_ok()
    )
    assert make_client(rec).images.generate(model="m", prompt="p", size=size).data


# ---- The character-count trap ------------------------------------------------


def test_the_priced_unit_is_utf16_code_units() -> None:
    # THE CROSS-LANGUAGE TRAP. len() counts code points; the server counts UTF-16
    # code units. Using len() would 409 on exactly the inputs containing emoji.
    assert utf16_length("Hi \U0001f600") == 5
    assert len("Hi \U0001f600") == 4
    assert utf16_length("plain") == 5
    assert utf16_length("\U0001f600\U0001f600") == 4


def test_the_bound_count_matches_the_text_that_is_sent() -> None:
    text = "emoji \U0001f600 and more \U0001f3a7"
    rec = Recorder(
        lambda r, _i: json_response(
            {"ticket": "tkt", "operation": "speech", "input_chars": utf16_length(text)}
        )
        if str(r.url).startswith(CONTROL)
        else speech_ok()
    )
    make_client(rec).audio.speech.create(model="m", input=text)
    minted = body_of(rec.control()[0])["input_chars"]
    sent = body_of(rec.inference()[0])["input"]
    assert minted == utf16_length(sent)
    assert minted != len(sent)


def test_canonical_image_size() -> None:
    assert canonical_image_size("1024x1024") == "1024x1024"
    assert canonical_image_size("0512x0512") == "512x512"
    for bad in ("big", "12x12", "4096x4096", "1024", "1024x", "100x100"):
        with pytest.raises(MediaError):
            canonical_image_size(bad)
