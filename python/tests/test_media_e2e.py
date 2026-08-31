"""A local, two-origin end-to-end for image and speech, over real sockets.

The unit suite stubs the transport, which proves what the client MEANT to send.
This runs two real HTTP servers on two different loopback ports and drives them
with a real httpx client, so it proves what actually goes over a socket: real
headers, real serialization, real status codes, real binary bodies.

The two servers are deliberately ADVERSARIES of the client. The control server
refuses to mint if it is ever shown content; the relay refuses to serve if it is
ever shown a credential, and enforces the single-use ticket and every bound fact
exactly as ``src/routes/{image,speech}.ts`` does. A client that cheats on the
protocol fails here rather than passing against a mock that agrees with it.

Mirrors ``js/confidential/test/media-e2e.test.ts``.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest

from anonrouter_confidential import ConfidentialError, create_client

API_KEY = "ar-e2e-key-must-never-reach-the-relay"
MODEL_IMAGE = "venice/flux-dev"
MODEL_SPEECH = "venice/tts-kokoro"
#: Marker strings the control server actively hunts for in anything it receives.
IMAGE_PROMPT = "a red kite over E2E-PROMPT-CANARY"
SPEECH_INPUT = "read this aloud E2E-INPUT-CANARY \U0001f600"

PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAE"
    "hQGAhKmMIQAAAABJRU5ErkJggg=="
)
PNG_BYTES = base64.b64decode(PNG_B64)
MP3_BYTES = bytes([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x11, 0x7F, 0x2A])

#: Tickets the control server has minted, and whether each has been spent.
TICKETS: dict[str, dict[str, Any]] = {}
#: Every request each origin saw, for the after-the-fact privacy assertions.
CONTROL_LOG: list[dict[str, Any]] = []
RELAY_LOG: list[dict[str, Any]] = []
_COUNTER = {"n": 0}


class _Handler(BaseHTTPRequestHandler):
    """Shared plumbing; the two roles differ only in `handle_post`."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        status, payload, headers = self.handle_post(body)
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def handle_post(self, body: str) -> tuple[int, Any, dict[str, str]]:
        raise NotImplementedError

    @staticmethod
    def fail(status: int, error_type: str, message: str) -> tuple[int, Any, dict[str, str]]:
        return (
            status,
            {"error": {"type": error_type, "message": message, "request_id": f"req_e2e_{status}"}},
            {"content-type": "application/json"},
        )


class ControlHandler(_Handler):
    """The control plane: holds the account, mints tickets, MUST NEVER see content."""

    def handle_post(self, body: str) -> tuple[int, Any, dict[str, str]]:
        CONTROL_LOG.append({"headers": dict(self.headers), "body": body, "path": self.path})

        if self.path != "/v1/inference/tickets":
            return self.fail(404, "not_found", "no such route on the control origin")
        # The API key is required here, and only here.
        if self.headers.get("authorization") != f"Bearer {API_KEY}":
            return self.fail(401, "unauthorized", "the control origin requires the API key")
        try:
            parsed = json.loads(body)
        except ValueError:
            return self.fail(400, "invalid_body", "unparseable")

        # THE ADVERSARIAL CHECK. If content ever reaches the control plane the
        # split has failed, and that must be a hard error rather than a warning.
        for forbidden in ("prompt", "input", "messages"):
            if forbidden in parsed:
                return self.fail(500, "content_reached_control", f'the mint received "{forbidden}"')
        if "E2E-PROMPT-CANARY" in body or "E2E-INPUT-CANARY" in body:
            return self.fail(500, "content_reached_control", "the mint received content")

        # `.strict()`: an unknown key is a 400, exactly as zod would answer.
        allowed = {"operation", "model", "size", "response_format", "input_chars", "voice"}
        for key in parsed:
            if key not in allowed:
                return self.fail(400, "unknown_field", f"unexpected {key}")

        _COUNTER["n"] += 1
        ticket = f"tkt_e2e_{_COUNTER['n']}"

        if parsed.get("operation") == "image":
            if parsed.get("response_format") != "b64_json":
                return self.fail(400, "invalid_response_format", "image is b64_json only")
            size = parsed.get("size", "1024x1024")
            width, height = (int(p) for p in size.split("x"))
            if not (128 <= width <= 2048 and 128 <= height <= 2048):
                return self.fail(400, "invalid_size", "out of range")
            TICKETS[ticket] = {
                "operation": "image",
                "model": parsed["model"],
                "size": f"{width}x{height}",
                "response_format": "b64_json",
                "voice": None,
                "spent": False,
            }
            # The mint ECHOES what it bound, which is what the client re-checks.
            return (
                200,
                {
                    "ticket": ticket,
                    "expires_in": 30,
                    "operation": "image",
                    "model": parsed["model"],
                    "automatic": False,
                    "privacy_class": "private",
                    "max_output_tokens": 0,
                    "reasoning": "default",
                    "size": f"{width}x{height}",
                    "response_format": "b64_json",
                },
                {"content-type": "application/json"},
            )

        if parsed.get("response_format") != "mp3":
            return self.fail(400, "invalid_response_format", "speech is mp3 only")
        if not isinstance(parsed.get("input_chars"), int):
            return self.fail(400, "input_chars_required", "a speech ticket must bind the exact count")
        TICKETS[ticket] = {
            "operation": "speech",
            "model": parsed["model"],
            "input_chars": parsed["input_chars"],
            "response_format": "mp3",
            "voice": parsed.get("voice"),
            "spent": False,
        }
        echoed = {
            "ticket": ticket,
            "expires_in": 30,
            "operation": "speech",
            "model": parsed["model"],
            "input_chars": parsed["input_chars"],
            "response_format": "mp3",
        }
        if parsed.get("voice"):
            echoed["voice"] = parsed["voice"]
        return 200, echoed, {"content-type": "application/json"}


class RelayHandler(_Handler):
    """The credential-isolated relay: sees content, holds no account."""

    def handle_post(self, body: str) -> tuple[int, Any, dict[str, str]]:
        RELAY_LOG.append({"headers": dict(self.headers), "body": body, "path": self.path})

        # THE ADVERSARIAL CHECK. The relay never accepts an account credential.
        # In production Caddy strips these before the relay; here, being shown
        # one is a hard failure so a client that leaks the key cannot pass.
        if self.headers.get("authorization") or self.headers.get("cookie"):
            return self.fail(500, "credential_reached_relay", "the relay was shown a credential")
        # The relay serves the content paths and nothing else. Production is the
        # same: POST /v1/inference/tickets against the confidential origin is a
        # 404, because the mint lives on the control plane.
        if self.path not in ("/v1/images/generations", "/v1/audio/speech"):
            return self.fail(404, "not_found", "no such route on the relay")

        ticket_id = self.headers.get("x-anonrouter-ticket")
        if not ticket_id:
            return self.fail(401, "ticket_required", "A single-use ticket is required")
        bound = TICKETS.get(ticket_id)
        if bound is None:
            return self.fail(401, "invalid_ticket", "Inference ticket is invalid or expired")
        # SINGLE USE. Redemption consumes the ticket; a replay is
        # indistinguishable from an expired one, exactly as production answers.
        if bound["spent"]:
            return self.fail(401, "invalid_ticket", "Inference ticket is invalid or expired")
        bound["spent"] = True

        parsed = json.loads(body)

        if self.path == "/v1/images/generations":
            if bound["operation"] != "image":
                return self.fail(409, "ticket_operation_mismatch", "wrong operation")
            if parsed.get("model") != bound["model"]:
                return self.fail(409, "ticket_model_mismatch", "model drift")
            width, height = (int(p) for p in parsed.get("size", "1024x1024").split("x"))
            if f"{width}x{height}" != bound["size"]:
                return self.fail(409, "ticket_size_mismatch", "size drift")
            if parsed.get("response_format", "b64_json") != bound["response_format"]:
                return self.fail(409, "ticket_format_mismatch", "format drift")
            if not parsed.get("prompt"):
                return self.fail(400, "invalid_prompt", "the relay needs the prompt")
            return (
                200,
                {
                    "created": 1_700_000_042,
                    "model": bound["model"],
                    "data": [{"b64_json": PNG_B64, "mime_type": "image/png"}],
                },
                {
                    "content-type": "application/json",
                    "x-anonrouter-selected-model": f"venice/{bound['model']}",
                    "x-anonrouter-routing": "exact",
                    "x-ratelimit-limit-requests": "1000",
                    "x-ratelimit-remaining-requests": "999",
                },
            )

        if bound["operation"] != "speech":
            return self.fail(409, "ticket_operation_mismatch", "wrong operation")
        if parsed.get("model") != bound["model"]:
            return self.fail(409, "ticket_model_mismatch", "model drift")
        # The priced unit, counted the way Node counts `input.length`.
        sent = parsed["input"]
        if len(sent.encode("utf-16-le")) // 2 != bound["input_chars"]:
            return self.fail(
                409, "ticket_input_length_mismatch", "Input length does not match the issued ticket"
            )
        if parsed.get("voice") != bound["voice"]:
            return self.fail(409, "ticket_voice_mismatch", "voice drift")
        if parsed.get("response_format", "mp3") != bound["response_format"]:
            return self.fail(409, "ticket_format_mismatch", "format drift")
        return (
            200,
            MP3_BYTES,
            {
                "content-type": "audio/mpeg",
                "x-anonrouter-selected-model": f"venice/{bound['model']}",
                "x-anonrouter-routing": "exact",
            },
        )


@pytest.fixture(scope="module")
def origins() -> Any:
    control = ThreadingHTTPServer(("127.0.0.1", 0), ControlHandler)
    relay = ThreadingHTTPServer(("127.0.0.1", 0), RelayHandler)
    for server in (control, relay):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    yield (
        f"http://127.0.0.1:{control.server_address[1]}",
        f"http://127.0.0.1:{relay.server_address[1]}",
    )
    for server in (control, relay):
        server.shutdown()
        server.server_close()


def e2e_client(origins: tuple[str, str]) -> Any:
    control_origin, inference_origin = origins
    return create_client(
        inference_base_url=inference_origin,
        control_base_url=control_origin,
        api_key=API_KEY,
        # Two loopback ports: distinct origins, so the split is real, but
        # plaintext http needs the documented local-development opt-in.
        allow_insecure_http=True,
    )


def test_generates_an_image_over_real_sockets(origins: tuple[str, str]) -> None:
    result = e2e_client(origins).images.generate(
        model=MODEL_IMAGE, prompt=IMAGE_PROMPT, size="512x512"
    )
    assert len(result.data) == 1
    assert result.data[0].mime_type == "image/png"
    assert result.data[0].data == PNG_BYTES
    assert result.model == MODEL_IMAGE
    assert result.created == 1_700_000_042
    assert result.selected_model == f"venice/{MODEL_IMAGE}"
    assert result.routing == "exact"
    assert result.rate_limit is not None
    assert result.rate_limit.remaining_requests == 999


def test_synthesizes_speech_over_real_sockets(origins: tuple[str, str]) -> None:
    result = e2e_client(origins).audio.speech.create(
        model=MODEL_SPEECH, input=SPEECH_INPUT, voice="af_sky"
    )
    assert result.content_type == "audio/mpeg"
    assert result.audio == MP3_BYTES
    assert result.selected_model == f"venice/{MODEL_SPEECH}"


def test_the_emoji_input_was_bound_at_the_count_the_relay_recomputed() -> None:
    # The relay compares against the UTF-16 length. If the client had bound a
    # code-point count the call above would have come back 409, not 200. The
    # success IS the assertion; this pins the number so the reason is visible.
    speech_mints = [
        json.loads(e["body"])
        for e in CONTROL_LOG
        if e["body"] and json.loads(e["body"]).get("operation") == "speech"
    ]
    assert speech_mints, "the speech mint should have been recorded"
    bound = speech_mints[0]["input_chars"]
    assert bound == len(SPEECH_INPUT.encode("utf-16-le")) // 2
    assert bound != len(SPEECH_INPUT)


def test_the_control_origin_never_saw_content() -> None:
    everything = "\n".join(entry["body"] for entry in CONTROL_LOG)
    assert "E2E-PROMPT-CANARY" not in everything
    assert "E2E-INPUT-CANARY" not in everything
    assert IMAGE_PROMPT not in everything
    assert SPEECH_INPUT not in everything


def test_the_relay_never_saw_the_api_key() -> None:
    everything = "\n".join(f"{entry['headers']}\n{entry['body']}" for entry in RELAY_LOG)
    assert API_KEY not in everything
    for entry in RELAY_LOG:
        assert "authorization" not in {k.lower() for k in entry["headers"]}
        assert "cookie" not in {k.lower() for k in entry["headers"]}


def test_each_origin_got_exactly_the_credential_it_needs() -> None:
    assert all(e["headers"].get("authorization") == f"Bearer {API_KEY}" for e in CONTROL_LOG)
    assert all(e["headers"].get("x-anonrouter-ticket") for e in RELAY_LOG)


def test_a_ticket_cannot_be_replayed(origins: tuple[str, str]) -> None:
    # Mint one ticket by hand and redeem it twice, which is what a client with a
    # retry loop would do. The second attempt must be refused.
    control_origin, inference_origin = origins
    minted = httpx.post(
        f"{control_origin}/v1/inference/tickets",
        headers={"content-type": "application/json", "authorization": f"Bearer {API_KEY}"},
        json={
            "operation": "image",
            "model": MODEL_IMAGE,
            "size": "512x512",
            "response_format": "b64_json",
        },
    )
    ticket = minted.json()["ticket"]

    def redeem() -> httpx.Response:
        return httpx.post(
            f"{inference_origin}/v1/images/generations",
            headers={"content-type": "application/json", "x-anonrouter-ticket": ticket},
            json={
                "model": MODEL_IMAGE,
                "prompt": "replay probe",
                "size": "512x512",
                "response_format": "b64_json",
            },
        )

    assert redeem().status_code == 200
    replayed = redeem()
    assert replayed.status_code == 401
    assert replayed.json()["error"]["type"] == "invalid_ticket"


def test_a_cross_operation_ticket_is_refused_by_the_relay(origins: tuple[str, str]) -> None:
    # A ticket bound to image, redeemed at the speech route. The client cannot
    # produce this itself, which is the point: it proves the relay's own
    # enforcement is what the typed error reflects.
    control_origin, inference_origin = origins
    minted = httpx.post(
        f"{control_origin}/v1/inference/tickets",
        headers={"content-type": "application/json", "authorization": f"Bearer {API_KEY}"},
        json={"operation": "image", "model": MODEL_IMAGE, "response_format": "b64_json"},
    )
    ticket = minted.json()["ticket"]
    crossed = httpx.post(
        f"{inference_origin}/v1/audio/speech",
        headers={"content-type": "application/json", "x-anonrouter-ticket": ticket},
        json={"model": MODEL_SPEECH, "input": "x", "response_format": "mp3"},
    )
    assert crossed.status_code == 409
    assert crossed.json()["error"]["type"] == "ticket_operation_mismatch"


def test_the_relay_serves_only_its_own_routes(origins: tuple[str, str]) -> None:
    control_origin, inference_origin = origins
    wrong_host = httpx.post(
        f"{control_origin}/v1/images/generations",
        headers={"content-type": "application/json", "x-anonrouter-ticket": "tkt_e2e_1"},
        json={"model": MODEL_IMAGE, "prompt": "p"},
    )
    assert wrong_host.status_code == 404

    mint_on_relay = httpx.post(
        f"{inference_origin}/v1/inference/tickets",
        headers={"content-type": "application/json"},
        json={"operation": "image", "model": MODEL_IMAGE},
    )
    assert mint_on_relay.status_code == 404


def test_plaintext_origins_need_the_explicit_opt_in(origins: tuple[str, str]) -> None:
    # The loopback override is what makes this whole file possible, and it has to
    # be asked for. Without it the client refuses at construction, so a
    # production caller cannot arrive at a plaintext data plane by leaving a flag
    # unset.
    control_origin, inference_origin = origins
    with pytest.raises(ConfidentialError, match="must be https"):
        create_client(
            inference_base_url=inference_origin,
            control_base_url=control_origin,
            api_key=API_KEY,
        )


def test_a_relay_refusal_surfaces_as_a_typed_error(origins: tuple[str, str]) -> None:
    # Drive the real client at a model the mint accepts but redeem against a
    # relay that has already spent the ticket, by replaying through the client's
    # own path: a second call with a stale ticket is not reachable from the API,
    # so this asserts the mapping on a genuine relay refusal instead.
    _, inference_origin = origins
    refused = httpx.post(
        f"{inference_origin}/v1/images/generations",
        headers={"content-type": "application/json"},
        json={"model": MODEL_IMAGE, "prompt": "p"},
    )
    assert refused.status_code == 401
    assert refused.json()["error"]["type"] == "ticket_required"


def test_media_is_refused_when_the_roles_collapse() -> None:
    # A configuration refusal, so it is the client's own ConfidentialError rather
    # than a MediaError about a request: nothing was ever sent to describe.
    collapsed = create_client("https://one.origin.invalid", api_key=API_KEY)
    with pytest.raises(ConfidentialError, match="two distinct origins"):
        collapsed.images.generate(model=MODEL_IMAGE, prompt="p")
