"""Ticketed media generation: image and text-to-speech over the two-origin split.

The Python port of ``js/confidential/src/media.ts``. The two files are kept
deliberately parallel -- same request shapes, same bound facts, same error codes,
same refusals -- because a privacy property that holds in one language and not
the other is not a property of the SDK.

THE WHOLE POINT. A media request is split across two hosts that are told
different things:

  control origin    sees the API key and the content-free shape of the work
                    (operation, model, image size/format, speech character
                    COUNT, voice, container). It mints a single-use ticket. It
                    never sees the prompt or the input text.
  inference origin  sees the prompt or the input text, authenticated by that
                    opaque single-use ticket ALONE. It never sees the API key,
                    a cookie, or any stable account identifier.

Neither host holds both halves, so neither can by itself say "this account asked
for this picture". An official OpenAI client cannot perform this exchange: it has
one base URL and one credential, so it would send the key and the prompt to the
same host in one request.

The contract is derived from deployed code -- ``src/routes/image.ts``,
``src/routes/speech.ts``, ``src/inference/ticketRequestSchema.ts`` and
``src/providers/types.ts`` in the AnonRouter production tree -- and was verified
against the live origins on 2026-08-30.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .errors import ConfidentialError

# ---- Canonical bounds, mirrored from the server -----------------------------
#
# Duplicated from AnonRouter's ``src/providers/types.ts`` so a request that
# cannot possibly succeed is refused BEFORE a ticket is minted. Minting first and
# failing at the relay would burn a single-use ticket for nothing.

#: ``parseImageSize`` bounds. A dimension outside these is a 400 at every surface.
IMAGE_MIN_DIMENSION = 128
IMAGE_MAX_DIMENSION = 2048
IMAGE_DEFAULT_SIZE = "1024x1024"
#: The only image container AnonRouter serves. The ticket binds it.
IMAGE_RESPONSE_FORMAT = "b64_json"
#: ``imageGenerationRequestSchema`` prompt bound.
IMAGE_MAX_PROMPT_CHARS = 10_000
#: The priced unit ceiling for speech: the ticket binds the exact count.
SPEECH_MAX_INPUT_CHARS = 20_000
SPEECH_MAX_VOICE_CHARS = 64
#: The only speech container AnonRouter serves. The ticket binds it.
SPEECH_RESPONSE_FORMAT = "mp3"

TICKET_HEADER = "x-anonrouter-ticket"
IMAGE_PATH = "/v1/images/generations"
SPEECH_PATH = "/v1/audio/speech"
TICKET_PATH = "/v1/inference/tickets"

#: Production defaults. The two origins are different hosts on purpose.
DEFAULT_CONTROL_ORIGIN = "https://api.anonrouter.ai"
DEFAULT_INFERENCE_ORIGIN = "https://api.private.anonrouter.ai"

_SIZE_RE = re.compile(r"^\d{3,4}x\d{3,4}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


# ---- Errors -----------------------------------------------------------------

#: Header names whose VALUES are credentials or capabilities. A diagnostic that
#: echoed one of these would turn a debugging aid into a credential leak: an
#: ``authorization`` value is the API key itself, and an ``x-anonrouter-ticket``
#: is a bearer capability for a paid generation until it is redeemed.
_REDACTED_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    TICKET_HEADER,
}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Replace every sensitive header value with a fixed marker.

    The NAMES are preserved so a caller can still see which headers a request
    carried. Exported because the same rule must apply to anything anyone else
    logs about a media call.
    """
    return {
        name: ("<redacted>" if name.lower() in _REDACTED_HEADERS else value)
        for name, value in headers.items()
    }


@dataclass(frozen=True)
class MediaErrorDiagnostics:
    """What a failed media call reports.

    Deliberately carries NO body: an error body from the relay could quote the
    prompt back, and a prompt in an exception is a prompt in a log aggregator.
    """

    origin: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    status: int | None = None
    #: The gateway's error ``type``, when it sent one. Machine-readable, content-free.
    error_type: str | None = None
    request_id: str | None = None


class MediaError(ConfidentialError):
    """A media failure with a machine-readable code and redacted diagnostics.

    A ``ConfidentialError`` subclass, so a caller who already writes
    ``except ConfidentialError`` keeps catching everything this SDK raises. The
    JavaScript ``MediaError`` extends ``ConfidentialError`` for the same reason.

    ``code`` matches the JavaScript ``ConfidentialErrorCode`` exactly. The
    distinction that matters for money: ``ticket_rejected`` and ``relay_refused``
    mean nothing was generated and nothing was charged, while ``provider_failed``
    means the request reached a provider and may have been.
    """

    def __init__(self, code: str, message: str, diagnostics: MediaErrorDiagnostics) -> None:
        super().__init__(message)
        self.code = code
        self.diagnostics = diagnostics


#: Every code the media surface can raise. Mirrors the JS union so a port of a
#: caller's error handling is mechanical.
MEDIA_ERROR_CODES = (
    "unsupported_request",
    "media_ticket_failed",
    "ticket_binding_mismatch",
    "ticket_rejected",
    "relay_refused",
    "provider_failed",
    "response_invalid",
    "transport_failed",
    "cancelled",
    "timeout",
)


def _reject(message: str) -> Any:
    """Refuse a request that cannot succeed, before anything is sent anywhere."""
    raise MediaError(
        "unsupported_request",
        message,
        MediaErrorDiagnostics(origin="", path="", headers={}),
    )


# ---- Validation -------------------------------------------------------------


def utf16_length(text: str) -> int:
    """The number of UTF-16 code units in ``text``.

    THIS IS THE PRICED UNIT AND IT MUST MATCH THE SERVER EXACTLY. AnonRouter runs
    on Node, where ``input.length`` and zod's ``.max()`` both count UTF-16 code
    units, and the relay rejects a body whose length differs from the ticket by
    even one (``ticket_input_length_mismatch``).

    Python's ``len()`` counts CODE POINTS, which disagrees with the server for
    every astral-plane character: "\U0001f600" is 1 to ``len()`` and 2 to the
    server. Using ``len()`` here would mint a ticket bound to the wrong count and
    have the relay reject the redemption, and the failure would look like a
    mysterious 409 on exactly the messages that contain emoji.
    """
    return len(text.encode("utf-16-le")) // 2


def _require_model(model: Any) -> str:
    if not isinstance(model, str) or not model or len(model) > 256:
        _reject("model must be a non-empty string of at most 256 characters.")
    return model


def canonical_image_size(size: str) -> str:
    """Canonicalize "WIDTHxHEIGHT" to the exact form the ticket mint echoes back.

    The mint re-emits the size as ``f"{width}x{height}"`` from parsed integers, so
    a caller who writes "0512x0512" (which the server's regex accepts) would get
    "512x512" back and a naive comparison of the echo would report drift that is
    not there. Canonicalizing here means the SAME string goes to both hosts and
    the echo check is exact.
    """
    if not isinstance(size, str) or not _SIZE_RE.match(size):
        _reject('size must look like "1024x1024" (three or four digits per side).')
    width, height = (int(part) for part in size.split("x"))
    if not (
        IMAGE_MIN_DIMENSION <= width <= IMAGE_MAX_DIMENSION
        and IMAGE_MIN_DIMENSION <= height <= IMAGE_MAX_DIMENSION
    ):
        _reject(
            f"size must be between {IMAGE_MIN_DIMENSION}x{IMAGE_MIN_DIMENSION} "
            f"and {IMAGE_MAX_DIMENSION}x{IMAGE_MAX_DIMENSION}."
        )
    return f"{width}x{height}"


# ---- Results ----------------------------------------------------------------


@dataclass(frozen=True)
class MediaRateLimit:
    limit_requests: int | None = None
    remaining_requests: int | None = None
    reset_requests: int | None = None
    limit_tokens: int | None = None
    remaining_tokens: int | None = None
    reset_tokens: int | None = None


@dataclass(frozen=True)
class GeneratedImage:
    """One generated image."""

    #: Base64 image bytes, exactly as the provider returned them.
    b64_json: str
    #: The concrete media type, e.g. "image/png". Needed to save or render.
    mime_type: str
    #: The decoded bytes, for callers that want to write a file directly.
    data: bytes


@dataclass(frozen=True)
class ImageGenerateResult:
    created: int
    #: The public model id the gateway reports for the generation.
    model: str
    data: list[GeneratedImage]
    #: ``x-anonrouter-selected-model``: "provider/model" actually routed to.
    selected_model: str | None = None
    #: ``x-anonrouter-routing``: how the model was chosen ("exact").
    routing: str | None = None
    request_id: str | None = None
    rate_limit: MediaRateLimit | None = None
    #: Provider reported the image was blurred by its safety layer.
    provider_blurred: bool | None = None
    #: Provider reported a content-policy violation for the prompt.
    provider_content_violation: bool | None = None


@dataclass(frozen=True)
class SpeechCreateResult:
    #: The audio bytes. The endpoint returns one complete buffer, not a stream.
    audio: bytes
    #: The concrete media type from the response, e.g. "audio/mpeg".
    content_type: str
    selected_model: str | None = None
    routing: str | None = None
    request_id: str | None = None
    rate_limit: MediaRateLimit | None = None

    def write_to(self, path: str) -> int:
        """Write the audio to ``path``. Returns the number of bytes written."""
        with open(path, "wb") as handle:
            return handle.write(self.audio)


# ---- HTTP plumbing ----------------------------------------------------------


def _code_for_status(status: int, error_type: str | None) -> str:
    """Map a relay/control status onto a code a caller can branch on."""
    if status == 401:
        # The relay answers 401 both for a missing ticket and for one already
        # spent or expired. ``invalid_ticket`` is specifically "you had a ticket
        # and it is no longer good", which is the replay/expiry case a caller
        # restarts rather than resends.
        return "ticket_rejected" if error_type == "invalid_ticket" else "relay_refused"
    if status == 409:
        return "ticket_rejected"
    # A 503 is `media_disabled`: the deployment does not serve media at all, so
    # nothing was generated and nothing was charged. It must be listed BEFORE the
    # 5xx branch below, or it would be reported as a provider failure and a
    # caller would reasonably assume they had been billed for an attempt.
    if status in (403, 404, 503):
        return "relay_refused"
    if status in (402, 429):
        return "relay_refused"
    if status >= 500:
        return "provider_failed"
    return "relay_refused"


def _error_envelope(response: httpx.Response) -> tuple[str | None, str | None]:
    """Read the gateway's content-free error envelope. The body is never surfaced."""
    try:
        body = response.json()
    except ValueError:
        # A non-JSON error body carries no machine-readable type. That is not a
        # failure in itself: the caller still gets the status and the code.
        return None, None
    if not isinstance(body, dict):
        return None, None
    error = body.get("error")
    if not isinstance(error, dict):
        return None, None
    error_type = error.get("type")
    request_id = error.get("request_id")
    return (
        error_type if isinstance(error_type, str) else None,
        request_id if isinstance(request_id, str) else None,
    )


def _int_header(response: httpx.Response, name: str) -> int | None:
    raw = response.headers.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _rate_limit_from(response: httpx.Response) -> MediaRateLimit | None:
    rate = MediaRateLimit(
        limit_requests=_int_header(response, "x-ratelimit-limit-requests"),
        remaining_requests=_int_header(response, "x-ratelimit-remaining-requests"),
        reset_requests=_int_header(response, "x-ratelimit-reset-requests"),
        limit_tokens=_int_header(response, "x-ratelimit-limit-tokens"),
        remaining_tokens=_int_header(response, "x-ratelimit-remaining-tokens"),
        reset_tokens=_int_header(response, "x-ratelimit-reset-tokens"),
    )
    has_any = any(
        getattr(rate, name) is not None
        for name in (
            "limit_requests",
            "remaining_requests",
            "reset_requests",
            "limit_tokens",
            "remaining_tokens",
            "reset_tokens",
        )
    )
    return rate if has_any else None


def _metadata_from(response: httpx.Response) -> dict[str, Any]:
    request_id = response.headers.get("x-request-id") or response.headers.get(
        "x-anonrouter-request-id"
    )
    return {
        "selected_model": response.headers.get("x-anonrouter-selected-model"),
        "routing": response.headers.get("x-anonrouter-routing"),
        "request_id": request_id,
        "rate_limit": _rate_limit_from(response),
    }


def _bool_header(response: httpx.Response, name: str) -> bool | None:
    raw = response.headers.get(name)
    if raw is None:
        return None
    return raw == "true"


class _MediaTransport:
    """The two-origin exchange. Holds no content beyond the call it is running."""

    def __init__(
        self,
        *,
        control_origin: str,
        inference_origin: str,
        api_key: str | None,
        http: httpx.Client,
    ) -> None:
        self.control_origin = control_origin
        self.inference_origin = inference_origin
        self.api_key = api_key
        self.http = http

    # -- step 1: the content-free ticket mint ---------------------------------

    def mint_ticket(
        self,
        payload: dict[str, Any],
        expected: dict[str, Any],
        timeout: float | None,
    ) -> str:
        """Exchange the API key for a single-use, operation-scoped ticket.

        ``payload`` is built by the caller from normalized input and is
        CONTENT-FREE by construction: the image path passes
        model/size/format, the speech path passes
        model/character-count/voice/format. Neither passes the prompt or the
        text. There is no code path here that could: this method never sees them.
        """
        if not self.api_key:
            _reject("An API key is required to mint a media ticket.")
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {self.api_key}",
        }
        diagnostics = MediaErrorDiagnostics(
            origin=self.control_origin, path=TICKET_PATH, headers=redact_headers(headers)
        )
        try:
            response = self.http.post(
                f"{self.control_origin}{TICKET_PATH}",
                headers=headers,
                json=payload,
                timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
            )
        except httpx.TimeoutException as exc:
            raise MediaError("timeout", "The media request timed out.", diagnostics) from exc
        except httpx.HTTPError as exc:
            raise MediaError(
                "media_ticket_failed",
                "Could not reach the AnonRouter control origin.",
                diagnostics,
            ) from exc

        if response.status_code >= 400:
            error_type, request_id = _error_envelope(response)
            raise MediaError(
                "media_ticket_failed",
                "The control origin refused to mint a media ticket "
                f"(HTTP {response.status_code}"
                f"{', ' + error_type if error_type else ''}).",
                MediaErrorDiagnostics(
                    origin=self.control_origin,
                    path=TICKET_PATH,
                    headers=redact_headers(headers),
                    status=response.status_code,
                    error_type=error_type,
                    request_id=request_id,
                ),
            )

        try:
            issued = response.json()
        except Exception as exc:
            raise MediaError(
                "media_ticket_failed",
                "The control origin returned an unreadable ticket response.",
                diagnostics,
            ) from exc
        if not isinstance(issued, dict):
            raise MediaError(
                "media_ticket_failed",
                "The control origin returned an unreadable ticket response.",
                diagnostics,
            )
        return _assert_ticket_binding(issued, expected, diagnostics)

    # -- step 2: the content request ------------------------------------------

    def post_content(
        self,
        path: str,
        ticket: str,
        body: dict[str, Any],
        accept: str,
        timeout: float | None,
    ) -> httpx.Response:
        """Send the content to the inference origin, ticket as the only credential.

        EXACTLY ONE POST. There is no retry loop here and there must never be
        one: a media generation is billed on the provider attempt, so a
        transparently retried POST would be a second charge for a caller who made
        one call. A failure is reported, not repeated.
        """
        headers = {
            "content-type": "application/json",
            "accept": accept,
            TICKET_HEADER: ticket,
        }
        diagnostics = MediaErrorDiagnostics(
            origin=self.inference_origin, path=path, headers=redact_headers(headers)
        )
        try:
            response = self.http.post(
                f"{self.inference_origin}{path}",
                headers=headers,
                json=body,
                timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
            )
        except httpx.TimeoutException as exc:
            raise MediaError("timeout", "The media request timed out.", diagnostics) from exc
        except httpx.HTTPError as exc:
            # The request may or may not have reached the provider, so this is
            # NOT retried and NOT reported as a clean refusal.
            raise MediaError(
                "transport_failed",
                "Could not reach the AnonRouter inference origin.",
                diagnostics,
            ) from exc

        if response.status_code >= 400:
            error_type, request_id = _error_envelope(response)
            raise MediaError(
                _code_for_status(response.status_code, error_type),
                "The inference origin refused the media request "
                f"(HTTP {response.status_code}"
                f"{', ' + error_type if error_type else ''}).",
                MediaErrorDiagnostics(
                    origin=self.inference_origin,
                    path=path,
                    headers=redact_headers(headers),
                    status=response.status_code,
                    error_type=error_type,
                    request_id=request_id,
                ),
            )
        return response


def _assert_ticket_binding(
    issued: dict[str, Any],
    expected: dict[str, Any],
    diagnostics: MediaErrorDiagnostics,
) -> str:
    """Check every fact the relay will independently re-check, FIRST.

    The relay compares the redeeming body against the ticket's bound constraints
    and answers 409 on any drift (``ticket_model_mismatch``,
    ``ticket_size_mismatch``, ``ticket_format_mismatch``,
    ``ticket_input_length_mismatch``, ``ticket_voice_mismatch``,
    ``ticket_operation_mismatch``). Checking the mint's echo here means a
    mismatch is caught BEFORE the prompt is sent anywhere: the request fails on
    the content-free half of the exchange, and the text never leaves the process.
    A ticket that does not bind what we asked for is not a ticket we are willing
    to spend content on.
    """
    ticket = issued.get("ticket")
    if not isinstance(ticket, str) or not ticket:
        raise MediaError(
            "media_ticket_failed",
            "The control origin did not return a usable single-use ticket.",
            diagnostics,
        )
    for field_name, want in expected.items():
        got = issued.get(field_name)
        if want is None:
            # "No voice" is a real bound value: the relay compares
            # ``(constraints.speechVoice or None) != (body.voice or None)``, so a
            # ticket that came back carrying a voice we did not ask for would be
            # redeemed against a body with none, and answer 409.
            if got is not None:
                raise MediaError(
                    "ticket_binding_mismatch",
                    f"The issued ticket bound a {field_name} that was not requested; "
                    "refusing to send content against it.",
                    diagnostics,
                )
            continue
        # The mint echoes the bound value; a missing echo is an older gateway,
        # not proof of drift, so only a PRESENT and DIFFERENT value is a mismatch.
        if got is not None and got != want:
            raise MediaError(
                "ticket_binding_mismatch",
                f"The issued ticket bound a different {field_name} than was requested; "
                "refusing to send content against it.",
                diagnostics,
            )
    return ticket


# ---- Response parsing -------------------------------------------------------


def _parse_image_response(
    body: Any, response: httpx.Response, diagnostics: MediaErrorDiagnostics
) -> ImageGenerateResult:
    """Parse and VALIDATE the image envelope.

    A malformed payload is refused rather than passed through. A caller who is
    handed an object with an empty or non-base64 ``b64_json`` will write a
    corrupt file and discover it much later; failing here, with the generation
    already paid for, at least names the problem accurately.
    """

    def invalid(message: str) -> Any:
        raise MediaError("response_invalid", message, diagnostics)

    if not isinstance(body, dict):
        invalid("The image response was not a JSON object.")
    entries = body.get("data")
    if not isinstance(entries, list) or not entries:
        invalid("The image response contained no image data.")
    images: list[GeneratedImage] = []
    for entry in entries:
        if not isinstance(entry, dict):
            invalid("An image entry was not an object.")
        b64 = entry.get("b64_json")
        mime = entry.get("mime_type")
        if not isinstance(b64, str) or not b64:
            invalid("An image entry carried no base64 image data.")
        if not _BASE64_RE.match(b64) or len(b64) % 4 != 0:
            invalid("An image entry carried data that is not canonical base64.")
        if not isinstance(mime, str) or not mime.startswith("image/"):
            invalid("An image entry carried no image media type.")
        try:
            decoded = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            invalid("An image entry carried base64 that could not be decoded.")
        if not decoded:
            invalid("An image entry decoded to zero bytes.")
        images.append(GeneratedImage(b64_json=b64, mime_type=mime, data=decoded))

    created = body.get("created")
    model = body.get("model")
    return ImageGenerateResult(
        created=created if isinstance(created, int) else int(time.time()),
        model=model if isinstance(model, str) else "",
        data=images,
        provider_blurred=_bool_header(response, "x-anonrouter-provider-blurred"),
        provider_content_violation=_bool_header(
            response, "x-anonrouter-provider-content-violation"
        ),
        **_metadata_from(response),
    )


# ---- The public surface -----------------------------------------------------


class SpeechApi:
    """``client.audio.speech`` -- the OpenAI-shaped speech accessor."""

    def __init__(self, owner: MediaOwner) -> None:
        self._owner = owner

    def create(
        self,
        *,
        model: str,
        # Shadows the `input` builtin deliberately: this is OpenAI's parameter
        # name, and a caller porting a working call must not have to rename it.
        input: str,
        voice: str | None = None,
        response_format: str | None = None,
        speed: float | None = None,
        timeout: float | None = None,
    ) -> SpeechCreateResult:
        """Synthesize speech over the two-origin ticketed exchange.

        The text goes only to the inference origin; the control origin learns its
        character COUNT (the priced unit), the model, voice, and container.
        """
        model = _require_model(model)
        if not isinstance(input, str) or not input:
            _reject("input must be a non-empty string.")
        input_chars = utf16_length(input)
        if input_chars > SPEECH_MAX_INPUT_CHARS:
            _reject(f"input must be at most {SPEECH_MAX_INPUT_CHARS} characters.")
        if voice is not None:
            if not isinstance(voice, str) or not voice:
                _reject("voice must be a non-empty string when supplied.")
            if utf16_length(voice) > SPEECH_MAX_VOICE_CHARS:
                _reject(f"voice must be at most {SPEECH_MAX_VOICE_CHARS} characters.")
        if response_format is not None and response_format != SPEECH_RESPONSE_FORMAT:
            _reject(f"AnonRouter serves speech only as {SPEECH_RESPONSE_FORMAT}.")
        # Speech is priced per character for a fixed rendering; a playback rate is
        # not part of the authorized work, so accepting and dropping it would
        # return audio at a speed the caller did not ask for.
        if speed is not None and speed != 1:
            _reject(
                "AnonRouter does not support a speech speed parameter; "
                "speed must be 1 or omitted."
            )

        transport = self._owner._media_transport()
        # CONTENT-FREE. ``input_chars`` is a COUNT; the text never appears here.
        mint_payload: dict[str, Any] = {
            "operation": "speech",
            "model": model,
            "input_chars": input_chars,
            "response_format": SPEECH_RESPONSE_FORMAT,
        }
        if voice is not None:
            mint_payload["voice"] = voice
        ticket = transport.mint_ticket(
            mint_payload,
            {
                "operation": "speech",
                "model": model,
                "input_chars": input_chars,
                "response_format": SPEECH_RESPONSE_FORMAT,
                "voice": voice,
            },
            timeout,
        )

        content_body: dict[str, Any] = {
            "model": model,
            "input": input,
            "response_format": SPEECH_RESPONSE_FORMAT,
        }
        if voice is not None:
            content_body["voice"] = voice
        response = transport.post_content(
            SPEECH_PATH, ticket, content_body, "audio/mpeg", timeout
        )

        diagnostics = MediaErrorDiagnostics(
            origin=transport.inference_origin,
            path=SPEECH_PATH,
            headers=redact_headers({"content-type": "application/json", TICKET_HEADER: ticket}),
            status=response.status_code,
        )
        content_type = response.headers.get("content-type", "")
        if not content_type.startswith("audio/"):
            raise MediaError(
                "response_invalid",
                f"The speech response was not audio (content-type: {content_type or 'absent'}).",
                diagnostics,
            )
        audio = response.content
        if not audio:
            raise MediaError(
                "response_invalid", "The speech response carried no audio bytes.", diagnostics
            )
        return SpeechCreateResult(
            audio=audio, content_type=content_type, **_metadata_from(response)
        )


class AudioApi:
    """``client.audio`` -- namespace matching the OpenAI and JS layouts."""

    def __init__(self, owner: MediaOwner) -> None:
        self.speech = SpeechApi(owner)


class ImagesApi:
    """``client.images`` -- the OpenAI-shaped image accessor."""

    def __init__(self, owner: MediaOwner) -> None:
        self._owner = owner

    def generate(
        self,
        *,
        model: str,
        prompt: str,
        size: str | None = None,
        response_format: str | None = None,
        n: int | None = None,
        timeout: float | None = None,
    ) -> ImageGenerateResult:
        """Generate one image over the two-origin ticketed exchange.

        The prompt goes only to the inference origin; the control origin learns
        the model, size, and format and mints a single-use ticket for exactly
        that work.
        """
        model = _require_model(model)
        if not isinstance(prompt, str) or not prompt:
            _reject("prompt must be a non-empty string.")
        if utf16_length(prompt) > IMAGE_MAX_PROMPT_CHARS:
            _reject(f"prompt must be at most {IMAGE_MAX_PROMPT_CHARS} characters.")
        if response_format is not None and response_format != IMAGE_RESPONSE_FORMAT:
            _reject(f"AnonRouter serves image generation only as {IMAGE_RESPONSE_FORMAT}.")
        # ``n`` exists so an OpenAI-shaped call is accepted verbatim, but
        # AnonRouter prices and returns exactly one image and the ticket
        # authorizes exactly one flat unit. Anything else must be an error, never
        # a silent single image.
        if n is not None and n != 1:
            _reject(
                "AnonRouter generates one image per request; n must be 1 or omitted. "
                "Issue separate calls to generate more, so each is ticketed and priced "
                "on its own."
            )
        canonical_size = canonical_image_size(size if size is not None else IMAGE_DEFAULT_SIZE)

        transport = self._owner._media_transport()
        # CONTENT-FREE. ``prompt`` is deliberately absent and must stay absent.
        ticket = transport.mint_ticket(
            {
                "operation": "image",
                "model": model,
                "size": canonical_size,
                "response_format": IMAGE_RESPONSE_FORMAT,
            },
            {
                "operation": "image",
                "model": model,
                "size": canonical_size,
                "response_format": IMAGE_RESPONSE_FORMAT,
            },
            timeout,
        )

        response = transport.post_content(
            IMAGE_PATH,
            ticket,
            {
                "model": model,
                "prompt": prompt,
                "size": canonical_size,
                "response_format": IMAGE_RESPONSE_FORMAT,
            },
            "application/json",
            timeout,
        )

        diagnostics = MediaErrorDiagnostics(
            origin=transport.inference_origin,
            path=IMAGE_PATH,
            headers=redact_headers({"content-type": "application/json", TICKET_HEADER: ticket}),
            status=response.status_code,
        )
        try:
            body = response.json()
        except Exception as exc:
            raise MediaError(
                "response_invalid", "The image response could not be parsed as JSON.", diagnostics
            ) from exc
        return _parse_image_response(body, response, diagnostics)


class MediaOwner:
    """What the media accessors need from the client that hosts them.

    Implemented by ``ConfidentialClient``. Kept as an explicit protocol-ish base
    so the media surface has no import cycle back into the client module and can
    be unit-tested against a stub.
    """

    def _media_transport(self) -> _MediaTransport:  # pragma: no cover - overridden
        raise NotImplementedError
