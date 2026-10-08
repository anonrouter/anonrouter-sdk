"""Private synchronous retained operation: one PKI-validated TLS socket ever.

HTTPX 0.28.1 / HTTPCore 1.0.9 only. System DNS and foreign verifier threads
cannot be physically interrupted; caller deadlines prevent later HTTP use.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import math
import secrets
import select
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, TypeVar, cast

import httpcore
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..errors import ConfidentialError
from .authority import assert_gateway_policy_security_floor
from .binding import canonical_gateway_origin
from .policy import GatewayMeasurementPolicy
from .transport_sync import BoundGatewayTransportError
from .verify import GatewayVerificationResult, verify_gateway_attestation

T = TypeVar("T")
_PAID_PATHS = {"/v1/chat/completions", "/v1/e2ee/chat/completions", "/v1/images/generations", "/v1/audio/speech", "/v1/embeddings"}


def _fail(code: str, dispatched: bool = False) -> BoundGatewayTransportError:
    return BoundGatewayTransportError(code, f"Retained gateway operation refused ({code}).", "may_have_dispatched" if dispatched else "before_http")


class _FrozenDict(dict[str, Any]):
    def _refuse(self, *args: Any, **kwargs: Any) -> Any:
        raise TypeError("verified gateway report is immutable")
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _refuse


class _FrozenRecord:
    """Read-only attribute/as_dict snapshot; never the live verifier object."""
    __slots__ = ("_serialized", "_values")

    def __init__(self, value: Any) -> None:
        object.__setattr__(self, "_values", _freeze({f.name: getattr(value, f.name) for f in fields(value)}))
        serialize = getattr(value, "as_dict", None)
        object.__setattr__(self, "_serialized", _freeze(serialize()) if callable(serialize) else self._values)

    def __getattr__(self, name: str) -> Any:
        try:
            return self._values[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError("verified gateway report is immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError("verified gateway report is immutable")

    def as_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], self._serialized)


def _freeze(value: Any) -> Any:
    if isinstance(value, _FrozenRecord):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return _FrozenRecord(value)
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def freeze_gateway_report(value: dict[str, Any]) -> dict[str, Any]:
    """Snapshot required-mode public reports, preserving JSON-compatible maps."""
    return cast(dict[str, Any], _freeze(value))


def _policy(value: GatewayMeasurementPolicy) -> GatewayMeasurementPolicy:
    result = copy.deepcopy(value)
    assert_gateway_policy_security_floor(result)
    if type(result.max_evidence_age_ms) not in {int, float} or not math.isfinite(result.max_evidence_age_ms) or not 0 < result.max_evidence_age_ms <= 300000:
        raise _fail("configuration")
    return result


@dataclass(frozen=True)
class RetainedGatewayIdentity:
    origin: str
    nonce: str
    tls_spki_sha256: str
    app_id: str
    instance_id: str
    compose_hash: str
    expires_at_ms: float


class _Channel:
    def __init__(self, cancel: threading.Event, budget: float, approval: float) -> None:
        self.cancel = cancel
        self.pre_expires = time.monotonic() + budget
        self.deadline = self.pre_expires
        self.approval = approval
        self.evidence_expiry = float("inf")
        self.opened = self.authorized = self.closed = self.retired = self.busy = False
        self.paid = self.dispatched = self.paid_attempted = self.challenge_attempted = False
        self.pin: str | None = None
        self.sock: socket.socket | None = None
        self.failure: str | None = None
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.pool: httpcore.ConnectionPool | None = None
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self) -> None:
        while not self.done.wait(.01):
            with self.lock:
                expired = time.monotonic() >= self.deadline
            if self.cancel.is_set() or expired:
                self.stop("cancelled" if self.cancel.is_set() else "timeout")
                return

    def stop(self, reason: str | None = None) -> None:
        with self.lock:
            self.closed = True
            if reason and not self.failure:
                self.failure = reason
            sock = self.sock
        self.done.set()
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def guard(self, *, predispatch: bool = True) -> None:
        if self.cancel.is_set():
            self.stop("cancelled")
        if self.failure:
            raise _fail(self.failure, self.dispatched)
        if self.closed:
            raise _fail("cancelled", self.dispatched)
        if self.retired or self.sock is not None and self.sock.fileno() < 0:
            raise _fail("connection_lost", self.dispatched)
        if time.monotonic() >= self.deadline:
            self.stop("timeout")
            raise _fail("timeout", self.dispatched)
        if predispatch and (time.monotonic() >= self.pre_expires or time.time() * 1000 >= min(self.evidence_expiry, self.approval)):
            raise ConfidentialError("the verified gateway approval or evidence expired before dispatch")

    def remaining(self, timeout: float | None = None) -> float:
        # A paid response already admitted may finish beyond approval/P expiry.
        self.guard(predispatch=not self.dispatched)
        remaining = self.deadline - time.monotonic()
        return remaining if timeout is None else min(remaining, timeout)

    def finish(self, paid: bool) -> None:
        self.busy = False
        if paid:
            self.stop()
        else:
            self.dispatched = False
            self.deadline = self.pre_expires


class _Stream(httpcore.NetworkStream):
    def __init__(self, sock: socket.socket, channel: _Channel, host: str, accepted: bool = False) -> None:
        self.sock, self.channel, self.host, self.accepted = sock, channel, host, accepted

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if not self.accepted:
            raise _fail("tls_certificate")
        try:
            self.sock.settimeout(self.channel.remaining(timeout))
            data = self.sock.recv(max_bytes)
            self.channel.remaining()
            return data
        except TimeoutError:
            self.channel.stop("timeout")
            raise _fail("timeout", self.channel.dispatched) from None
        except (OSError, ValueError):
            raise _fail(self.channel.failure or "transport", self.channel.dispatched) from None

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if not self.accepted:
            raise _fail("tls_certificate")
        # HTTPCore calls this immediately before headers/body, ALSO on reuse.
        # Returning a previously accepted socket never bypasses this guard.
        self.sock.settimeout(self.channel.remaining(timeout))
        self.channel.dispatched = True
        try:
            self.sock.sendall(buffer)
            self.channel.remaining()
        except TimeoutError:
            self.channel.stop("timeout")
            raise _fail("timeout", self.channel.dispatched) from None
        except (OSError, ValueError):
            raise _fail(self.channel.failure or "transport", self.channel.dispatched) from None

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None) -> httpcore.NetworkStream:
        if self.accepted or server_hostname != self.host or ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
            raise _fail("tls_certificate")
        try:
            handshake_end = time.monotonic() + min(10.0, self.channel.remaining(timeout))
            tls = ssl_context.wrap_socket(self.sock, server_hostname=self.host, do_handshake_on_connect=False)
            self.channel.sock = tls
            tls.setblocking(False)
            while True:
                remaining = min(self.channel.remaining(), handshake_end - time.monotonic())
                if remaining <= 0:
                    raise _fail("timeout")
                try:
                    tls.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    select.select([tls], [], [], min(.01, remaining))
                except ssl.SSLWantWriteError:
                    select.select([], [tls], [], min(.01, remaining))
            tls.setblocking(True)
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise _fail("tls_certificate")
            self.channel.pin = hashlib.sha256(x509.load_der_x509_certificate(der).public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            self.channel.guard()
            return _Stream(tls, self.channel, self.host, True)
        except Exception as error:
            self.channel.stop()
            if isinstance(error, (BoundGatewayTransportError, ConfidentialError)):
                raise
            raise _fail(self.channel.failure or "tls_certificate") from None

    def close(self) -> None:
        self.sock.close()

    def get_extra_info(self, info: str) -> Any:
        if info in {"ssl_object", "socket"}:
            return self.sock
        if info == "is_readable":
            try:
                return bool(select.select([self.sock], [], [], 0)[0])
            except (OSError, ValueError):
                return True
        if info == "client_addr":
            return self.sock.getsockname()
        if info == "server_addr":
            return self.sock.getpeername()
        return None


class _Backend(httpcore.NetworkBackend):
    def __init__(self, channel: _Channel, origin: httpx.URL) -> None:
        self.channel, self.origin = channel, origin

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None, socket_options: Any = None) -> httpcore.NetworkStream:
        if host != self.origin.host or port != (self.origin.port or 443) or local_address or socket_options:
            raise _fail("configuration")
        with self.channel.lock:
            if self.channel.opened or self.channel.closed or self.channel.retired:
                raise _fail("connection_lost")
            self.channel.opened = True
        self.channel.guard()
        try:
            # Only one address attempt, one lookup ever. DNS itself is not interruptible.
            family, kind, protocol, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
            self.channel.guard()
            sock = socket.socket(family, kind, protocol)
            self.channel.sock = sock
            sock.settimeout(min(10.0, self.channel.remaining(timeout)))
            sock.connect(address)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.channel.guard()
            return _Stream(sock, self.channel, host)
        except Exception as error:
            self.channel.stop()
            if isinstance(error, (BoundGatewayTransportError, ConfidentialError)):
                raise
            raise _fail(self.channel.failure or "transport") from None

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
        raise _fail("configuration")


class _Body(httpx.SyncByteStream):
    def __init__(self, body: Any, channel: _Channel, paid: bool) -> None:
        self.body, self.channel, self.paid, self.closed = body, channel, paid, False

    def __iter__(self) -> Iterator[bytes]:
        try:
            for chunk in self.body:
                self.channel.remaining()
                yield chunk
        except Exception as error:
            self.channel.stop()
            if isinstance(error, (BoundGatewayTransportError, ConfidentialError)):
                raise
            raise _fail(self.channel.failure or "transport", self.channel.dispatched) from None
        finally:
            self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.body.close()
        finally:
            self.channel.finish(self.paid)


class _Transport(httpx.BaseTransport):
    def __init__(self, origin: httpx.URL, channel: _Channel, challenge: str,
                 request_timeout: float, ca_pem: str | None) -> None:
        self.origin, self.channel, self.challenge, self.request_timeout = origin, channel, challenge, request_timeout
        self.pool = httpcore.ConnectionPool(ssl_context=ssl.create_default_context(cadata=ca_pem), max_connections=1,
            max_keepalive_connections=1, keepalive_expiry=None, http1=True, http2=False, retries=0,
            network_backend=_Backend(channel, origin))
        channel.pool = self.pool

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if (url.scheme, url.host, url.port or 443) != (self.origin.scheme, self.origin.host, self.origin.port or 443) or url.userinfo or url.fragment:
            raise _fail("configuration")
        if set(request.extensions) - {"timeout", "bound_gateway_cancel"} or request.extensions.get("bound_gateway_cancel", self.channel.cancel) is not self.channel.cancel:
            raise _fail("configuration")
        if request.headers.get("host") != url.netloc.decode("ascii") or any(name in request.headers for name in ("authorization", "cookie", "transfer-encoding", "upgrade", "trailer", "expect")) or any(name.startswith("proxy-") for name in request.headers):
            raise _fail("configuration")
        if request.headers.get("connection", "keep-alive").lower() != "keep-alive":
            raise _fail("configuration")
        try:
            content = request.content
        except httpx.RequestNotRead:
            raise _fail("configuration") from None
        if "content-length" in request.headers and request.headers["content-length"] != str(len(content)):
            raise _fail("configuration")
        challenge = not self.channel.authorized and url.raw_path.decode() == self.challenge and request.method == "GET" and not content
        paid = url.path in _PAID_PATHS
        if challenge:
            if self.channel.challenge_attempted:
                raise _fail("configuration")
        elif not self.channel.authorized or not (paid and request.method == "POST" or url.path == "/v1/tee/attestation" and request.method in {"GET", "POST"}):
            raise _fail("configuration")
        if request.method == "GET" and content or paid and self.channel.paid_attempted:
            raise _fail("configuration")
        budgets = request.extensions.get("timeout", {})
        if not isinstance(budgets, dict) or set(budgets) - {"connect", "read", "write", "pool"}:
            raise _fail("configuration")
        if any(value is not None and (type(value) not in {int, float} or not math.isfinite(value) or value <= 0) for value in budgets.values()):
            raise _fail("configuration")
        self.channel.guard()
        with self.channel.lock:
            if self.channel.busy:
                raise _fail("busy")
            self.channel.busy = True
            self.channel.paid, self.channel.dispatched = paid, False
            if paid:
                self.channel.paid_attempted = True
            if challenge:
                self.channel.challenge_attempted = True
            duration = min([self.request_timeout] + [budgets[k] for k in ["read", "write"] if budgets.get(k) is not None])
            self.channel.deadline = time.monotonic() + duration if paid else min(self.channel.pre_expires, time.monotonic() + min(30.0, duration))
        headers = [(name, value) for name, value in request.headers.raw if name.lower() not in {b"accept-encoding", b"connection"}]
        headers.extend([(b"accept-encoding", b"identity"), (b"connection", b"keep-alive")])
        try:
            core = self.pool.handle_request(httpcore.Request(method=request.method,
                url=httpcore.URL(scheme=url.raw_scheme, host=url.raw_host, port=url.port, target=url.raw_path),
                headers=headers, content=content, extensions={"timeout": {"connect": min(10.0, budgets.get("connect") or 10.0), "read": duration, "write": duration, "pool": min(10.0, duration)}}))
            if 300 <= core.status < 400:
                raise _fail("redirect", self.channel.dispatched)
            encoding = [value for name, value in core.headers if name.lower() == b"content-encoding"]
            if encoding and encoding != [b"identity"]:
                raise _fail("transport", self.channel.dispatched)
            closing = any(b"close" in [token.strip() for token in value.lower().split(b",")] for name, value in core.headers if name.lower() == b"connection")
            if closing and not paid:
                raise _fail("connection_lost")
            # Final paid close is allowed through full body/DONE. Never reuse it.
            return httpx.Response(core.status, headers=core.headers, stream=_Body(core.stream, self.channel, paid), extensions=core.extensions)
        except Exception as error:
            self.close()
            if isinstance(error, (BoundGatewayTransportError, ConfidentialError)):
                raise
            raise _fail(self.channel.failure or "transport", self.channel.dispatched) from None

    def close(self) -> None:
        self.channel.stop()
        self.pool.close()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise _fail("configuration")

    async def __aenter__(self) -> _Transport:
        raise _fail("configuration")

    async def aclose(self) -> None:
        self.close()


class RetainedGatewayConnection:
    """Only built-in full verification can authorize this operation's socket."""
    def __init__(self, *, origin: str, policy: GatewayMeasurementPolicy, chain_verifier: Any,
                 approval_expires_at_ms: float | None = None, cancel_event: threading.Event | None = None,
                 timeout: float = 300.0, pre_dispatch_budget: float = 180.0, ca_pem: str | None = None,
                 refresh_policy: Callable[[], tuple[GatewayMeasurementPolicy, float | None]] | None = None) -> None:
        if httpx.__version__ != "0.28.1" or httpcore.__version__ != "1.0.9":
            raise _fail("configuration")
        if not isinstance(origin, str) or ca_pem is not None and (not isinstance(ca_pem, str) or not ca_pem.strip()):
            raise _fail("configuration")
        parsed = httpx.URL(origin)
        if parsed.scheme != "https" or parsed.userinfo or parsed.query or parsed.fragment or parsed.path != "/" or chain_verifier is None:
            raise _fail("configuration")
        origin = canonical_gateway_origin(origin)
        if any(type(v) not in {int, float} or not math.isfinite(v) or not 0 < v <= cap for v, cap in [(timeout, 900), (pre_dispatch_budget, 180)]):
            raise _fail("configuration")
        if approval_expires_at_ms is not None and (type(approval_expires_at_ms) not in {int, float} or not math.isfinite(approval_expires_at_ms) or approval_expires_at_ms <= 0):
            raise _fail("configuration")
        if cancel_event is not None and not isinstance(cancel_event, threading.Event):
            raise _fail("configuration")
        if any(inspect.iscoroutinefunction(getattr(chain_verifier, name, None)) for name in ["prepare", "verify_chain"]) or refresh_policy is not None and not callable(refresh_policy):
            raise _fail("configuration")
        active = _policy(policy)
        self._cancel = cancel_event or threading.Event()
        self._channel = _Channel(self._cancel, pre_dispatch_budget, approval_expires_at_ms if approval_expires_at_ms is not None else float("inf"))
        self._report: dict[str, Any] = freeze_gateway_report({})
        nonce = secrets.token_hex(32)
        challenge = "/v1/gateway/attestation?nonce=" + nonce
        try:
            self._transport = _Transport(parsed, self._channel, challenge, timeout, ca_pem)
            self.http = httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False, timeout=timeout)
        except Exception:
            self._channel.stop()
            raise
        try:
            self._channel.guard()
            with self.http.stream("GET", origin + challenge, headers={"accept": "application/json"}) as response:
                if not response.is_success:
                    raise _fail("untrusted")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 2097152:
                        raise _fail("untrusted")
            evidence = json.loads(raw)
            if not isinstance(evidence, dict):
                raise _fail("untrusted")
            prepared = chain_verifier
            prepare = getattr(chain_verifier, "prepare", None)
            if callable(prepare):
                prepared = self._bounded(lambda: prepare(str(evidence.get("quote", "")), accepted_tcb_statuses=list(active.acceptable_tcb_statuses), now_ms=time.time() * 1000))
            def verify() -> GatewayVerificationResult:
                return verify_gateway_attestation(evidence, nonce=nonce, origin=origin, policy=active,
                    now_ms=time.time() * 1000, observed_tls_spki_sha256=self._channel.pin,
                    observed_tls_spki_supplied=True, chain_verifier=prepared)
            verdict = self._bounded(verify)
            moved = verdict.status == "failed" and any(c.name == "quote_signature_chain" and c.passed for c in verdict.checks) and any(not c.passed and c.name in {"app_id_pinned", "compose_hash_pinned", "release_pinned", "platform_measurements_pinned", "os_image_pinned", "key_provider_pinned"} for c in verdict.checks)
            if moved and refresh_policy:
                updated = self._bounded(refresh_policy)
                if not isinstance(updated, tuple) or len(updated) != 2:
                    raise _fail("configuration")
                active = _policy(updated[0]); approval = updated[1]
                if approval is not None and (type(approval) not in {int, float} or not math.isfinite(approval) or approval <= 0):
                    raise _fail("configuration")
                self._channel.approval = approval if approval is not None else float("inf")
                self._channel.guard(); verdict = self._bounded(verify)
            binding = verdict.binding
            if verdict.status != "ok" or verdict.verification_level != "hardware-verified" or verdict.tcb_status != "UpToDate" or binding is None or binding.tls_spki_sha256 != self._channel.pin or not any(c.name == "quote_signature_chain" and c.passed for c in verdict.checks) or any(c.required and not c.passed for c in verdict.checks) or type(evidence.get("issued_at_ms")) is not int:
                raise ConfidentialError("a fully verified gateway identity is required for connection binding")
            self._channel.evidence_expiry = evidence["issued_at_ms"] + active.max_evidence_age_ms
            self._channel.authorized = True
            self._verdict = cast(GatewayVerificationResult, _freeze(verdict))
            self._raw_evidence = freeze_gateway_report(evidence)
            self._identity = RetainedGatewayIdentity(origin, nonce, self._channel.pin or "", binding.app_id, binding.instance_id, binding.compose_hash, min(self._channel.evidence_expiry, self._channel.approval))
            self.assert_dispatch_allowed()
        except Exception:
            self.close()
            raise

    def _bounded(self, run: Callable[[], T]) -> T:
        complete = threading.Event(); output: list[T] = []; errors: list[BaseException] = []
        def worker() -> None:
            try:
                value = run()
                if inspect.isawaitable(value):
                    if inspect.iscoroutine(value):
                        value.close()
                    raise _fail("configuration")
                output.append(value)
            except BaseException as error:  # noqa: BLE001 -- Marshal foreign synchronous adapter errors.
                errors.append(error)
            finally:
                complete.set()
        self._channel.guard()
        end = min(self._channel.pre_expires, time.monotonic() + 10)
        threading.Thread(target=worker, daemon=True).start()
        while not complete.wait(.01):
            self._channel.guard()
            if time.monotonic() >= end:
                raise _fail("timeout")
        self._channel.guard()
        if errors:
            if isinstance(errors[0], ConfidentialError):
                raise errors[0]
            raise ConfidentialError("a fully verified gateway identity is required for connection binding") from None
        return output[0]

    @property
    def identity(self) -> RetainedGatewayIdentity:
        return self._identity

    @property
    def verdict(self) -> GatewayVerificationResult:
        return self._verdict

    @property
    def raw_evidence(self) -> dict[str, Any]:
        return self._raw_evidence

    @property
    def report(self) -> dict[str, Any]:
        return self._report

    @report.setter
    def report(self, value: dict[str, Any]) -> None:
        if self._report:
            raise TypeError("verified gateway report is immutable")
        self._report = freeze_gateway_report(value)

    @property
    def cancel_event(self) -> threading.Event:
        return self._cancel

    def assert_dispatch_allowed(self) -> None:
        self._channel.guard()
        if self._channel.authorized and not self._channel.busy and any(c.is_closed() or c.has_expired() for c in self._transport.pool.connections):
            self._channel.retired = True
            raise _fail("connection_lost")

    def close(self) -> None:
        self.http.close()
