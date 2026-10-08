"""Opt-in sync transport primitive; SDK defaults never select it implicitly.

A supplied fingerprint is not a verification verdict. Install it only after
fresh quote/policy verification. Tested API: httpx 0.28.1, httpcore 1.0.9.
"""
from __future__ import annotations

import hashlib
import math
import re
import select
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpcore
import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class BoundGatewayTransportError(Exception):
    def __init__(self, code: str, message: str, dispatch_phase: str = "may_have_dispatched") -> None:
        super().__init__(message)
        self.code = code
        self.dispatch_phase = dispatch_phase


def _failure(code: str) -> BoundGatewayTransportError:
    phase = "before_http" if code in {"configuration", "tls_pin_mismatch", "tls_certificate", "authorization"} else "may_have_dispatched"
    return BoundGatewayTransportError(code, f"Bound gateway transport refused ({code}).", phase)


class _Operation:
    def __init__(self, cancel: threading.Event, timeout: float, before_http_dispatch: Callable[[], None] | None = None) -> None:
        self.cancel = cancel
        self.before_http_dispatch = before_http_dispatch
        self.expires = time.monotonic() + timeout
        self.done = threading.Event()
        self.lock = threading.Lock()
        self.sockets: set[socket.socket] = set()
        self.failure: str | None = None
        self.watcher = threading.Thread(target=self._watch, daemon=True)
        self.watcher.start()

    def _watch(self) -> None:
        while not self.done.wait(0.01):
            if self.cancel.is_set() or time.monotonic() >= self.expires:
                self.stop("cancelled" if self.cancel.is_set() else "timeout")
                return

    def remaining(self, timeout: float | None = None) -> float:
        if self.failure:
            raise _failure(self.failure)
        if self.cancel.is_set():
            self.stop("cancelled")
            raise _failure("cancelled")
        remaining = self.expires - time.monotonic()
        if remaining <= 0:
            self.stop("timeout")
            raise _failure("timeout")
        return remaining if timeout is None else min(remaining, timeout)

    def own(self, sock: socket.socket) -> None:
        with self.lock:
            self.sockets.add(sock)
        self.remaining()

    def replace(self, previous: socket.socket, current: socket.socket) -> None:
        with self.lock:
            self.sockets.discard(previous)
            self.sockets.add(current)
        self.remaining()

    def stop(self, reason: str | None = None) -> None:
        with self.lock:
            if reason and not self.failure:
                self.failure = reason
            sockets = list(self.sockets)
            self.sockets.clear()
        self.done.set()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


class _BoundStream(httpcore.NetworkStream):
    def __init__(self, sock: socket.socket, operation: _Operation, host: str,
                 pin: str, verified: bool = False) -> None:
        self.socket, self.operation, self.host, self.pin = sock, operation, host, pin
        # Internal state set solely after our TLS proof; never a public escape flag.
        self._tls_accepted = verified

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if not self._tls_accepted:
            raise _failure("tls_certificate")
        self.socket.settimeout(self.operation.remaining(timeout))
        try:
            chunk = self.socket.recv(max_bytes)
            # A watcher shutdown can look like ordinary EOF to OpenSSL. Check
            # cancellation/deadline again so a truncated stream is not reported
            # as a normal successful completion.
            self.operation.remaining()
            return chunk
        except TimeoutError:
            self.operation.stop("timeout")
            raise _failure(self.operation.failure or "timeout") from None
        except OSError:
            raise _failure(self.operation.failure or "transport") from None

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if not self._tls_accepted:
            raise _failure("tls_certificate")
        self.socket.settimeout(self.operation.remaining(timeout))
        try:
            self.socket.sendall(buffer)
            self.operation.remaining()
        except TimeoutError:
            self.operation.stop("timeout")
            raise _failure(self.operation.failure or "timeout") from None
        except OSError:
            raise _failure(self.operation.failure or "transport") from None

    def close(self) -> None:
        self.socket.close()

    def start_tls(self, ssl_context: ssl.SSLContext, server_hostname: str | None = None,
                  timeout: float | None = None) -> httpcore.NetworkStream:
        if (self._tls_accepted or server_hostname != self.host
                or ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname):
            raise _failure("tls_certificate")
        try:
            handshake_expires = time.monotonic() + self.operation.remaining(timeout)
            # Register the SSL socket before the blocking handshake so cancellation
            # can shut it down. No HTTP byte can be written through this stream yet.
            tls = ssl_context.wrap_socket(self.socket, server_hostname=self.host,
                                          do_handshake_on_connect=False)
            self.operation.replace(self.socket, tls)
            # Poll a nonblocking handshake. Closing an SSLSocket from another
            # thread does not reliably interrupt OpenSSL's blocking handshake on
            # every platform; this loop bounds cancellation independently of it.
            tls.setblocking(False)
            while True:
                remaining = min(self.operation.remaining(), handshake_expires - time.monotonic())
                if remaining <= 0:
                    self.operation.stop("timeout")
                    raise _failure("timeout")
                try:
                    tls.do_handshake()  # ordinary chain + hostname validation
                    break
                except ssl.SSLWantReadError:
                    select.select([tls], [], [], min(remaining, 0.01))
                except ssl.SSLWantWriteError:
                    select.select([], [tls], [], min(remaining, 0.01))
            tls.setblocking(True)
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise _failure("tls_certificate")
            actual = hashlib.sha256(x509.load_der_x509_certificate(der).public_key()
                                    .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            if actual != self.pin:
                raise _failure("tls_pin_mismatch")
            self.operation.remaining()
            try:
                if self.operation.before_http_dispatch:
                    self.operation.before_http_dispatch()
            except Exception:  # noqa: BLE001 -- Fail any authorization guard before HTTP without exposing its inputs.
                raise _failure("authorization") from None
            # Returning is the enforcement point: HTTPCore cannot construct/write
            # its HTTP exchange until the TLS upgrade has returned successfully.
            return _BoundStream(tls, self.operation, self.host, self.pin, verified=True)
        except BoundGatewayTransportError:
            self.operation.stop()
            raise
        except Exception:  # noqa: BLE001 -- Sanitize all foreign TLS/crypto errors and close before HTTP ownership.
            reason = self.operation.failure or "tls_certificate"
            self.operation.stop()
            raise _failure(reason) from None

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object":
            return self.socket if isinstance(self.socket, ssl.SSLSocket) else None
        if info == "socket":
            return self.socket
        if info == "is_readable":
            try:
                return bool(select.select([self.socket], [], [], 0)[0])
            except (OSError, ValueError):
                return True
        if info == "client_addr":
            return self.socket.getsockname()
        if info == "server_addr":
            return self.socket.getpeername()
        return None


class _BoundBackend(httpcore.NetworkBackend):
    def __init__(self, operation: _Operation, host: str, port: int, pin: str) -> None:
        self.operation, self.host, self.port, self.pin = operation, host, port, pin

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None, socket_options: Any = None) -> httpcore.NetworkStream:
        if host != self.host or port != self.port or local_address or socket_options:
            raise _failure("configuration")
        try:
            # System DNS resolution itself is synchronous and cannot be interrupted
            # by an Event. The watcher prevents later use, but is not a DNS SLA.
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            self.operation.remaining(timeout)
            connect_expires = time.monotonic() + self.operation.remaining(timeout)
            for family, kind, protocol, _, address in addresses:
                sock = socket.socket(family, kind, protocol)
                self.operation.own(sock)
                sock.settimeout(max(0.001, min(self.operation.remaining(), connect_expires - time.monotonic())))
                try:
                    sock.connect(address)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.operation.remaining()
                    return _BoundStream(sock, self.operation, host, self.pin)
                except OSError:
                    sock.close()
                    self.operation.remaining()
            raise _failure("transport")
        except BoundGatewayTransportError:
            raise
        except Exception:  # noqa: BLE001 -- Content-free network boundary, never expose resolver inputs/errors.
            raise _failure(self.operation.failure or "transport") from None

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
        raise _failure("configuration")


class _Body(httpx.SyncByteStream):
    def __init__(self, body: Any, pool: httpcore.ConnectionPool, operation: _Operation,
                 finish: Any) -> None:
        self.body, self.pool, self.operation, self.finish = body, pool, operation, finish

    def __iter__(self) -> Iterator[bytes]:
        try:
            for chunk in self.body:
                self.operation.remaining()
                yield chunk
        except BoundGatewayTransportError:
            raise
        except Exception:  # noqa: BLE001 -- Stream/library errors must not expose HTTP data in user-facing exceptions.
            raise _failure(self.operation.failure or "transport") from None
        finally:
            self.close()

    def close(self) -> None:
        try:
            self.body.close()
        finally:
            self.pool.close()
            self.operation.stop()
            self.finish(self.operation)


class SpkiBoundGatewayTransport(httpx.BaseTransport):
    """Fresh private pool per request, immutable origin/pin, no redirects/retries.

    Cancellation: pass a threading.Event as the request extension
    ``bound_gateway_cancel``. Setting it closes owned sockets through streaming.
    This is sync-only preparation, not HTTPX AsyncClient support.
    """
    def __init__(self, *, origin: str, expected_tls_spki_sha256: str, ca_pem: str | None = None,
                 handshake_timeout: float = 10.0, request_timeout: float = 900.0,
                 cancel_event: threading.Event | None = None,
                 before_http_dispatch: Callable[[], None] | None = None) -> None:
        # This preparation is accepted against one reviewed API combination.
        # SDK integration must widen this matrix through tests, not assumptions.
        if httpx.__version__ != "0.28.1" or httpcore.__version__ != "1.0.9":
            raise _failure("configuration")
        if (not isinstance(origin, str) or not isinstance(expected_tls_spki_sha256, str)
                or (cancel_event is not None and not isinstance(cancel_event, threading.Event))
                or (before_http_dispatch is not None and not callable(before_http_dispatch))):
            raise _failure("configuration")
        self._fixed_cancel = cancel_event is not None
        self._cancel_event = cancel_event or threading.Event()
        self._before_http_dispatch = before_http_dispatch
        self._origin = httpx.URL(origin)
        if (self.origin.scheme != "https" or self.origin.userinfo or self.origin.query
                or self.origin.fragment or self.origin.path != "/"
                or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_tls_spki_sha256)
                or any(not math.isfinite(t) or not 0 < t <= 3600 for t in [handshake_timeout, request_timeout])):
            raise _failure("configuration")
        self._pin = expected_tls_spki_sha256.lower()
        self._context = ssl.create_default_context(cadata=ca_pem)
        self._handshake_timeout, self._request_timeout = handshake_timeout, request_timeout
        self.pending: set[_Operation] = set()
        self.lock = threading.Lock()
        self.closed = False

    @property
    def origin(self) -> httpx.URL:
        return self._origin

    @property
    def pin(self) -> str:
        return self._pin

    def _finish(self, operation: _Operation) -> None:
        with self.lock:
            self.pending.discard(operation)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if (url.scheme, url.host, url.port or 443) != (self.origin.scheme, self.origin.host, self.origin.port or 443) or url.userinfo or url.fragment:
            raise _failure("configuration")
        if set(request.extensions) - {"timeout", "bound_gateway_cancel"}:
            raise _failure("configuration")
        if request.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise _failure("configuration")
        if request.headers.get("host") != url.netloc.decode("ascii"):
            raise _failure("configuration")
        if any(name in request.headers for name in ["transfer-encoding", "upgrade", "trailer", "expect"]) or any(name.startswith("proxy-") for name in request.headers):
            raise _failure("configuration")
        # HTTPX's Request owns framing. Streaming uploads are deliberately excluded
        # so exact framing cannot be substituted after pin validation.
        try:
            content = request.content
        except httpx.RequestNotRead:
            raise _failure("configuration") from None
        if request.method in {"GET", "HEAD"} and content:
            raise _failure("configuration")
        if "content-length" in request.headers and request.headers["content-length"] != str(len(content)):
            raise _failure("configuration")
        cancel = request.extensions.get("bound_gateway_cancel", self._cancel_event)
        if not isinstance(cancel, threading.Event) or (self._fixed_cancel and cancel is not self._cancel_event):
            raise _failure("configuration")
        if cancel.is_set():
            raise _failure("cancelled")
        budgets = request.extensions.get("timeout", {})
        if not isinstance(budgets, dict) or set(budgets) - {"connect", "read", "write", "pool"}:
            raise _failure("configuration")
        for value in budgets.values():
            if value is not None and (type(value) not in {int, float} or not math.isfinite(value) or value <= 0):
                raise _failure("configuration")
        # Caller deadlines can tighten the owned operation, never remove its
        # absolute stream deadline. This narrow adapter uses the smaller read/
        # write budget as a whole-operation bound rather than a per-read reset.
        request_timeout = min([self._request_timeout] + [budgets[name] for name in ["read", "write"] if budgets.get(name) is not None])
        handshake_timeout = min(self._handshake_timeout, budgets.get("connect") or self._handshake_timeout)
        operation = _Operation(cancel, request_timeout, self._before_http_dispatch)
        with self.lock:
            if self.closed:
                operation.stop()
                raise _failure("cancelled")
            self.pending.add(operation)
        pool = httpcore.ConnectionPool(ssl_context=self._context, max_connections=1,
                                      max_keepalive_connections=0, http1=True, http2=False,
                                      retries=0, network_backend=_BoundBackend(operation, self.origin.host,
                                                                             self.origin.port or 443, self.pin))
        headers = [(k, v) for k, v in request.headers.raw if k.lower() not in {b"accept-encoding", b"connection"}]
        headers.extend([(b"accept-encoding", b"identity"), (b"connection", b"close")])
        try:
            core = pool.handle_request(httpcore.Request(
                method=request.method, url=httpcore.URL(scheme=url.raw_scheme, host=url.raw_host,
                                                       port=url.port, target=url.raw_path),
                headers=headers, content=content,
                extensions={"timeout": {"connect": handshake_timeout, "read": request_timeout,
                                        "write": request_timeout, "pool": handshake_timeout}},
            ))
            if 300 <= core.status < 400 and core.status != 304:
                raise _failure("redirect")
            encoding = [value for name, value in core.headers if name.lower() == b"content-encoding"]
            if encoding and encoding != [b"identity"]:
                raise _failure("transport")
            return httpx.Response(status_code=core.status, headers=core.headers,
                                  stream=_Body(core.stream, pool, operation, self._finish), extensions=core.extensions)
        except Exception as error:
            pool.close()
            operation.stop()
            self._finish(operation)
            if isinstance(error, BoundGatewayTransportError):
                raise
            raise _failure(operation.failure or "transport") from None

    async def __aenter__(self) -> SpkiBoundGatewayTransport:
        raise _failure("configuration")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise _failure("configuration")

    async def aclose(self) -> None:
        self.close()

    def close(self) -> None:
        with self.lock:
            self.closed = True
            operations = list(self.pending)
            self.pending.clear()
        for operation in operations:
            operation.stop("cancelled")
