"""The canonical binding object for AnonRouter GATEWAY attestation.

This is deliberately separate from the provider verifiers in ``verify/``. Those
answer "did the UPSTREAM model provider run my request in an enclave?". This
module answers the other half: "is the AnonRouter data plane I am talking to right
now the exact reviewed build running inside an Intel TDX confidential VM, and is
the key protecting this connection the one that TD holds?".

The binding is the single object whose SHA-512 digest is placed in the TDX quote's
64-byte ``report_data`` field. Because the TD cannot forge report_data, a caller
that recomputes this digest from the returned fields and finds it equal to the
quote's report_data has proven that the attesting TD asserted every field at quote
time: the caller's fresh nonce, the app/instance identity, the compose
measurement, the release identity, the public origin, and the application key.

Byte-for-byte equivalent to ``@anonrouter/confidential``'s binding module and to
the in-TEE producer, and proven so by ``shared/vectors/gateway-binding.json``. The
serialization is emitted with an explicit field order and JSON escaping that
matches ``JSON.stringify`` exactly; a one-byte difference would mean this verifier
rejects every genuine quote.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

#: Binding format version. Bump on ANY change to fields or serialization.
GATEWAY_BINDING_VERSION = 1

#: Report data is exactly 64 bytes in an Intel TDX quote; SHA-512 fills it.
GATEWAY_BINDING_DIGEST_ALGORITHM = "sha512"
GATEWAY_BINDING_DIGEST_HEX_LENGTH = 128

#: Caller nonce: exactly 32 bytes, lowercase hex.
GATEWAY_NONCE_BYTES = 32
GATEWAY_NONCE_HEX_LENGTH = GATEWAY_NONCE_BYTES * 2

GatewayKeyAlgorithm = Literal["x25519", "ed25519", "secp256k1"]
_KEY_ALGORITHMS = ("x25519", "ed25519", "secp256k1")

#: Where the client's TLS session terminates.
#:
#: ``in-tee-tls``  the private key for the served certificate was generated inside
#: this TD and never left it, so ``tls_spki_sha256`` names a certificate a client
#: can pin its own connection to.
#: ``gateway-tls`` TLS terminates in front of the TD. The TD still attests its own
#: code and application key, but the transport itself is NOT proof of who you are
#: talking to. Making the weaker mode explicit is the point.
GatewayTransportBinding = Literal["in-tee-tls", "gateway-tls"]
_TRANSPORT_BINDINGS = ("in-tee-tls", "gateway-tls")

_LOWER_HEX = re.compile(r"^[0-9a-f]+$")
_RELEASE_ID = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")

#: Fixed serialization order. This tuple, not the dataclass field order and not a
#: sort, defines the canonical form. Adding a field means bumping
#: GATEWAY_BINDING_VERSION and appending here.
_CANONICAL_FIELD_ORDER = (
    "v",
    "nonce",
    "app_id",
    "instance_id",
    "compose_hash",
    "release_id",
    "origin",
    "key_alg",
    "public_key",
    "transport",
    "tls_spki_sha256",
)

#: Ports JS's URL.origin omits, so a canonical origin never spells them out.
_DEFAULT_PORTS = {"http": 80, "https": 443}


class GatewayBindingError(ValueError):
    """A binding field that could not be validated. Carries the offending field."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class GatewayAttestationBinding:
    """The exact object hashed into report_data. Field names are the wire contract."""

    v: int
    nonce: str
    app_id: str
    instance_id: str
    compose_hash: str
    release_id: str
    origin: str
    key_alg: str
    public_key: str
    transport: str
    tls_spki_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in _CANONICAL_FIELD_ORDER}


def _require_lowercase_hex(field: str, value: Any, exact_chars: int | None = None) -> str:
    if not isinstance(value, str):
        raise GatewayBindingError(field, f"{field} must be a string")
    if not _LOWER_HEX.match(value):
        raise GatewayBindingError(field, f"{field} must be lowercase hex")
    if exact_chars is not None and len(value) != exact_chars:
        raise GatewayBindingError(field, f"{field} must be exactly {exact_chars} hex characters")
    if exact_chars is None and (len(value) == 0 or len(value) > 512):
        raise GatewayBindingError(field, f"{field} must be 1..512 hex characters")
    return value


def canonical_gateway_origin(value: Any) -> str:
    """Normalize an origin to the canonical ``scheme://host[:port]`` form.

    Origins are compared byte-for-byte by the verifier, so only the canonical form
    is accepted: no trailing slash, path, query, credentials, or fragment. This
    prevents an "equivalent" origin from silently passing an equality check that a
    different client would fail. The result matches JavaScript's ``URL.origin``.
    """
    if not isinstance(value, str) or len(value) == 0 or len(value) > 253 + 16:
        raise GatewayBindingError("origin", "origin must be a non-empty string")
    try:
        parts = urlsplit(value)
    except ValueError as exc:  # pragma: no cover - urlsplit is very permissive
        raise GatewayBindingError("origin", "origin must be an absolute URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise GatewayBindingError("origin", "origin must be http(s)")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise GatewayBindingError("origin", "origin must contain only scheme, host, and optional port")
    if parts.path not in ("", "/"):
        raise GatewayBindingError("origin", "origin must contain only scheme, host, and optional port")
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise GatewayBindingError("origin", "origin has an invalid port") from exc
    if not hostname:
        raise GatewayBindingError("origin", "origin must have a host")
    # urlsplit strips the brackets from an IPv6 literal; URL.origin keeps them.
    host = f"[{hostname}]" if ":" in hostname else hostname.lower()
    origin = f"{scheme}://{host}"
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        origin = f"{origin}:{port}"
    # Strip exactly ONE trailing slash, matching the JS `value.replace(/\/$/, "")`.
    compared = value.removesuffix("/")
    if origin != compared:
        raise GatewayBindingError(
            "origin", "origin must already be in canonical scheme://host[:port] form"
        )
    return origin


def assert_gateway_nonce(nonce: Any) -> str:
    """Validate a caller nonce. Rejects anything that is not exactly 32 bytes hex."""
    if not isinstance(nonce, str):
        raise GatewayBindingError("nonce", "nonce must be a string")
    return _require_lowercase_hex("nonce", nonce.lower(), GATEWAY_NONCE_HEX_LENGTH)


def _strip_prefix(value: Any) -> Any:
    if isinstance(value, str):
        lowered = value.lower()
        return lowered.removeprefix("0x")
    return value


def normalize_gateway_binding(raw: Any) -> GatewayAttestationBinding:
    """Validate and normalize an untrusted binding into the canonical shape.

    A field the verifier cannot validate can never contribute to a digest it
    accepts, so every field is checked here before any hashing happens.
    """
    if isinstance(raw, GatewayAttestationBinding):
        raw = raw.as_dict()
    if not isinstance(raw, dict):
        raise GatewayBindingError("binding", "binding must be a JSON object")

    # Reject unknown fields: a verifier that silently ignores an extra field would
    # accept a digest computed over data it never inspected.
    for key in raw:
        if key not in _CANONICAL_FIELD_ORDER:
            raise GatewayBindingError(key, f"binding carries unknown field {key}")

    if raw.get("v") != GATEWAY_BINDING_VERSION:
        raise GatewayBindingError("v", f"binding version must be {GATEWAY_BINDING_VERSION}")
    key_alg = raw.get("key_alg")
    if not isinstance(key_alg, str) or key_alg not in _KEY_ALGORITHMS:
        raise GatewayBindingError("key_alg", f"key_alg must be one of {', '.join(_KEY_ALGORITHMS)}")
    release_id = raw.get("release_id")
    if not isinstance(release_id, str) or not _RELEASE_ID.match(release_id):
        raise GatewayBindingError(
            "release_id", "release_id must be 1..128 chars of [A-Za-z0-9._:@+-]"
        )
    transport = raw.get("transport")
    if not isinstance(transport, str) or transport not in _TRANSPORT_BINDINGS:
        raise GatewayBindingError(
            "transport", f"transport must be one of {', '.join(_TRANSPORT_BINDINGS)}"
        )
    # A missing key would serialize away entirely; require an explicit null so the
    # absence of a TD-owned certificate is a signed assertion, not an omission.
    if "tls_spki_sha256" not in raw:
        raise GatewayBindingError(
            "tls_spki_sha256", "tls_spki_sha256 must be present (hex or null)"
        )
    spki_raw = raw["tls_spki_sha256"]
    tls_spki = (
        None
        if spki_raw is None
        else _require_lowercase_hex(
            "tls_spki_sha256", spki_raw.lower() if isinstance(spki_raw, str) else spki_raw, 64
        )
    )
    # A TD that claims to own the transport must name the certificate it owns.
    if transport == "in-tee-tls" and tls_spki is None:
        raise GatewayBindingError("tls_spki_sha256", "in-tee-tls requires a certificate SPKI digest")
    if transport == "gateway-tls" and tls_spki is not None:
        raise GatewayBindingError(
            "tls_spki_sha256", "gateway-tls must not claim a TD-owned certificate"
        )

    return GatewayAttestationBinding(
        v=GATEWAY_BINDING_VERSION,
        nonce=assert_gateway_nonce(raw.get("nonce")),
        app_id=_require_lowercase_hex("app_id", _strip_prefix(raw.get("app_id"))),
        instance_id=_require_lowercase_hex("instance_id", _strip_prefix(raw.get("instance_id"))),
        compose_hash=_require_lowercase_hex("compose_hash", _strip_prefix(raw.get("compose_hash")), 64),
        release_id=release_id,
        origin=canonical_gateway_origin(raw.get("origin")),
        key_alg=key_alg,
        public_key=_require_lowercase_hex("public_key", _strip_prefix(raw.get("public_key"))),
        transport=transport,
        tls_spki_sha256=tls_spki,
    )


def _js_json(value: Any) -> str:
    """Serialize one scalar exactly as ``JSON.stringify`` would.

    ``separators`` removes the spaces Python inserts by default, and
    ``ensure_ascii=False`` keeps non-ASCII characters raw the way JSON.stringify
    does rather than escaping them to ``\\uXXXX``. Every binding field is
    regex-constrained to ASCII, so this is belt and braces, but the serialization
    is the whole contract and a surprise here is a total verification failure.
    """
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def canonical_gateway_binding_json(binding: Any) -> str:
    """The canonical byte string hashed into report_data."""
    normalized = normalize_gateway_binding(binding).as_dict()
    parts = [f"{_js_json(field)}:{_js_json(normalized[field])}" for field in _CANONICAL_FIELD_ORDER]
    return "{" + ",".join(parts) + "}"


def gateway_binding_digest(binding: Any) -> bytes:
    """The 64-byte digest placed in the TDX quote's report_data field."""
    return hashlib.sha512(canonical_gateway_binding_json(binding).encode("utf-8")).digest()


def gateway_binding_hash(binding: Any) -> str:
    """Lowercase hex form of :func:`gateway_binding_digest` (128 characters)."""
    return gateway_binding_digest(binding).hex()
