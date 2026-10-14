"""Byte-exact encoding for AnonRouter release policy v3 (GCP-native content nodes).

Mirrors the server's ``canonical()``/``digest()`` helpers and the JavaScript
``release-v3-canonical.ts`` so both languages derive the same signed message,
owner root, tuple digests and policy SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

#: The server's PROTOCOL constant: the prefix of every v3 digest domain.
RELEASE_V3_DIGEST_PROTOCOL = "anonrouter-content-node-bootstrap-v1"

_MAX_SAFE_INTEGER = 2**53 - 1
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]*$")

#: The ten quote registers a v3 measured tuple pins, without its label.
RELEASE_MEASURED_REGISTER_FIELDS: tuple[str, ...] = (
    "mrTd", "mrConfigId", "mrOwner", "mrOwnerConfig", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "tdAttributes", "xfam",
)


class ReleaseCanonicalError(ValueError):
    """A value with no canonical release encoding."""

    def __init__(self) -> None:
        super().__init__("value has no canonical release encoding")


def canonical_release_json(value: Any, depth: int = 0) -> str:
    """Sorted keys, printable ASCII strings, non-negative safe integers, plain
    objects and arrays, depth at most 12. Anything else refuses."""
    if depth > 12:
        raise ReleaseCanonicalError()
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if value < 0 or value > _MAX_SAFE_INTEGER:
            raise ReleaseCanonicalError()
        return str(value)
    if isinstance(value, float):
        # JSON.parse yields 1 for "1.0"; accept only exact safe integers.
        if not value.is_integer() or value < 0 or value > _MAX_SAFE_INTEGER:
            raise ReleaseCanonicalError()
        return str(int(value))
    if isinstance(value, str):
        if not _PRINTABLE_ASCII.match(value):
            raise ReleaseCanonicalError()
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_release_json(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            if not isinstance(key, str) or not _PRINTABLE_ASCII.match(key):
                raise ReleaseCanonicalError()
            parts.append(json.dumps(key) + ":" + canonical_release_json(value[key], depth + 1))
        return "{" + ",".join(parts) + "}"
    raise ReleaseCanonicalError()


def canonical_release_bytes(value: Any) -> bytes:
    return canonical_release_json(value).encode("ascii")


def release_digest_hex(domain: str, value: Any) -> str:
    """digest(domain, v) = SHA-256(ASCII(PROTOCOL + "/" + domain + "\\0") || canonical(v))."""
    prefix = f"{RELEASE_V3_DIGEST_PROTOCOL}/{domain}\0".encode("ascii")
    return hashlib.sha256(prefix + canonical_release_bytes(value)).hexdigest()


def release_tuple_digest(registers: dict[str, Any]) -> str:
    """tupleDigest = digest("measured-tuple", tuple without tupleId), the rule included."""
    unlabeled: dict[str, Any] = {field: registers[field] for field in RELEASE_MEASURED_REGISTER_FIELDS}
    rule = registers.get("mrOwnerRule")
    if rule is not None:
        unlabeled["mrOwnerRule"] = {
            "kind": rule["kind"], "projectNumber": rule["projectNumber"], "zones": list(rule["zones"]),
        }
    return release_digest_hex("measured-tuple", unlabeled)


def release_policy_sha256(payload: Any) -> str:
    """SHA-256 of the canonical payload bytes: the checkpoint's policy identity."""
    return hashlib.sha256(canonical_release_bytes(payload)).hexdigest()
