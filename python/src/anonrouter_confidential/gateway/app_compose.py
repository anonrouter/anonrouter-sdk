"""Inspection of the attested dstack app-compose manifest.

``tcb_info.app_compose`` is the exact JSON string whose SHA-256 is measured into
RTMR3 as the "compose-hash" event. Because it is measured, everything inside it is
a hardware-backed fact about the running deployment, including the full
docker-compose text and the dstack feature switches. That makes two of AnonRouter's
privacy claims checkable rather than merely asserted::

    public_logs=false        the platform will not serve container logs publicly
    image digests pinned     the images that ran cannot be swapped behind a tag

This module does NOT parse YAML. Pulling a YAML parser into the verifier would add
an attack surface and a dependency for a job that needs only a scan for image
references. It extracts ``image:`` values lexically and requires each to carry an
``@sha256:`` digest, which is a conservative check: anything it cannot confidently
read as digest-pinned is reported as unpinned.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

_MAX_MANIFEST_BYTES = 1_000_000
_IMAGE_LINE = re.compile(r"^[ \t-]*image:[ \t]*[\"']?([^\"'#\r\n]+?)[\"']?[ \t]*(?:#.*)?$", re.MULTILINE)
_DIGEST_SUFFIX = re.compile(r"@sha256:[0-9a-f]{64}$")


class AppComposeError(ValueError):
    """An app-compose manifest that could not be read."""


@dataclass(frozen=True)
class AttestedImageReference:
    #: The reference exactly as written in the compose document.
    reference: str
    #: True when the reference carries an @sha256:<64 hex> digest.
    digest_pinned: bool


@dataclass(frozen=True)
class AttestedAppCompose:
    #: SHA-256 of the exact manifest string, lowercase hex.
    compose_hash: str
    name: str | None
    runner: str | None
    #: False is the hardened value; None means the field was absent.
    public_logs: bool | None
    public_sysinfo: bool | None
    kms_enabled: bool | None
    gateway_enabled: bool | None
    #: The raw docker-compose document, when the runner is docker-compose.
    docker_compose_file: str | None
    #: Environment variable names the manifest allows into the CVM.
    allowed_envs: list[str] = field(default_factory=list)
    #: Every ``image:`` reference found in the compose document.
    images: list[AttestedImageReference] = field(default_factory=list)


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def extract_compose_images(docker_compose_file: str) -> list[AttestedImageReference]:
    """Extract every image reference from a docker-compose document."""
    images: list[AttestedImageReference] = []
    seen: set[str] = set()
    for match in _IMAGE_LINE.finditer(docker_compose_file):
        reference = match.group(1).strip()
        if not reference or reference in seen:
            continue
        seen.add(reference)
        images.append(
            AttestedImageReference(
                reference=reference,
                digest_pinned=bool(_DIGEST_SUFFIX.search(reference)),
            )
        )
    return images


def read_attested_app_compose(manifest: Any) -> AttestedAppCompose:
    """Parse and hash the attested manifest.

    The returned ``compose_hash`` is computed from the string as given: the caller
    compares it to the measured RTMR3 "compose-hash" event, which is what makes the
    rest of this object evidence rather than a claim.
    """
    if not isinstance(manifest, str) or len(manifest) == 0:
        raise AppComposeError("app_compose must be a non-empty string")
    encoded = manifest.encode("utf-8")
    if len(encoded) > _MAX_MANIFEST_BYTES:
        raise AppComposeError("app_compose exceeds the maximum inspected size")
    compose_hash = hashlib.sha256(encoded).hexdigest()

    try:
        parsed = json.loads(manifest)
    except json.JSONDecodeError as exc:
        raise AppComposeError("app_compose is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise AppComposeError("app_compose must decode to a JSON object")

    docker_compose_file = _optional_str(parsed.get("docker_compose_file"))
    allowed = parsed.get("allowed_envs")
    return AttestedAppCompose(
        compose_hash=compose_hash,
        name=_optional_str(parsed.get("name")),
        runner=_optional_str(parsed.get("runner")),
        public_logs=_optional_bool(parsed.get("public_logs")),
        public_sysinfo=_optional_bool(parsed.get("public_sysinfo")),
        kms_enabled=_optional_bool(parsed.get("kms_enabled")),
        gateway_enabled=_optional_bool(parsed.get("gateway_enabled")),
        docker_compose_file=docker_compose_file,
        allowed_envs=[e for e in allowed if isinstance(e, str)] if isinstance(allowed, list) else [],
        images=extract_compose_images(docker_compose_file) if docker_compose_file else [],
    )
