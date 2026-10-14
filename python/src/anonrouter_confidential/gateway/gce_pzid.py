"""GCE "PZID": what MROWNER means on a Google Cloud C3 Intel TDX VM.

On GCE C3 TDX VMs Google writes MR_OWNER = SHA-384(PZID), where PZID is the
canonical ASCII JSON of the VM's numeric project, zone and instance id, exactly
go-tdx-guest ``gce/pzid.go`` ``PZIDPayload``::

    {"instanceId":<uint64>,"numericalProjectId":<uint64>,"zone":"<zone>"}

C4 VMs leave MR_OWNER zero. A release policy v3 tuple may carry the owner-signed
rule ``mrOwnerRule: {kind: "gce-pzid", projectNumber, zones}`` with the zero
MR_OWNER placeholder; a quote then matches only with a PZID whose SHA-384 is the
quoted MR_OWNER, in the pinned project and a listed zone. A PZID is never trusted
by itself: the comparison against the hardware-quoted register binds it.

Numbers travel as decimal strings: instance ids exceed 2^53. Mirrors the
JavaScript ``gce-pzid.ts``; shared vectors in ``shared/vectors/gce-pzid.json``.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

GCE_PZID_RULE_KIND = "gce-pzid"
#: The 48-byte zero MR_OWNER: C4, and the placeholder a gce-pzid tuple carries.
GCE_ZERO_MR_OWNER = "00" * 48
MAX_GCE_PZID_RULE_ZONES = 8
MAX_GCE_PZID_CHARS = 256

_U64_MAX = 18446744073709551615
_UINT64_DIGITS = re.compile(r"^(?:0|[1-9][0-9]{0,19})\Z")
_ZONE = re.compile(r"^[a-z0-9-]{1,63}\Z")
_PZID = re.compile(
    r'^\{"instanceId":(0|[1-9][0-9]{0,19}),"numericalProjectId":(0|[1-9][0-9]{0,19}),"zone":"([a-z0-9-]{1,63})"\}\Z'
)


class GcePzidError(ValueError):
    pass


def is_gce_uint64(value: Any) -> bool:
    return isinstance(value, str) and bool(_UINT64_DIGITS.match(value)) and int(value) <= _U64_MAX


def is_gce_positive_uint64(value: Any) -> bool:
    return is_gce_uint64(value) and value != "0"


def is_gce_zone(value: Any) -> bool:
    return isinstance(value, str) and bool(_ZONE.match(value))


def validate_gce_mr_owner_rule(raw: Any, at: str = "mrOwnerRule") -> dict[str, Any]:
    """Validate an ``mrOwnerRule`` exactly as the server's gcePzidRuleSchema does."""
    if not isinstance(raw, dict):
        raise GcePzidError(f"{at} must be an object")
    if set(raw) != {"kind", "projectNumber", "zones"}:
        raise GcePzidError(f"{at} must have exactly the fields kind, projectNumber, zones")
    if raw["kind"] != GCE_PZID_RULE_KIND:
        raise GcePzidError(f"{at}.kind must be {GCE_PZID_RULE_KIND}")
    if not is_gce_positive_uint64(raw["projectNumber"]):
        raise GcePzidError(f"{at}.projectNumber must be a nonzero canonical uint64 decimal string")
    zones = raw["zones"]
    if not isinstance(zones, list) or not 1 <= len(zones) <= MAX_GCE_PZID_RULE_ZONES:
        raise GcePzidError(f"{at}.zones must contain 1..{MAX_GCE_PZID_RULE_ZONES} zones")
    for index, zone in enumerate(zones):
        if not is_gce_zone(zone):
            raise GcePzidError(f"{at}.zones[{index}] is not a GCE zone")
    for index in range(1, len(zones)):
        if not zones[index - 1] < zones[index]:
            raise GcePzidError(f"{at}.zones must be sorted and unique")
    return {"kind": GCE_PZID_RULE_KIND, "projectNumber": raw["projectNumber"], "zones": list(zones)}


def gce_pzid_payload(instance: dict[str, str]) -> str:
    """go-tdx-guest ``PZIDPayload``, byte for byte."""
    zone = instance["zone"]
    if not isinstance(zone, str) or not re.fullmatch(r"[a-z0-9-]+", zone):
        raise GcePzidError("zone contains non-GCE zone characters")
    if not is_gce_uint64(instance["instanceId"]) or not is_gce_uint64(instance["projectNumber"]):
        raise GcePzidError("not a canonical uint64")
    return (
        f'{{"instanceId":{instance["instanceId"]},"numericalProjectId":{instance["projectNumber"]},'
        f'"zone":"{zone}"}}'
    )


def gce_pzid_digest_hex(payload: str) -> str:
    return hashlib.sha384(payload.encode("utf-8")).hexdigest()


def parse_gce_pzid(payload: Any) -> dict[str, str] | None:
    """Parse a presented PZID strictly; None for anything but the exact form."""
    if not isinstance(payload, str) or len(payload) > MAX_GCE_PZID_CHARS:
        return None
    match = _PZID.match(payload)
    if not match:
        return None
    instance_id, project_number, zone = match.groups()
    if not is_gce_positive_uint64(instance_id) or not is_gce_positive_uint64(project_number) or not is_gce_zone(zone):
        return None
    instance = {"projectNumber": project_number, "zone": zone, "instanceId": instance_id}
    return instance if gce_pzid_payload(instance) == payload else None


def gce_instance_from_mr_owner(payload: Any, mr_owner: Any) -> dict[str, str] | None:
    """The VM a quoted MR_OWNER names, from a presented PZID, or None."""
    normalized = mr_owner.lower() if isinstance(mr_owner, str) else ""
    if not re.fullmatch(r"[0-9a-f]{96}", normalized) or normalized == GCE_ZERO_MR_OWNER:
        return None
    instance = parse_gce_pzid(payload)
    if instance is None or gce_pzid_digest_hex(payload) != normalized:
        return None
    return instance


def gce_pzid_rule_admits(rule: Any, instance: dict[str, str]) -> bool:
    return (
        isinstance(rule, dict)
        and instance["projectNumber"] == rule.get("projectNumber")
        and isinstance(rule.get("zones"), list)
        and instance["zone"] in rule["zones"]
    )


def gce_instance_resource(instance: dict[str, str]) -> str:
    return f'projects/{instance["projectNumber"]}/zones/{instance["zone"]}/instances/{instance["instanceId"]}'
