"""Synthetic Intel TDX quote + dstack event log builder for the gateway tests.

This fabricates the STRUCTURE of a quote (byte offsets, registers, report_data) so
the verifier's structural, replay, binding, and policy logic can be exercised
deterministically without TDX hardware.

It deliberately cannot fabricate a valid Intel ECDSA signature. That is the point:
tests using this fixture must never assert ``hardware-verified``, only
``provider-attested``, which is exactly the honest ceiling the real verifier applies
when no DCAP chain verifier is wired.

Mirrors ``js/confidential/test/helpers/gateway-fixtures.ts`` so a failure in one
language is reproducible in the other.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, replace
from typing import Any

from anonrouter_confidential.gateway.event_log import (
    DstackEventLogEntry,
    compute_rtmr3_event_digest_v1,
    replay_register,
    rtmr3_event_digest,
)

_HEADER_LEN = 48
_BODY_LEN = 584
TEE_TYPE_TDX = 0x00000081

# Offsets from the start of the quote, mirroring anonrouter_confidential.tdx.
OFF_TD_ATTRIBUTES = 168
OFF_MR_TD = 184
OFF_MR_CONFIG_ID = 232
OFF_RTMR0 = 376
OFF_REPORT_DATA = 568

#: Shape of MRCONFIGID as observed on the production TDX CVM: a 33-byte
#: compressed SEC1 point, zero-padded to 48.
SYNTHETIC_MR_CONFIG_ID = "02" + "ab" * 32 + "00" * 15

#: The dstack OS image hash the synthetic event log measures.
SYNTHETIC_OS_IMAGE_HASH = "de" * 32

DSTACK_EVENT_TYPE = 134_217_729

_ZERO_48 = "0" * 96


def build_synthetic_tdx_quote(
    *,
    report_data_hex: str,
    rtmr0: str = _ZERO_48,
    rtmr1: str = _ZERO_48,
    rtmr2: str = _ZERO_48,
    rtmr3: str = _ZERO_48,
    mr_td: str = _ZERO_48,
    mr_config_id: str = SYNTHETIC_MR_CONFIG_ID,
    tee_type: int = TEE_TYPE_TDX,
    debug: bool = False,
) -> str:
    """Build a structurally valid TDX v4 quote with the given measurements."""
    buf = bytearray(_HEADER_LEN + _BODY_LEN)
    struct.pack_into("<H", buf, 0, 4)  # version
    struct.pack_into("<H", buf, 2, 2)  # att_key_type (ECDSA-P256)
    struct.pack_into("<I", buf, 4, tee_type)
    if debug:
        buf[OFF_TD_ATTRIBUTES] |= 0x01

    def write(offset: int, hex_value: str, size: int) -> None:
        value = bytes.fromhex(hex_value)
        if len(value) != size:
            raise ValueError(f"expected {size} bytes at offset {offset}")
        buf[offset : offset + size] = value

    write(OFF_MR_TD, mr_td, 48)
    write(OFF_MR_CONFIG_ID, mr_config_id, 48)
    write(OFF_RTMR0, rtmr0, 48)
    write(OFF_RTMR0 + 48, rtmr1, 48)
    write(OFF_RTMR0 + 96, rtmr2, 48)
    write(OFF_RTMR0 + 144, rtmr3, 48)
    write(OFF_REPORT_DATA, report_data_hex, 64)
    return bytes(buf).hex()


def quote_register(quote_hex: str, offset: int) -> str:
    """Read one 48-byte register back out of a synthetic quote, for pinning tests."""
    return quote_hex[offset * 2 : (offset + 48) * 2]


def rtmr3_event(
    event: str, payload_hex: str, event_type: int = DSTACK_EVENT_TYPE
) -> DstackEventLogEntry:
    """A dstack V1 RTMR3 event.

    ``digest`` is left EMPTY, matching what a real guest agent returns: RTMR3
    entries ship without a digest and the verifier derives it.
    """
    return DstackEventLogEntry(
        imr=3, event_type=event_type, digest="", event=event, event_payload=payload_hex
    )


def rtmr3_event_with_digest(
    event: str, payload_hex: str, event_type: int = DSTACK_EVENT_TYPE
) -> DstackEventLogEntry:
    """The same event, additionally carrying the digest it derives to."""
    entry = rtmr3_event(event, payload_hex, event_type)
    return replace(entry, digest=compute_rtmr3_event_digest_v1(entry))


def rtmr3_event_v2(
    event: str, payload_hex: str, event_type: int = DSTACK_EVENT_TYPE
) -> DstackEventLogEntry:
    """A dstack V2 RTMR3 event: the hashed bytes are published as ``preimage``."""
    # Canonical JSON with sorted keys, matching dstack's JCS serialization.
    preimage = json.dumps(
        {"name": event, "payload": payload_hex, "type": event_type},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return DstackEventLogEntry(
        imr=3,
        event_type=event_type,
        digest=hashlib.sha384(preimage).hexdigest(),
        event=event,
        event_payload=payload_hex,
        preimage=preimage.hex(),
        version=2,
    )


def boot_event(imr: int, seed: str) -> DstackEventLogEntry:
    """A boot-chain event for RTMR0..2, whose digest is opaque firmware output."""
    return DstackEventLogEntry(
        imr=imr,
        event_type=2_147_483_659,
        digest=hashlib.sha384(seed.encode("utf-8")).hexdigest(),
        event="",
        event_payload="",
    )


@dataclass(frozen=True)
class SyntheticEventLog:
    events: list[DstackEventLogEntry]
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str

    def as_json(self, transform: Any = None) -> str:
        events = [transform(e) if transform else e for e in self.events]
        return json.dumps([_entry_dict(e) for e in events])


def _entry_dict(entry: DstackEventLogEntry) -> dict[str, Any]:
    out: dict[str, Any] = {
        "imr": entry.imr,
        "event_type": entry.event_type,
        "digest": entry.digest,
        "event": entry.event,
        "event_payload": entry.event_payload,
    }
    if entry.preimage is not None:
        out["preimage"] = entry.preimage
    if entry.version is not None:
        out["version"] = entry.version
    return out


def build_synthetic_event_log(
    *,
    app_id: str,
    compose_hash: str,
    instance_id: str,
    key_provider_id: str | None = None,
    os_image_hash: str | None = None,
    extra_rtmr3: list[DstackEventLogEntry] | None = None,
) -> SyntheticEventLog:
    """Build a complete event log for a dstack CVM and the RTMRs it replays to."""
    # Event order mirrors a real dstack 0.5.9 boot, so a test that depends on
    # ordering is depending on the same ordering production has.
    events: list[DstackEventLogEntry] = [
        boot_event(0, "virtual-firmware"),
        boot_event(1, "kernel"),
        boot_event(2, "kernel-cmdline"),
        rtmr3_event("system-preparing", ""),
        rtmr3_event("app-id", app_id),
        rtmr3_event("compose-hash", compose_hash),
        rtmr3_event("instance-id", instance_id),
        rtmr3_event("os-image-hash", os_image_hash or SYNTHETIC_OS_IMAGE_HASH),
        rtmr3_event(
            "key-provider",
            json.dumps({"name": "kms", "id": key_provider_id or "0" * 64}).encode("utf-8").hex(),
        ),
        *(extra_rtmr3 or []),
    ]
    # RTMR3 replays from DERIVED digests, exactly as the verifier does, because the
    # real agent ships those entries without one.
    registers = [
        replay_register(
            [
                (rtmr3_event_digest(e) or "ff" * 48) if imr == 3 else e.digest
                for e in events
                if e.imr == imr
            ]
        )
        for imr in range(4)
    ]
    return SyntheticEventLog(
        events=events, rtmr0=registers[0], rtmr1=registers[1], rtmr2=registers[2], rtmr3=registers[3]
    )


def build_vm_config(os_image_hash: str = SYNTHETIC_OS_IMAGE_HASH) -> str:
    """The vm_config blob a CVM serves, as a JSON string."""
    return json.dumps(
        {
            "os_image_hash": os_image_hash,
            "cpu_count": 1,
            "memory_size": 2_147_483_648,
            "spec_version": 1,
        }
    )


def build_app_compose(**overrides: Any) -> tuple[str, str]:
    """Build the ``app_compose`` manifest string and its measured SHA-256."""
    docker_compose = "\n".join(
        [
            "services:",
            "  relay:",
            "    image: ghcr.io/example/anonrouter@sha256:" + "1" * 64,
            "    read_only: true",
            "  gateway-attestation:",
            "    image: ghcr.io/example/anonrouter@sha256:" + "2" * 64,
        ]
    )
    manifest_obj: dict[str, Any] = {
        "manifest_version": 2,
        "name": "anonrouter-tee",
        "runner": "docker-compose",
        "docker_compose_file": docker_compose,
        "public_logs": False,
        "public_sysinfo": False,
        "kms_enabled": True,
        "gateway_enabled": True,
    }
    manifest_obj.update(overrides)
    manifest = json.dumps(manifest_obj, separators=(",", ":"))
    return manifest, hashlib.sha256(manifest.encode("utf-8")).hexdigest()
