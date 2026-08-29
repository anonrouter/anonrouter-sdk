"""Independent replay of a dstack/TDX RTMR event log.

The TDX quote carries RTMR0..RTMR3 as measured by hardware. The CVM also hands
back a plaintext event log describing WHAT was measured. Neither alone is
trustworthy: the quote's registers are authentic but opaque, and the event log is
readable but forgeable. Replaying the log and checking that it reproduces the
quote's registers is what turns the readable log into evidence.

Replay rule (matches dstack's guest agent): each RTMR starts at 48 zero bytes and
is extended per event as ``rtmr = SHA384(rtmr_prev || right_zero_pad_48(digest))``.
Implemented with hashlib so a verifier does not have to trust, or even install, the
vendor SDK to check the vendor's own claim.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

#: 48 zero bytes: the reset value of every RTMR.
RTMR_INITIAL_VALUE = "0" * 96

_RTMR_COUNT = 4
_DIGEST_BYTES = 48
#: A single event log is bounded so a hostile response cannot pin the CPU.
_MAX_EVENTS = 4096

_ANY_HEX = re.compile(r"^[0-9a-fA-F]*$")
_LOWER_HEX = re.compile(r"^[0-9a-f]*$")


class EventLogError(ValueError):
    """A structurally invalid event log."""


@dataclass(frozen=True)
class DstackEventLogEntry:
    """One measured event as reported by the guest agent."""

    imr: int
    event_type: int
    #: 48-byte SHA-384 digest, lowercase hex. Empty for V1 RTMR3 entries.
    digest: str
    #: Event name, e.g. "compose-hash", "instance-id", "key-provider".
    event: str
    #: Event value, hex. For "compose-hash" this is the compose hash itself.
    event_payload: str
    #: V2 events publish the exact hashed bytes, as hex.
    preimage: str | None = None
    version: int | None = None


def _as_int(value: Any, fallback: int | None) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else fallback


def parse_event_log(raw: Any) -> list[DstackEventLogEntry]:
    """Parse the guest agent's event log.

    ``event_log`` arrives as a JSON *string* alongside the quote; ``tcb_info
    .event_log`` arrives already parsed. Both are accepted. Raises on anything
    structurally wrong rather than skipping entries: a skipped entry would change
    the replay and could hide a measurement.
    """
    value = raw
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise EventLogError("event log is not valid JSON") from exc
    if not isinstance(value, list):
        raise EventLogError("event log must be an array")
    if len(value) > _MAX_EVENTS:
        raise EventLogError(f"event log exceeds {_MAX_EVENTS} entries")

    entries: list[DstackEventLogEntry] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise EventLogError(f"event {index} is not an object")
        imr = _as_int(entry.get("imr"), None)
        digest = entry.get("digest")
        if imr is None or imr < 0 or imr >= _RTMR_COUNT:
            raise EventLogError(f"event {index} has an out-of-range imr")
        if not isinstance(digest, str) or not _ANY_HEX.match(digest) or len(digest) % 2 != 0:
            raise EventLogError(f"event {index} has a malformed digest")
        if len(digest) > _DIGEST_BYTES * 2:
            raise EventLogError(f"event {index} digest is longer than {_DIGEST_BYTES} bytes")
        preimage = entry.get("preimage")
        if preimage is not None and not isinstance(preimage, str):
            raise EventLogError(f"event {index} has a malformed preimage")
        event = entry.get("event")
        payload = entry.get("event_payload")
        # A non-integer event_type becomes -1, which rtmr3_event_digest treats as
        # unhashable. That is deliberate: it fails the replay rather than letting a
        # missing field quietly drop an event out of the measurement.
        event_type = _as_int(entry.get("event_type"), -1)
        entries.append(
            DstackEventLogEntry(
                imr=imr,
                event_type=event_type if event_type is not None else -1,
                digest=digest.lower(),
                event=event if isinstance(event, str) else "",
                event_payload=payload.lower() if isinstance(payload, str) else "",
                preimage=preimage.lower() if isinstance(preimage, str) else None,
                version=_as_int(entry.get("version"), None),
            )
        )
    return entries


def replay_register(digests: Sequence[str]) -> str:
    """Extend one register with an ordered list of event digests."""
    register = bytes.fromhex(RTMR_INITIAL_VALUE)
    for digest in digests:
        content = bytes.fromhex(digest)
        if len(content) < _DIGEST_BYTES:
            content = content + b"\x00" * (_DIGEST_BYTES - len(content))
        register = hashlib.sha384(register + content).digest()
    return register.hex()


def compute_rtmr3_event_digest_v1(event: DstackEventLogEntry) -> str:
    """Recompute a dstack V1 RTMR3 event digest from its own fields.

    This is the check that makes the readable part of the log trustworthy. Replay
    alone only proves the DIGESTS are the measured ones; it says nothing about the
    ``event`` and ``event_payload`` strings printed next to them. Without
    recomputing, a hostile server could take a genuine quote and its genuine log,
    leave every digest untouched so the replay still matches RTMR3, and simply
    rewrite the compose-hash payload to a value the client's policy accepts.

    V1 serialization::

        sha384( u32_le(event_type) || ":" || utf8(event) || ":" || bytes(payload) )
    """
    material = (
        struct.pack("<I", event.event_type & 0xFFFFFFFF)
        + b":"
        + event.event.encode("utf-8")
        + b":"
        + bytes.fromhex(event.event_payload)
    )
    return hashlib.sha384(material).hexdigest()


def _v2_digest_is_self_consistent(event: DstackEventLogEntry) -> bool:
    """Check a V2 event, which publishes the exact hashed bytes as ``preimage``.

    Two things must hold, and checking only the first is a trap: the digest must be
    SHA-384 of the preimage, AND the preimage must itself name the same event and
    payload that are displayed. Otherwise a server could ship a genuine
    preimage/digest pair beside arbitrary display fields.
    """
    preimage = event.preimage
    if preimage is None:
        return False
    if not _LOWER_HEX.match(preimage) or len(preimage) % 2 != 0 or len(preimage) == 0:
        return False
    raw = bytes.fromhex(preimage)
    if hashlib.sha384(raw).hexdigest() != event.digest:
        return False
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(decoded, dict):
        return False
    payload = decoded.get("payload")
    normalized = payload.lower().removeprefix("0x") if isinstance(payload, str) else None
    declared_type = decoded.get("type")
    return (
        decoded.get("name") == event.event
        and normalized == event.event_payload.removeprefix("0x")
        and (declared_type is None or declared_type == event.event_type)
    )


def rtmr3_event_digest(event: DstackEventLogEntry) -> str | None:
    """The digest an RTMR3 event MUST have, derived from its own fields.

    A real dstack guest agent (observed on dstack 0.5.9 / guest agent 0.5.7)
    returns RTMR3 entries with an EMPTY ``digest`` and expects the verifier to
    derive it. That is the stronger arrangement: when the replay is performed over
    digests derived from (event_type, event, event_payload), reproducing the
    hardware register proves the payloads are exactly what was measured.

    Returns None when the entry cannot be hashed at all, which is a verification
    failure rather than something to skip.
    """
    if not _LOWER_HEX.match(event.event_payload) or len(event.event_payload) % 2 != 0:
        return None
    if event.preimage is not None:
        return event.digest if _v2_digest_is_self_consistent(event) else None
    if event.event_type < 0:
        return None
    return compute_rtmr3_event_digest_v1(event)


def replay_rtmrs(events: Sequence[DstackEventLogEntry]) -> tuple[str, str, str, str]:
    """Replay RTMR0..RTMR3 from a parsed event log, in log order per register.

    RTMR0 through RTMR2 come from firmware and the TCG log, whose digests we cannot
    recompute, so those are replayed from the supplied values. RTMR3 is replayed
    from digests DERIVED from each event's own fields. An RTMR3 entry that cannot
    be hashed contributes a value that cannot match, so the replay fails rather
    than silently skipping it.
    """
    unhashable = "ff" * 48
    replayed = [
        replay_register(
            [
                (rtmr3_event_digest(event) or unhashable) if index == 3 else event.digest
                for event in events
                if event.imr == index
            ]
        )
        for index in range(_RTMR_COUNT)
    ]
    return (replayed[0], replayed[1], replayed[2], replayed[3])


def rtmr3_event_digest_is_self_consistent(event: DstackEventLogEntry) -> bool:
    """True when an RTMR3 entry's digest commits to its own name and payload.

    An entry with no digest is consistent by construction, because the replay will
    use the derived one. An entry that DOES carry a digest must agree with the
    derived value, so a log cannot supply a digest that replays correctly while
    displaying a different payload beside it.
    """
    derived = rtmr3_event_digest(event)
    if derived is None:
        return False
    if not event.digest:
        return True
    return derived == event.digest


def inconsistent_rtmr3_events(
    events: Sequence[DstackEventLogEntry],
) -> list[DstackEventLogEntry]:
    """Every imr==3 entry whose digest does NOT commit to its own name and payload.

    RTMR0..RTMR2 entries come from firmware and the TCG log and use a different
    serialization, so they are deliberately out of scope here.
    """
    return [e for e in events if e.imr == 3 and not rtmr3_event_digest_is_self_consistent(e)]


def single_event_payload(events: Sequence[DstackEventLogEntry], name: str) -> str | None:
    """Read exactly one named RTMR3 event's payload, if its digest commits to it.

    Returns None when the event is absent. Raises when it appears more than once (a
    duplicated "compose-hash" would let a server present whichever value the reader
    picks first) or when the digest does not match its own fields.
    """
    matches = [e for e in events if e.event == name]
    if not matches:
        return None
    if len(matches) > 1:
        raise EventLogError(f'event log contains {len(matches)} "{name}" events')
    match = matches[0]
    if match.imr != 3:
        raise EventLogError(f'"{name}" event is not in RTMR3')
    if not rtmr3_event_digest_is_self_consistent(match):
        raise EventLogError(f'"{name}" event digest does not commit to its payload')
    return match.event_payload
