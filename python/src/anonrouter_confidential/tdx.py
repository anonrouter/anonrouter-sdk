"""Structural parser for an Intel TDX v4 DCAP quote.

Byte-for-byte equivalent to the parser in ``@anonrouter/confidential``, and proven
so by the shared TDX quote vectors in ``shared/vectors/tdx-quotes.json``. This is
deterministic byte-offset parsing, NOT signature verification: the ECDSA chain to
Intel roots is never verified here, so a passing parse alone never earns a
"hardware-verified" claim. Parsing never raises; it returns None so callers fail
closed.

Offsets from the start of the quote (header included):
  version@0 u16le, teeType@4 u32le, td_attributes@168 (bit0 = TUD.DEBUG),
  mrTd@184(48), mrConfigId@232(48), rtmr0@376, rtmr1@424, rtmr2@472, rtmr3@520
  (each 48), reportData@568(64).
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass

TDX_TEE_TYPE = 0x00000081

_HEADER_LEN = 48
_BODY_LEN = 584
_QUOTE_MIN_LEN = _HEADER_LEN + _BODY_LEN  # 632
# Reject an oversized "quote" before allocating: a real TDX v4 quote is a few KB.
_QUOTE_MAX_LEN = 64 * 1024

# Byte offsets (see module docstring).
_OFF_TD_ATTRIBUTES = 168
_OFF_MR_TD = 184
_OFF_MR_CONFIG_ID = 232
_OFF_RTMR0 = 376
_OFF_REPORT_DATA = 568

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


@dataclass(frozen=True)
class ParsedTdxQuote:
    """A parsed TDX quote. All measurement fields are lowercase hex."""

    version: int
    tee_type: int
    mr_td: str
    mr_config_id: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    # 64-byte report_data (nonce / key-binding region), lowercase hex.
    report_data: str
    # td_attributes (8 bytes), lowercase hex.
    td_attributes: str
    # True when the TUD.DEBUG bit (td_attributes bit 0) is set.
    debug_enabled: bool


def _is_canonical_base64(value: str) -> bool:
    if len(value) == 0 or len(value) % 4 != 0:
        return False
    return bool(_B64_RE.match(value))


def _decode_quote(raw: str) -> bytes | None:
    clean = raw.strip()
    if len(clean) == 0 or len(clean) > _QUOTE_MAX_LEN * 2:
        return None
    # Accept hex (NEAR/Venice intel_quote) or base64 (Chutes quote). Hex first,
    # exactly like the JavaScript parser, so an all-hex string is never read as b64.
    if _HEX_RE.match(clean) and len(clean) % 2 == 0:
        try:
            return bytes.fromhex(clean)
        except ValueError:
            return None
    if not _is_canonical_base64(clean):
        return None
    try:
        decoded = base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) >= _QUOTE_MIN_LEN else None


def parse_tdx_quote(raw: object) -> ParsedTdxQuote | None:
    """Parse a hex- or base64-encoded TDX v4 quote. Returns None on any malformed
    input (fail closed), never raises."""
    if not isinstance(raw, str) or len(raw) == 0:
        return None
    buf = _decode_quote(raw)
    if buf is None or len(buf) < _QUOTE_MIN_LEN or len(buf) > _QUOTE_MAX_LEN:
        return None

    def hexat(off: int, length: int) -> str:
        return buf[off : off + length].hex()

    version = struct.unpack_from("<H", buf, 0)[0]
    tee_type = struct.unpack_from("<I", buf, 4)[0]
    return ParsedTdxQuote(
        version=version,
        tee_type=tee_type,
        mr_td=hexat(_OFF_MR_TD, 48),
        mr_config_id=hexat(_OFF_MR_CONFIG_ID, 48),
        rtmr0=hexat(_OFF_RTMR0, 48),
        rtmr1=hexat(_OFF_RTMR0 + 48, 48),
        rtmr2=hexat(_OFF_RTMR0 + 96, 48),
        rtmr3=hexat(_OFF_RTMR0 + 144, 48),
        report_data=hexat(_OFF_REPORT_DATA, 64),
        td_attributes=hexat(_OFF_TD_ATTRIBUTES, 8),
        # TUD.DEBUG is bit 0 of the first td_attributes byte.
        debug_enabled=(buf[_OFF_TD_ATTRIBUTES] & 0x01) == 0x01,
    )


def match_measurement_allowlist(
    quote: ParsedTdxQuote, allowlist: Sequence[dict]
) -> str | None:
    """Whether a parsed quote's complete reviewed measurement identity (MRTD +
    RTMR0..3) matches an allowlist entry. RTMR3 is never ignored. Returns the
    matched entry name, or None."""

    def eq(a: str, b: str) -> bool:
        return a.lower() == b.lower()

    for entry in allowlist:
        if (
            eq(quote.mr_td, str(entry["mrTd"]))
            and eq(quote.rtmr0, str(entry["rtmr0"]))
            and eq(quote.rtmr1, str(entry["rtmr1"]))
            and eq(quote.rtmr2, str(entry["rtmr2"]))
            and eq(quote.rtmr3, str(entry["rtmr3"]))
        ):
            return str(entry["name"])
    return None
