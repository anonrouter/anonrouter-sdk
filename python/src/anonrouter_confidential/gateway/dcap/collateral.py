"""Intel-signed DCAP collateral: the inputs a quote's signature is checked against.

A TDX quote does not carry everything needed to judge it. The signature chains to
Intel through a PCK certificate the quote does embed, but deciding whether that
platform's TCB is current, whether the Quoting Enclave is one Intel blesses, and
whether anything has been revoked needs four documents Intel signs and serves: TCB
info for the platform's FMSPC, the QE identity, the PCK CRL, and the root CA CRL.

WHY THE SDK FETCHES THEM RATHER THAN THE ENGINE

The reviewed engine performs NO network access at all. That is the right shape: a
verifier that fetches its own trust inputs is only as trustworthy as whatever it
happened to reach. Collateral is therefore acquired out here, by the caller's
process, and handed in.

NOTHING IN THIS MODULE IS A SECURITY CHECK. Everything it returns is untrusted
input. The signatures, the issuer chains, the FMSPC relationship, and the
freshness are all re-verified inside the engine under ITS pinned Intel root. If
this module were the thing that decided, then whoever served the collateral would
be trusted, which is the arrangement the whole design removes. A bug here costs a
failed verification, never a false pass.

PRIVACY NOTE, stated because it is a real cost: fetching from Intel tells Intel
which platform's FMSPC you are verifying and when. Supply ``collateral`` yourself
to avoid it. The engine revalidates either way, so a mirror is not a party you
have to trust.

Mirrors ``js/confidential/src/gateway/dcap/collateral.ts``.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

#: Intel's Provisioning Certification Service. The only API host fetched from.
INTEL_PCS_BASE = "https://api.trustedservices.intel.com"

#: Intel's certificate host, which serves the root CA CRL.
#:
#: Note the trap in the file name: ``IntelSGXRootCA.der`` on this host is the root
#: CA's **CRL**, not its certificate. The engine pins the certificate at build
#: time; only the CRL is fetched here.
INTEL_CERT_BASE = "https://certificates.trustedservices.intel.com"

#: A real TDX v4 quote is a few KB.
MAX_QUOTE_BYTES = 64 * 1024
#: Bound every response so a hostile or broken endpoint cannot exhaust memory.
MAX_RESPONSE_CHARS = 4 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0

_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_PEM_END = "-----END CERTIFICATE-----"
#: 06 0a <OID 1.2.840.113741.1.13.1.4>, the Intel SGX FMSPC extension.
_FMSPC_OID = bytes.fromhex("060a2a864886f84d010d0104")


class CollateralError(Exception):
    """Collateral could not be acquired. Never raised as a verification verdict."""


@dataclass(frozen=True)
class DcapCollateral:
    """The collateral wire shape the AnonRouter DCAP engine accepts.

    Byte fields are hex; the signed JSON documents are the exact bytes Intel signed.
    """

    pck_crl_issuer_chain: str
    root_ca_crl: str
    pck_crl: str
    tcb_info_issuer_chain: str
    tcb_info: str
    tcb_info_signature: str
    qe_identity_issuer_chain: str
    qe_identity: str
    qe_identity_signature: str
    pck_certificate_chain: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """The exact JSON object the engine reads. Key order matches the JS twin."""
        payload: dict[str, Any] = {
            "pck_crl_issuer_chain": self.pck_crl_issuer_chain,
            "root_ca_crl": self.root_ca_crl,
            "pck_crl": self.pck_crl,
            "tcb_info_issuer_chain": self.tcb_info_issuer_chain,
            "tcb_info": self.tcb_info,
            "tcb_info_signature": self.tcb_info_signature,
            "qe_identity_issuer_chain": self.qe_identity_issuer_chain,
            "qe_identity": self.qe_identity,
            "qe_identity_signature": self.qe_identity_signature,
        }
        if self.pck_certificate_chain is not None:
            payload["pck_certificate_chain"] = self.pck_certificate_chain
        return payload

    @staticmethod
    def from_dict(raw: Any) -> DcapCollateral:
        """Parse a collateral document a caller supplied. Fails closed on shape."""
        if not isinstance(raw, dict):
            raise CollateralError("collateral must be a JSON object")
        required = (
            "pck_crl_issuer_chain",
            "root_ca_crl",
            "pck_crl",
            "tcb_info_issuer_chain",
            "tcb_info",
            "tcb_info_signature",
            "qe_identity_issuer_chain",
            "qe_identity",
            "qe_identity_signature",
        )
        values = {}
        for field_name in required:
            value = raw.get(field_name)
            if not isinstance(value, str) or len(value) == 0:
                raise CollateralError(f"collateral.{field_name} must be a non-empty string")
            values[field_name] = value
        chain = raw.get("pck_certificate_chain")
        return DcapCollateral(
            **values,
            pck_certificate_chain=chain if isinstance(chain, str) and chain else None,
        )


@dataclass(frozen=True)
class AcquiredCollateral:
    collateral: DcapCollateral
    #: FMSPC this collateral was fetched for, lowercase hex.
    fmspc: str
    #: ``nextUpdate`` from the signed TCB info, epoch ms. This is the cache expiry.
    next_update_ms: float
    fetched_at_ms: float


def _is_hex(value: str) -> bool:
    return len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value)


def normalize_quote_hex(raw: Any) -> str | None:
    """Decode a quote given as hex or base64 into lowercase hex. None if neither."""
    if not isinstance(raw, str):
        return None
    clean = raw.strip()
    if len(clean) == 0 or len(clean) > MAX_QUOTE_BYTES * 2:
        return None
    if _is_hex(clean):
        return clean.lower()
    try:
        decoded = base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded.hex() if decoded else None


def extract_pck_chain(quote: str) -> str | None:
    """Pull the PCK certificate chain out of a quote.

    For Intel cert data type 5 the chain is embedded in the quote as PEM. Scanning
    for the PEM armour rather than walking the signature structure is deliberate:
    the result is handed to the engine as untrusted input and re-parsed there, so a
    wrong guess costs a failed verification, never a false pass.
    """
    quote_hex = normalize_quote_hex(quote)
    if quote_hex is None:
        return None
    text = bytes.fromhex(quote_hex).decode("latin-1")
    start = text.find(_PEM_BEGIN)
    if start == -1:
        return None
    end = text.rfind(_PEM_END)
    if end == -1 or end < start:
        return None
    # dstack leaves NUL padding after the chain; strip it so the PEM parses.
    return text[start : end + len(_PEM_END)].replace("\x00", "")


def _first_certificate_der(pem_chain: str) -> bytes | None:
    start = pem_chain.find(_PEM_BEGIN)
    if start == -1:
        return None
    end = pem_chain.find(_PEM_END, start)
    if end == -1:
        return None
    body = re.sub(r"[^A-Za-z0-9+/=]", "", pem_chain[start + len(_PEM_BEGIN) : end])
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None


def extract_fmspc(pem_chain: str) -> str | None:
    """Read the FMSPC from the leaf PCK certificate's Intel SGX extension.

    The FMSPC selects which TCB info applies to this platform, so it must come out
    of the quote rather than be configured. OID 1.2.840.113741.1.13.1.4, DER
    encoded, followed by a 6-byte OCTET STRING. The same OID prefix can appear
    inside other structures, so only an OCTET STRING of exactly 6 bytes is taken.
    """
    der = _first_certificate_der(pem_chain)
    if der is None:
        return None
    at = 0
    while True:
        found = der.find(_FMSPC_OID, at)
        if found == -1:
            return None
        tag_at = found + len(_FMSPC_OID)
        if tag_at + 8 <= len(der) and der[tag_at] == 0x04 and der[tag_at + 1] == 6:
            return der[tag_at + 2 : tag_at + 8].hex()
        at = found + 1


def slice_signed_document(body: str, key: str) -> str:
    """Slice a signed sub-document out of a PCS response by brace matching.

    ``{"tcbInfo":{...},"signature":"..."}`` is signed over the exact bytes of the
    inner object. Parsing and re-serializing would produce different bytes and a
    signature that no longer verifies, so the original bytes are sliced out.
    """
    marker = f'"{key}":'
    at = body.find(marker)
    if at == -1:
        raise CollateralError(f"Intel PCS response has no {key}")
    start = body.find("{", at + len(marker))
    if start == -1:
        raise CollateralError(f"Intel PCS {key} is not an object")
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(body)):
        ch = body[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return body[start : i + 1]
    raise CollateralError(f"Intel PCS {key} is not balanced")


def read_signed_document_signature(body: str) -> str:
    """The detached signature Intel returns beside a signed document, lowercase hex."""
    match = re.search(r'"signature"\s*:\s*"([0-9a-fA-F]+)"', body)
    if not match:
        raise CollateralError("Intel PCS response has no signature")
    return match.group(1).lower()


def read_next_update_ms(tcb_info: str) -> float:
    """``nextUpdate`` out of signed TCB info, epoch ms. This is what bounds the cache."""
    match = re.search(r'"nextUpdate"\s*:\s*"([^"]+)"', tcb_info)
    if not match:
        raise CollateralError("signed TCB info has no nextUpdate")
    raw = match.group(1)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollateralError("signed TCB info has an unparsable nextUpdate") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp() * 1000.0


def _require_header(headers: Any, name: str) -> str:
    value = headers.get(name)
    if not value:
        raise CollateralError(f"Intel PCS response is missing the {name} header")
    return unquote(value)


def fetch_intel_collateral(
    quote: str,
    *,
    pcs_base: str = INTEL_PCS_BASE,
    cert_base: str = INTEL_CERT_BASE,
    http_client: Any = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> AcquiredCollateral:
    """Fetch the collateral for one quote from Intel.

    Everything returned is untrusted; the engine checks it. Raises
    ``CollateralError`` rather than returning a partial document, because a caller
    that proceeded with half the collateral would get a refusal it could not
    explain.
    """
    import time

    import httpx

    quote_hex = normalize_quote_hex(quote)
    if quote_hex is None:
        raise CollateralError("quote is neither hex nor base64")

    pck_chain = extract_pck_chain(quote_hex)
    if not pck_chain:
        raise CollateralError(
            "quote carries no PCK certificate chain (Intel cert data type 5 expected)"
        )
    fmspc = extract_fmspc(pck_chain)
    if not fmspc:
        raise CollateralError("could not read the FMSPC from the PCK certificate")

    base = pcs_base.rstrip("/")
    certs = cert_base.rstrip("/")
    client = http_client or httpx.Client(timeout=timeout_seconds)
    try:
        tcb = _get(client, f"{base}/tdx/certification/v4/tcb?fmspc={fmspc}")
        qe = _get(client, f"{base}/tdx/certification/v4/qe/identity")
        # `encoding=der` returns raw binary, not hex text.
        pck_crl = _get(client, f"{base}/sgx/certification/v4/pckcrl?ca=platform&encoding=der")
        # IntelSGXRootCA.der is the root CA's CRL, despite the name.
        root_crl = _get(client, f"{certs}/IntelSGXRootCA.der")
    finally:
        if http_client is None:
            client.close()

    tcb_info = slice_signed_document(tcb.text, "tcbInfo")
    qe_identity = slice_signed_document(qe.text, "enclaveIdentity")

    return AcquiredCollateral(
        collateral=DcapCollateral(
            pck_crl_issuer_chain=_require_header(pck_crl.headers, "SGX-PCK-CRL-Issuer-Chain"),
            root_ca_crl=pck_crl_bytes_to_hex(root_crl.content),
            pck_crl=pck_crl_bytes_to_hex(pck_crl.content),
            tcb_info_issuer_chain=_require_header(tcb.headers, "TCB-Info-Issuer-Chain"),
            tcb_info=tcb_info,
            tcb_info_signature=read_signed_document_signature(tcb.text),
            qe_identity_issuer_chain=_require_header(
                qe.headers, "SGX-Enclave-Identity-Issuer-Chain"
            ),
            qe_identity=qe_identity,
            qe_identity_signature=read_signed_document_signature(qe.text),
            pck_certificate_chain=pck_chain,
        ),
        fmspc=fmspc,
        next_update_ms=read_next_update_ms(tcb_info),
        fetched_at_ms=time.time() * 1000.0,
    )


def pck_crl_bytes_to_hex(content: bytes) -> str:
    """Hex-encode a DER response, bounded."""
    if len(content) > MAX_RESPONSE_CHARS:
        raise CollateralError("Intel response exceeds the maximum size")
    return content.hex()


def _get(client: Any, url: str) -> Any:
    import httpx

    try:
        response = client.get(url, headers={"accept": "application/json"})
    except httpx.HTTPError as exc:
        raise CollateralError(f"could not reach {httpx.URL(url).host}") from exc
    if response.status_code >= 400:
        raise CollateralError(
            f"{httpx.URL(url).host} returned {response.status_code} for {httpx.URL(url).path}"
        )
    if len(response.content) > MAX_RESPONSE_CHARS:
        raise CollateralError(f"response from {httpx.URL(url).host} exceeds the maximum size")
    return response


class CollateralCache:
    """An in-process cache keyed by FMSPC, expiring at the collateral's own signed
    ``nextUpdate``.

    The expiry comes from the signed document rather than from a policy constant,
    so the cache cannot outlive what Intel signed for. The engine independently
    rejects stale collateral, so a bug here degrades to a failed verification.
    """

    def __init__(self, fetcher: Any = None) -> None:
        self._entries: dict[str, AcquiredCollateral] = {}
        self._fetcher = fetcher or (lambda quote: fetch_intel_collateral(quote))

    def get(self, quote: str, now_ms: float | None = None) -> AcquiredCollateral:
        import time

        moment = time.time() * 1000.0 if now_ms is None else now_ms
        quote_hex = normalize_quote_hex(quote)
        pck_chain = extract_pck_chain(quote_hex) if quote_hex else None
        fmspc = extract_fmspc(pck_chain) if pck_chain else None
        if fmspc:
            hit = self._entries.get(fmspc)
            if hit and hit.next_update_ms > moment:
                return hit
        fresh = self._fetcher(quote)
        self._entries[fresh.fmspc] = fresh
        return fresh

    def peek(self, fmspc: str) -> AcquiredCollateral | None:
        return self._entries.get(fmspc)

    def clear(self) -> None:
        self._entries.clear()
