"""Chutes ML-KEM-768 whole-body crypto (protocol ``chutes-mlkem-v1``).

Verified against Chutes' live enclave endpoints, and identical to the Chutes
transport in ``@anonrouter/confidential``:

  - ML-KEM-768 (FIPS 203) encapsulate/decapsulate.
  - HKDF-SHA256 with the ML-KEM ciphertext's first 16 bytes as salt; info
    ``e2e-req-v1`` (request) / ``e2e-resp-v1`` (response).
  - ChaCha20-Poly1305 (12-byte nonce).
  - gzip of the JSON body.
  - response wire = [1088-byte ML-KEM ct][12-byte nonce][ChaCha20-Poly1305(gzip(json))].

ML-KEM-768 is provided by the ``kyber-py`` package, installed via the ``mlkem``
optional dependency. It is imported lazily so the rest of the SDK works without it;
calling into the Chutes path without it raises a clear ``ChutesMlKemUnavailable``.
"""

from __future__ import annotations

import gzip
import json
import os
import zlib
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MLKEM_CIPHERTEXT_BYTES = 1088
_RESPONSE_NONCE_OFFSET = _MLKEM_CIPHERTEXT_BYTES  # 1088
_RESPONSE_BODY_OFFSET = _MLKEM_CIPHERTEXT_BYTES + 12  # 1100
_MIN_RESPONSE_BYTES = 1116
_MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024

REQ_INFO = b"e2e-req-v1"
RESP_INFO = b"e2e-resp-v1"


class ChutesMlKemUnavailable(RuntimeError):
    """Raised when the Chutes ML-KEM path is used but ``kyber-py`` is not installed."""


def _ml_kem_768() -> Any:
    try:
        from kyber_py.ml_kem import ML_KEM_768
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ChutesMlKemUnavailable(
            "ML-KEM-768 support requires the 'mlkem' optional dependency "
            "(pip install 'anonrouter-confidential[mlkem]')."
        ) from exc
    return ML_KEM_768


def _bounded_gunzip(compressed: bytes, max_bytes: int) -> bytes:
    """Gunzip refusing to expand beyond ``max_bytes`` (decompression-bomb defense).

    Unlike ``gzip.decompress``, this bounds output DURING inflation so a small
    ciphertext cannot force multi-GB allocation before the size check. Parity with
    the JS ``gunzip(data, MAX_DECOMPRESSED_BYTES)`` cap.
    """
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip framing
    out = decompressor.decompress(compressed, max_bytes)
    if decompressor.unconsumed_tail:
        raise ValueError("Chutes response decompressed payload is too large")
    out += decompressor.flush()
    if len(out) > max_bytes:
        raise ValueError("Chutes response decompressed payload is too large")
    return out


def _chutes_key(shared_secret: bytes, mlkem_ciphertext: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 with the ML-KEM ciphertext's first 16 bytes as salt."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=mlkem_ciphertext[:16],
        info=info,
    ).derive(shared_secret)


def decrypt_response(blob_bytes: bytes, response_secret_key_bytes: bytes) -> dict:
    """Decrypt + gunzip a Chutes ML-KEM whole-body response and return the parsed
    JSON object.

    ``blob_bytes`` is the raw octet-stream response body; ``response_secret_key_bytes``
    is the client's ephemeral ML-KEM-768 decapsulation key (the expanded 2400-byte dk).
    """
    if len(blob_bytes) < _MIN_RESPONSE_BYTES:
        raise ValueError("Chutes response is too short")
    mlkem_ciphertext = blob_bytes[:_MLKEM_CIPHERTEXT_BYTES]
    nonce = blob_bytes[_RESPONSE_NONCE_OFFSET:_RESPONSE_BODY_OFFSET]
    encrypted = blob_bytes[_RESPONSE_BODY_OFFSET:]

    ml_kem = _ml_kem_768()
    shared_secret = ml_kem.decaps(response_secret_key_bytes, mlkem_ciphertext)
    response_key = _chutes_key(shared_secret, mlkem_ciphertext, RESP_INFO)
    compressed = ChaCha20Poly1305(response_key).decrypt(nonce, encrypted, None)
    raw = _bounded_gunzip(compressed, _MAX_DECOMPRESSED_BYTES)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Chutes decrypted body was not a JSON object")
    return parsed


def encrypt_request(payload: dict, instance_public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to the instance ML-KEM key, gzip + encrypt the JSON payload, and
    return ``(request_blob, response_secret_key)``.

    The caller must embed the response ML-KEM public key (base64) inside ``payload``
    under ``e2e_response_pk`` and keep the returned response secret key to decrypt the
    reply. Provided for the client and round-trip tests.
    """
    ml_kem = _ml_kem_768()
    response_public_key, response_secret_key = ml_kem.keygen()
    if "e2e_response_pk" not in payload:
        import base64

        payload = {**payload, "e2e_response_pk": base64.b64encode(response_public_key).decode()}
    shared_secret, mlkem_ciphertext = ml_kem.encaps(instance_public_key)
    request_key = _chutes_key(shared_secret, mlkem_ciphertext, REQ_INFO)
    nonce = os.urandom(12)
    compressed = gzip.compress(json.dumps(payload).encode("utf-8"))
    encrypted = ChaCha20Poly1305(request_key).encrypt(nonce, compressed, None)
    return mlkem_ciphertext + nonce + encrypted, response_secret_key
