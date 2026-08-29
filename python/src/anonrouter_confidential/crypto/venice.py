"""Venice legacy field crypto (protocol ``venice-legacy``).

Verified against Venice's live enclave endpoints, and identical to the Venice
transport in ``@anonrouter/confidential``. The scheme follows Venice's own
``veniceai/venice-cli`` reference example:

  - ECDH on secp256k1, using the shared point's 32-byte X coordinate.
  - HKDF-SHA256, info ``ecdsa_encryption``, no salt.
  - AES-256-GCM, 12-byte nonce, 16-byte tag.
  - wire = [65-byte uncompressed ephemeral pub][12-byte nonce][ciphertext+tag], hex.

The Ethereum-address helper (``eth_address_from_pub``) is keccak256(pub_x||pub_y)[12:32],
used by the verifier to bind Venice's declared ``signing_address`` to its key.
"""

from __future__ import annotations

import os

from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"ecdsa_encryption"
_PUBKEY_BYTES = 65
_NONCE_BYTES = 12
_MIN_WIRE_BYTES = _PUBKEY_BYTES + _NONCE_BYTES + 16  # 93
_CURVE = ec.SECP256K1()


def _hkdf(shared_x: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared_x)


def _derive_aes_key(private_int: int, peer_public_bytes: bytes) -> bytes:
    """ECDH(secp256k1) -> 32-byte X coord -> HKDF-SHA256(``ecdsa_encryption``)."""
    private_key = ec.derive_private_key(private_int, _CURVE)
    peer_public = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, peer_public_bytes)
    # cryptography's ECDH exchange returns exactly the shared point's X coordinate.
    shared_x = private_key.exchange(ec.ECDH(), peer_public)
    return _hkdf(shared_x)


def decrypt(ciphertext_hex: str, client_private_hex: str) -> str:
    """Decrypt a Venice ``venice-legacy`` response field.

    ``ciphertext_hex`` is the hex wire blob (the enclave embeds its ephemeral pub in
    every field); ``client_private_hex`` is the client's 32-byte secp256k1 private
    scalar in hex. Returns the UTF-8 plaintext.
    """
    clean = ciphertext_hex.lower().removeprefix("0x")
    blob = bytes.fromhex(clean)
    if len(blob) < _MIN_WIRE_BYTES:
        raise ValueError("Venice ciphertext is too short")
    peer_public = blob[:_PUBKEY_BYTES]
    nonce = blob[_PUBKEY_BYTES : _PUBKEY_BYTES + _NONCE_BYTES]
    ciphertext = blob[_PUBKEY_BYTES + _NONCE_BYTES :]
    private_int = int(client_private_hex.lower().removeprefix("0x"), 16)
    key = _derive_aes_key(private_int, peer_public)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8", errors="replace")


def encrypt_field(plaintext: str, client_private_hex: str, model_public_hex: str) -> str:
    """Encrypt a field to the enclave's uncompressed secp256k1 key, embedding the
    client's uncompressed public key (the Venice session pubkey) in the wire blob."""
    private_int = int(client_private_hex.lower().removeprefix("0x"), 16)
    private_key = ec.derive_private_key(private_int, _CURVE)
    client_public = private_key.public_key().public_bytes(
        encoding=_enc_x962(), format=_fmt_uncompressed()
    )
    model_public = bytes.fromhex(model_public_hex.lower().removeprefix("0x"))
    key = _derive_aes_key(private_int, model_public)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return (client_public + nonce + ciphertext).hex()


def eth_address_from_pub(public_key_hex: str) -> str:
    """Derive the lowercase 0x Ethereum address from a secp256k1 public key.

    Accepts uncompressed (65 bytes / 0x04 prefix), raw x||y (64 bytes), or
    compressed (33 bytes) hex. address = keccak256(x || y)[12:32].
    """
    key = bytes.fromhex(public_key_hex.lower().removeprefix("0x"))
    if len(key) == 65 and key[0] == 0x04:
        xy = key[1:]
    elif len(key) == 64:
        xy = key
    elif len(key) == 33 and key[0] in (0x02, 0x03):
        point = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, key)
        uncompressed = point.public_bytes(encoding=_enc_x962(), format=_fmt_uncompressed())
        xy = uncompressed[1:]
    else:
        raise ValueError("malformed secp256k1 public key")
    digest = keccak.new(digest_bits=256)
    digest.update(xy)
    return "0x" + digest.digest()[12:32].hex()


def _enc_x962():  # small indirections keep the imports tidy + mypy-friendly.
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.X962


def _fmt_uncompressed():
    from cryptography.hazmat.primitives.serialization import PublicFormat

    return PublicFormat.UncompressedPoint
