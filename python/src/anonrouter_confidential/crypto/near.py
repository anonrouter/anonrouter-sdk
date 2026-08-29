"""NEAR AI v2 field crypto (protocol ``near-v2``).

Verified against NEAR AI's live enclave endpoints, and identical to the NEAR
transport in ``@anonrouter/confidential``:

  - Ed25519 client key; converted to X25519 for ECDH.
  - per-field ephemeral X25519 key.
  - HKDF-SHA256, info ``ed25519_encryption``, no salt.
  - XChaCha20-Poly1305 (24-byte nonce).
  - wire = [32-byte X25519 ephemeral pub][24-byte nonce][ciphertext+tag], lowercase hex.

The Ed25519 -> X25519 conversion uses libsodium (PyNaCl bindings):
``crypto_sign_ed25519_pk_to_curve25519`` / ``crypto_sign_ed25519_sk_to_curve25519``,
matching Noble's ``edwardsToMontgomeryPub`` / ``edwardsToMontgomeryPriv``.
"""

from __future__ import annotations

import os

import nacl.bindings as nb
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"ed25519_encryption"
# 32-byte X25519 pub + 24-byte nonce + 16-byte tag.
_MIN_WIRE_BYTES = 32 + 24 + 16


def _hkdf(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared)


def _x25519_private_from_ed25519_seed(client_ed25519_secret: bytes) -> bytes:
    """Convert a 32-byte Ed25519 seed (or 64-byte expanded secret) to the X25519
    private scalar, the same value Noble's ``edwardsToMontgomeryPriv`` produces."""
    if len(client_ed25519_secret) == 32:
        # libsodium's sk->curve25519 wants the 64-byte (seed || pubkey) secret key.
        _pub, full_sk = nb.crypto_sign_seed_keypair(client_ed25519_secret)
    elif len(client_ed25519_secret) == 64:
        full_sk = client_ed25519_secret
    else:
        raise ValueError("client Ed25519 secret must be 32 (seed) or 64 bytes")
    return nb.crypto_sign_ed25519_sk_to_curve25519(full_sk)


def decrypt(ciphertext_hex: str, client_ed25519_secret_hex: str) -> str:
    """Decrypt a NEAR ``near-v2`` response field.

    ``ciphertext_hex`` is the lowercase-hex wire blob; ``client_ed25519_secret_hex``
    is the client's 32-byte Ed25519 secret (seed) in hex. Returns the UTF-8 plaintext.
    """
    clean = ciphertext_hex.lower().removeprefix("0x")
    wire = bytes.fromhex(clean)
    if len(wire) < _MIN_WIRE_BYTES:
        raise ValueError("NEAR ciphertext is too short")
    ephemeral_public = wire[:32]
    nonce = wire[32:56]
    ciphertext = wire[56:]

    x_priv = _x25519_private_from_ed25519_seed(bytes.fromhex(client_ed25519_secret_hex))
    shared = nb.crypto_scalarmult(x_priv, ephemeral_public)
    key = _hkdf(shared)
    plaintext = nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, b"", nonce, key)
    return plaintext.decode("utf-8", errors="replace")


def encrypt_field(plaintext: str, model_ed25519_public_hex: str) -> str:
    """Encrypt a field to an enclave Ed25519 public key. Produces the same wire
    layout the JavaScript transport sends. Used by the client and round-trip tests."""
    model_ed_pub = bytes.fromhex(model_ed25519_public_hex.lower().removeprefix("0x"))
    mont_pub = nb.crypto_sign_ed25519_pk_to_curve25519(model_ed_pub)
    ephemeral_secret = nb.randombytes(32)
    ephemeral_public = nb.crypto_scalarmult_base(ephemeral_secret)
    nonce = os.urandom(24)
    shared = nb.crypto_scalarmult(ephemeral_secret, mont_pub)
    key = _hkdf(shared)
    ciphertext = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext.encode("utf-8"), b"", nonce, key
    )
    return (ephemeral_public + nonce + ciphertext).hex()
