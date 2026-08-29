"""The JS <-> Python parity gate.

Load the shared crypto-decrypt.json KAT vectors (generated once from the proven
private-repo crypto) and decrypt each case with the Python implementation. Because
decrypt is pure, Python MUST reproduce the exact plaintext/JSON the JS SDK produces.
A failure here means the two languages have drifted bit-for-bit.
"""

from __future__ import annotations

import base64

import pytest

from anonrouter_confidential.crypto import chutes, near, venice

try:
    import kyber_py  # noqa: F401

    _HAVE_MLKEM = True
except ImportError:
    _HAVE_MLKEM = False


def _case(vectors: list[dict], provider: str) -> dict:
    for entry in vectors:
        if entry["provider"] == provider:
            return entry
    raise AssertionError(f"no vector for provider {provider}")


def test_near_response_decrypt(crypto_vectors: list[dict]) -> None:
    case = _case(crypto_vectors, "near-ai")
    plaintext = near.decrypt(case["ciphertextHex"], case["clientSecretHex"])
    assert plaintext == case["expectedPlaintext"]


def test_venice_response_decrypt(crypto_vectors: list[dict]) -> None:
    case = _case(crypto_vectors, "venice")
    plaintext = venice.decrypt(case["ciphertextHex"], case["clientPrivateHex"])
    assert plaintext == case["expectedPlaintext"]


@pytest.mark.skipif(not _HAVE_MLKEM, reason="ML-KEM extra ('mlkem') not installed")
def test_chutes_response_decrypt(crypto_vectors: list[dict]) -> None:
    case = _case(crypto_vectors, "chutes")
    blob = base64.b64decode(case["responseBlobBase64"])
    secret_key = base64.b64decode(case["responseSecretKeyBase64"])
    result = chutes.decrypt_response(blob, secret_key)
    assert result == case["expectedJson"]


def test_near_field_roundtrip() -> None:
    """encrypt_field(msg, edPub) then decrypt(hex, edSecret) round-trips."""
    import nacl.bindings as nb

    seed = bytes(range(1, 33))
    pub, _full = nb.crypto_sign_seed_keypair(seed)
    wire = near.encrypt_field("near round-trip", pub.hex())
    assert near.decrypt(wire, seed.hex()) == "near round-trip"


def test_venice_field_roundtrip() -> None:
    """A self-encrypted Venice field (client == enclave key) round-trips."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = ec.derive_private_key(0x2222222222222222222222222222222222222222222222222222222222222222, ec.SECP256K1())
    priv_hex = format(priv.private_numbers().private_value, "064x")
    pub_hex = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
    wire = venice.encrypt_field("venice round-trip", priv_hex, pub_hex)
    assert venice.decrypt(wire, priv_hex) == "venice round-trip"


def test_venice_eth_address_helper() -> None:
    """keccak256(x||y)[12:32] address derivation is deterministic and 20 bytes."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = ec.derive_private_key(0x1234, ec.SECP256K1())
    uncompressed = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    compressed = priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    addr_u = venice.eth_address_from_pub(uncompressed.hex())
    addr_c = venice.eth_address_from_pub(compressed.hex())
    assert addr_u == addr_c
    assert addr_u.startswith("0x") and len(addr_u) == 42
