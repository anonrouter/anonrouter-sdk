# anonrouter-confidential

Independently verify AnonRouter TEE / E2EE routes and run confidential inference
from Python. This package mirrors the JS `@anonrouter/confidential` surface and
passes the SAME shared known-answer-test (KAT) vectors, so Python and JS agree
bit-for-bit.

"Don't trust us, verify." The verifier is pure over its inputs and fails closed.

## Install

**Not on PyPI yet.** The JavaScript packages are published; this one is still
working through PyPI onboarding. Until it lands, install from a clone of the
[monorepo](https://github.com/anonrouter/anonrouter-sdk):

```
pip install ./python                  # verify + NEAR/Venice E2EE + TDX
pip install "./python[mlkem]"         # adds the Chutes ML-KEM-768 transport
pip install "./python[tinfoil]"       # adds Tinfoil SDK verification
```

Once it is published the same extras apply to the package name:

```
pip install "anonrouter-confidential[mlkem]"
```

## Provider crypto (protocols)

- `near-ai` (`near-v2`): Ed25519 client key, per-field ephemeral X25519,
  HKDF-SHA256 info `ed25519_encryption`, XChaCha20-Poly1305. Wire = 32-byte X25519
  pub then 24-byte nonce then ciphertext+tag, lowercase hex.
- `venice` (`venice-legacy`): secp256k1 ECDH over the shared point's X coordinate,
  HKDF-SHA256 info `ecdsa_encryption`, AES-256-GCM. Wire = 65-byte uncompressed pub
  then 12-byte nonce then ciphertext+tag, hex.
- `chutes` (`chutes-mlkem-v1`): ML-KEM-768, HKDF-SHA256 salt = ML-KEM ciphertext's
  first 16 bytes, info `e2e-req-v1` / `e2e-resp-v1`, ChaCha20-Poly1305, gzip. Wire =
  1088-byte ML-KEM ciphertext then 12-byte nonce then ciphertext+tag.

```python
from anonrouter_confidential.crypto import near, venice, chutes

near.decrypt(ciphertext_hex, client_ed25519_secret_hex)     # -> str
venice.decrypt(ciphertext_hex, client_private_hex)          # -> str
chutes.decrypt_response(blob_bytes, response_secret_key)    # -> dict
```

## Verify a route

```python
from anonrouter_confidential import create_client

with create_client("https://api.anonrouter.ai", api_key="...") as client:
    result = client.verify_attestation(model="venice-uncensored", provider="venice")
    verdict = result["verdict"]            # OUR independent NormalizedVerdict
    assert verdict.status == "ok"
    assert verdict.verification_level == "provider-attested"
```

## Confidential chat

```python
out = client.chat(
    model="venice-uncensored",
    provider="venice",
    messages=[{"role": "user", "content": "hello"}],
    max_output_tokens=256,
)
print(out["content"])
```

## Verification ceiling (honest by design)

The ceiling is `provider-attested` for NEAR / Venice / Chutes: the DCAP / NRAS
chain-to-vendor-roots is deliberately not wired, and faking it would be dishonest.
Tinfoil reaches `sdk-verified` via its official verifier (the optional `tinfoil`
dependency); without it, Tinfoil verification fails closed. This package NEVER emits
`hardware-verified`. A TEE route is enclave-verified but AnonRouter's gateway may
still see plaintext; only the E2EE routes keep content opaque to the gateway.

## License

Apache-2.0.
