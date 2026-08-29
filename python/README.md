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

## The two hops

A request travels through two parties, and verifying one tells you nothing about
the other:

| | Question it answers | How to verify |
| --- | --- | --- |
| **Hop 1** AnonRouter's own routing plane | Is the data plane I am connected to the exact reviewed build, running inside an Intel TDX confidential VM, bound to my nonce and my origin? | `verify_gateway()` |
| **Hop 2** the downstream provider route | Did the model provider terminate my request inside a verified enclave running measurements I pinned? | `verify_attestation()` |

## Verify a route (hop 2)

```python
from anonrouter_confidential import create_client

with create_client("https://api.anonrouter.ai", api_key="...") as client:
    result = client.verify_attestation(model="venice-uncensored", provider="venice")
    verdict = result["verdict"]            # OUR independent NormalizedVerdict
    assert verdict.status == "ok"
    assert verdict.verification_level == "provider-attested"
```

## Verify AnonRouter itself (hop 1)

```python
result = client.verify_gateway()           # or policy=... to pin it yourself
verdict = result["verdict"]
assert verdict.status == "ok"
print(verdict.binding.release_id, verdict.binding.compose_hash)
```

The policy a gateway is held to must never come from that gateway: a server that
could hand you the list of builds you accept could always name itself. So the pins
ship inside this package, and an origin with no pin raises rather than falling back
to whatever the server claims.

Two things to know about the pin shipped today. It is marked `candidate`, because
the confidential plane is pre-release and its measurements move on every release,
so resolving it takes `allow_candidate_policy=True`. And it sets
`requireHardwareVerified` while this package ships **no DCAP engine**, so
verification fails closed with reason `quote_signature_chain` unless you pass your
own `chain_verifier`. That is the honest answer: without chaining the quote's
signature to Intel's roots, nobody has checked it came from real silicon.

## Both hops at once

```python
report = client.verify(
    model="venice-uncensored",
    provider="venice",
    gateway=True,                          # omit to skip hop 1 entirely
)

report["trusted"]                          # every hop this call ASKED for verified
report["gateway"]["requested"]             # whether hop 1 was in scope at all
report["gateway"]["status"]                # ok | failed | unavailable | unpinned | not-requested
report["route"]["content_visible_to_anonrouter"]   # True on a tee route
```

`trusted` only ever covers the hops you asked for, which is why
`gateway["requested"]` sits beside it. A report with `trusted: True` and
`gateway["requested"]: False` establishes the provider enclave and makes no claim
about the router.

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

To refuse to send anything unless AnonRouter's own plane attests, pass
`require_gateway=True`. The check runs before the first authenticated call, so a
failure means no ticket was spent and no plaintext went near the wire.

## Verification ceiling (honest by design)

The ceiling is `provider-attested` for NEAR / Venice / Chutes: the DCAP / NRAS
chain-to-vendor-roots is deliberately not wired, and faking it would be dishonest.
Tinfoil reaches `sdk-verified` via its official verifier (the optional `tinfoil`
dependency); without it, Tinfoil verification fails closed. This package NEVER emits
`hardware-verified`. A TEE route is enclave-verified but AnonRouter's gateway may
still see plaintext; only the E2EE routes keep content opaque to the gateway.

## License

Apache-2.0.
