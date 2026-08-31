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

Python 3.10 or newer. CI runs the suite on 3.10, 3.11, 3.12 and 3.13. Four runtime
dependencies: `cryptography`, `pynacl`, `httpx`, `pycryptodome`.

Installing also installs the `anonrouter-verify` command. See below.

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
`requireHardwareVerified` while this package bundles no engine, so verification
fails closed with reason `quote_signature_chain` until you install one (see
below). That is the honest answer: without chaining the quote's signature to
Intel's roots, nobody has checked it came from real silicon.

## Reaching `hardware_verified`

This package bundles **no DCAP engine**, on purpose: shipping prebuilt binaries
would mean asserting that a binary we did not build reproducibly is the reviewed
one, and a hand-rolled Python reimplementation would be an unreviewed version of
the single component whose failure mode is reporting `hardware_verified` for a
forged quote.

What ships instead is a strict adapter to the reviewed engine, plus the
Intel-signed collateral it needs (the engine performs no network access, on
purpose). Install `anonrouter-dcap-verifier`, put it on PATH or name it in
`ANONROUTER_DCAP_VERIFIER_BIN`, and hop 1 can reach `hardware_verified`:

```python
from anonrouter_confidential.gateway.dcap import (
    create_anonrouter_dcap_verifier,
    describe_dcap_installation,
)

describe_dcap_installation()   # is one installed? which one? what is its digest?

verdict = client.verify_route(
    model=..., provider=...,
    gateway={"chain_verifier": create_anonrouter_dcap_verifier()},
)
```

The adapter fails closed on every path: a missing engine, a digest that does not
match `expected_binary_sha256`, a timeout, a crash, non-JSON output, collateral it
could not acquire, or a verdict whose measured report disagrees with the quote the
SDK parsed. Without an engine the ceiling is `cryptographically_checked` and a
policy demanding hardware verification fails closed. It never silently downgrades.

Hop 2 is unaffected and still caps at `provider-attested`: several provider routes
run GPU enclaves whose NVIDIA attestation chain is not available to verify, and
chaining only the CPU quote would claim more than was checked.

## Verify from a terminal

```bash
anonrouter-verify doctor --origin https://api.private.anonrouter.ai
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --allow-candidate
echo $?   # 0 met, 1 not met, 2 the command itself was wrong
```

It prints one JSON document, identical to the one the JavaScript command prints,
and exits nonzero unless the assurance you asked for was established. `gateway` is
credential-free; `route` adds hop 2 and reads an API key only from an environment
variable, never from argv. Neither prints a key, a ticket, request content, or the
raw evidence body.

## Both hops at once

`verify_route()` is the stable contract: it establishes both hops, cross-binds them
to the route you asked for, and reports ordered states rather than a boolean.

```python
from anonrouter_confidential import at_least

verdict = client.verify_route(
    model="venice-uncensored",
    provider="venice",
    gateway=True,                          # omit to skip hop 1 entirely
)

verdict.overall_state                      # the weakest hop you ASKED about
verdict.gateway.requested                  # whether hop 1 was in scope at all
verdict.gateway.state                      # hardware_verified | ... | unavailable
verdict.gateway.failed_checks              # the exact required checks that failed
verdict.binding_mismatches                 # the route you asked for vs what was served
verdict.content_visible_to_anonrouter      # True on a tee route

if not at_least(verdict.overall_state, "cryptographically_checked"):
    raise SystemExit(verdict.reason)
```

Gate with `at_least()` rather than comparing strings: it is the one place the
ordering lives, so a threshold keeps meaning the same thing if a state is later
inserted into the scale.

`overall_state` only ever covers the hops you asked for, which is why
`gateway.requested` sits beside it. A trusted verdict with
`gateway.requested is False` establishes the provider enclave and makes no claim
about the router. And any entry in `binding_mismatches` forces the whole verdict
untrusted however strong the individual hops were.

`verify()` returns the earlier report shape and is still supported; prefer
`verify_route()`.

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

Hop 2's ceiling is `provider-attested` for NEAR / Venice / Chutes: the chain to
the vendor roots is deliberately not wired there, because several of those routes
run GPU enclaves whose NVIDIA attestation is not available to verify, and chaining
only the CPU quote would claim more than was checked. Tinfoil reaches
`sdk-verified` via its official verifier (the optional `tinfoil` dependency);
without it, Tinfoil verification fails closed.

Hop 1 can reach `hardware_verified`, and only with a real engine that actually
chained the quote to Intel's roots with an accepted TCB status. Nothing here emits
that state on its own.

A TEE route is enclave-verified but AnonRouter's gateway may still see plaintext;
only the E2EE routes keep content opaque to the gateway.

## License

Apache-2.0.
