# anonrouter-confidential

Independently verify AnonRouter TEE / E2EE routes and run confidential inference
from Python. This package mirrors the JS `@anonrouter/confidential` surface and
passes the SAME shared known-answer-test (KAT) vectors, so Python and JS agree
bit-for-bit.

"Don't trust us, verify." The verifier is pure over its inputs and fails closed.

## Install

**Not on PyPI yet**, and neither are the JavaScript packages. Install from a clone
of the [monorepo](https://github.com/anonrouter/anonrouter-sdk). The wheel and the
sdist are built and installed into clean virtualenvs on every CI run, so what PyPI
would carry is the thing already being tested; publishing is an owner decision
rather than a technical gap.

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

with create_client(
    "https://api.private.anonrouter.ai",
    api_key="...",
    control_base_url="https://api.anonrouter.ai",
) as client:
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

The production pin ships as `published` from an independently retained release
manifest. It sets `requireHardwareVerified` while this package bundles no native
engine, so verification fails closed with reason `quote_signature_chain` until
you install one (see below). That is the honest answer: without chaining the
quote's signature to Intel's roots, nobody has checked it came from real silicon.

## Reaching `hardware_verified`

This package bundles **no DCAP engine** inside the pure-Python wheel. The official
linux/amd64 engine is built reproducibly in a digest-pinned container and can be
installed separately; keeping it separate also makes the executable digest an
explicit operator choice rather than an opaque wheel payload.

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
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --dcap \
  --require hardware_verified
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

## Images and speech

`client.images.generate(...)` and `client.audio.speech.create(...)` run
AnonRouter's two-origin ticket exchange for you. The API key mints a
**content-free** single-use ticket at the control origin; the prompt or text then
goes to the confidential origin with that ticket as its only credential. Neither
host sees both your identity and your content.

```python
from anonrouter_confidential import create_client

# The production origins are the defaults, so this is the whole configuration.
client = create_client(api_key=os.environ["ANONROUTER_API_KEY"])

image = client.images.generate(
    model="venice/flux-dev",
    prompt="a lighthouse in a storm",
    size="1024x1024",
)
open("out.png", "wb").write(image.data[0].data)
print(image.selected_model, image.data[0].mime_type)

speech = client.audio.speech.create(
    model="venice/tts-kokoro",
    input="The quick brown fox.",
    voice="af_sky",
)
speech.write_to("out.mp3")
```

**The official OpenAI SDK cannot perform this exchange.** It has one base URL and
one credential, so it would send your API key and your prompt to the same host in
one request. Point it at the confidential origin and the mint answers 404; point
it at the control origin and media answers 503. Both failures are the design
working. AnonRouter's OpenAI-compatibility broker is a **different, lower-privacy
option** — one service receives the key and the prompt together — and this SDK
never selects it implicitly, never falls back to it, and has no flag that enables
it.

Unsupported OpenAI parameters are **refused, not dropped**: `n` other than 1,
`response_format` other than `b64_json` / `mp3`, `speed` other than 1, and unknown
keywords like `quality`. Silently ignoring them would hand you something other
than what you paid for. Failed POSTs are **never retried**, because a media
generation is billed on the provider attempt.

One detail that matters for speech: the ticket binds the exact character count,
and the server counts **UTF-16 code units**, not Python code points. `"Hi 😀"` is
4 to `len()` and 5 to the server. The SDK uses the server's counting
(`utf16_length`), so emoji do not produce a mysterious 409.

**Media is not end-to-end encrypted, unlike `chat()`.** The prompt reaches the
confidential origin as plaintext. What protects it is the origin split (the host
holding the prompt never holds your credential) plus the TDX enclave that host
runs in — which you can verify yourself with `verify_gateway()` before you send
anything, against the same origin the content goes to. That is a real property
and a weaker one than E2EE chat; if your threat model needs AnonRouter to be
unable to read the content even in principle, media does not meet it today.

Full contract, compatibility matrix, bound ticket facts, and the error taxonomy:
[`docs/ticketed-media.md`](../docs/ticketed-media.md).

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

On the production confidential origin your plaintext never reaches ordinary
AnonRouter infrastructure: the relay runs inside an attested Intel TDX CVM and
terminates TLS in-enclave (`transport_terminates_in_tee` and
`tls_certificate_bound_to_quote` are required checks in the shipped policy).

What still differs between the modalities is the TRUST SET. On a `tee` route the
relay handles your plaintext inside that enclave, so you are trusting the reviewed
build — a build changed to exfiltrate it would change the measurements and hop 1
would stop verifying, which makes cheating detectable rather than impossible. On an
`e2ee` route the request is encrypted to the provider's attested key, so the relay
holds ciphertext whatever code it runs and our build is not in your trust set at
all. That is what `content_visible_to_anonrouter` marks.

## License

Apache-2.0.
