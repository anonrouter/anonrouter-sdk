
# anonrouter-confidential

Verify what is running behind AnonRouter, then send encrypted requests from your own Python app.

AnonRouter's privacy claims should not depend on taking our word for them. This package checks them on your machine, and it refuses to continue when a check fails.

- **Verify AnonRouter's servers** against a signed release policy and Intel's hardware attestation.
- **Verify a model route** using the provider's attestation evidence.
- **Send end-to-end encrypted chat** that is encrypted on your machine before it leaves.
- **Keep your API key and your prompts apart.** The key goes to one host, and the prompt goes to another with a single-use ticket.

## Install

```bash
pip install "anonrouter-confidential[connection-binding]"
```

Requires Python 3.10 or newer. Add the `mlkem` extra for routes that use the ML-KEM transport.

## Verify AnonRouter

This needs no API key and sends no inference.

```python
from anonrouter_confidential import verify_content_node

result = verify_content_node()
print(result["policy"]["sequence"], result["verdict"].verification_level)
```

This prints `hardware-verified` when the check succeeds. Full hardware verification needs the `anonrouter-dcap-verifier` program, which is a separate download so that you choose exactly which binary you trust. Get the Linux amd64 build from the [GitHub releases](https://github.com/anonrouter/anonrouter-sdk/releases), or build it from source and compare digests. Without it, this prints `unverified`.

## Encrypted chat

```python
import os
from anonrouter_confidential import at_least, create_client

with create_client(api_key=os.environ["ANONROUTER_API_KEY"]) as client:
    verdict = client.verify_route(
        model="google/gemma-4-26b-a4b-uncensored",
        provider="venice",
    )
    if not at_least(verdict.overall_state, "cryptographically_checked"):
        raise SystemExit(verdict.reason)

    out = client.chat(
        model="google/gemma-4-26b-a4b-uncensored",
        provider="venice",
        messages=[{"role": "user", "content": "hello"}],
        max_output_tokens=256,
    )
    print(out["content"])
```

This checks the provider route and encrypts your prompt on your machine. It does not verify AnonRouter's own servers. For that, use strict mode.

## Strict mode

Strict mode verifies AnonRouter's servers on the same connection before each operation. If verification fails, nothing is sent. It needs the `anonrouter-dcap-verifier` program.

```python
import os
from anonrouter_confidential import create_client
from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

with create_client(
    api_key=os.environ["ANONROUTER_API_KEY"],
    gateway_policy_updates=True,
    gateway_connection_binding={
        "mode": "required",
        "verification": {"chain_verifier": create_anonrouter_dcap_verifier()},
    },
) as client:
    verdict = client.verify_route(
        model="google/gemma-4-26b-a4b-uncensored",
        provider="venice",
    )
    print(verdict.gateway.state, verdict.overall_state)

    out = client.chat(
        model="google/gemma-4-26b-a4b-uncensored",
        provider="venice",
        messages=[{"role": "user", "content": "hello"}],
        max_output_tokens=256,
    )
    print(out["content"])
```

`verdict.gateway.state` covers AnonRouter's servers and can reach `hardware_verified`. `verdict.overall_state` is the weakest result across everything checked, so it also reflects the provider route. Any mismatch between the route you requested and the route that was served makes the whole result untrusted.

## Images and speech

Your API key gets a single-use ticket from one host, and the prompt goes to the other host with only that ticket.

```python
import os
from anonrouter_confidential import create_client

with create_client(api_key=os.environ["ANONROUTER_API_KEY"]) as client:
    image = client.images.generate(
        model="alibaba/z-image-turbo",
        prompt="a lighthouse in a storm",
        size="1024x1024",
    )
    open("out.webp", "wb").write(image.data[0].data)

    speech = client.audio.speech.create(
        model="hexgrad/kokoro-82m",
        input="The quick brown fox.",
        voice="af_sky",
    )
    speech.write_to("out.mp3")
```

These requests are not end-to-end encrypted. The prompt is readable inside the attested enclave that handles it. Use strict mode to verify that enclave before sending. See the [media guide](https://github.com/anonrouter/anonrouter-sdk/blob/main/docs/ticketed-media.md).

## Verify from a terminal

```bash
anonrouter-verify doctor --origin https://api.anonrouter.ai
anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap --require hardware_verified
```

The command exits with an error unless the assurance you asked for was established, so you can use it to gate a deploy or CI job.

## What this proves, and what it doesn't

| Result | Meaning |
| --- | --- |
| `hardware_verified` | The evidence chains to Intel's roots with an accepted security status. Needs the separate verifier program. |
| `cryptographically_checked` | The evidence is internally consistent and matches the expected identity, but it is not proof of real hardware. |
| `policy_matched` | The identity the evidence claims matched what you expected, but nothing cryptographically ties it to hardware. |
| `untrusted` | A check failed. Do not rely on this route. |
| `unavailable` | Verification could not run. This is also a failure. |

Provider route checks currently stop at `cryptographically_checked`, because the GPU attestation on several routes is not available to verify.

On a `tee` route, your prompt is readable inside the verified enclave. On an `e2ee` route, it is encrypted to the provider's attested key, so AnonRouter's relay only handles ciphertext.

## More

- [Verification guide](https://github.com/anonrouter/anonrouter-sdk/blob/main/VERIFYING.md)
- [Security and trust model](https://github.com/anonrouter/anonrouter-sdk/blob/main/SECURITY.md)
- [Source code](https://github.com/anonrouter/anonrouter-sdk)

## License

Apache-2.0
