# anonrouter

The AnonRouter Python package. Verify what is running behind AnonRouter, then send encrypted requests from your own app.

## Install

```bash
pip install anonrouter
```

Requires Python 3.10 or newer. This installs [`anonrouter-confidential`](https://pypi.org/project/anonrouter-confidential/) and gives you its main functions under the shorter `anonrouter` name.

## Verify AnonRouter

This needs no API key and sends no inference.

```python
from anonrouter import verify_content_node

result = verify_content_node()
print(result["policy"]["sequence"], result["verdict"].verification_level)
```

This prints `hardware-verified` when the check succeeds. Full hardware verification needs the separate `anonrouter-dcap-verifier` program from the [GitHub releases](https://github.com/anonrouter/anonrouter-sdk/releases). Without it, this prints `unverified`.

## Encrypted chat

```python
import os
from anonrouter import at_least, create_client

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

Your prompt is encrypted on your machine before it leaves. This checks the provider route. It does not verify AnonRouter's own servers.

## More

Strict mode, images and speech, and the `anonrouter-verify` command are covered on the [`anonrouter-confidential` page](https://pypi.org/project/anonrouter-confidential/).

- [Documentation](https://docs.anonrouter.ai)
- [Source code](https://github.com/anonrouter/anonrouter-sdk)

## License

Apache-2.0
