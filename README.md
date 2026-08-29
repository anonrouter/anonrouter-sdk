# AnonRouter SDKs

Open-source SDKs to independently verify AnonRouter's confidential inference
routes, and to run confidential inference from your own app. The guiding
principle is "don't trust us, verify": these packages check the provider
evidence themselves, so you do not have to take AnonRouter's word for it.

This monorepo is public and deliberately separate from AnonRouter's private
product code. It holds only the verification logic, the client, the reviewed
measurement pins, and the known-answer test vectors. Everything trust-critical
lives here in the open.

## Packages

| Package | Language | What it is |
| --- | --- | --- |
| `@anonrouter/confidential` | JavaScript / TypeScript (npm) | Independently verify TEE / E2EE routes and run end-to-end-encrypted inference. |
| `@anonrouter/client` | JavaScript / TypeScript (npm) | Thin, dependency-free API client for the public (plaintext / TEE / private) routes. |
| `anonrouter-confidential` | Python (PyPI) | The Python twin of `@anonrouter/confidential`: same verification, same E2EE. |

Layout:

```
shared/
  measurements.json     # canonical, reviewed measurement pins (single source of truth)
  vectors/              # language-neutral known-answer test vectors
js/
  confidential/         # @anonrouter/confidential
  client/               # @anonrouter/client
python/                 # anonrouter-confidential
scripts/                # sync + cross-language parity gate
.github/workflows/      # CI: js, python, parity
```

## What "confidential" means here, honestly

AnonRouter offers routes at different privacy levels. Read this before you rely
on any of them, because the words matter.

- **TEE (Trusted Execution Environment) is NOT content-private from AnonRouter.**
  A TEE protects your content from the infrastructure host and proves which code
  is running inside the enclave. It does not hide your content from AnonRouter's
  own gateway, which sees the plaintext in order to route and meter the request.
  Use a TEE route when you want a hardware attestation of the serving stack, not
  when you need AnonRouter itself to be unable to read the content.
- **Only E2EE (end-to-end encryption) hides content from AnonRouter.** On the
  E2EE providers (`near-ai`, `venice`, `chutes`), the SDK encrypts your request
  to a key bound to the attested enclave and relays only ciphertext. AnonRouter's
  relay never sees plaintext. This is the mode to use when the requirement is
  that AnonRouter cannot read your content.
- **`@anonrouter/client` is the plaintext client.** It speaks the ordinary
  OpenAI-style chat surface over AnonRouter's ticketed flow. Content on these
  routes is visible to the gateway. It is here for convenience and for the
  plaintext / TEE / private routes, and it is explicitly not the confidential
  package.

### The trust boundary that actually earns the claim

Verification is only as strong as where the verifier runs.

- Code that AnonRouter delivers to your browser at request time is convenient,
  but AnonRouter controls that code path, so it cannot, by itself, be evidence
  against AnonRouter. It is a UX affordance, not an independent check.
- An SDK that you install yourself, pin, and run in your own process is
  different. It is your code, checking the provider's raw evidence against pins
  that you can read and review. That is the configuration that earns the stronger
  claim, and it is exactly what this repo is for.

So: install the SDK, review the pins in `shared/measurements.json`, and let the
package verify the evidence on your side of the boundary.

### Verification ceiling (what each level actually proves)

The SDK reports a `verification_level` and never inflates it:

- `provider-attested` for `near-ai`, `venice`, and `chutes`. The SDK checks the
  provider's attestation and cryptographic bindings (for example the Chutes X.509
  certificate possession and the Venice secp256k1 signing address) against the
  reviewed pins. The DCAP / NRAS chain all the way to the silicon vendor roots is
  deliberately not wired here, because faking that chain would be dishonest.
- `sdk-verified` for `tinfoil`, via Tinfoil's official verifier (an optional
  dependency: `tinfoil` on npm, `tinfoil` on PyPI). Tinfoil is a TEE route, so it
  is attested but not content-private from AnonRouter.
- `hardware-verified` is a clearly labeled future upgrade, not a current claim.
  The Intel side is within reach (a pinned Intel root chain already exists in the
  product code). The NVIDIA GPU root pinning is the hard, partly blocked piece.
  Until it ships, the SDK will not print `hardware-verified`.

## Quickstart: `@anonrouter/confidential` (JavaScript)

```bash
npm install @anonrouter/confidential
```

```ts
import { createClient } from "@anonrouter/confidential";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!
});

// Independently verify a route's attestation before you trust it.
const result = await client.verifyAttestation({
  model: "openai/gpt-oss-120b",
  provider: "near-ai"
});
console.log(result.verdict.status, result.verdict.verification_level);

// End-to-end-encrypted chat: keys and nonce are fresh per call, and only
// ciphertext ever reaches AnonRouter's relay.
const reply = await client.chat({
  model: "openai/gpt-oss-120b",
  provider: "near-ai",
  messages: [{ role: "user", content: "Draft a private message." }],
  maxOutputTokens: 512
});
console.log(reply.content);
```

## Quickstart: `anonrouter-confidential` (Python)

> **Not on PyPI yet.** The JavaScript packages are published; the Python package
> is still working through PyPI onboarding. Until it lands, install it from a
> clone of this repository. The code, the pins, and the test vectors are the same
> ones the published release will carry.

```bash
# From a clone of this repo:
pip install "./python[mlkem]"                  # mlkem extra enables the Chutes route

# Once it is on PyPI:
# pip install "anonrouter-confidential[mlkem]"
```

```python
import os

from anonrouter_confidential import create_client

client = create_client(
    base_url="https://api.anonrouter.ai",
    api_key=os.environ["ANONROUTER_API_KEY"],
)

# verify_attestation() and chat() return dicts; the verdict is a NormalizedVerdict.
result = client.verify_attestation(model="openai/gpt-oss-120b", provider="near-ai")
verdict = result["verdict"]
print(verdict.status, verdict.verification_level)

reply = client.chat(
    model="openai/gpt-oss-120b",
    provider="near-ai",
    messages=[{"role": "user", "content": "Draft a private message."}],
    max_output_tokens=512,
)
print(reply["content"])
```

## Quickstart: `@anonrouter/client` (plaintext API client)

```bash
npm install @anonrouter/client
```

```ts
import { createClient } from "@anonrouter/client";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!
});

const models = await client.models();

// Two-request ticketed flow. The API key authorizes the ticket, then only the
// single-use ticket accompanies the content. Content on this route is visible
// to the gateway: use @anonrouter/confidential when it must not be.
const completion = await client.chat({
  model: "openai/gpt-oss-120b",
  messages: [{ role: "user", content: "Hello." }]
});
```

## One source of truth, enforced across languages

The measurement pins and the known-answer test vectors are shared by both
languages so they can never quietly disagree:

- `shared/measurements.json` is the single source of truth for the reviewed
  TEE / E2EE measurement pins. Per-package copies are generated from it, not
  hand-edited.
- `shared/vectors/` holds language-neutral known-answer vectors covering all three
  layers: provider crypto decrypts, TDX quote parses, and full verifier verdicts.
  The JS and Python test suites both load the same vectors and must produce
  identical results, so a divergence fails that language's CI job.
- `shared/vectors/attestation.json` pins the complete verdict for each case: the
  status, the verification level, the failure reason, and the exact set of
  required checks that failed. That is deliberately strict. A verifier change that
  lands in one language and not the other cannot pass CI, and neither can a change
  that quietly relaxes a required check into an advisory one.
- A dedicated parity gate (`scripts/check-parity.mjs`) runs in CI and fails the
  build if any per-package measurement copy drifts from the canonical pins.

Run the gate locally:

```bash
node scripts/check-parity.mjs
```

## Contributing and security

See `CONTRIBUTING.md` for dev setup and how the pins are maintained, and
`SECURITY.md` for disclosure and the pin rotation policy.

## License

Apache-2.0. See `LICENSE`.
