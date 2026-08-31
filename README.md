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

Both `@anonrouter/confidential` and `anonrouter-confidential` also install an
`anonrouter-verify` command. See [Verify from a terminal](#verify-from-a-terminal).

**None of the three is on a registry yet.** The registry column above is where each
one is headed. Install from a clone until then; the artifacts are built and used
from empty environments on every CI run, so publishing is an owner decision rather
than a technical gap.

Layout:

```
shared/
  measurements.json       # canonical, reviewed measurement pins (single source of truth)
  gateway-policies.json   # canonical pins for AnonRouter's own confidential plane
  vectors/                # language-neutral known-answer test vectors
js/
  confidential/           # @anonrouter/confidential
  client/                 # @anonrouter/client
python/                   # anonrouter-confidential
docs/                     # what the live origins actually serve
scripts/                  # sync, parity gates, artifact smoke installs
.github/workflows/        # CI: js, python, parity, CLI parity, packaging
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

### Two hops, verified separately

A request passes through two parties, and verifying one tells you nothing about
the other:

| | Question it answers | How to verify |
| --- | --- | --- |
| **Hop 1** AnonRouter's own routing plane | Is the data plane I am connected to the exact reviewed build, running inside an Intel TDX confidential VM, bound to my nonce and my origin? | `verifyGateway()` / `verify_gateway()` |
| **Hop 2** the downstream provider route | Did the model provider terminate my request inside a verified enclave running measurements I pinned? | `verifyAttestation()` / `verify_attestation()` |

A verified hop 2 says nothing about who routed the request to it. A verified hop 1
says nothing about where inference actually ran. `verify()` establishes both and
reports them separately, and `trusted` covers only the hops the call asked for, so
a report can never read as though it had covered a hop it skipped.

Hop 1 pins live in `shared/gateway-policies.json`. The policy a gateway is held to
must never be fetched from that gateway: a server that could hand you the list of
builds you accept could always name itself. So the pins ship inside the packages,
and an origin with no pin fails closed rather than falling back to the server's own
claim about itself.

Two caveats on the pin shipped today. It is marked `candidate`, because the
confidential plane is pre-release and its measurements move on every release, so
resolving it takes an explicit opt-in. And it requires hardware verification,
which needs a DCAP engine these packages do not bundle, so a default call fails
closed with reason `quote_signature_chain`. Installing the engine is the
[one-step fix](#reaching-hardware_verified), and the failure is the honest
outcome until you do: nobody has checked the quote came from real silicon.

## Verify from a terminal

Both packages install a command called `anonrouter-verify`. It prints one JSON
document and exits nonzero unless the assurance you asked for was established, so
it can gate a deploy rather than only inform one:

```bash
anonrouter-verify doctor --origin https://api.private.anonrouter.ai
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --allow-candidate
echo $?    # 0 met, 1 not met, 2 the command itself was wrong
```

`gateway` is credential-free. `route` adds hop 2 and needs an API key, read only
from an environment variable, never from argv. Neither command ever prints a key,
a ticket, request content, or the raw evidence body.

Which origin serves which hop today is inventoried in
[`docs/live-contract-inventory.md`](docs/live-contract-inventory.md).

## Reaching `hardware_verified`

These packages bundle **no DCAP engine**, and the reason is not laziness. Shipping
prebuilt binaries would mean asserting that a binary we did not build reproducibly
is the reviewed one, and a hand-rolled JavaScript or Python reimplementation would
be an unreviewed version of the single component whose failure mode is printing
`hardware_verified` for a forged quote.

What ships instead is a first-class adapter to the reviewed engine, plus the Intel
collateral acquisition that engine needs (it performs no network access, on
purpose). Install `anonrouter-dcap-verifier`, put it on PATH or name it in
`ANONROUTER_DCAP_VERIFIER_BIN`, and hop 1 can reach `hardware_verified`:

```ts
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

const verdict = await client.verifyRoute({
  model, provider,
  gateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
```

```python
from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

verdict = client.verify_route(
    model=..., provider=...,
    gateway={"chain_verifier": create_anonrouter_dcap_verifier()},
)
```

`anonrouter-verify doctor` reports whether an engine is installed, its SHA-256,
and exactly what to do if not. With no engine the verdict is capped at
`cryptographically_checked` and a policy demanding hardware verification fails
closed. It never silently downgrades.

**Hop 2 is a different story and is not affected by this.** The provider hop still
caps at `provider-attested`, because several provider routes run GPU enclaves
whose NVIDIA attestation chain is not available to verify. Chaining only the CPU
quote and printing `hardware_verified` would claim more than was checked.

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
- `hardware-verified` is reachable **on hop 1**, and only with a real engine. The
  Intel chain is wired: install `anonrouter-dcap-verifier` and hop 1's verdict can
  reach it, having actually chained the quote's ECDSA signature to Intel's roots
  with an accepted TCB status. Supply no engine and a policy demanding it fails
  closed rather than quietly settling for the weaker level while reporting success.
  On **hop 2** it remains a labeled future upgrade: the NVIDIA GPU root pinning
  several provider routes would need is the hard, partly blocked piece, and the SDK
  will not print `hardware-verified` for a chain it did not complete.

## Quickstart: `@anonrouter/confidential` (JavaScript)

```bash
# Once it is on npm:
# npm install @anonrouter/confidential

# Until then, from a clone of this repo:
cd js && npm ci && npm run build
```

Node 22 or newer. The verification core and the E2EE transports are browser-safe
(Web Crypto and `fetch` only, no `Buffer`, no `node:*`), so `@anonrouter/confidential`
itself runs unchanged in a browser. The `./dcap` and `./chain-verifiers` subpaths
are Node-only by design: they spawn a process, and a browser that could not run
the engine must fail closed rather than silently verify less.

```ts
import { createClient, atLeast } from "@anonrouter/confidential";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!
});

// Verify BOTH hops and gate on the result. This is the stable contract; see
// VERIFYING.md for the five states and what each one does and does not prove.
const verdict = await client.verifyRoute({
  model: "openai/gpt-oss-120b",
  provider: "near-ai",
  gateway: { allowCandidatePolicy: true }   // omit `gateway` to skip hop 1 entirely
});
if (!atLeast(verdict.overallState, "cryptographically_checked")) {
  throw new Error(`route not established: ${verdict.reason}`);
}

// End-to-end-encrypted chat: keys and nonce are fresh per call, only ciphertext
// reaches AnonRouter's relay, and requireGateway re-establishes hop 1 with a new
// nonce BEFORE a ticket is spent or a model is named.
const reply = await client.chat({
  model: "openai/gpt-oss-120b",
  provider: "near-ai",
  messages: [{ role: "user", content: "Draft a private message." }],
  maxOutputTokens: 512,
  requireGateway: { allowCandidatePolicy: true }
});
console.log(reply.content);
```

## Quickstart: `anonrouter-confidential` (Python)

> **Not published yet.** None of the three packages is on a registry at the time of
> writing (`@anonrouter/confidential`, `@anonrouter/client` and
> `anonrouter-confidential` all 404). Install from a clone. The artifacts are built
> and exercised on every CI run by `scripts/smoke-artifacts.mjs`, which installs
> them into empty environments and uses them there, so what a registry would carry
> is the thing that is already being tested; publishing is an owner decision, not a
> technical gap.

```bash
# From a clone of this repo:
pip install "./python[mlkem]"                  # mlkem extra enables the Chutes route

# Once it is on PyPI:
# pip install "anonrouter-confidential[mlkem]"
```

Python 3.10 or newer. CI runs the suite on 3.10, 3.11, 3.12 and 3.13.

```python
import os

from anonrouter_confidential import at_least, create_client

client = create_client(
    base_url="https://api.anonrouter.ai",
    api_key=os.environ["ANONROUTER_API_KEY"],
)

# Verify BOTH hops and gate on the result. This is the stable contract; see
# VERIFYING.md for the five states and what each one does and does not prove.
verdict = client.verify_route(
    model="openai/gpt-oss-120b",
    provider="near-ai",
    gateway={"allow_candidate_policy": True},   # omit `gateway` to skip hop 1
)
if not at_least(verdict.overall_state, "cryptographically_checked"):
    raise SystemExit(f"route not established: {verdict.reason}")

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
- `shared/vectors/dcap.json` pins the wire contract with the DCAP engine: how a
  PCK chain and its FMSPC are read out of a quote, how Intel's signed documents are
  sliced without breaking their signatures, and every way a malformed engine
  verdict must fail to parse rather than be coerced into a pass.
- `shared/vectors/cli-contract.json` pins the `anonrouter-verify` command: its exit
  codes, its document shape, the inputs it must refuse before contacting anything,
  and the substrings it must never print.

Three gates run in CI and can be run locally:

```bash
node scripts/check-parity.mjs      # per-package pin copies match shared/
node scripts/check-cli-parity.mjs  # both real anonrouter-verify binaries agree
node scripts/smoke-artifacts.mjs   # every artifact installs into an empty env and works
```

The last one is the one that catches what the others cannot. Every other gate runs
against the working tree, which says nothing about whether the published
**artifact** is right: a missing entry in `files`, an `exports` map that does not
resolve, a `bin` that is not executable, or a wheel that omits the measurement
pins are all invisible until somebody installs the thing.

## What has actually been verified

[`docs/release-readiness.md`](docs/release-readiness.md) records every gate with
exact counts, what a live run against real TDX hardware establishes, and, more
usefully, what a green run does **not** cover. A list of green checks is easy; the
second list is what makes the first one worth anything.

## Contributing and security

See `CONTRIBUTING.md` for dev setup and how the pins are maintained, and
`SECURITY.md` for disclosure and the pin rotation policy.

## License

Apache-2.0. See `LICENSE`.
