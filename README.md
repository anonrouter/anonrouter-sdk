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
| `@anonrouter/confidential` | JavaScript / TypeScript (npm) | Independently verify TEE / E2EE routes, run end-to-end-encrypted inference, and generate images / speech over the two-origin ticket exchange. |
| `@anonrouter/client` | JavaScript / TypeScript (npm) | Thin, dependency-free API client for the public (plaintext / TEE / private) routes. |
| `anonrouter-confidential` | Python (PyPI) | The Python twin of `@anonrouter/confidential`: same verification, same E2EE, same media surface. |

Both `@anonrouter/confidential` and `anonrouter-confidential` also install an
`anonrouter-verify` command. See [Verify from a terminal](#verify-from-a-terminal).

The JavaScript packages are released independently from the Python registry
package. If npm has not propagated the current release yet, install its
checksummed tarballs from the GitHub release or build from this repository. The
Python wheel and sdist remain available from the GitHub release while PyPI
organization approval is pending. Every tarball, wheel and sdist is installed
into an empty environment before release. The `v0.1.2` candidate has passed that
artifact-install smoke test but is not yet published.

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
native/dcap-verifier/     # the offline Intel DCAP engine, AGPL-3.0-only, build it yourself
docs/                     # what the live origins serve; the ticketed media contract
scripts/                  # sync, parity gates, artifact smoke installs, release artifacts
.github/workflows/        # CI: js, python, parity, CLI parity, packaging; and the release
```

## What "confidential" means here, honestly

AnonRouter offers routes at different privacy levels. Read this before you rely
on any of them, because the words matter.

- **Your plaintext does not reach ordinary AnonRouter infrastructure.** All
  content now goes to the confidential origin, `api.anonrouter.ai`, whose
  relay runs inside an attested Intel TDX CVM and terminates TLS *in-enclave*. The
  shipped policy makes `transport_terminates_in_tee` and
  `tls_certificate_bound_to_quote` REQUIRED checks, so the attested TD provably
  holds the key for the connection carrying your request. The credential-only
  control origin (`control.anonrouter.ai`) mints tickets and serves account and
  catalog operations; it does not receive request content.
- **A TEE route still asks you to trust our reviewed build.** Inside that enclave,
  the relay handles your plaintext to route and meter it. What keeps that from
  being a matter of faith is that a build changed to exfiltrate it would change
  the measurements, so hop 1 stops verifying. Cheating is *detectable* — provided
  you actually verify, which is what this SDK is for.
  - "Reviewed build" is meant literally. The compose measured by the CVM names the
    content plane by image digest, and that image is built in public CI from
    [`anonrouter/confidential-content-plane`](https://github.com/anonrouter/confidential-content-plane)
    at tag `content-plane-v1.0.20`, with a signed SLSA provenance attestation
    naming the same digest. Two of its base images still have no source-to-digest
    binding; the release manifest names them rather than rounding them up, and so
    does [`docs/release-readiness.md`](docs/release-readiness.md).
- **E2EE removes us from the trust set entirely.** On an E2EE route the SDK
  encrypts your request to a key bound to the *provider's* attested enclave, so
  AnonRouter's relay holds ciphertext whatever code it happens to be running. Use
  this when the requirement is that AnonRouter cannot read your content **even if
  we wanted to and shipped code to try**, rather than that we would be caught
  doing so. The SDK ships E2EE transports and verifiers for `venice`, `chutes`
  and `near-ai`; which of them the catalog actually serves changes, so read
  `client.models()` rather than this list — `npm run example:route-matrix` prints
  it.
- **`@anonrouter/client` is the plaintext client.** It speaks the ordinary
  OpenAI-style chat surface over the ticketed flow, and it neither verifies the
  plane nor encrypts anything — so while it benefits from the same in-enclave
  termination, nothing in it proves that to you. It is explicitly not the
  confidential package.

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

The pin shipped today is `published` and is bound to the independently retained
production release manifest. It still requires hardware verification, which
needs the separately built DCAP engine, so a call without an engine fails closed
with reason `quote_signature_chain`. Installing the engine is the
[one-step fix](#reaching-hardware_verified); the SDK never turns missing hardware
verification into a reassuring result.

## Verify from a terminal

Both packages install a command called `anonrouter-verify`. It prints one JSON
document and exits nonzero unless the assurance you asked for was established, so
it can gate a deploy rather than only inform one:

```bash
anonrouter-verify doctor --origin https://api.anonrouter.ai
anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap \
  --require hardware_verified
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
purpose). The engine's source is in [`native/dcap-verifier`](native/dcap-verifier)
under AGPL-3.0-only, and `scripts/build-dcap-verifier.sh --reproduce` builds it
twice from clean in a digest-pinned container and fails unless the two outputs are
byte-identical. The release also carries a checksummed `linux/amd64` build of that
same source, so you can compare rather than trust. Put the binary on PATH or name
it in `ANONROUTER_DCAP_VERIFIER_BIN`, and hop 1 can reach `hardware_verified`:

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

### Checking every confidential route at once

Two runnable harnesses live in `js/confidential/examples`. Both read the live
catalog rather than a written-down provider list, and both write content-free
evidence: statuses, verdict fields, check names, timings — never a prompt, a
key, or an evidence body.

```bash
cd js/confidential

# Every callable tee/e2ee route in the live catalog, both hops, with the
# reproducible DCAP engine on PATH so hop 1 can reach hardware_verified.
npm run example:route-matrix -- --env-file ~/path/to/.env --out matrix.json

# ...and one minimal real provider-pinned request per route, so the matrix says
# the route RUNS rather than only that it verifies. This spends money.
npm run example:route-matrix -- --env-file ~/path/to/.env --paid

# The refusals: what the mint, the redemption, and this SDK must each reject.
npm run example:negative-controls -- --env-file ~/path/to/.env --out controls.json
```

`--env-file` reads one variable out of a `.env` you already have, so a key that
already lives somewhere is not copied to a second file to satisfy a tool.
`--key-file` remains for a file whose whole contents are the key.

### The trust boundary that actually earns the claim

Verification is only as strong as where the verifier runs.

- Code that AnonRouter delivers to your browser at request time is convenient,
  but AnonRouter controls that code path, so it cannot, by itself, be evidence
  against AnonRouter. It is a UX affordance, not an independent check.
- An SDK that you install yourself, pin, and run in your own process is
  different. It is your code, checking the provider's raw evidence against pins
  that you can read and review. That is the configuration that earns the stronger
  claim, and it is exactly what this repo is for.

So: install the SDK, review the verification policy in `shared/measurements.json`,
and let the package verify the evidence on your side of the boundary. Static
measurements are pinned where the provider contract requires them; Tinfoil pins
its official signed-release authority and repository instead of each release's
generated fingerprint.

### Verification ceiling (what each level actually proves)

The SDK reports a `verification_level` and never inflates it:

- `provider-attested` for `near-ai`, `venice`, and `chutes`. The SDK checks the
  provider's attestation and cryptographic bindings (for example the Chutes X.509
  certificate possession and the Venice secp256k1 signing address) against the
  reviewed pins. The DCAP / NRAS chain all the way to the silicon vendor roots is
  deliberately not wired here, because faking that chain would be dishonest.
- `sdk-verified` for `tinfoil`, based on Tinfoil's official verifier document
  plus an independently observed TLS binding. What that proves is the signed
  tagged release for the exact `tinfoilsh/confidential-model-router` repository,
  AMD SEV-SNP evidence, equality between the signed code and the live enclave,
  and a serving connection whose certificate key was read off the wire and found
  equal to the key in that verified report. What it does not prove: nothing here
  verifies NVIDIA GPU confidential-compute evidence, and nothing binds the model
  weights. In Node, `verifyTinfoilEnclave()` performs both halves itself through
  the optional `tinfoil` npm dependency, so it needs nothing from AnonRouter;
  Python validates the gateway-supplied document, including the transport
  observation the gateway recorded, or you can use Tinfoil's own Python client
  for a fully independent check. Tinfoil is a TEE route, so our attested relay
  handles the plaintext in-enclave rather than ciphertext: the route asks you to
  trust our reviewed build, where an E2EE route does not.
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
npm install @anonrouter/confidential

# Before registry propagation, build from a clone of this repo:
git clone https://github.com/anonrouter/anonrouter-sdk
cd anonrouter-sdk/js && npm ci && npm run build
```

Node 22 or newer.

**Browser support.** The default `@anonrouter/confidential` package works in
browsers and supports E2EE routes. Full Intel TDX hardware verification is
currently available in Node.js through `@anonrouter/confidential/dcap`. Browsers
cannot run the native verifier or inspect the server's TLS certificate, so the
SDK does not claim full gateway hardware verification in a browser. Use the
Node.js SDK or `anonrouter-verify` CLI when you need that proof.

```ts
import { createClient, atLeast } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  controlBaseUrl: "https://control.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!
});

// Verify BOTH hops and gate on the result. This is the stable contract; see
// VERIFYING.md for the five states and what each one does and does not prove.
const verdict = await client.verifyRoute({
  model: "z-ai/glm-5.2",
  provider: "venice",
  gateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
if (!atLeast(verdict.overallState, "cryptographically_checked")) {
  throw new Error(`route not established: ${verdict.reason}`);
}

// End-to-end-encrypted chat: keys and nonce are fresh per call, only ciphertext
// reaches AnonRouter's relay, and requireGateway re-establishes hop 1 with a new
// nonce BEFORE a ticket is spent or a model is named.
const reply = await client.chat({
  model: "z-ai/glm-5.2",
  provider: "venice",
  messages: [{ role: "user", content: "Draft a private message." }],
  maxOutputTokens: 512,
  requireGateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
console.log(reply.content);
```

## Quickstart: `anonrouter-confidential` (Python)

> **Not on PyPI yet.** Install the Python package from this repository or from the
> checksummed wheel/sdist attached to the GitHub release while PyPI organization
> approval is pending. JavaScript registry publication is independent. Every
> artifact is installed into an empty environment by
> `scripts/smoke-artifacts.mjs` before release.

```bash
# From a clone of this repo:
git clone https://github.com/anonrouter/anonrouter-sdk
cd anonrouter-sdk
pip install "./python[mlkem]"                  # mlkem extra enables the Chutes route

# Once it is on PyPI:
# pip install "anonrouter-confidential[mlkem]"
```

Python 3.10 or newer. CI runs the suite on 3.10, 3.11, 3.12 and 3.13.

```python
import os

from anonrouter_confidential import at_least, create_client
from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

client = create_client(
    base_url="https://api.anonrouter.ai",
    control_base_url="https://control.anonrouter.ai",
    api_key=os.environ["ANONROUTER_API_KEY"],
)

# Verify BOTH hops and gate on the result. This is the stable contract; see
# VERIFYING.md for the five states and what each one does and does not prove.
verdict = client.verify_route(
    model="z-ai/glm-5.2",
    provider="venice",
    gateway={"chain_verifier": create_anonrouter_dcap_verifier()},
)
if not at_least(verdict.overall_state, "cryptographically_checked"):
    raise SystemExit(f"route not established: {verdict.reason}")

reply = client.chat(
    model="z-ai/glm-5.2",
    provider="venice",
    messages=[{"role": "user", "content": "Draft a private message."}],
    max_output_tokens=512,
)
print(reply["content"])
```

## Quickstart: `@anonrouter/client` (plaintext API client)

```bash
# Same clone as above; this package is a workspace in js/.
cd anonrouter-sdk/js && npm ci && npm run build
```

```ts
import { createClient } from "@anonrouter/client";

// The production origins are the defaults. Pass controlBaseUrl /
// inferenceBaseUrl explicitly to point at another deployment, or a single
// baseUrl for a monolithic or local one.
const client = createClient({ apiKey: process.env.ANONROUTER_API_KEY! });

const models = await client.models();

// Two-request ticketed flow. The API key authorizes the ticket, then only the
// single-use ticket accompanies the content. Content on this route is visible
// to the gateway: use @anonrouter/confidential when it must not be.
const completion = await client.chat({
  model: "z-ai/glm-5.2",
  messages: [{ role: "user", content: "Hello." }]
});
```

## Images and speech, over the two-origin split

`client.images.generate(...)` and `client.audio.speech.create(...)` exist in both
`@anonrouter/confidential` and `anonrouter-confidential`, with the same parameters
and the same guarantees.

```ts
const client = createClient({ apiKey: process.env.ANONROUTER_API_KEY! });

const image = await client.images.generate({ model: "alibaba/z-image-turbo", prompt: "a lighthouse" });
await writeFile("out.png", image.data[0].bytes);

const speech = await client.audio.speech.create({ model: "venice/kokoro-text-to-speech", input: "Hello." });
await writeFile("out.mp3", speech.audio);
```

```python
client = create_client(api_key=os.environ["ANONROUTER_API_KEY"])

image = client.images.generate(model="alibaba/z-image-turbo", prompt="a lighthouse")
open("out.png", "wb").write(image.data[0].data)

client.audio.speech.create(model="venice/kokoro-text-to-speech", input="Hello.").write_to("out.mp3")
```

One call is two requests to two hosts. The API key mints a **content-free**
single-use ticket at the control origin — model, size, voice, and for speech the
character *count*, never the text. The prompt then goes to the confidential origin
with that ticket as its only credential. Neither host holds both your identity and
your content.

**The official OpenAI SDK cannot perform this exchange**: one base URL, one
credential, so the key and the prompt would reach the same host. AnonRouter's
OpenAI-compatibility broker is a **separate, lower-privacy option** where one
service receives both, and these SDKs never select it implicitly or fall back to
it.

Read [`docs/ticketed-media.md`](docs/ticketed-media.md) for the compatibility
matrix, the exact facts the ticket binds, the error taxonomy, and why a failed
media POST is never retried.

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
