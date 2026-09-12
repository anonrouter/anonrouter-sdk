# @anonrouter/confidential

Independently verify AnonRouter's TEE / E2EE routes and run end-to-end-encrypted
confidential inference from your own Node or browser app. The guiding principle is
"don't trust us, verify": this package checks the provider's raw attestation
evidence itself, against measurement pins you can read and review, so you do not
have to take AnonRouter's word for it.

Part of the [AnonRouter SDK monorepo](https://github.com/anonrouter/anonrouter-sdk).
For the plaintext API surface, see `@anonrouter/client`.

## Install

```bash
npm install @anonrouter/confidential

# Before registry propagation, build from a clone of the monorepo:
git clone https://github.com/anonrouter/anonrouter-sdk
cd anonrouter-sdk/js && npm ci && npm run build
```

The release tarball is also attached to the corresponding GitHub release. It is
built and installed into an empty environment before publication, so the exact
bytes npm carries are exercised rather than only the working tree.

Node 22 or newer. Four runtime dependencies, all `@noble` audited crypto
(`ciphers`, `curves`, `hashes`, `post-quantum`) and nothing else.

Optional dependency: install `tinfoil` to verify Tinfoil TEE routes via its
official verifier.

**Browser support, stated honestly.** The verification core and the E2EE
transports use only Web Crypto, `fetch`, `TextEncoder` and `Uint8Array`, so the
main entry point runs unchanged in a browser, an Electron renderer, or a service
worker. Two subpaths do not and are not meant to: `@anonrouter/confidential/dcap`
and `@anonrouter/confidential/chain-verifiers` spawn a process, and a browser that
cannot run the engine has to fail closed rather than silently verify less. In a
browser the TLS certificate binding is also unobservable, so it is recorded as an
advisory gap rather than assumed away.

## Quickstart

```ts
import { createClient, atLeast } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  controlBaseUrl: "https://control.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!
});

// Verify BOTH hops, cross-bound to the route you asked for, and gate on it.
const verdict = await client.verifyRoute({
  model: "z-ai/glm-5.2",
  provider: "venice",
  gateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
if (!atLeast(verdict.overallState, "cryptographically_checked")) {
  throw new Error(`route not established: ${verdict.reason}`);
}

// End-to-end-encrypted chat: keys and nonce are fresh per call, and only
// ciphertext ever reaches AnonRouter's relay. requireGateway re-establishes hop 1
// with a NEW nonce before a ticket is spent or a model is named, because a verdict
// from a minute ago is a fact about a minute ago.
const reply = await client.chat({
  model: "z-ai/glm-5.2",
  provider: "venice",
  messages: [{ role: "user", content: "Draft a private message." }],
  maxOutputTokens: 512,
  requireGateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
console.log(reply.content);
```

## Images and speech

`images.generate` and `audio.speech.create` run AnonRouter's two-origin ticket
exchange for you. The API key mints a **content-free** single-use ticket at the
control origin; the prompt or text then goes to the confidential origin with that
ticket as its only credential. Neither host sees both your identity and your
content.

```ts
import { createClient } from "@anonrouter/confidential";

// The production origins are the defaults, so this is the whole configuration.
const client = createClient({ apiKey: process.env.ANONROUTER_API_KEY! });

const image = await client.images.generate({
  model: "alibaba/z-image-turbo",
  prompt: "a lighthouse in a storm",
  size: "1024x1024"
});
await writeFile("out.png", image.data[0].bytes);
console.log(image.selected_model, image.data[0].mime_type);

const speech = await client.audio.speech.create({
  model: "venice/kokoro-text-to-speech",
  input: "The quick brown fox.",
  voice: "af_sky"
});
await writeFile("out.mp3", speech.audio);
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
keys like `quality`. Silently ignoring them would hand you something other than
what you paid for. Failed POSTs are **never retried**, because a media generation
is billed on the provider attempt.

**Media is not end-to-end encrypted, unlike `chat()`.** The prompt reaches the
confidential origin as plaintext. What protects it is the origin split (the host
holding the prompt never holds your credential) plus the TDX enclave that host
runs in — which you can verify yourself with `verifyGateway()` before you send
anything, against the same origin the content goes to. That is a real property
and a weaker one than E2EE chat; if your threat model needs AnonRouter to be
unable to read the content even in principle, media does not meet it today.

Full contract, compatibility matrix, bound ticket facts, and the error taxonomy:
[`docs/ticketed-media.md`](../../docs/ticketed-media.md).

## Verify from a terminal

Installing this package installs `anonrouter-verify`. It prints one JSON document
and exits nonzero unless the assurance you asked for was established:

```bash
npx anonrouter-verify doctor --origin https://api.anonrouter.ai
npx anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap \
  --require hardware_verified
echo $?   # 0 met, 1 not met, 2 the command itself was wrong
```

`gateway` is credential-free. `route` adds hop 2 and needs an API key, read only
from an environment variable and never accepted on argv, where it would be visible
in the process table. Neither command prints a key, a ticket, request content, or
the raw evidence body.

## Reaching `hardware_verified`

This package bundles **no DCAP engine**, on purpose: shipping prebuilt binaries
would mean asserting that a binary we did not build reproducibly is the reviewed
one, and a hand-rolled JavaScript reimplementation would be an unreviewed version
of the single component whose failure mode is printing `hardware_verified` for a
forged quote.

What ships instead is a strict adapter to the reviewed engine, plus the
Intel-signed collateral it needs (the engine performs no network access, on
purpose). Get `anonrouter-dcap-verifier` either as the checksummed `linux/amd64`
[release asset](https://github.com/anonrouter/anonrouter-sdk/releases) or, better,
by building the same source yourself with `scripts/build-dcap-verifier.sh
--reproduce` and comparing digests. Put it on PATH or name it in
`ANONROUTER_DCAP_VERIFIER_BIN`, and hop 1 can reach `hardware_verified`:

```ts
import { createAnonRouterDcapVerifier, describeDcapInstallation } from "@anonrouter/confidential/dcap";

describeDcapInstallation();   // is one installed? which one? what is its digest?

const verdict = await client.verifyRoute({
  model, provider,
  gateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
```

The adapter fails closed on every path: a missing engine, a digest that does not
match `expectedBinarySha256`, a timeout, a crash, non-JSON output, collateral it
could not acquire, or a verdict whose measured report disagrees with the quote the
SDK parsed. Without an engine the ceiling is `cryptographically_checked` and a
policy demanding hardware verification fails closed. It never silently downgrades.

Hop 2 is unaffected and still caps at `provider-attested`: several provider routes
run GPU enclaves whose NVIDIA attestation chain is not available to verify, and
chaining only the CPU quote would claim more than was checked.

## The two hops

A request travels through two parties, and verifying one tells you nothing about
the other:

| | Question it answers | How to verify |
| --- | --- | --- |
| **Hop 1** AnonRouter's own routing plane | Is the data plane I am connected to the exact reviewed build, running inside an Intel TDX confidential VM, bound to my nonce and my origin? | `verifyGateway()` |
| **Hop 2** the downstream provider route | Did the model provider terminate my request inside a verified enclave running measurements I pinned? | `verifyAttestation()` |

A verified hop 2 says nothing about who routed the request. A verified hop 1 says
nothing about where inference ran. `verifyRoute()` establishes both, cross-binds
them to the route you asked for, and reports them separately:

```ts
const verdict = await client.verifyRoute({
  model: "z-ai/glm-5.2",
  provider: "venice",
  gateway: true            // omit to skip hop 1 entirely
});

verdict.overallState;                          // the weakest hop you ASKED about
verdict.gateway.requested;                     // whether hop 1 was in scope at all
verdict.gateway.state;                         // hardware_verified | ... | unavailable
verdict.gateway.failedChecks;                  // the exact required checks that failed
verdict.bindingMismatches;                     // the route you asked for vs what was served
verdict.contentVisibleToAnonRouter;            // true on a tee route, false on e2ee
```

Gate with `atLeast()` rather than comparing strings: it is the one place the
ordering lives, so a threshold keeps meaning the same thing if a state is later
inserted into the scale.

`overallState` only ever covers the hops you asked for, which is why
`gateway.requested` sits beside it. A trusted verdict with
`gateway.requested: false` establishes the provider enclave and makes no claim
about the router. And any entry in `bindingMismatches` forces the whole verdict
untrusted however strong the individual hops were, because two honestly-attested
parties on the wrong route is still the wrong route.

`verify()` returns the earlier report shape and is still supported; prefer
`verifyRoute()`.

To refuse to send anything unless AnonRouter's own plane attests, gate `chat()`.
The check runs before the first authenticated call, so a failure means no ticket
was spent and no plaintext went near the wire:

```ts
await client.chat({ /* ... */, requireGateway: true });
```

### Pinning hop 1

The policy a gateway is held to must never come from that gateway: a server that
could hand you the list of builds you accept could always name itself. So the pins
ship inside this package, and an origin with no pin fails closed rather than
falling back to whatever the server claims.

```ts
import { loadGatewayPolicy } from "@anonrouter/confidential";

await client.verifyGateway({ policy: loadGatewayPolicy(myReviewedPolicy) });
```

Two things to know about the pin this package ships today:

- It is marked `published` from the independently retained production release
  manifest. A different app id, compose hash or platform measurement fails
  closed until a newly reviewed policy ships.
- It sets `requireHardwareVerified`, and this package bundles no engine. So
  `verifyGateway()` fails closed with reason `quote_signature_chain` until you
  install the separate reproducible engine (see above). That is the honest answer,
  not a bug: without chaining
  the quote's signature to Intel's roots, nobody has checked that the quote came
  from real silicon.

## What "confidential" means here, honestly

- **Your plaintext does not reach ordinary AnonRouter infrastructure.** On the
  production confidential origin the relay runs inside an attested Intel TDX CVM
  and terminates TLS *in-enclave*: the shipped policy makes
  `transport_terminates_in_tee` and `tls_certificate_bound_to_quote` required
  checks, so the attested TD provably holds the key for the connection carrying
  your request. No operator can read it off a running host.
- **A TEE route still asks you to trust our reviewed build.** Inside the enclave,
  the relay handles your plaintext to route and meter it. What stops that being a
  matter of faith is that a build changed to exfiltrate it would change the
  measurements, so hop 1 stops verifying — cheating is *detectable*, provided you
  actually check.
- **E2EE removes us from the trust set entirely.** On `near-ai`, `venice` and
  `chutes` this package encrypts to a key bound to the *provider's* attested
  enclave, so the relay holds ciphertext whatever code it happens to be running.
  That is the difference `contentVisibleToAnonRouter` marks — which routes require
  trusting our build, not which routes leak plaintext to normal servers.
- **The SDK never inflates its verdict.** It reports `provider-attested` for
  `near-ai` / `venice` / `chutes` and `sdk-verified` for `tinfoil`. It never emits
  `hardware-verified` on its own: the DCAP / NRAS chain to the silicon vendor
  roots is deliberately not wired here. Hop 1 will report `hardware-verified`, but
  only when you supply a `chainVerifier` and it actually passes.
- **Attestation is not a promise about behavior.** Both hops prove which measured
  code is running. Neither proves that code behaves well; that is what reviewing
  the source behind a pinned compose hash is for.

See the [repository README](https://github.com/anonrouter/anonrouter-sdk#readme)
for the full trust-boundary discussion and the reviewed measurement pins.

## License

Apache-2.0. See `LICENSE`.
