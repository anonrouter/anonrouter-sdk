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

# For the unpublished 0.1.3 candidate, build from its prepared checkout:
git clone https://github.com/anonrouter/anonrouter-sdk
cd anonrouter-sdk/js && npm ci && npm run build
```

The release tarball is also attached to the corresponding GitHub release. It is
built and installed into an empty environment before publication, so the exact
bytes npm carries are exercised rather than only the working tree.

Node 22 or newer. Four runtime dependencies, all `@noble` audited crypto
(`ciphers`, `curves`, `hashes`, `post-quantum`) and nothing else.

Optional dependency: install `tinfoil` to check a Tinfoil TEE route yourself with
`verifyTinfoilEnclave()`, which runs the provider's official verifier and then
pins its own connection to the enclave. That function is Node-only, for the same
reason the DCAP path is; see "Browser support" below.

**Browser support.** The default `@anonrouter/confidential` package works in
browsers and supports E2EE routes. Importing it never pulls in a Node builtin.
Full Intel TDX hardware verification is currently available in Node.js through
`@anonrouter/confidential/dcap`. Browsers cannot run the native verifier or
inspect the server's TLS certificate, so the SDK does not claim full gateway
hardware verification in a browser. The same limit applies to
`verifyTinfoilEnclave()`: pinning the enclave's serving key means reading a peer
certificate, which no browser exposes, so in a browser it fails closed with
`tinfoil_tls_observation_unsupported` rather than returning a verdict that
skipped the pin. Use the Node.js SDK or `anonrouter-verify` CLI when you need
that proof.

## GCP content-node verification

This checkout prepares 0.1.3; npm latest is 0.1.2 as checked 2026-10-14.
Build/install this candidate locally to use these APIs. Publication awaits the
owner's go.

GCP-native is the default qualified platform for `api.anonrouter.ai`.
The SDK fixes the owner root public keys and follows the independently signed
[release-v3 feed](https://anonrouter.ai/.well-known/anonrouter-content-release-v3.json).
It ships no GCP node image measurements; approved images need no SDK release.
Legacy Phala is available explicitly.

```typescript
import { verifyContentNode, createClient } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

// Native verifier on PATH or ANONROUTER_DCAP_VERIFIER_BIN. No API key or cost.
const result = await verifyContentNode();
console.log(result.policy.sequence, result.verdict.verificationLevel);

// Inference must retain its own verified connection.
const client = createClient({
  apiKey: process.env.ANONROUTER_API_KEY!,
  gatewayConnectionBinding: {
    mode: "required",
    verification: { chainVerifier: createAnonRouterDcapVerifier() }
  }
});
await client.verifyGateway(); // fresh read-only evidence, no credential sent
```

Hardware DCAP, `UpToDate` TCB, fresh nonce and retained-socket TLS binding stay
required. `gce_pzid` is optional: absence reports machine identity as
`unverified`, while malformed/mismatched presented identity fails. A future
signed `requireGcePzid: true` policy can require it. Browser hardware/socket
verification remains unavailable. See
[signed policy updates](../../docs/gateway-policy-updates.md) for roots,
rollback protection, cache limits and the Python support boundary.

## Quickstart

```ts
import { createClient, atLeast } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  controlBaseUrl: "https://control.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!,
  gatewayPolicyUpdates: true,
  gatewayConnectionBinding: {
    mode: "required",
    verification: { chainVerifier: createAnonRouterDcapVerifier() }
  }
});

// Verify BOTH hops, cross-bound to the route you asked for, and gate on it.
const verdict = await client.verifyRoute({
  model: "google/gemma-4-26b-a4b-uncensored",
  provider: "venice",
  gateway: true
});
if (!atLeast(verdict.overallState, "cryptographically_checked")) {
  throw new Error(`route not established: ${verdict.reason}`);
}

// End-to-end-encrypted chat: keys and nonce are fresh per call, and only
// ciphertext ever reaches AnonRouter's relay. Required connection binding obtains
// fresh gateway evidence for this operation and checks the attested TLS key
// before sending provider evidence or inference to the content origin.
const reply = await client.chat({
  model: "google/gemma-4-26b-a4b-uncensored",
  provider: "venice",
  messages: [{ role: "user", content: "Draft a private message." }],
  maxOutputTokens: 512,
  requireGateway: true
});
console.log(reply.content);
```

## Required gateway connection binding in Node

`gatewayConnectionBinding` is an opt-in Node mode. It verifies a fresh gateway
quote for each operation on a normally validated TLS connection, checks that
connection's key against the quote, and keeps the same connection for provider
evidence, encrypted chat, image prompts or speech text. Control requests use
the separate control origin. Approval and evidence expiry are checked before
tickets and immediately before content dispatch.

This mode requires a hardware chain verifier, HTTPS and distinct control/content
origins. It refuses custom `fetch`, browsers and per-call options that disable or
replace the required verification. `gateway: true` and `requireGateway: true`
retain the configured requirement. Streams keep their operation's checked
identity until they finish or are cancelled. An operation never reconnects to a
replacement gateway or retries inference. A final response that closes its
connection during draining is consumed through completion; an earlier close
refuses further use before content. Signed-policy refresh rechecks the original
quote and connection against the updated approved policy.

Before any HTTP bytes are sent, an initial connection reset or handshake timeout
may trigger one fresh preparation attempt. Failed local socket/request/DNS work
finishes before retry; the new attempt uses a fresh nonce and current policy.
Both attempts share one 180-second preparation/admission deadline beginning
before initial policy resolution. Certificate, quote, policy and verification
failures are refused, and inference is never retried.

With `gatewayConnectionBinding.mode: "required"`, `verifyGateway()`
uses the configured policy and native retained TLS connection, returns that
connection's independent verdict, and closes it when the operation finishes.
Only `{ signal }` is accepted per call in this mode: nonce, policy, verifier and
other replacements are refused before connecting. Use the configured bound
client methods for later operations; each establishes its own fresh connection.

`verifyGateway()` without required binding still does not bind a later generic
HTTP connection. The default transport, `@anonrouter/client` and external OpenAI
clients do not inherit this Node option. Python has a separate synchronous
binding option described in its [README](../../python/README.md).

Operational acceptance remains pending. Fresh quotes per operation can hit the
current service limit of 20 requests per client address per minute (240 aggregate).
The retained connection removes the A-quote/B-connect race during a DNS switch.
The current operation allows at most 180 seconds from initial preparation to paid
dispatch; approval or evidence expiry can shorten that. Deployment retirement
must preserve the old serving instance through routing convergence and that
admission window, then allow admitted streams to finish. Local TLS tests do not
establish the platform's routing bound, socket lifetime or native quote capacity.

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

The collateral cache shares only platform-wide Intel documents between nodes
with the same FMSPC. Each returned input gets the PCK chain from its own quote.
When preparing the native verifier, the adapter omits any supplied PCK-chain
override so the engine parses that chain directly from the current quote.
Signed TCB documents, revocation lists, freshness and quote signatures are still
checked by the same pinned engine. A malformed or mismatched quote fails closed.

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
  model: "google/gemma-4-26b-a4b-uncensored",
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

## How AnonRouter protects your requests

AnonRouter cannot read or log your prompts or responses. Content-bearing
requests go to `api.anonrouter.ai`, where TLS terminates inside an attested Intel
TDX enclave. Plaintext exists only inside the measured relay while the request
is routed and metered. The separate service at `control.anonrouter.ai` handles
authorization and billing metadata and does not receive request content.

On a TEE route, the measured relay processes plaintext inside the enclave. The
SDK verifies AnonRouter's relay against its published measurements. For Tinfoil's
upstream enclave, the official Tinfoil verifier validates the current release's
GitHub/Sigstore authority, AMD SEV-SNP evidence and live code measurement, and it
does not wait for AnonRouter to republish that release's fingerprint. The
attested TLS key is then bound to a real pinned connection, because the document
states that key twice from one report field and so cannot establish it alone. No
NVIDIA GPU evidence is verified on this route and nothing binds the model
weights. In Node.js, the DCAP verifier can also verify the Intel hardware chain.
If the deployed code or configuration of AnonRouter changes, its measurements
change and gateway verification fails until the new release is reviewed and
pinned.

On an E2EE route, the SDK encrypts content to a key bound to the destination
enclave's attestation. The AnonRouter relay receives only ciphertext and never
processes prompt or response plaintext.

The SDK reports only the verification it actually completes. Gateway
verification reaches `hardware_verified` only when the DCAP verifier validates
the quote against Intel's roots and every required policy check passes. Missing
or failed checks are never reported as successful.

Attestation identifies the exact code and configuration running inside the
enclave. The published source and pinned compose hash let you inspect what that
measured build contains.

See the [repository README](https://github.com/anonrouter/anonrouter-sdk#readme)
for the full trust-boundary discussion and the reviewed measurement pins.

## License

Apache-2.0. See `LICENSE`.
