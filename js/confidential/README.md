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
```

Optional peer dependency: install `tinfoil` to verify Tinfoil TEE routes via its
official verifier.

## Quickstart

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

## The two hops

A request travels through two parties, and verifying one tells you nothing about
the other:

| | Question it answers | How to verify |
| --- | --- | --- |
| **Hop 1** AnonRouter's own routing plane | Is the data plane I am connected to the exact reviewed build, running inside an Intel TDX confidential VM, bound to my nonce and my origin? | `verifyGateway()` |
| **Hop 2** the downstream provider route | Did the model provider terminate my request inside a verified enclave running measurements I pinned? | `verifyAttestation()` |

A verified hop 2 says nothing about who routed the request. A verified hop 1 says
nothing about where inference ran. `verify()` establishes both and reports them
separately:

```ts
const report = await client.verify({
  model: "openai/gpt-oss-120b",
  provider: "near-ai",
  gateway: true            // omit to skip hop 1 entirely
});

report.trusted;                              // every hop this call ASKED for verified
report.gateway.requested;                    // whether hop 1 was in scope at all
report.gateway.status;                       // ok | failed | unavailable | unpinned | not-requested
report.provider.verificationLevel;           // provider-attested | sdk-verified | ...
report.route.contentVisibleToAnonRouter;     // true on a tee route, false on e2ee
```

`trusted` only ever covers the hops you asked for, which is why `gateway.requested`
sits beside it. A report with `trusted: true` and `gateway.requested: false`
establishes the provider enclave and makes no claim about the router.

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

- It is marked `candidate`, because the confidential plane is pre-release and its
  measurements move on every release. Resolving it takes an explicit
  `allowCandidatePolicy: true`.
- It sets `requireHardwareVerified`, and this package ships **no DCAP engine**. So
  `verifyGateway()` against that origin fails closed with reason
  `quote_signature_chain` unless you supply your own `chainVerifier`. That is the
  honest answer, not a bug: without chaining the quote's signature to Intel's
  roots, nobody has checked that the quote came from real silicon.

## What "confidential" means here, honestly

- **TEE is not content-private from AnonRouter.** A TEE proves which code runs in
  the enclave and protects content from the infrastructure host, but AnonRouter's
  gateway still sees the plaintext to route and meter the request.
- **Only E2EE hides content from AnonRouter.** On the E2EE providers (`near-ai`,
  `venice`, `chutes`) this package encrypts your request to a key bound to the
  attested enclave and relays only ciphertext.
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
