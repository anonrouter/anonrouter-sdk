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

## What "confidential" means here, honestly

- **TEE is not content-private from AnonRouter.** A TEE proves which code runs in
  the enclave and protects content from the infrastructure host, but AnonRouter's
  gateway still sees the plaintext to route and meter the request.
- **Only E2EE hides content from AnonRouter.** On the E2EE providers (`near-ai`,
  `venice`, `chutes`) this package encrypts your request to a key bound to the
  attested enclave and relays only ciphertext.
- **The SDK never inflates its verdict.** It reports `provider-attested` for
  `near-ai` / `venice` / `chutes` and `sdk-verified` for `tinfoil`. It never emits
  `hardware-verified`: the DCAP / NRAS chain to the silicon vendor roots is
  deliberately not wired here.

See the [repository README](https://github.com/anonrouter/anonrouter-sdk#readme)
for the full trust-boundary discussion and the reviewed measurement pins.

## License

Apache-2.0. See `LICENSE`.
