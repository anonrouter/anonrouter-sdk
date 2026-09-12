# @anonrouter/client

A thin, dependency-free JavaScript/TypeScript client for AnonRouter's public API.
It speaks the OpenAI-style chat surface over AnonRouter's two-request ticketed flow
and targets the plaintext, TEE, and private routes.

Part of the [AnonRouter SDK monorepo](https://github.com/anonrouter/anonrouter-sdk).

> This is **not** the confidential client. It sends your prompt as plaintext, so
> AnonRouter's relay software handles it to route and meter the request. On the
> production confidential origin that relay runs inside an attested Intel TDX CVM,
> so the plaintext does not reach ordinary AnonRouter infrastructure — but this
> package neither verifies that nor encrypts anything, so nothing here proves it
> to you. To check the claim rather than take it, or to keep content opaque to
> AnonRouter's build entirely, use
> [`@anonrouter/confidential`](https://github.com/anonrouter/anonrouter-sdk/tree/main/js/confidential).

The one thing this client enforces for you: the stable API key is sent only on the
control-plane ticket request, never on the request that carries content. Content is
presented to the relay with a single-use ticket and no account credential attached.

## Install

Install from npm:

```bash
npm install @anonrouter/client
```

Before registry propagation, build from the repository:

```bash
git clone https://github.com/anonrouter/anonrouter-sdk
cd anonrouter-sdk/js && npm ci && npm run build
```

## Quickstart

```ts
import { createClient } from "@anonrouter/client";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  apiKey: process.env.ANONROUTER_API_KEY!
});

const models = await client.models();

// Two-request ticketed flow. The API key authorizes the ticket; only the
// single-use ticket accompanies the content. Content on this route is visible to
// the gateway: use @anonrouter/confidential when it must not be.
const completion = await client.chat({
  model: "openai/gpt-oss-120b",
  messages: [{ role: "user", content: "Hello." }]
});
```

## License

Apache-2.0. See `LICENSE`.
