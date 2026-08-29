# @anonrouter/client

A thin, dependency-free JavaScript/TypeScript client for AnonRouter's public API.
It speaks the OpenAI-style chat surface over AnonRouter's two-request ticketed flow
and targets the plaintext, TEE, and private routes.

Part of the [AnonRouter SDK monorepo](https://github.com/anonrouter/anonrouter-sdk).

> This is **not** the confidential client. On these routes AnonRouter's gateway can
> still see request content (a TEE protects content from the host, not from the
> gateway). For content AnonRouter must never see, use
> [`@anonrouter/confidential`](https://www.npmjs.com/package/@anonrouter/confidential),
> which end-to-end-encrypts to independently attested keys.

The one thing this client enforces for you: the stable API key is sent only on the
control-plane ticket request, never on the request that carries content. Content is
presented to the relay with a single-use ticket and no account credential attached.

## Install

```bash
npm install @anonrouter/client
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
