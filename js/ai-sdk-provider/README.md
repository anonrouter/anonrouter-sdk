# AnonRouter for the Vercel AI SDK

Use AnonRouter with Vercel AI SDK 7 on Node.js 22 or later. The provider supports
chat, streaming, tool calls, and text embeddings. Keep `ANONROUTER_API_KEY`
on your server.

## Install

```sh
npm install ai@7 @anonrouter/ai-sdk-provider
```

To build the installable package from a checkout, run these commands from the
repository root. Install the resulting tarball alongside `ai@7` in your app.

```sh
cd js
npm ci
npm run build -w @anonrouter/ai-sdk-provider
npm pack -w @anonrouter/ai-sdk-provider
```

## Generate text

```ts
import { anonrouter } from '@anonrouter/ai-sdk-provider';
import { generateText } from 'ai';

const result = await generateText({
  model: anonrouter('deepseek/deepseek-v3.2'),
  prompt: 'Explain binary search in two sentences.',
  maxOutputTokens: 256,
  maxRetries: 0,
});

const selectedModel = result.providerMetadata?.anonrouter?.selectedModel;
```

Use model IDs from the [AnonRouter catalog](https://anonrouter.ai/models). The
provider also accepts router IDs such as `/auto` and `anonrouter/free`. Free
routing requires account opt-in. See [routing](https://docs.anonrouter.ai/provider-routing)
and [free models](https://docs.anonrouter.ai/free-models).

Set `maxRetries: 0` on AI SDK calls. A connection can drop after a generation
has been charged. Repeating the call can create a second charge.

## Stream and call tools

```ts
import { anonrouter } from '@anonrouter/ai-sdk-provider';
import { isStepCount, streamText, tool } from 'ai';
import { z } from 'zod';

const result = streamText({
  model: anonrouter.chat('deepseek/deepseek-v3.2'),
  prompt: 'Use the conversion tool to convert 21 Celsius to Fahrenheit.',
  maxOutputTokens: 512,
  maxRetries: 0,
  stopWhen: isStepCount(2),
  tools: {
    celsiusToFahrenheit: tool({
      description: 'Convert a temperature from Celsius to Fahrenheit.',
      inputSchema: z.object({ celsius: z.number().min(-273.15).max(10000) }),
      execute: async ({ celsius }) => ({ fahrenheit: celsius * 9 / 5 + 32 }),
    }),
  },
});

for await (const part of result.fullStream) {
  if (part.type === 'text-delta') process.stdout.write(part.text);
  if (part.type === 'error') throw part.error;
}
```

Install `zod@4` for this example. Your application executes function tools.
Each model step makes its own request and uses your account's available funding.

## Embeddings

```ts
import { anonrouter } from '@anonrouter/ai-sdk-provider';
import { embed } from 'ai';

const { embedding } = await embed({
  model: anonrouter.embedding('qwen/qwen3-embedding-0.6b'),
  value: 'The Pacific Ocean is the largest ocean on Earth.',
  maxRetries: 0,
});
```

In private mode, you can also pass a `provider` setting to select an embedding
provider.

## Route and reasoning options

Pass settings when you select the model, or pass them for a single call under
`providerOptions.anonrouter`.

```ts
import { anonrouter } from '@anonrouter/ai-sdk-provider';
import { generateText } from 'ai';

const result = await generateText({
  model: anonrouter('deepseek/deepseek-v3.2'),
  prompt: 'Compare breadth-first search and depth-first search.',
  maxOutputTokens: 1024,
  maxRetries: 0,
  providerOptions: {
    anonrouter: {
      provider: { minimum_privacy: 'tee', allow_fallbacks: false },
    },
  },
});
```

The `provider` field accepts an exact provider ID or a
[provider policy](https://docs.anonrouter.ai/provider-routing).
Use `routing` with an eligible automatic router, or `reasoning_effort` and
`reasoning` on a model that supports those controls. The
[reasoning guide](https://docs.anonrouter.ai/reasoning) lists the accepted values.
`venice_parameters` carries Venice-specific options.

When the API reports them, `providerMetadata.anonrouter` exposes
`selectedModel`, `provider`, `routing`, `providerAttempts`, `providerFallback`,
and `privacyClass`. These describe the API's route selection. It also exposes
`cost` for the amount charged in USD and `webSearch` for the managed search
summary, when the response includes them.

### Managed web search

Set `webSearch: true` for the default allowance, or configure `maxUses`
(1–3), `maxResults` (1–8), and `maxTotalResults` (1–15).

```ts
import { anonrouter } from '@anonrouter/ai-sdk-provider';
import { generateText } from 'ai';

const result = await generateText({
  model: anonrouter('deepseek/deepseek-v3.2', {
    provider: { only: ['venice', 'deepinfra'], minimum_privacy: 'private' },
    webSearch: { maxUses: 1, maxResults: 3 },
  }),
  prompt: 'Find and summarize one recent change in the Node.js release schedule.',
  maxOutputTokens: 1024,
  maxRetries: 0,
});
```

Managed search requires an explicit, eligible model ID and charges for
successful searches in addition to model usage. See the [web search guide](https://docs.anonrouter.ai/web-search)
for route restrictions, pricing, and response details.

## Provider settings

```ts
import { createAnonRouter } from '@anonrouter/ai-sdk-provider';

const anonrouter = createAnonRouter({
  apiKey: process.env.ANONROUTER_API_KEY,
  mode: 'private',
  baseURL: 'https://api.anonrouter.ai/v1',
  controlBaseURL: 'https://control.anonrouter.ai/v1',
});
```

The factory also accepts `headers`, `fetch`, `appName`, and `appUrl`. Only set
app attribution if you want to identify the calling application. Use a trusted
custom transport and origins when overriding defaults.

`anonrouter(modelId)`, `anonrouter.chat(modelId)`,
`anonrouter.chatModel(modelId)`, and `anonrouter.languageModel(modelId)`
all select a chat model. `embedding`, `embeddingModel`, and
`textEmbeddingModel` all select an embedding model.

### Privacy modes

- **Private**, the default, exchanges the API key for a single-use ticket on
  the control origin. The content origin receives your request with the ticket.
- **Compatibility**, selected with `mode: 'compatibility'`, uses an inference
  key with OpenAI-compatible access. The compatibility broker receives the
  API-key identity and content together in memory. See the
  [compatibility guide](https://docs.anonrouter.ai/compatibility).

For cross-model fallback, use compatibility mode and set `models` to an
ordered list of up to four concrete fallback model IDs. AnonRouter tries the
primary model first. Provider fallback within the selected model is available
in both modes through the `provider` policy.

The private mode provides credential separation over HTTPS. For independent
attestation and end-to-end encryption, use
[`@anonrouter/confidential`](https://github.com/anonrouter/anonrouter-sdk/tree/main/js/confidential).
