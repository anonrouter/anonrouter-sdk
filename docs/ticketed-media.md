# Ticketed media: images and speech

`client.images.generate(...)` and `client.audio.speech.create(...)` generate an
image or synthesize speech across AnonRouter's two-origin privacy split, in both
JavaScript and Python.

This document is the contract. It says what each host learns, why a stock OpenAI
client cannot do this, what is bound into the ticket, and what the SDK refuses.

## The shape of one call

A media call is two HTTP requests to two different hosts, and the split is the
product:

```
  YOU ──API key, model, size/voice, character COUNT──▶  control.anonrouter.ai
                                                        (control origin)
       ◀──────── single-use ticket, 30s ────────────────┘

  YOU ──ticket, prompt or text──────────────────────▶  api.anonrouter.ai
                                                        (confidential origin)
       ◀──────── image bytes / audio bytes ────────────┘
```

| | control origin | confidential inference origin |
| --- | --- | --- |
| Learns your account | **yes** — the API key authenticates here | no |
| Learns the prompt or text | **no** | **yes** |
| Learns the priced shape | model, image size/format, speech character count, voice | the same, re-derived from the body |
| Credential it accepts | `Authorization: Bearer <key>` | the single-use ticket, and nothing else |
| What it is | the public API, accounts, catalog, billing | an Intel TDX confidential VM |

Neither host holds both halves. The control plane can say "this account paid for
one 1024x1024 image" and cannot say what was in it. The confidential plane holds
the prompt and cannot say whose it was.

### This is not end-to-end encryption, and is not claimed to be

These methods live on the same client as `chat()`, so it is worth being exact
about how they differ.

`chat()` on an E2EE provider encrypts in your process: AnonRouter's relay
receives **ciphertext** and could not read your prompt if it wanted to.

Ticketed media does **not** do that. The prompt reaches the confidential origin
as **plaintext**. What protects it is:

1. the **origin split** — the host that holds the prompt never holds your account
   credential, so it cannot attribute the prompt to you; and
2. the **enclave** — that host is an Intel TDX confidential VM whose build you can
   verify yourself with `verifyGateway()` / `verify_gateway()` before you send
   anything, against the same origin the content goes to.

That is a real and strong property, and it is a weaker one than E2EE chat. The
difference is what it would take for AnonRouter to read a media prompt: shipping a
different build into the CVM. That is not undetectable — the measurements would
change and `verifyGateway()` would stop passing — but it is possible, whereas on
an E2EE route the relay holds ciphertext no matter what code it runs. If your
threat model requires that AnonRouter cannot read the content **even if we shipped
code to try**, rather than that we would be caught, media does not meet it today.

Verify hop 1 first and decide with the verdict in hand:

```ts
const verdict = await client.verifyGateway({ chainVerifier: createAnonRouterDcapVerifier() });
// then, on the SAME origin, with the plane established:
const image = await client.images.generate({ model, prompt });
```

## The official OpenAI SDK cannot do this

This is the reason these methods exist rather than a base-URL swap.

An OpenAI client is built around **one base URL and one credential**. Every
request it makes carries the API key to the host it is configured with. To run
the exchange above it would have to:

1. send a content-free request to host A with the key,
2. read a ticket out of that response,
3. send the content to **host B** with the ticket and *without* the key,
4. bind and re-check the ticket's facts between the two.

There is no configuration of the standard OpenAI SDK — Python or Node — that
performs this two-origin exchange. Pointing it at `api.anonrouter.ai` selects the
single-origin compatibility surface inside the CVM: convenient and compatible,
but the same in-CVM broker receives both the API key and content. The methods
documented here instead perform the unlinkable ticket exchange automatically.

### The compatibility broker is a different, lower-privacy mode

AnonRouter also offers an OpenAI-compatibility broker, where one endpoint accepts
an ordinary OpenAI-shaped request and performs the mint internally. It is a real
option and it is not what these methods use.

The difference is not cosmetic: in broker mode a single AnonRouter-operated
service receives your API key **and** your prompt in the same request, and does
the split on your behalf on the other side of that boundary. You are trusting the
broker not to correlate them. In the two-origin exchange the split happens *in
your process*, before anything leaves it, so no AnonRouter component is ever in a
position to correlate them.

**This SDK never selects broker mode implicitly.** There is no fallback to it, no
environment variable that enables it, and no error path that quietly retries
through it. If a call cannot be made privately it fails.

## Compatibility matrix

What an OpenAI-shaped call maps to, and what is refused rather than dropped.

### `client.images.generate(...)`

| Parameter | Supported | Behaviour |
| --- | --- | --- |
| `model` | yes | required; bound into the ticket |
| `prompt` | yes | required; **sent only to the confidential origin**; max 10,000 chars |
| `size` | yes | `"WIDTHxHEIGHT"`, 128–2048 per side, default `1024x1024`; bound into the ticket |
| `response_format` | `b64_json` only | any other value is **refused**, not coerced |
| `n` | `1` only | `n: 1` is accepted; any other value is **refused** — AnonRouter prices one image per ticket, so silently returning one would charge for one while you believed you asked for four |
| `quality`, `style`, `user` | no | **refused** as unknown keys; the server schema is strict and accepting them would produce a different image than you asked for |

Returns `{ created, model, data: [{ b64_json, mime_type, bytes }], ... }` plus
response metadata (below).

### `client.audio.speech.create(...)`

| Parameter | Supported | Behaviour |
| --- | --- | --- |
| `model` | yes | required; bound into the ticket |
| `input` | yes | required; **sent only to the confidential origin**; max 20,000 chars |
| `voice` | yes | optional; bound into the ticket; omitting it binds "no voice", which is a distinct bound value |
| `response_format` | `mp3` only | any other value is **refused**, not coerced |
| `speed` | `1` only | **refused** otherwise — playback rate is not part of the authorized work, so accepting and dropping it would return audio at a speed you did not ask for |

Returns `{ audio, content_type, ... }`. `audio` is the complete buffer: this
endpoint returns one response body, not a stream, and the SDK does not pretend
otherwise. Python adds `result.write_to(path)`.

### Response metadata, on both

Kept because it is how you reconcile a generation against your bill:

| Field | Source |
| --- | --- |
| `selected_model` | `x-anonrouter-selected-model` — the exact `provider/model` that ran |
| `routing` | `x-anonrouter-routing` |
| `request_id` | the gateway request id, when reported |
| `rate_limit` | the `x-ratelimit-*` family |
| `provider_blurred` (image) | `x-anonrouter-provider-blurred` |
| `provider_content_violation` (image) | `x-anonrouter-provider-content-violation` |

## What the ticket binds, and what the SDK checks

The relay independently re-derives every bound fact from the body you send and
answers **409** on any drift. The SDK checks the mint's echo *first*, so a
mismatch fails on the content-free half of the exchange and **the prompt is never
sent at all**.

| Operation | Bound facts | Relay's error on drift |
| --- | --- | --- |
| image | `operation`, `model`, width, height, `response_format` | `ticket_operation_mismatch`, `ticket_model_mismatch`, `ticket_size_mismatch`, `ticket_format_mismatch` |
| speech | `operation`, `model`, exact input character count, `voice`, `response_format` | as above plus `ticket_input_length_mismatch`, `ticket_voice_mismatch` |

### The character count is UTF-16 code units

Speech is priced per character, so the ticket binds the **exact** count and the
relay rejects a body that differs by one.

AnonRouter runs on Node, where `input.length` counts UTF-16 code units. Python's
`len()` counts code points. They disagree on every emoji and every astral-plane
character: `"Hi 😀"` is **4** to `len()` and **5** to the server.

The Python SDK therefore counts UTF-16 code units (`utf16_length`), not `len()`.
A client that used `len()` would mint a ticket bound to the wrong number and get
a 409 on exactly the inputs containing emoji. Both SDKs export the counter, and
`shared/vectors/media-contract.json` pins the case in both suites.

## Configuration

```ts
// JavaScript — production defaults, so this is the whole configuration.
const client = createClient({ apiKey: process.env.ANONROUTER_API_KEY! });
```

```python
# Python — the same defaults.
client = create_client(api_key=os.environ["ANONROUTER_API_KEY"])
```

| Option (JS / Python) | Default |
| --- | --- |
| `inferenceBaseUrl` / `inference_base_url` (alias: `baseUrl` / `base_url`) | `https://api.anonrouter.ai` |
| `controlBaseUrl` / `control_base_url` | `https://control.anonrouter.ai` |

Two rules, both fail-closed:

- **Media requires two distinct origins.** If the control and inference origins
  are the same host, media is refused. One host would receive the API key and the
  prompt together, which is the exact linkage the ticket exists to prevent. That
  is not a degraded mode worth supporting quietly; it is the absence of the
  feature. (Verification and E2EE chat are unaffected — in E2EE chat the relay
  receives ciphertext, so a single origin still never holds readable content.)
- **`baseUrl` and `inferenceBaseUrl` naming different origins is refused**, not
  resolved by precedence. The ambiguity is about where prompts go.

The one documented exception is the **loopback local-test override**: with
`allowInsecureHttp` / `allow_insecure_http` set *and* a loopback host, a single
origin is permitted, because a developer running both roles on one machine has no
privacy boundary to collapse. It cannot be reached for a remote host, and it is
the same escape hatch the package already documents for plaintext `http://`.

## Errors

Typed, with a machine-readable `code` and redacted diagnostics. The distinction
that matters is whether money moved.

| Code | Meaning | Was anything charged? |
| --- | --- | --- |
| `unsupported_request` | refused locally, before any network call | no |
| `media_ticket_failed` | the control origin would not mint | no |
| `ticket_binding_mismatch` | the ticket bound facts we did not request — **content was not sent** | no |
| `ticket_rejected` | expired, already spent, or drifted (401 `invalid_ticket` / 409) | no |
| `relay_refused` | refused outright: no ticket, `media_disabled`, quota, 4xx | no |
| `provider_failed` | reached a provider and failed there (5xx) | **possibly** |
| `response_invalid` | the response was not well-formed media | the generation happened |
| `transport_failed` | the connection failed mid-request | **unknown** |
| `cancelled` / `timeout` | your abort signal, or a deadline | **unknown** |

Both `MediaError` types subclass the package's `ConfidentialError`, so an
existing `catch`/`except ConfidentialError` keeps catching everything.

### No automatic retry

**A failed media POST is never retried.** A generation is billed on the provider
attempt, so a transparently retried POST is a second charge for a caller who made
one call. This includes 500, 502, 503, 429, 408 and transport failures. Tickets
are single-use, so a retry would also fail with `invalid_ticket` anyway — but the
rule is enforced regardless of that, and pinned by a test that counts POSTs.

### Nothing sensitive in an error

Error messages and diagnostics never contain the prompt, the input text, the API
key, or the ticket. Diagnostics carry the origin, path, status, the gateway's
machine-readable error `type`, the request id, and the request headers **with
every credential value replaced by `<redacted>`** — names preserved, values gone.
An error body that quotes your prompt back is discarded rather than passed
through. `redactHeaders` / `redact_headers` is exported so the same rule applies
to anything you log yourself.

## What is verified, and what is not

Verified offline, in both languages, on every CI run:

- the exact two request shapes, from `shared/vectors/media-contract.json`
- planted negatives: prompt reaching control, key reaching the relay, ticket
  drift, ticket reuse, a retried POST, malformed media accepted
- a two-origin end-to-end over real loopback sockets, where the mock control
  server *fails the mint* if it is ever shown content and the mock relay *fails
  the request* if it is ever shown a credential

Verified live, credential-free, with no spend (`ANONROUTER_LIVE_GATEWAY_ORIGIN` /
`ANONROUTER_LIVE_PUBLIC_ORIGIN`):

- the confidential origin serves both media routes and answers **401
  `ticket_required`** without a ticket, and does not serve the mint (**404**)
- the control origin serves **no** media content (**503 `media_disabled`**) and
  does serve the mint, refusing an unauthenticated call

**Not established:** that a generation succeeds for a given account and model.
That needs a real inference-scoped API key and a callable model, and it spends
money. No test in this repository performs a paid generation.
