# Verifiable end-to-end examples

Runnable scripts that prove `@anonrouter/confidential` works end to end. Run them
from `js/confidential/` after `npm install`. They are type-checked by
`npm run typecheck`, because an example is documentation people copy and a rotted
one should fail CI rather than fail a reader.

## 1. Self-test (no key, no network, no spend)
```bash
npm run example:selftest
```
Runs the full flow (verify attestation + E2EE chat) against an in-process mock
gateway backed by mock enclaves that speak the real provider crypto. If this passes,
the client orchestration, the E2EE transports, and the verifier are wired correctly.
Deterministic. Safe to run anytime.

## 2. Verify a TEE / E2EE route (real gateway, your key, NOT billable)
```bash
ANONROUTER_API_KEY=ar_... npm run example:verify-tee
```
Independently verifies a route's enclave attestation against the real gateway,
running OUR verifier over the raw evidence (it does not just trust the gateway's
verdict). This is attestation only, so it does not spend anything.

Env: `ANONROUTER_BASE_URL` (default `https://api.anonrouter.ai`),
`ANONROUTER_CONTROL_URL` (default `https://control.anonrouter.ai`), `TEE_MODEL`
(default `openai/gpt-oss-120b`), `TEE_PROVIDER` (default `tinfoil`; also try
`near-ai`, `venice`, `chutes`).

## 3. Verify both hops and read the verdict (real gateway, your key, NOT billable)
```bash
ANONROUTER_API_KEY=ar_... npm run example:verify-route
```
Runs `verifyRoute()` and prints what each hop established, what it did not, and
why, then exits nonzero if the route did not reach the threshold. This is the
smallest complete picture of the contract.

Env: `ANONROUTER_BASE_URL`, `ANONROUTER_CONTROL_URL`, `ANONROUTER_MODEL`,
`ANONROUTER_PROVIDER`.

## 4. Verify, then call (real gateway, your key, BILLABLE)
```bash
ANONROUTER_API_KEY=ar_... npm run example:verify-then-call
```
The shape most applications want: gate before sending, re-verify hop 1 at send
time with a fresh nonce, and say out loud what the verdict did not cover. Supplies
the DCAP chain verifier unconditionally, so it reaches `hardware_verified` where
an engine is installed and fails the chain check rather than downgrading where one
is not.

Env: everything from example 3, plus `ANONROUTER_REQUIRE` (default
`cryptographically_checked`; try `hardware_verified` with an engine installed),
`PROMPT`, `MAX_TOKENS`.

## 5. Full E2EE chat (real gateway, your key, BILLABLE)
```bash
ANONROUTER_API_KEY=ar_... npm run example:chat-e2ee
```
Verifies the enclave, encrypts your prompt in-process, relays only ciphertext, and
decrypts the reply. It wraps `fetch` to PROVE the relay never received your prompt
in plaintext, then prints the decrypted answer. This makes a real, tiny billable
inference call.

Env: `E2EE_MODEL` (default `openai/gpt-oss-120b`), `E2EE_PROVIDER`
(default `near-ai`; E2EE only: `near-ai`, `venice`, `chutes`), `MAX_TOKENS`
(default 32), `PROMPT`, `ANONROUTER_BASE_URL`.

## 6. Image and speech over the two-origin split (real gateway, your key, BILLABLE)
```bash
ANONROUTER_API_KEY=ar_... npm run example:media
```
Generates an image and synthesizes speech, writing `anonrouter-image.png` and
`anonrouter-speech.mp3`. One call is two requests to two hosts: the API key mints
a content-free ticket at the control origin, then the prompt goes to the
confidential origin with only that ticket. The official OpenAI SDK cannot perform
this exchange. Makes two real, billable generations.

To check the same routes for FREE, with no key and no spend, run the live probes
instead -- they confirm both media routes answer `401 ticket_required` without a
ticket and that the control origin serves no media content at all:
```bash
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://control.anonrouter.ai \
  npx vitest run test/live-media.test.ts
```

Env: `ANONROUTER_IMAGE_MODEL` (default `alibaba/z-image-turbo`),
`ANONROUTER_SPEECH_MODEL` (default `venice/kokoro-text-to-speech`),
`ANONROUTER_SPEECH_VOICE`, `ANONROUTER_BASE_URL`, `ANONROUTER_CONTROL_URL`.

## Notes
- `ANONROUTER_BASE_URL` is the confidential inference origin and defaults to
  `https://api.anonrouter.ai`. `ANONROUTER_CONTROL_URL` is the
  content-free identity/billing origin and defaults to `https://control.anonrouter.ai`.
  Both may point at one loopback origin for a monolithic local deployment.
- The API key needs the `inference` scope. It is sent only on the authenticated,
  content-free control requests, never to the relay.
- These examples import from `../src` so they run without a build step. A real
  external app installs the package and does
  `import { createClient } from "@anonrouter/confidential"`.
