# Verifiable end-to-end examples

Three runnable scripts that prove `@anonrouter/confidential` works end to end. Run
them from `js/confidential/` after `npm install`.

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

Env: `ANONROUTER_BASE_URL` (default `https://api.anonrouter.ai`), `TEE_MODEL`
(default `openai/gpt-oss-120b`), `TEE_PROVIDER` (default `tinfoil`; also try
`near-ai`, `venice`, `chutes`).

## 3. Full E2EE chat (real gateway, your key, BILLABLE)
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

## Notes
- `ANONROUTER_BASE_URL` is the AnonRouter API origin. It defaults to
  `https://api.anonrouter.ai`; point it at `http://127.0.0.1:3000` for a local
  dev backend.
- The API key needs the `inference` scope. It is sent only on the authenticated,
  content-free control requests, never to the relay.
- These examples import from `../src` so they run without a build step. A real
  external app installs the package and does
  `import { createClient } from "@anonrouter/confidential"`.
