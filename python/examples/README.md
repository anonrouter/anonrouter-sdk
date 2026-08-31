# Runnable examples

Run them from `python/` after `pip install -e ".[dev,mlkem]"`. They are type-checked
by `mypy`, because an example is documentation people copy and a rotted one should
fail CI rather than fail a reader.

Each has a JavaScript twin under `js/confidential/examples/` that prints the same
things in the same order, so the two SDKs can be compared side by side.

## 1. Verify both hops and read the verdict (real gateway, your key, NOT billable)

```bash
ANONROUTER_API_KEY=ar_... python examples/verify_route.py
```

Runs `verify_route()` and prints what each hop established, what it did not, and
why, then exits nonzero if the route did not reach the threshold. Attestation
only, so it spends nothing.

Env: `ANONROUTER_BASE_URL` (default `https://api.private.anonrouter.ai`),
`ANONROUTER_CONTROL_URL` (default `https://api.anonrouter.ai`),
`ANONROUTER_MODEL`, `ANONROUTER_PROVIDER`.

## 2. Verify, then call (real gateway, your key, BILLABLE)

```bash
ANONROUTER_API_KEY=ar_... python examples/verify_then_call.py
```

The shape most applications want: gate before sending, re-verify hop 1 at send
time with a fresh nonce, and say out loud what the verdict did not cover. Supplies
the DCAP chain verifier unconditionally, so it reaches `hardware_verified` where
an engine is installed and fails the chain check rather than downgrading where one
is not. Makes one small real inference call.

Env: everything from example 1, plus `ANONROUTER_REQUIRE` (default
`cryptographically_checked`; try `hardware_verified` with an engine installed),
`PROMPT`, `MAX_TOKENS`.

## 3. Image and speech over the two-origin split (real gateway, your key, BILLABLE)

```bash
ANONROUTER_API_KEY=ar_... python examples/media.py
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
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.private.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://api.anonrouter.ai \
  pytest tests/test_live_media.py
```

Env: `ANONROUTER_IMAGE_MODEL` (default `venice/flux-dev`),
`ANONROUTER_SPEECH_MODEL` (default `venice/tts-kokoro`),
`ANONROUTER_SPEECH_VOICE`, `ANONROUTER_BASE_URL`, `ANONROUTER_CONTROL_URL`.

## Notes

- The API key needs the `inference` scope. It is sent only on the authenticated,
  content-free control requests, never to the relay.
- Gateway evidence, provider evidence and encrypted inference stay on
  `ANONROUTER_BASE_URL`; `ANONROUTER_CONTROL_URL` is used only to mint tickets
  and read content-free catalog metadata.
- To check a deployment without any key at all, use the command instead:
  `anonrouter-verify gateway --origin https://your-cvm.example --dcap`.
  Hop 1 is credential-free by design, because a client verifies the plane before
  it trusts the endpoint with anything.
