# Release readiness for 0.1.0

Recorded 2026-09-01 against `sdk-production-readiness` after the canonical API
hostname cutover.

## Production binding

- inference, compatibility, and gateway attestation default to
  `https://api.anonrouter.ai`;
- identity, catalog, billing, and content-free ticket minting default to
  `https://control.anonrouter.ai`;
- `https://api.private.anonrouter.ai` remains an attested alias, not a customer
  configuration requirement;
- the published gateway policy is derived from retained release manifest
  SHA-256 `ebb976a12b274afc34fb31459578e3ef107764d697ef074d1a82b27d79b1707c`;
- the policy pins the live app id, compose hash, release id, key provider, OS
  image, MRCONFIGID, MRTD, RTMR0..2, private logs, digest-pinned images,
  in-TD TLS, fresh evidence, an `UpToDate` TCB, and hardware verification.

The manifest still records three third-party source-to-image provenance gaps.
They remain explicit supply-chain limitations rather than being rounded up to
verified.

## Verification gates

| Gate | Result |
| --- | --- |
| JavaScript offline suites | 403 confidential + 12 client passed; 39 live/platform cases skipped |
| Python offline suite | 317 passed; 41 live/platform cases skipped |
| JavaScript live suite with DCAP engine | 442 confidential + 12 client passed, 0 skipped |
| Python live suite with DCAP engine | 357 passed, 1 intentionally unavailable case skipped |
| JavaScript types and builds | clean |
| Python mypy and ruff | clean |
| Shared pin parity | all package copies byte-identical to `shared/` |
| CLI parity | 4/4 cases produced matching JavaScript/Python documents and exit codes |
| Artifact smoke installs | all npm tarballs, wheel, and sdist installed and ran from empty environments; Twine metadata check passed |

The live tests use fresh nonces and include adversarial changes to origin,
release, measurements, event log, report data, freshness, transport, TLS key,
debug state, key provider, quote signature, and accepted TCB status. A missing or
wrong check is required to fail at the check that covers it.

## Real route proof

Both language clients completed the full production route for provider `venice`
and model `openai/gpt-oss-20b`:

1. hop 1 reached `hardware_verified` under the shipped pin and the reproducible
   DCAP engine;
2. hop 2 independently recomputed the provider evidence and reached
   `cryptographically_checked`;
3. the API key went only to `control.anonrouter.ai`;
4. encrypted inference went to `api.anonrouter.ai` with a single-use ticket;
5. both clients decrypted the expected bounded response.

One first provider attempt returned the documented E2EE no-fallback refusal. A
fresh attestation and ticket succeeded; the SDK did not switch providers or fall
back to plaintext.

## Real media proof

The JavaScript client completed both ticketed media calls against production:

- image: `alibaba/z-image-turbo`, 224,834-byte WebP;
- speech: `venice/kokoro-text-to-speech`, 14,157-byte MPEG audio.

The account credential and content were sent to different origins. The control
origin saw the content-free priced shape; the CVM received the prompt or speech
text with only a single-use ticket. The previous example model ids had left the
live catalog and were replaced with models confirmed in the current catalog.

## DCAP artifact

The release artifact `anonrouter-dcap-verifier-linux-amd64` was built twice in a
digest-pinned Linux/amd64 environment and the outputs were byte-identical. Its
SHA-256 is:

`c7d7bc21bf44a1a606e44832b6cbab1f4b74eade06743ee2324edbf396db8d67`

On macOS, the release validation ran that exact ELF in a local Linux container;
the SDK still checked real production collateral and the live quote. The first
published native artifact supports Linux/amd64. Other native targets must not be
claimed until reproducible artifacts for them exist.

## Remaining publication authority

The code and artifacts are release-ready, but publication requires owner access
to external registries:

- both npm package names currently return 404 and this machine is not logged in
  to npm;
- the PyPI project currently returns 404 and no upload token is configured;
- the documented public source repository currently returns 404.

Those are account/visibility decisions, not technical test failures. No package
or repository has been published implicitly.
