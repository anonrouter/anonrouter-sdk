# Release readiness for 0.1.0

Recorded 2026-09-04 against the `v0.1.0` release candidate. Every number below
was produced by a run on that tree, not carried forward from an earlier one.

## Production binding

- inference, compatibility, and gateway attestation default to
  `https://api.anonrouter.ai`;
- identity, catalog, billing, and content-free ticket minting default to
  `https://control.anonrouter.ai`;
- `https://api.private.anonrouter.ai` remains an attested alias, not a customer
  configuration requirement;
- the published gateway policy is derived from retained release manifest
  SHA-256 `83205494da15f59b4b9a86ce3be77d331ef06d212ab9ed1a9cacfea1cdcbb730`,
  which binds reviewed source commit
  `696b8dde01ed3087611ba43c7572d50098360b98`;
- the policy pins the live app id, compose hash
  `c6f11cc5…`, release id `anonrouter-tee@xl-696b8dd`, key provider, OS image,
  MRCONFIGID, MRTD, RTMR0..2, private logs, digest-pinned images, in-TD TLS,
  fresh evidence, an `UpToDate` TCB, and hardware verification.

Every pinned field was re-observed on 2026-09-04 in two independent nonce-bound
quotes, one per origin, and the leaf key each quote names was separately observed
on the wire for that hostname.

**RTMR0 was not reproduced offline with `dstack-mr`.** It measures hardware
configuration and moves with the CVM's size, and the tooling to recompute it
outside the machine was not available. It rests on agreeing independent quotes
and the retained manifest. That is weaker than an offline recomputation and is
recorded rather than rounded up.

The manifest records **two** third-party source-to-image provenance gaps: the
base images of the in-CVM edge proxy and of the content-plane runtime. A third,
the in-CVM TLS terminator, was closed by rebuilding it from source. The remaining
two are explicit supply-chain limitations, not attestation bypasses.

## Verification gates

| Gate | Result |
| --- | --- |
| JavaScript offline suites | 450 confidential + 14 client passed; 39 live cases skipped |
| Python offline suite | 371 passed; 40 live cases skipped |
| JavaScript live suite with the DCAP engine | 489 confidential + 14 client passed, 0 skipped |
| Python live suite with the DCAP engine | 411 passed, 0 skipped |
| JavaScript types and builds | clean |
| Python mypy and ruff | clean |
| Shared pin parity | all six package copies byte-identical to `shared/` |
| CLI parity | 4/4 cases produced matching JavaScript/Python documents and exit codes |
| Artifact smoke installs | both npm tarballs, the wheel and the sdist installed and ran from empty environments; Twine metadata check passed |
| DCAP verifier reproducibility | two builds from clean in a digest-pinned container, byte-identical |

The live tests use fresh nonces and include adversarial changes to origin,
release, measurements, event log, report data, freshness, transport, TLS key,
debug state, key provider, quote signature, and accepted TCB status. A missing or
wrong check is required to fail at the check that covers it.

## What the shipped pin refuses

Run against live production on 2026-09-04, with the reproducible engine:

| Policy under test | Outcome |
| --- | --- |
| the shipped `published` pin | `hardware_verified`, TCB `UpToDate`, no failed or advisory checks |
| the superseded pin this release replaces | `untrusted` — `compose_hash_pinned`, `release_pinned`, `platform_measurements_pinned` |
| an origin the policy does not authorize | `untrusted` — `origin_pinned` |
| one character changed in the release id | `untrusted` — `release_pinned` |
| `UpToDate` removed from the accepted TCB list | `untrusted` — `quote_signature_chain`, `tcb_status_acceptable` |
| a 1 ms evidence age window | `untrusted` — `evidence_recent` |
| no DCAP engine at all | `untrusted` — `quote_signature_chain`; the CLI refuses `--require hardware_verified` without `--dcap` outright |

The second row is the one worth reading: the previous pin does not merely age
out, it actively refuses the running service. Publishing it would have shipped an
SDK that reports production as unverified.

## Live route matrix

Read from the authenticated live catalog, never from a written-down list.
**11 callable `tee`/`e2ee` routes across three providers**, all establishing both
hops:

| Provider | Class | Routes | Hop 1 | Hop 2 |
| --- | --- | --- | --- | --- |
| `chutes` | e2ee | 2 | `hardware_verified` | `cryptographically_checked` |
| `venice` | e2ee | 3 | `hardware_verified` | `cryptographically_checked` |
| `tinfoil` | tee | 6 (5 text, 1 embedding) | `hardware_verified` | `policy_matched` |

Two advisory gaps are reported rather than hidden. Tinfoil's evidence format
exposes no caller nonce, so `nonce_binding` is advisory there. Chutes' evidence
names no model, so `model_binding` is advisory there and the route model rests on
AnonRouter's own attested echo — a weaker statement than a provider enclave
naming its own weights.

17 of 17 live negative controls hold: five mint refusals (private route, provider
without a verifier, `/auto`, a provider that does not serve the model, an unknown
model), five redemption refusals (no ticket, stable key instead of a ticket, a
forged ticket, a replayed ticket, a malformed nonce, plus an expired one after
waiting out the TTL), and six client-side refusals this SDK makes even where the
service would not.

### Paid canaries

One minimal real request per route, capped at 16 output tokens, with the provider
pinned explicitly. Two completed and nine were refused `402 insufficient_balance`
at admission, before any provider was contacted:

- `tinfoil` / `nomic-ai/nomic-embed-text`: 1 vector, 768 dimensions, 3 prompt
  tokens, echoed model equal to the requested model;
- `venice` / `qwen/qwen-2.5-7b`: E2EE round trip, decrypted client-side, 2
  completion tokens.

No provider substitution, no `/auto` fallback, no stranded reservation: the
refusals are pre-admission and release nothing. Total spend was a few tokens,
far inside the USD 1 cap.

**The remaining nine are blocked on account credit, not on code.** The account
behind the API key used for this run cannot cover the admission reservation for a
16-token completion on the other nine routes. The minimum owner action is to add
credit to that account (or point the harness at a funded key); USD 1 covers the
entire matrix many times over, and the harness caps itself there.

## DCAP artifact

`anonrouter-dcap-verifier-linux-amd64`, built from
[`native/dcap-verifier`](../native/dcap-verifier) by
`scripts/build-dcap-verifier.sh --reproduce`:

- builder `rust:1.94.1-alpine3.22@sha256:797631f9efd6957d0013f200e410478c380907eee3b469c6f80d89022df28bc7`;
- target `x86_64-unknown-linux-musl`, static, 1,020,536 bytes;
- SHA-256 `0bc89698c5b905b8b5de5e3d252fab02558e3de5d951a1e21d18d4fab2753cb9`;
- two builds from clean produced byte-identical output, and the digest did not
  move when `SOURCE_DATE_EPOCH` changed.

Live verification on macOS used a native `aarch64-apple-darwin` build of the same
source (SHA-256 `ed3516d285ecc343f899cf0334e9920420a15766624b5d3e39427204b67275a9`),
because the published artifact is a Linux ELF. The SDK still checked real
production collateral and a live quote. **`linux/amd64` is the only target with a
published reproducible artifact and the only one this release claims.**

## Publication

The public source repository and the `v0.1.0` release exist and carry the
checksummed artifacts. Registry publication does not:

- both npm package names return 404 and no npm account or `anonrouter` org
  exists on this machine;
- the PyPI project returns 404 and no trusted publisher is configured.

The release workflow contains complete, switched-off npm and PyPI jobs that use
short-lived OIDC identities rather than stored tokens. They run only when the
repository variables `PUBLISH_NPM` / `PUBLISH_PYPI` are set to `true`, which is
an owner action taken once the registry accounts and their trusted publishers
exist. No token is stored anywhere to enable them.
