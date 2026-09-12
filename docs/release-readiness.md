# Release readiness for 0.1.2

Recorded 2026-09-11 against the `v0.1.2` release candidate. Results below are
from this candidate unless a row is explicitly labeled as the last authenticated
production observation.

## Why this patch is required

`v0.1.1` shipped a correct AnonRouter hop-1 pin, but Tinfoil rotates its signed
router release more frequently than AnonRouter releases this SDK. Keeping a
second static list of Tinfoil release fingerprints caused valid Tinfoil routes
to report unverified until AnonRouter manually copied each new fingerprint.

`v0.1.2` replaces only that redundant list with a fixed provider-authority
policy: the official verifier, exact Tinfoil GitHub repository and tagged
Sigstore workflow, signed code/live-enclave equality, production endpoint, and
TLS key binding remain required. It does not loosen AnonRouter's hop-1 pins,
other providers' policies, or the inference protocol.

## Production binding

- inference, compatibility, and gateway attestation default to
  `https://api.anonrouter.ai`;
- identity, catalog, billing, and content-free ticket minting default to
  `https://control.anonrouter.ai`;
- `https://api.private.anonrouter.ai` remains an attested alias, not a customer
  configuration requirement;
- the published gateway policy is derived from retained release manifest
  SHA-256 `d992b00b085d9d500d88ff926dea5c9916d29c103fe127e61273d6bde084e2a5`,
  which binds reviewed monorepo source commit
  `3e4e9c818759b123a0cfd9a6f089c3a11769b1e1` and public content-plane commit
  `997bf0c181e672f0111f4a78ecb27b336c387fbf`;
- the policy pins content-plane tag `content-plane-v1.0.19`, image
  `sha256:0e7e5625538b16303c7b759e8c924f043b4da1ebfc23416f5bebaea6bb717c0f`,
  measured compose
  `9329f5078f9ca6fe658ec999d92a3d5d7661b7d81f60d6410ac3377ce6090f02`,
  and release id `anonrouter-tee@xl-7a84989`;
- app id, key provider, OS image, MRCONFIGID, MRTD, RTMR0..2, private logs,
  digest-pinned images, in-TD TLS, evidence expiry, `UpToDate` TCB, and hardware
  verification remain required.

Every pinned identity and platform field was re-observed on 2026-09-11 in two
independent fresh nonce-bound quotes, one per production hostname. The leaf key
named in each quote was separately observed on the wire for that hostname. Both
origins reached `hardware_verified` with Intel TCB `UpToDate` and zero failed or
advisory checks in both the JavaScript and Python CLIs.

**RTMR0 was not reproduced offline with `dstack-mr`.** It measures hardware
configuration. It rests on the retained manifest and agreeing independent
quotes, not an offline recomputation. That limitation is unchanged and is
recorded rather than rounded up.

The manifest still records two source-to-image provenance gaps for
plaintext-capable third-party bases: `caddy-edge-base` and `node-base-image`.
They are supply-chain limitations, not attestation bypasses.

## Verification gates

| Gate | Result |
| --- | --- |
| JavaScript offline suites | 453 confidential + 14 client passed; 39 live cases skipped |
| Python offline suite | 377 passed; 40 live cases skipped |
| JavaScript types and builds | clean |
| Python mypy and ruff | clean |
| Production dependency audit | 0 vulnerabilities (`npm audit --omit=dev`); 2 moderate advisories exist only in development tooling |
| Shared pin parity | all six package copies byte-identical to `shared/` |
| CLI parity | 4/4 cases produced matching JavaScript/Python documents and exit codes |
| Live gateway verification | both languages, both production origins: `hardware_verified`, `UpToDate`, no failed or advisory checks |
| Artifact smoke installs | both npm tarballs, the wheel, and the sdist installed and ran from empty environments; Twine metadata passed |
| Live Tinfoil provider check | official verifier accepted the current signed release; normalized result `sdk-verified`, zero required failures |

The live gateway checks were credential-free and content-free. They exercised
fresh nonce binding, TLS-key binding, the current independently shipped policy,
and the DCAP chain verifier. They did not send a model request or mutate
production.

## Route coverage boundary

The last authenticated catalog review was 2026-09-09. It found **9 callable
`tee`/`e2ee` routes**:

| Provider | Class | Callable routes | Hop 2 result |
| --- | --- | ---: | --- |
| `tinfoil` | tee | 6 | `policy_matched` |
| `venice` | e2ee | 3 | `cryptographically_checked` |

Chutes remains listed but emergency-disabled and contributes zero callable
routes. This patch does not re-enable it. No authenticated catalog matrix or
paid provider canary was rerun for `v0.1.2`. The Tinfoil check was
credential-free and content-free: it verified the provider release and enclave
but sent no model request. The 9-route count is therefore a dated production
observation, not a claim freshly established by this release candidate.

Tinfoil evidence exposes no caller nonce, so its hop-2 `nonce_binding` remains
advisory. That is a provider-evidence limitation and is not hidden by the
`policy_matched` verdict.

## What the package pin does now

| Policy under test | Outcome on 2026-09-11 |
| --- | --- |
| the unchanged `v0.1.1` AnonRouter gateway pin | `hardware_verified`, TCB `UpToDate`, no failed or advisory checks |
| the released `v0.1.0` pin | `untrusted` — `compose_hash_pinned`, `release_pinned`, `platform_measurements_pinned` |
| the `v0.1.2` Tinfoil provider authority | current signed release accepted as `sdk-verified`; no static release fingerprint involved |
| no DCAP engine supplied | cannot satisfy `--require hardware_verified` |

The old hop-1 pin still fails closed as designed. The Tinfoil row is different:
release rotation is accepted only after the provider's signed release authority
and live enclave checks pass.

## DCAP artifact

The release builder reproduces `anonrouter-dcap-verifier-linux-amd64` twice from
clean inside the digest-pinned Rust builder and refuses non-identical output. It
also ships the corresponding AGPL source archive. The verifier source is
unchanged from `v0.1.0`; package versions move together while the native binary's
own engine version remains `0.1.0`.

Live verification on macOS used a native `aarch64-apple-darwin` build of that
same source, SHA-256
`53b8c8029e9456ed6dbd9276302a54637578f9a136b8bf3163abe27aaeef0786`.
The downloadable reproducible binary remains Linux/amd64; the macOS binary is a
local verification tool and is not a release asset.

## Publication boundary

This tree is a release candidate, not a registry publication.

- Both npm packages are live at `0.1.1`; `0.1.2` is not published. Use the
  established npm release workflow for the patch release and verify the exact
  packed artifacts before enabling its publish gate.
- npm publication is independent of PyPI and can proceed without enabling the
  Python registry job.
- `PUBLISH_PYPI` must remain unset or false while the PyPI organization request
  is pending. The Python wheel and sdist can ship as checksummed GitHub release
  assets without publishing to PyPI.
- No registry token belongs in this repository, its commits, release notes, or
  handoff documents.

Do not create or push tag `v0.1.2` until the final artifact builder, checksum
verification, npm publication review, and owner signing step have all completed.
