# Release readiness for 0.1.2

Recorded 2026-09-12 against the `v0.1.2` release candidate. Results below are
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
serving TLS key binding remain required. It does not loosen AnonRouter's hop-1
pins, other providers' policies, or the inference protocol.

## Two corrections from independent review

An independent review of the first candidate found two Tinfoil checks that read
stronger than they were. Neither was waived.

1. **The TLS binding was a tautology.** The verifier required
   `enclaveMeasurement.tlsPublicKeyFingerprint` to equal `tlsPublicKey`. Both
   are copies of one field of one AMD SEV-SNP report, so the comparison passed
   for every document, forged ones included, and established nothing about the
   connection actually serving the route. Both languages now require a
   `transportBinding` observed on a real pinned connection, whose recorded
   certificate SPKI must equal the key in the verified report. A document
   without one fails `attested_key_binding`. Nine new shared vector cases and
   matched JavaScript/Python mutation tests cover it, including a real local TLS
   server that must accept a matching peer and refuse a wrong one.
2. **The route claimed NVIDIA evidence it never checked.** Verdicts reported
   hardware type `amd-sev-snp+nvidia-cc` and the copy described GPU attestation,
   on a route whose official verifier establishes no NVIDIA
   confidential-compute evidence. Tinfoil now reports `amd-sev-snp`, the union
   member is removed, and every Tinfoil-facing GPU or model-weight claim is
   withdrawn from packages, tests, vectors and documentation.

A third finding is addressed as wording rather than code: of the four fields in
the pinned Tinfoil policy, only `configRepo` is re-derived from evidence.
`authority`, `releaseSelection` and `requireTaggedRelease` record the reviewed
trust decision and pin the policy file against a silent edit; the guarantees
they name belong to the official verifier. That is now stated in
`SECURITY.md`, in `shared/measurements.json`, and beside both implementations.

While correcting the above, `enclaveHost` was also brought under the endpoint
check. Previously only `selectedRouterEndpoint` was compared, so a document
could name the supported router in one field and anywhere at all in the other.

## Production binding

- inference, compatibility, and gateway attestation default to
  `https://api.anonrouter.ai`;
- identity, catalog, billing, and content-free ticket minting default to
  `https://control.anonrouter.ai`;
- `https://api.private.anonrouter.ai` remains an attested alias, not a customer
  configuration requirement;
- the published gateway policy is derived from retained release manifest
  SHA-256 `303e61fb7c89a6b7079c489a58955aa9cc76b1e09e03b777f133cdf525f34c8d`,
  which binds reviewed monorepo source commit
  `4c9b984b981a823c016efbbb7d019817e22beca4` and public content-plane commit
  `644f50d48f920f1f7720bd5edde4fb93bb1267bf`;
- the policy pins content-plane tag `content-plane-v1.0.20`, image
  `sha256:d10f4f129efa395bb724798058e93c51f9eb150a25744abee0cbbbc7622de885`,
  measured compose
  `9e369fb632fb3b98c604b0c8457448ce88a29077c1766948b87fb6673db494fb`,
  and release id `anonrouter-tee@xl-4c9b984`;
- app id, key provider, OS image, MRCONFIGID, MRTD, RTMR0..2, private logs,
  digest-pinned images, in-TD TLS, evidence expiry, `UpToDate` TCB, and hardware
  verification remain required.

Every pinned identity and platform field was re-observed on 2026-09-12 in two
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
| JavaScript offline suites | 490 confidential + 14 client passed; 39 live cases skipped |
| Python offline suite | 386 passed; 41 live cases skipped |
| JavaScript types and builds | clean |
| Python mypy and ruff | clean |
| JavaScript end-to-end self-test | verify plus E2EE chat round trip passed against the in-process mock gateway |
| Production dependency audit | 0 vulnerabilities (`npm audit --omit=dev`); 2 moderate advisories exist only in development tooling |
| Shared pin parity | all six package copies byte-identical to `shared/` |
| Verifier vector parity | 18 shared cases, 11 of them Tinfoil, produce identical verdicts in both languages |
| CLI parity | 4/4 cases produced matching JavaScript/Python documents and exit codes |
| Live gateway verification | both languages, both production origins: `hardware_verified`, `UpToDate`, no failed or advisory checks (fresh observation from this candidate, 2026-09-12) |
| Artifact smoke installs | both npm tarballs, the wheel, and the sdist installed and ran from empty environments; Twine metadata passed |
| Live Tinfoil provider check | official verifier accepted the current signed release; the pinned connection's observed peer SPKI matched the key in the AMD report; normalized result `sdk-verified`, zero required failures (fresh credential-free observation from this candidate, 2026-09-12) |

The live gateway checks were credential-free and content-free. They exercised
fresh nonce binding, TLS-key binding, the current independently shipped policy,
and the DCAP chain verifier. They did not send a model request or mutate
production.

The live gateway row was re-established from this exact candidate in both
languages against both production origins. The TLS-binding change is exercised
both offline against a real local TLS server and live against Tinfoil from this
exact candidate. Offline, a
matching peer is accepted and its key returned, a wrong pin is refused with no
observation recorded, and a peer that fails ordinary PKI validation is refused
even when its key would have matched. Live on 2026-09-12,
`verifyTinfoilEnclave()` returned `sdk-verified` with AMD SEV-SNP, the official
signed-release authority, a present attested TLS SPKI, and zero required
failures. It sent one credential-free, body-free `HEAD`; no inference or billing
occurred.

## Route coverage boundary

The authenticated catalog and route matrix were rerun from this exact candidate
on 2026-09-12. The catalog advertised **9 callable `tee`/`e2ee` routes**:

| Provider | Class | Callable routes | Hop 2 result |
| --- | --- | ---: | --- |
| `tinfoil` | tee | 6 | 6/6 `policy_matched`; six paid provider-pinned canaries passed |
| `venice` | e2ee | 3 | 2/3 `cryptographically_checked`; two paid E2EE canaries passed |

Chutes remains listed but emergency-disabled and contributes zero callable
routes. This patch does not re-enable it.

One production route failed closed: Venice `z-ai/glm-5.2` omitted the required
NVIDIA evidence on six consecutive fresh samples, so `gpu_evidence_present`
failed and the SDK refused to send its paid request with
`attestation_untrusted`. The other eight routes established both hops and their
minimal paid provider-pinned calls passed. This is a production
catalog/provider-evidence inconsistency, not a Tinfoil-policy regression or an
SDK fail-open: the unsafe call never left the client. The route should be
withheld until Venice supplies the evidence it advertises or AnonRouter stops
classifying it as a callable E2EE route.

Tinfoil evidence exposes no caller nonce, so its hop-2 `nonce_binding` remains
advisory. That is a provider-evidence limitation and is not hidden by the
`policy_matched` verdict.

## What the package pin does now

| Policy under test | Latest outcome |
| --- | --- |
| the unchanged `v0.1.1` AnonRouter gateway pin | `hardware_verified`, TCB `UpToDate`, no failed or advisory checks |
| the released `v0.1.0` pin | `untrusted` — `compose_hash_pinned`, `release_pinned`, `platform_measurements_pinned` |
| the `v0.1.2` Tinfoil provider authority | current signed release accepted as `sdk-verified`; no static release fingerprint involved |
| a Tinfoil document with no observed transport binding | `untrusted`, failing `attested_key_binding`, in both languages |
| no DCAP engine supplied | cannot satisfy `--require hardware_verified` |

The old hop-1 pin still fails closed as designed. The Tinfoil row is different:
release rotation is accepted only after the provider's signed release authority
and live enclave checks pass, and only when the serving connection's key was
observed and matched.

## What the Tinfoil route still does not establish

Stated here rather than left to be inferred from a passing verdict.

- **No NVIDIA GPU evidence and no model-weight binding.** The hardware claim is
  AMD SEV-SNP. Nothing on this route attests a GPU or ties the running weights to
  the model id the caller asked for, so `model_weight_identity` is null.
- **Three of the four policy fields are labels.** Only `configRepo` is
  re-derived from evidence. `authority`, `releaseSelection` and
  `requireTaggedRelease` record which Tinfoil workflow this package was reviewed
  against; the guarantees they name are enforced inside the official verifier,
  which checks a Fulcio identity and workflow ref this SDK never receives.
- **No rollback floor.** The official verifier selects the release Tinfoil calls
  latest. This SDK adds no monotonic version floor, so an older release Tinfoil
  still signs and serves is accepted. Adding a floor would reintroduce the
  per-release state this patch removed.
- **On the client path, the observation is AnonRouter's.** The gateway supplies
  both the document and the transport binding, so that path proves the route
  against AnonRouter's measured worker rather than independently of it. In Node,
  `verifyTinfoilEnclave()` makes the observation itself and needs nothing from
  AnonRouter; in a browser it fails closed, because no browser can read a peer
  certificate.
- **Connection-bound, not nonce-bound.** Tinfoil evidence exposes no caller
  nonce, so hop-2 `nonce_binding` stays advisory.

## DCAP artifact

The release builder reproduces `anonrouter-dcap-verifier-linux-amd64` twice from
clean inside the digest-pinned Rust builder and refuses non-identical output. It
also ships the corresponding AGPL source archive. The verifier source is
unchanged from `v0.1.0`; package versions move together while the native binary's
own engine version remains `0.1.0`.

Live verification on macOS used a native `aarch64-apple-darwin` build of that
same source, SHA-256
`c728a123657cbc309bfb9cfa907c059a1ae7c726ac900ab153f137cc93d1a00c`.
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
