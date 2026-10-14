# Release readiness for 0.1.3

Prepared 2026-10-06; GCP release-v3 update 2026-10-14 (branch
`sdk-0.1.3-gcp-release`, based on `sdk-gce-pzid` 31bd154 plus the earlier
candidate f8e7921). Unpublished: npm latest is 0.1.2 for both packages and PyPI
returns 404 for `anonrouter-confidential`. Nothing is tagged, pushed or published
until the owner gives the go.

## GCP release-v3 update, 2026-10-14

Since 2026-10-14 02:37Z `api.anonrouter.ai` is served by GCP Intel TDX content
nodes; 0.1.2 fails closed against them. 0.1.3, in JavaScript **and** Python:

- verifies hop 1 for `api.anonrouter.ai` against the owner-signed release
  policy v3 feed with the packaged owner root
  `10034ad2b11e9ef9f300da180a794010da369f2f14b2a896df42ceaf47077acb` (keys and
  root cross-checked against the backend's
  `deploy/gcp/content-guest/production/anchors.json`) and minimum sequence 6.
  No node image measurements ship;
- refuses rollback, forks and revocation reversal in-session, and lower
  sequences across restarts (durable high-water mark);
- verifies `gce_pzid` when present, accepts its absence as
  `instanceIdentity: "unverified"`, and honors an SDK-local signed
  `requireGcePzid` (not signable until the backend schema carries it);
- accepts the backend's signed `tcbGrace` without relaxing `UpToDate`;
- verifies only on the retained socket (connection binding,
  `verifyContentNode()` / `verify_content_node()`, `anonrouter-verify gateway --dcap`);
- keeps the Phala pin for explicit use and for the deprecated
  `api.private.anonrouter.ai` rollback name.

Upgrade guide for 0.1.2 users: [migrating-to-0.1.3.md](migrating-to-0.1.3.md),
including the npm deprecation recommendation.

### Validation (local, macOS arm64, Node 22, Python 3.14)

- JS: typecheck, `npm test` (757 confidential + 14 client tests, 39 live cases
  skipped), build, mock E2EE self-test, 42 real-local-TLS bound-client cases
  (7 new `verifyContentNode` cases), 33 retained-operation cases.
- Python: 582 tests (40 live skipped), ruff, mypy; acceptance 43 bound-client,
  23 retained and 14 transport cases.
- Shared: `release-policy-v3.json` (42 policy, 15 attestation cases, compared
  check by check) passes in both languages, as do the backend's own signed
  envelopes, successor and `tcbGrace` digest. Pin parity, NEAR parity,
  authority parity, policy release tooling, GCP qualification tooling (P8 now
  satisfied by construction) and CLI parity (now including doctor for the GCP
  origin) pass. Artifact smoke installs both npm tarballs, the wheel and the
  sdist into empty environments.

### Live, read-only, credential-free (2026-10-14, fresh nonces)

`scripts/check-live-gateways.mjs` against locally packed 0.1.3 artifacts
(npm tarballs and the wheel with the `connection-binding` extra) with the
locally built native engine (SHA-256 `b92a83b4...`):

| Language | Origin | Result |
|---|---|---|
| JavaScript | api.anonrouter.ai (required) | hardware_verified, `signed-release-policy-v3` sequence 6 (`7dbe4b66...`), TCB UpToDate, TLS key on the retained socket, advisory gaps `firmware_event_log_replayed`, `gce_instance_identity` |
| Python | api.anonrouter.ai (required) | same |
| JavaScript | api.private.anonrouter.ai (informational) | hardware_verified, package-pinned Phala policy |
| Python | api.private.anonrouter.ai (informational) | same |

`scripts/verify-live-gcp.mjs` (source build) also passed and refused a wrong
nonce, wrong origin, wrong observed TLS key, a separate-socket claim and a
tampered owner signature. No API key, ticket, prompt or inference request was
sent. The native engine was built locally from locked SDK source; the release
workflow uses its own reproducible linux/amd64 build.

### Release workflow notes

- `.github/workflows/release.yml` runs on a `v*` tag: gates, reproducible
  artifacts, the live gate above (now requiring release-v3 on
  `api.anonrouter.ai`; Phala informational), the GitHub release (body
  `.github/release-notes/v0.1.3.md`), then `publish-npm` because repository
  variable `PUBLISH_NPM` is `true`. `PUBLISH_PYPI` is not set, so PyPI is
  skipped and Python ships as GitHub release assets.
- The `NPM_TOKEN` bootstrap secret still exists (created 2026-09-12). If npm
  trusted publishing is configured for both packages, delete it after this
  release, as `docs/npm-first-publication.md` already requires.
- `@anonrouter/client` 0.1.3 is unchanged from 0.1.2 apart from its version.

### Publish commands (owner go only)

Run from the main checkout. `<COMMIT>` is the reviewed head of
`sdk-0.1.3-gcp-release`; the branch fast-forwards `origin/main` (16980d0).

```bash
cd ~/Desktop/anonrouter-sdk
git fetch origin
git log --oneline -1 sdk-0.1.3-gcp-release            # confirm <COMMIT>
git merge-base --is-ancestor origin/main sdk-0.1.3-gcp-release && echo fast-forward-ok
git push origin sdk-0.1.3-gcp-release:main            # optional, keeps doc links on main current
git tag -a v0.1.3 <COMMIT> -m "v0.1.3"
git push origin v0.1.3                                # starts release.yml; publishes npm after the live gate
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

The workflow then runs, from the checksummed artifacts it built:

```bash
npm publish anonrouter-client-0.1.3.tgz --provenance --access public
npm publish anonrouter-confidential-0.1.3.tgz --provenance --access public
```

Afterwards (read-only checks, then the recommended deprecation):

```bash
npm view @anonrouter/confidential dist-tags --json     # expect latest 0.1.3
npm view @anonrouter/client dist-tags --json
mkdir -p /tmp/ar013 && cd /tmp/ar013 && npm init -y >/dev/null && npm install @anonrouter/confidential@0.1.3
ANONROUTER_DCAP_VERIFIER_BIN=/path/to/anonrouter-dcap-verifier \
  npx anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap --require hardware_verified
npm deprecate "@anonrouter/confidential@<0.1.3" \
  "Cannot verify api.anonrouter.ai since 2026-10-14 (GCP content nodes). Upgrade to 0.1.3: https://github.com/anonrouter/anonrouter-sdk/releases/tag/v0.1.3"
```

PyPI is not part of this release. If the owner later enables it:
`gh variable set PUBLISH_PYPI --body true` after configuring the PyPI trusted
publisher, then re-run the release workflow for the tag.

### Rollback

```bash
# Point latest back at 0.1.2 and warn 0.1.3 installs (both reversible):
npm dist-tag add @anonrouter/confidential@0.1.2 latest
npm dist-tag add @anonrouter/client@0.1.2 latest
npm deprecate @anonrouter/confidential@0.1.3 "Withdrawn; use 0.1.2 pending a fix"
npm deprecate @anonrouter/client@0.1.3 "Withdrawn; use 0.1.2 pending a fix"
# If the 0.1.2 deprecation was already applied, undo it:
npm deprecate "@anonrouter/confidential@<0.1.3" ""
# GitHub release: mark it as a pre-release instead of deleting it.
gh release edit v0.1.3 --prerelease
```

`npm unpublish` is possible only within 72 hours and burns the version number;
prefer deprecation. Note that rolling back to 0.1.2 restores a client that
cannot verify `api.anonrouter.ai` at all.

### Limits

Google CCEL is not replayed (UKI/verity provenance rests on the owner's release
review). Browsers cannot verify hop 1 for GCP nodes (no TLS key or native
engine). Durable state keeps sequence and hash; revocation-subset checks use the
policy held in process. `requireGcePzid` and honoring `tcbGrace` need backend
or reviewed SDK changes respectively.

The preceding W8/v1 notes and the sections below describe the earlier repair
candidate. Their activation/renewal dates are historical; use the GCP defaults
above for current JavaScript production verification.

## Repairs

- Refresh the packaged hop-1 policy from reviewed retained accepted W8 manifest
  SHA-256 `5abba136544c2f961072b70e3e0c8ac7c20fad126044ba4dc16c3e9b604b4829`.
  Measured compose, app, release, image and accepted evidence agree. All security
  requirements remain strict; only the reviewed deployment identity moves.
- Support public provider `other` on `near-v2` in JavaScript and Python. The
  public identity is preserved in ticket issuance, session, request body and
  encryption headers. It is never silently aliased to a different provider.
- Review `z-ai/glm-5.3-flash` against NEAR's fixed publication authority:
  nearai/cvm-compose-files, nearai/compose-manager, dstack production OS images,
  and the specified Base KMS. Replay quote-bound boot events, manager actions
  and publication bindings rather than copying a serving enclave's measurements.
- Require a nonce-bound GPU evidence document and an Ed25519 encryption key
  equal to the signing address actually committed by the quote for `other`.
  A substituted key or gateway-key disagreement is refused before encryption.
- Withhold Venice GLM 5.2 E2EE before network/ticket issuance, matching the
  operator-authorized production disable for missing GPU evidence.
- Add a credential-free packed-artifact production gate in the release workflow.
  Both languages must verify both hostnames with real DCAP and packaged policy
  before any GitHub/npm/PyPI publication job. npm publishes the exact checked
  tarballs, not a separate rebuild.
- Implement signed gateway-policy updates, persistent antirollback and bounded
  release refresh in both languages. Owner signer installation, real feed
  publication and packed/browser acceptance are complete. Default activation
  remains disabled pending continuing renewal ownership and SDK release; see
  [gateway-policy-updates.md](gateway-policy-updates.md).

## Trust boundary and limitations

NEAR hop 2 remains `provider-attested`: CPU/GPU vendor signatures are not
verified by this provider verifier. GitHub, dstack image and Base RPC records
arrive through AnonRouter's measured worker. The SDK recomputes their bindings
but does not independently retrieve every authority. Require verified hop 1
when relying on that fetch layer. No failure is waived or downgraded silently.

The retained gateway deployment carries supply-chain provenance gaps and an
unavailable live application-log sweep. RTMR0 was not reproduced offline.
These remain documented limitations, not failed cryptographic gates relabeled
as accepted. No production configuration, provider credential or customer
traffic routing was changed by this SDK repair.

## Validation checkpoint

JavaScript: 559 confidential + 14 client tests pass, 39 live cases skipped.
Python: 446 tests pass, 40 live cases skipped. Types/build, Python mypy and ruff
pass. New shared public evidence and adversarial tests cover publication, key,
nonce, model, GPU and provider substitution plus encrypted transport round trips.

Prior repair checkpoint (commit `a8bbf688e9bdc2dd3a4e30cb987136553fc0aba2`):
both source CLIs independently verified both production origins as
`hardware_verified` with real DCAP, zero failed/advisory checks. Fresh direct
`other` attestation passed in both languages; JavaScript encrypted session setup
passed. Paid inference was not performed and is not claimed as newly accepted.

The signed-authority additions pass 27 shared vectors and cross-language durable
rollback checks, release preparation/refusal tests, browser bundling and empty
environment installation of npm tarballs, wheel and sdist. New publication/live
canaries against real sequence-1 publication passed for exact packed commit
`16f1612d40984eae866503dd6f960b48c4e6b3a9`: both languages/origins reached
hardware_verified with signed-release-authority provenance, forced refresh and
durable cross-process state. Browser live CORS/signatures/IndexedDB/reload passed.
Expiry/tamper/threshold/conflict and simulated higher-state rollback refuse.
Backend publication source `c0102538909f52b1fd82266f40e62e2187e37117`, KMS site
sequence 1791329336, is accepted. Approval expires October 13; renew by October 11.
These canaries use explicit opt-in; SDK default flag remains false. Documentation
updates do not replace the recorded artifact identities.
Publication is pending explicit GitHub release authorization under the project
source-control rule. No registry setting, tag or public branch was changed.
The [0.1.2 readiness record](release-readiness-0.1.2.md) is historical.

## Connection-binding candidate — 2026-10-07

A separate unpublished candidate, based on cf1e9470, adds opt-in required Node
connection binding to the confidential client. Fresh fully checked gateway quotes
provide immutable operation identity; actual content sockets check normal CA,
hostname and the attested SPKI before sending HTTP. Provider evidence, encrypted
chat, image and speech use the operation transport; control is separate. Generic
fetch/browser/per-call downgrade refuses, expiry is checked before tickets and
HTTP dispatch, streams retain ownership, and no paid inference retry is added.
Standalone verifyGateway remains evidence-only and authority defaults stay off.

The isolated port passes 17 real local TLS client cases, 17 transport cases and 547
existing offline regressions, package/example types and build. Synthetic native
verifier boundaries are explicit; these are not new hardware or paid acceptance.
The network-dependent no-insecure-escape-hatch file was excluded: an earlier
scratch broad run attempted one credential-free public evidence GET and failed
before its expected chain check. No content/ticket/inference was sent or retried.

Python synchronous confidential-client integration passes 26 real local TLS
client cases, 14 primitive cases and 436 offline regressions importing the changed
source, plus ruff and full source/examples mypy (41 files). Required mode covers
provider evidence, encrypted chat and image/speech. The optional connection-binding
extra pins the reviewed HTTPX 0.28.1 / HTTPCore 1.0.9 pair; ordinary mode preserves
its broader dependency support. Async and ordinary-client/embeddings integration
remain incomplete. Fresh per-operation quotes can hit the
current 20/client-address and 240 aggregate per-minute service limits; capacity is
unverified. A quote from A followed by a connection to B safely refuses but can
still fail visibly during switching. Packed-artifact installation, hardware and
operational acceptance, complete client integration and publication remain gates.
The older acceptance records above describe their exact previous bytes only.
