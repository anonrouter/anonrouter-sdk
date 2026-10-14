# Release readiness for 0.1.3

Prepared 2026-10-06. This is an unpublished repair candidate; npm latest remains
0.1.2 until the separate publication succeeds. Python registry availability must
be established separately; existing wheel/sdist release assets are supported.

## GCP release-v3 update, 2026-10-14

0.1.3 package versions were already staged on `sdk-gce-pzid` at `31bd154`.
This work completes that version's GCP verification changes; it does not bump
the unpublished candidate again. npm latest remains 0.1.2 for both JS packages.
PyPI returns 404 for the Python project. No npm/PyPI publish or production
mutation is authorized.

JavaScript now defaults to the production owner-signed release-v3 feed with
fixed USB/laptop public keys and minimum sequence 6. There are no packaged GCP
image pins. GCP is qualified in both verifier cores; Python release-v3 feed
support remains pending. Phala exact policies and the opt-in v1 source remain.
PZID is optional; a signed `requireGcePzid: true` can require it later.

Fresh credential-free attestation passed on the real production endpoint with
native dcap-qvl 0.6.1, Intel QE/platform `UpToDate`, nonce binding, approved
release tuple and the TLS key observed on the retained socket. The live node
omits PZID; its image verifies and machine identity stays `unverified`.
Google CCEL replay remains advisory: UKI/verity provenance rests on release
review. This acceptance is read-only and spends no inference credit.

Validation of this candidate: 697 JS confidential tests and 14 client tests;
515 Python tests; JS/Python type checks; ruff; 35 Node and 43 Python real
loopback TLS cases; 33 retained-operation cases; mock E2EE self-test; shared
file and CLI parity; installed npm tarballs plus wheel/sdist smoke checks.
Live checks ran from the installed JS tarball with fresh nonces. Wrong nonce,
origin, observed TLS key, separate-socket assertion and owner signature all
failed closed. `scripts/verify-live-gcp.mjs` reproduces the read-only check. The content-free
result is retained in [the live evidence record](evidence/sdk-0.1.3-gcp-live-2026-10-14.json).

Live suites in the ordinary unit runs skipped because no live origin was set;
the dedicated packed GCP probe above ran against production instead. The native
engine was built locally from locked SDK source; this is hardware verification,
not proof of reproducible Linux distribution bytes. The PCK cache cancellation
fixture had the wrong platform ID and now uses the quote fixture's FMSPC and
platform-only cache expectation. Existing Python cache-test lint was corrected.

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
