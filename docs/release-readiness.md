# Release readiness for 0.1.3

Prepared 2026-10-06. This is an unpublished repair candidate; npm latest remains
0.1.2 until the separate publication succeeds. Python registry availability must
be established separately; existing wheel/sdist release assets are supported.

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
