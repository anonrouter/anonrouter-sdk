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

JavaScript: 512 confidential + 14 client tests pass, 39 live cases skipped.
Python: 408 tests pass, 40 live cases skipped. Types/build, Python mypy and ruff
pass. New shared public evidence and adversarial tests cover publication, key,
nonce, model, GPU and provider substitution plus encrypted transport round trips.

Both source CLIs independently verify both production origins as
`hardware_verified` with real DCAP, zero failed/advisory checks. Fresh direct
`other` attestation passes in both languages; JavaScript encrypted session setup
passes. Paid inference was not performed and is not claimed as newly accepted.

Artifact checks and their exact checksums are recorded in the repair handoff.
Publication is pending explicit GitHub release authorization under the project
source-control rule. No registry setting, tag or public branch was changed.
The [0.1.2 readiness record](release-readiness-0.1.2.md) is historical.
