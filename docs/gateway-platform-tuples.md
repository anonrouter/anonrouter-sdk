# Gateway platform kinds and release tuples

Implemented in the unpublished 0.1.3 candidate, on private branch
`gcp-sdk-platform-tuples-20261008` (based on `sdk-connection-binding-20261007`
at `277b976`). **Nothing here is published, deployed or production-approved.**
The packaged production policy, the signed feed contract and every default call
behave exactly as before.

## Why

Two problems block a multi-node or Google Cloud content plane:

1. A policy checked app ids, compose hashes, release ids and each platform
   register as independent allowlists. A policy listing an old and a new release
   therefore accepted a mixture of them, for example old firmware registers with
   a new compose hash.
2. Behind a load balancer each node has its own per-boot TLS key. A certificate
   observed on a separate connection proves nothing about the node that later
   receives content.

## Policy forms

A policy document **without** `platformKind` is the legacy
`phala-dstack-kms` form. It parses and verifies exactly as before, so the
packaged W8 pin, live signed-feed v1 payloads and existing caller policies keep
working.

A policy document **with** `platformKind` is the tuple form:

```json
{
  "platformKind": "gcp-tdx-native",
  "source": "...", "version": "...", "origins": ["https://..."],
  "releaseTuples": [{
    "tupleId": "release-a@c4-standard-2@fw1", "releaseId": "...",
    "appId": "<64 hex dm-verity root>", "composeHash": "<64 hex>",
    "mrTd": "<96 hex>", "rtmr0": "<96 hex>", "rtmr1": "<96 hex>",
    "rtmr2": "<96 hex>", "tdAttributes": "<16 hex>",
    "notBeforeMs": 0, "expiresAtMs": 0
  }],
  "requireInTeeTls": true, "requirePrivateLogs": true,
  "requireDigestPinnedImages": true, "requireHardwareVerified": true,
  "acceptableTcbStatuses": ["UpToDate"], "requireEvidenceExpiry": true,
  "maxEvidenceAgeMs": 300000
}
```

- Evidence passes only if **one** tuple matches **every** observed value at
  once (`release_tuple_matched`). Tuples are OR; values within a tuple are AND.
  Firmware rolls (MRTD) and machine shapes (RTMR0) are additional complete
  tuples, never wildcards.
- Each tuple has its own validity window, `notBeforeMs <= now < expiresAtMs`,
  as safe non-negative integers spanning at most 366 days. At most 64 tuples.
- Mixed documents are refused: `platformKind` with any of `appIds`,
  `composeHashes`, `releaseIds`, `keyProviderId` or `platform`, or
  `releaseTuples` without `platformKind`. Unknown fields at either level are
  refused, so a vTPM/PCR allowlist cannot be added or silently ignored.
- Register and digest values must already be lowercase hex of exact length.
- Every tuple pins `tupleId`, `releaseId`, `appId`, `composeHash`, `mrTd`,
  `rtmr0`, `rtmr1`, `rtmr2` and its validity window. `phala-dstack-kms` tuples
  add `mrConfigId`, `osImageHash` and the exact `keyProviderPayload` (compared
  byte for byte; it must decode to JSON naming `kms`). `gcp-tdx-native` tuples
  add only `tdAttributes` (exact, debug bit refused) and their `appId` must be
  the 32-byte dm-verity root; they cannot carry MRCONFIGID, an OS image or a key
  provider, because that guest has none of them.
- The parsed policy also carries `appIds`/`composeHashes`/`releaseIds` as unions
  of the tuples for display. They are never a second source of acceptance, and
  the floor refuses an object whose unions disagree with its tuples.

The tuple-form floor always requires native DCAP hardware verification, in-TEE
TLS, private logs, digest-pinned images, evidence expiry of at most five minutes
and TCB exactly `UpToDate`. The verifier re-checks it on every call
(`policy_security_floor`), so a mutated policy object cannot drop a switch.

## gcp-tdx-native verification

- **Native DCAP only.** `quote_signature_chain` and `tcb_status_acceptable` are
  required. No vTPM quote, PCR or Google attestation token substitutes for them.
- **Hardware registers are the measurements.** MRTD, RTMR0..RTMR2 and
  td_attributes come from the quote and must equal one tuple. The application
  (compose and images) is baked into the dm-verity root named on the UKI command
  line, which firmware measures into RTMR1, so RTMR1 pins it and `appId` names
  it. RTMR3 must be zero (`rtmr3_unextended`) and MRCONFIGID, MROWNER and
  MROWNERCONFIG must be zero (`owner_config_registers_zero`). No event log,
  key-provider event or app-compose is consulted, even if a document carries
  one. `firmware_event_log_replayed` stays an unmet advisory: the SDK does not
  replay Google's CCEL, so a tuple's UKI Authenticode and verity-root provenance
  rest on its release review.
- **Per-boot identity.** `instance_id` must equal SHA-256 of the per-boot
  Ed25519 boot key carried as the binding's `public_key`
  (`instance_id_derives_from_boot_key`); it is never pinned.
- **Mandatory real-connection key binding.** `tls_certificate_bound_to_quote`
  is required even when no certificate was observed, and
  `tls_observed_on_retained_connection` passes only when the SPKI was read from
  the SDK's own retained socket, which fetched the evidence and is the only one
  allowed to carry tickets and content (Node `openRetainedGatewayOperation`,
  Python sync `RetainedGatewayConnection`).
- **Not qualified.** `GATEWAY_PLATFORM_QUALIFIED["gcp-tdx-native"]` is `false`.
  `platform_boot_chain_qualified` fails as a required check unless the caller
  passes `unqualifiedPlatformPilot: true` (`unqualified_platform_pilot=True`);
  then it stays visible as an unmet advisory. The opt-in relaxes nothing else.

## Client behavior

Refusals happen during policy resolution, before evidence, tickets or content:

| Path | gcp-tdx-native result |
|---|---|
| Packaged registry entry | Refused at parse; none ships |
| Signed feed approval | Refused (`platform kind is not qualified for signed approval`) even with valid signatures |
| `verifyGateway` / `verify_gateway` (separate connection) | `unsupported_request`, no request sent |
| Unbound `chat`/`verify` with `requireGateway` | `unsupported_request`, no ticket or content |
| CLI separate-connection SPKI observation | Fails `tls_observed_on_retained_connection` |
| Python async, browsers, custom fetch | Already cannot use required binding; refused |
| Required binding without pilot opt-in | `unsupported_request` before any connection |
| Required binding, caller policy, pilot opt-in | Verified on the retained socket; wrong key, platform or tuple refuses before any ticket |

## Evidence protocol

From the GCP content-guest worker (`native/gcp-content-guest`, not yet
hardware-qualified), relayed by the coordinator on 2026-10-08:

1. Gateway binding v1 is unchanged (canonical JSON, SHA-512 into report_data).
   The in-TD broker fills `app_id` = dm-verity root hex (stable per release),
   `instance_id` = SHA-256 of the per-boot Ed25519 boot key, `compose_hash` =
   baked compose SHA-256, `release_id` from the baked manifest,
   `key_alg` = `ed25519`, `public_key` = the boot key, `transport` =
   `in-tee-tls`, and `tls_spki_sha256` = SHA-256 of the DER SPKI of the TLS key
   it generated in TD memory. Callers supply only the nonce and one measured
   origin; there is no arbitrary report_data API.
2. RTMR3 carries no dstack events and must be zero. There is no app-compose,
   KMS, vTPM-derived key or key-provider payload.
3. RTMR0..RTMR2 come from Google OVMF's CCEL (TCG crypto-agile, SHA-384).
   Tuples are created only from a reference boot that passes the native semantic
   check (`ar-guest-verify`: CCEL replay equals the quote, exactly one RTMR1
   EV_EFI_BOOT_SERVICES_APPLICATION equal to the UKI Authenticode SHA-384, and
   allowlisted code events). The release policy records the UKI Authenticode
   digest and verity root beside each tuple.
4. Evidence may later add an advisory `gcp_boot.ccel_base64`; the SDK ignores it.

SDK assumption to confirm with that worker: `instance_id` is SHA-256 over the
raw 32-byte Ed25519 public key (the hex-decoded `public_key`). A different
encoding fails closed.

## Gaps and gates

- No real GCP pins exist. The C4 hardware qualification proved a genuine native
  quote on stock Ubuntu, not the AnonRouter guest. Hardware gate N1 (Google
  firmware measures the UKI Authenticode digest into RTMR1 with the vTPM
  present) is still open, so no GCP tuple can be written yet.
- Qualifying the platform requires a reviewed SDK release that flips
  `GATEWAY_PLATFORM_QUALIFIED`, with real tuples, and a reviewed procedure for
  preparing tuple-form signed approvals. `scripts/gateway-policy-release.mjs`
  refuses tuple-form policies until then.
- TCB remains exactly `UpToDate`. A lag between an Intel TCB recovery and
  Google's firmware rollout will fail closed; any widening is a separate reviewed
  decision.
- Firmware-roll procedure (Google's published firmware binary and MRTD
  endorsement to a new tuple) is documented as a requirement, not implemented.
- Default SDK traffic and published 0.1.2 remain hostname-bound only. Mandatory
  same-connection binding applies to the opt-in bound path and to every
  gcp-tdx-native verification.

## Tests

- `shared/vectors/gateway-release-tuples.json`, generated by
  `npm run gen:gateway-tuple-vectors`, holds 30 policy-document, 22 verdict and 2
  signed-approval cases. JavaScript (`test/gateway-release-tuples.test.ts`) and
  Python (`tests/test_gateway_release_tuples.py`) verify the same bytes.
- Real loopback TLS: four gcp-tdx-native cases each in
  `js/confidential/test/gateway-bound-client.test.ts` (`npm run test:bound`) and
  `acceptance/python-bound-client-tests.py`: pilot success on the retained
  socket; another node's key, and an unapproved firmware register, both refused
  with zero tickets and zero content; no pilot refused before any connection.
- `scripts/smoke-artifacts.mjs` checks that installed npm, wheel and sdist
  artifacts keep gcp-tdx-native unqualified and the shipped pin legacy-form.

All values in these tests are synthetic. None is a Google firmware measurement,
an Intel-signed quote or an AnonRouter production pin.
