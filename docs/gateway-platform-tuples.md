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
    "tupleId": "release-a@fw1", "releaseId": "...", "appId": "<hex>",
    "composeHash": "<64 hex>", "mrTd": "<96 hex>", "mrConfigId": "<96 hex>",
    "rtmr0": "<96 hex>", "rtmr1": "<96 hex>", "rtmr2": "<96 hex>",
    "keyProviderPayload": "<hex of the measured key-provider event>",
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
- `phala-dstack-kms` tuples also pin `osImageHash` and their key-provider payload
  must name `kms`. `gcp-tdx-native` tuples have no `osImageHash` (the OS is what
  RTMR1/RTMR2 measure) and their key-provider payload must name the ephemeral
  `none` provider. The pinned payload is compared byte for byte.
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
- **Hardware registers pinned directly.** MRTD, MRCONFIGID and RTMR0..RTMR2 come
  from the quote and must equal the tuple. Google firmware does not emit a dstack
  boot log, so only RTMR3 application events are replayed
  (`event_log_replays_rtmr3`). `firmware_event_log_replayed` is recorded as an
  unmet advisory until the native CCEL/UKI proof is integrated.
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

## Evidence protocol assumptions

The coordinator accepted these as the SDK side of the interface; the GCP guest
adapter is being built separately and the native boot protocol integration will
follow:

1. Gateway binding v1 is unchanged: `report_data` is SHA-512 of the canonical
   binding including per-boot `instance_id`, `public_key` and `tls_spki_sha256`.
2. `event_log` carries RTMR3 application events in dstack JSON form: `app-id`,
   `compose-hash`, `instance-id` and `key-provider`, replaying to the quote's
   RTMR3. Entries for imr 0..2, if present, are not consulted.
3. The exact ephemeral-none key-provider payload bytes are an open item. Tests use
   a synthetic `{"name":"none","id":""}`; it is not a pin.

## Gaps and gates

- No real GCP pins exist. The C4 hardware qualification proved a genuine native
  quote on stock Ubuntu, not the AnonRouter guest. Native UKI/command-line/verity
  measurement into RTMR1/RTMR2, application measurement and CCEL replay are not
  qualified, so no GCP tuple can be written yet.
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
  `npm run gen:gateway-tuple-vectors`, holds 25 policy-document, 17 verdict and 2
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
