# What the live origins actually serve

Observed 2026-08-30. Read-only, credential-free, fresh 32-byte nonces. No prompt,
no account identity, and no real API key was sent, and nothing was mutated.

This is an **observation**, not a pin and not a policy. Nothing here may be copied
into `shared/gateway-policies.json`: a value taken from the server it describes
proves nothing about that server. See `VERIFYING.md` for what a refresh requires.

## Two origins, and they do not serve the same contract

| | `api.anonrouter.ai` | `api.private.anonrouter.ai` |
| --- | --- | --- |
| What it is | The public API. The route existing users have always used. | The confidential data plane, an Intel TDX CVM. |
| `GET /healthz` | 200 | 200 |
| `GET /v1/gateway/attestation?nonce=…` | **404** | **200**, 86,879 bytes |
| `GET /v1/gateway/attestation` (no nonce) | 404 | 400 |
| `GET /v1/tee/attestation` (no credentials) | 401 | 401 |
| `POST /v1/tee/attestation` (no credentials) | 404 | 401 |
| `POST /v1/inference/attestation-tickets` (no credentials) | **403** | **404** |
| `GET /v1/models` (no credentials) | **403** | **404** |
| DNS | `8.231.147.44` | `dstack-pha-prod5.phala.network` → `66.220.6.105` |
| TLS issuer | Let's Encrypt YE1 | Let's Encrypt YE2 |
| Leaf SPKI SHA-256 (observed with `openssl`) | `416e1196…4bf61d5e` | `b5d2f366…e2ac0a47` |

**The headline: hop 1 and hop 2 are not both reachable at one origin today.**

- Hop 1 (`GET /v1/gateway/attestation`) exists **only** on the confidential origin.
  The public API answers 404, which the SDK reports as `unavailable`, meaning "we
  could not look", not "we looked and it failed".
- The two credentialed control routes hop 2 needs, `/v1/inference/attestation-tickets`
  and `/v1/models`, answer **403** on the public origin (present, authorization
  required) and **404** on the confidential origin.

A 403 and a 404 are different answers to different questions, and that difference
is the whole finding: the public origin has those routes and refused an
unauthenticated caller, while the confidential origin did not recognize them at
all. Both `/v1/tee/attestation` variants answer 401 on the confidential origin, so
that route does exist there.

This matches the product handoff, which records that the public API still uses the
legacy path and that customer routing has deliberately not been moved. It is the
current deployment shape rather than a defect.

### What that means for `verifyRoute`

Against either origin today, one hop is `unavailable` and the SDK says so:

```
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --allow-candidate
  gateway  -> verifiable (see below)
  provider -> not requested

anonrouter-verify route --origin https://api.anonrouter.ai --provider venice --model …
  gateway  -> unavailable: no pinned gateway policy for this origin
  provider -> reachable, subject to your API key
```

The SDK deliberately offers **no way to verify hop 1 at one origin while sending
content to another**. That configuration would produce a verdict about a machine
that is not on your request path, which is worse than no verdict at all.

## What the confidential origin returns

A fresh-nonce fetch returns a document with `binding`, `binding_hash`, `quote`,
`event_log`, `app_compose`, `vm_config`, `issued_at_ms`, `info`, and `note`. The
SDK verifies all of it. Two properties were confirmed independently on the day:

- **The transport binding holds.** The leaf SPKI observed with `openssl` on the
  public connection equals `binding.tls_spki_sha256` exactly. That is the check
  that turns "somebody named a certificate" into "the TD holds this key".
- **The chain to Intel's roots verifies.** With the reviewed DCAP engine and
  collateral fetched from Intel PCS, the quote verifies with `tcb_status`,
  `qe_tcb_status` and `platform_tcb_status` all `UpToDate`, no advisories, and
  `debug: false`. The engine's own view of `mr_td`, the RTMRs and `report_data`
  agrees with the SDK's parse of the same bytes.

## Why the shipped pin still does not match, and why that is correct

The shipped `candidate` pin fails against the live plane on `app_id_pinned`,
`compose_hash_pinned`, `release_pinned` and `platform_measurements_pinned`, and on
nothing else. Every structural and cryptographic check passes. That is a stale
allowlist, not a broken verifier, and the live suites assert exactly that
distinction.

One new fact strengthens the 2026-08-29 decision to reject the refresh rather than
weakening it. Between 2026-08-29 and 2026-08-30 the plane's `compose_hash` changed
(`d5fc4ac2…` to `07d803b3…`) while `release_id` stayed **`anonrouter-tee@xl-7b1b12a`**.
The release id is injected by an environment variable and carries no measurements,
so it did not move when the measured configuration did. Pinning a public SDK's
trust anchor to a release id that demonstrably does not track the measurements
would pin nothing.

## What this inventory does not establish

- **Whether hop 2 works end to end.** Confirming that needs a real API key, which
  is the one input an owner has to supply. With a fabricated key both origins
  answer as expected for an unauthorized caller, so "the route is absent" and
  "your key was refused" cannot be told apart from outside. `ANONROUTER_API_KEY`
  plus a callable `(provider, model)` pair would close it.
- **Whether the confidential origin can mint attestation tickets for an
  authorized caller.** The 404s above were observed without credentials.
- **Anything about the code behind the measurements.** Attestation names the
  build; reviewing the source behind that compose hash is a separate act.

## Reproducing this

Every row above comes from `curl` and `openssl` against public endpoints. The SDK
reproduces the interesting parts:

```bash
anonrouter-verify doctor --origin https://api.private.anonrouter.ai
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --allow-candidate
node scripts/capture-gateway-pins.mjs https://api.private.anonrouter.ai
```

The live test suites run the same probes with negatives attached:

```bash
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.private.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://api.anonrouter.ai \
  npm test          # in js/
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.private.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://api.anonrouter.ai \
  pytest -q         # in python/
```
