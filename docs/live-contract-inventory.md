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

**The headline: both evidence hops and encrypted inference share the confidential
origin; content-free ticket minting and catalog lookup use the control origin.**

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

This is the production trust split, not a missing route. The API key and
identity/billing metadata go to the public control plane. The resulting
single-use ticket is presented to the confidential plane, where both attestation
hops and encrypted request content stay on one exact, attested origin.

### What that means for `verifyRoute`

Use the confidential origin as `--origin` and the public control plane as
`--control-origin`:

```
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --dcap \
  --require hardware_verified
  gateway  -> hardware_verified
  provider -> not requested

anonrouter-verify route --origin https://api.private.anonrouter.ai \
  --control-origin https://api.anonrouter.ai --provider venice --model …
  gateway  -> verified on the same confidential origin used for content
  provider -> verified from raw provider evidence, subject to your API key
```

`--control-origin` does not split verification from content. It only moves the
content-free API-key operations. The SDK deliberately offers **no way to verify
one inference origin while sending content to another**.

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

## Why the shipped pin now matches

The SDK now ships the production policy derived from the independently retained
release manifest whose SHA-256 is
`46da4d4210c21ea76681ef044dd2da29d8a3a4cff135348ef9f168f6a09c6bf4`.
The manifest binds the production origin, reviewed source, exact measured
app-compose, content-plane image, app and instance ids, TLS SPKI and platform
measurements. A live fresh-nonce run matches every pin and reaches
`hardware_verified` with Intel TCB status `UpToDate`.

The earlier 2026-08-29 refresh remains recorded as rejected because that review
did not have a production-origin manifest. That gap was later closed. The
`release_id` still is not considered sufficient identity by itself: app id,
compose hash and every platform measurement are also pinned. The manifest names
three third-party source-to-digest provenance gaps; those remain explicit
supply-chain limitations rather than being rounded up to verified.

## What this inventory does not establish

- **Whether hop 2 works for a particular account and model.** That final check
  needs a real inference-scoped API key and a callable `(provider, model)` pair.
  The key is used only at the control origin to mint a single-use ticket; it is
  never sent to the confidential relay or provider.
- **Anything about the code behind the measurements.** Attestation names the
  build; reviewing the source behind that compose hash is a separate act.

## Reproducing this

Every row above comes from `curl` and `openssl` against public endpoints. The SDK
reproduces the interesting parts:

```bash
anonrouter-verify doctor --origin https://api.private.anonrouter.ai
anonrouter-verify gateway --origin https://api.private.anonrouter.ai --dcap \
  --require hardware_verified
anonrouter-verify route --origin https://api.private.anonrouter.ai \
  --control-origin https://api.anonrouter.ai --provider venice --model MODEL
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
