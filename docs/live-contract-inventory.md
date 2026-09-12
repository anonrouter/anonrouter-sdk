# What the live origins actually serve

Observed 2026-09-11 with read-only, credential-free requests and fresh 32-byte
nonces. No prompt, account identity, API key, or mutation was involved.

This is an observation, not a trust anchor. The shipped pin comes from the
independently retained release manifest, never from the server being verified.

## Production hostname contract

| Host | Customer role | Credential-free observation |
| --- | --- | --- |
| `api.anonrouter.ai` | Canonical content, compatibility, and attestation origin inside the Intel TDX CVM | `/v1/gateway/attestation` 200; unauthenticated content routes fail closed |
| `control.anonrouter.ai` | Identity, catalog, billing, and content-free ticket minting | gateway attestation 404; authenticated routes reject a bogus key |
| `api.private.anonrouter.ai` | Attested alias for the canonical content origin | same app, instance, compose, release, and attested public key as the canonical origin |

The customer default is `https://api.anonrouter.ai/v1`. The private hostname is
an alias, not a second API customers need to configure. SDK ticketed calls send
the stable API key only to `control.anonrouter.ai`; the content request goes to
`api.anonrouter.ai` with a single-use ticket and no account credential.

## Current attested identity

The canonical name and alias report the same workload identity:

- app id `91c6a04ea7044f28d53142449c9badddbc30eff7`
- instance id `f4324b6186f90f101f18e274e8a81102510677d1`
- compose hash `9329f5078f9ca6fe658ec999d92a3d5d7661b7d81f60d6410ac3377ce6090f02`
- release id `anonrouter-tee@xl-7a84989`
- OS image hash `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033`

Each hostname has its own certificate and attested SPKI, as expected for
separate TLS identities. Both terminate inside the same measured trust domain.
The leaf key each quote names was also observed on the wire for that hostname,
so the binding is not the server's word about a key it might not hold.

## Why the shipped pin matches

`shared/gateway-policies.json` is derived from release manifest SHA-256
`d992b00b085d9d500d88ff926dea5c9916d29c103fe127e61273d6bde084e2a5`.
The retained manifest binds reviewed source commit
`3e4e9c818759b123a0cfd9a6f089c3a11769b1e1`, the exact measured compose,
digest-pinned content image, deployment identity, canonical origin, TLS SPKI,
and platform measurements. The SDK additionally requires an `UpToDate` TCB,
fresh evidence, in-TD TLS, private logs, and hardware chain verification.

Two source-to-image provenance links remain explicitly unproven in that
manifest: the base images of the in-CVM edge proxy and of the content-plane
runtime. They are supply-chain limitations; the SDK does not relabel them as
verified. A third link, the in-CVM TLS terminator, was closed by rebuilding it
from source.

## Confidential routes on the day this was recorded

The last authenticated catalog review was 2026-09-09: **9 callable `tee` /
`e2ee` routes across two providers.** The gateway identity above was observed
again on 2026-09-11; no credential was used merely to restate the route count.

| Provider | Class | Routes |
| --- | --- | --- |
| `tinfoil` | `tee` | 6 (5 text, 1 embedding) |
| `venice` | `e2ee` | 3 |

Chutes remains listed in the catalog but is emergency-disabled and has zero
callable routes. A disabled route is not counted as available merely because
the SDK contains its transport and verifier.

This number moves. Rows are enabled and disabled, and providers come and go —
`near-ai` has E2EE support in this SDK and no route in the catalog today. Treat
the table as a dated observation and get the current answer from the catalog:

```bash
cd js/confidential
npm run example:route-matrix -- --env-file ~/path/to/.env
```

## Reproduce the verification

```bash
anonrouter-verify doctor --origin https://api.anonrouter.ai
anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap \
  --require hardware_verified
anonrouter-verify route --origin https://api.anonrouter.ai \
  --control-origin https://control.anonrouter.ai \
  --provider venice --model MODEL
```

`--control-origin` only moves content-free, API-key-authenticated operations.
Both evidence hops and request content remain bound to the exact inference
origin being verified.

The live suites use the same split:

```bash
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://control.anonrouter.ai npm test

ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://control.anonrouter.ai pytest -q
```
