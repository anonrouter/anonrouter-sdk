# What the live origins actually serve

Observed 2026-09-01 with read-only, credential-free requests and fresh 32-byte
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
- compose hash `031015cb34bb1a95b57d6611f4d0f6d6ea26fd16d7ee91c5ff512f28658141d6`
- release id `anonrouter-tee@xl-7b1b12a`
- OS image hash `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033`

Each hostname has its own certificate and attested SPKI, as expected for
separate TLS identities. Both terminate inside the same measured trust domain.

## Why the shipped pin matches

`shared/gateway-policies.json` is derived from release manifest SHA-256
`ebb976a12b274afc34fb31459578e3ef107764d697ef074d1a82b27d79b1707c`.
The retained manifest binds reviewed source commit
`e792667508edc4e2c06b5f058cccd7b3e077b0a8`, the exact measured compose,
digest-pinned content image, deployment identity, canonical origin, TLS SPKI,
and platform measurements. The SDK additionally requires an `UpToDate` TCB,
fresh evidence, in-TD TLS, private logs, and hardware chain verification.

Three source-to-image provenance links remain explicitly unproven in that
manifest. They are supply-chain limitations; the SDK does not relabel them as
verified.

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
