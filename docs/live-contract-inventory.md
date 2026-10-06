# Current SDK production contract

Verified 2026-10-06 with free, content-free checks. This is an observation;
the package policy comes from a reviewed retained manifest, never a download
from the gateway being verified.

- `api.anonrouter.ai`: default content/attestation origin, in-TD TLS.
- `api.private.anonrouter.ai`: attested alias with its own certificate.
- `control.anonrouter.ai`: stable API key, catalog and content-free tickets.

The v0.1.3 candidate ships policy `2026-10-06-content-plane-v1.0.26-pool`,
derived from retained accepted manifest SHA-256
`5abba136544c2f961072b70e3e0c8ac7c20fad126044ba4dc16c3e9b604b4829`.
App id `91c6a04ea7044f28d53142449c9badddbc30eff7`, compose
`ddaf9ec16ea2099a0bf1da5d394c421b4efe470f3a90c97ed8003123556841f0`,
release `anonrouter-tee@pool-a07ae22e`. JavaScript and Python verify both
origins as `hardware_verified` with real DCAP, observed TLS and no advisory gaps.
No private logging, identity, Intel TCB or hardware requirement was removed.

The direct `z-ai/glm-5.3-flash` encrypted route is advertised as `other`, using
`near-v2`. Both candidate SDKs independently accept its current raw evidence
as **provider-attested**, not hardware-verified. Publication/RPC collateral is
obtained by AnonRouter's measured worker; clients recheck the quote, replay,
release authority, nonce, model and encryption-key bindings. This is not an
independent client fetch from every authority. Require gateway verification when
relying on that fetch layer. Legacy `near-ai` remains supported for old/custom
contracts and is not silently rewritten to `other`.

Venice Gemma attestation passes. Venice `z-ai/glm-5.2` E2EE was disabled by the
operator for missing GPU evidence and is also refused early by this candidate;
its standard/private routes are unaffected. Provider transports in the package
are not promises of live catalog availability. Consult authenticated models.

No fresh paid inference was run in this repair. Mock encrypted round trips and
free live attestations do not establish current provider latency/capacity.
The [September 12 inventory](live-contract-inventory-2026-09-12.md) is historical.
