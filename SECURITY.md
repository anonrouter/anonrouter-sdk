# Security policy

## Reporting a vulnerability

Email **contact@anonrouter.ai** with the details and, if you can, a proof of
concept. Please do not open a public issue for a security report. We will
acknowledge receipt and work with you on a coordinated disclosure timeline.

## The measurement pins are security policy, not provider assertions

The values in `shared/measurements.json` are the trust anchors for this whole
repo. Treat them accordingly:

- They are **operator-reviewed security policy**. A human reviews each pin
  against the provider's published evidence before it is accepted, and the pin is
  then an immutable, code-reviewed entry in this repository.
- They are **not mutable provider assertions**. The SDK does not accept whatever
  measurement a provider happens to return at request time. It checks the
  provider's live evidence against these pinned values. A provider that changes
  its measurements does not silently change what the SDK will accept: a human has
  to review and add the new pin first.

Because the pins are policy rather than live data, an attacker who can influence
a provider's runtime response still cannot move the goalposts. They would have to
land a reviewed change in this repository.

## How a pin rotation works

When a provider ships a new enclave, release, or compose file, its measurements
change and the pins must be rotated. The process is deliberate:

1. **Verify the provider's published evidence.** Confirm the new release or
   measurement against the provider's own transparency log, signed release, or
   published attestation (for example Tinfoil's Sigstore transparency log entry
   for a release tag, or NEAR's pinned compose file at a specific repository
   commit). Do not trust a value that is only asserted at request time.
2. **Add a new immutable entry.** Append the new measurement to the `accepted`
   list for that provider in `shared/measurements.json`. Prefer adding alongside
   the current entry over replacing it, so in-flight deployments keep verifying
   during the rollover. Record the source and a dated version string.
3. **Bump the policy version.** Update the provider's `version` field so the
   change is visible and auditable in history.
4. **Sync and let CI enforce parity.** Run `node scripts/sync-shared.mjs` to
   regenerate the per-package copies, then commit. CI runs
   `node scripts/check-parity.mjs`, which fails the build if any copy drifts from
   the canonical file, so the JS and Python packages can never disagree about
   what is pinned.

Retire an old pin only after the corresponding provider deployment is fully gone,
and note the retirement in the version string.

## Trust model: what verification does and does not prove

This SDK is built to be honest about its own limits. The headline guarantee it
earns is **prompt confidentiality on the E2EE providers**: on `near-ai`,
`venice`, and `chutes` your request is encrypted to a key bound to the attested
enclave, and AnonRouter's relay only ever sees ciphertext. The following residual
trust boundaries are known and deliberate. Understand them before you rely on a
route.

- **No hardware signature-chain verification (ceiling is `provider-attested`).**
  The TDX quote is parsed and its measurements are checked against the reviewed
  pins, but the ECDSA/DCAP chain to the Intel roots (and the NVIDIA NRAS chain) is
  not verified client-side. A passing check therefore proves "this evidence is
  internally consistent and matches reviewed pins," not "this silicon is genuine."
  The SDK never prints `hardware-verified` for this reason. Wiring a real
  browser/Python DCAP+NRAS verifier is the main upgrade path.

- **NEAR/Venice responses are confidential but not authenticated.** For `near-ai`
  and `venice` the client's public key travels in a request header and responses
  are sealed to it without an enclave signature, so a malicious relay that drops
  the real enclave stream could return a **fabricated** answer the client would
  still decrypt. This does not expose your prompt (confidentiality holds), but it
  means response *integrity* on those two providers rests on trusting the relay.
  `chutes` is not affected: its response key is carried inside the encrypted
  request body, so only the enclave can produce a decryptable reply.

- **The NEAR encryption key is bound indirectly.** The NEAR verifier binds
  `sha256(signing_address ‖ tls_cert_fingerprint)` into the quote's report data,
  and the client encrypts to the enclave's `signing_public_key`. The SDK does not
  yet independently check that `signing_public_key` derives from the attested
  `signing_address`, so that last hop relies on the provider evidence being
  self-consistent. Adding an explicit derive-and-check (as the Venice verifier
  already does for its secp256k1 address) is a tracked hardening item.

- **Tinfoil `sdk-verified` reflects a verification document.** The `tinfoil`
  verdict returned by `verifyAttestation` / `verify_attestation` validates the
  fields of a Tinfoil verification document (security-verified flag, step
  outcomes, code fingerprint) against the reviewed allowlist. In the client flow
  that document is supplied by the gateway. To verify Tinfoil independently of the
  gateway, run Tinfoil's own verifier (the optional `tinfoil` dependency, exposed
  here as `verifyTinfoilEnclave`) in your process. Tinfoil is also a TEE route, so
  it is attested but not content-private from AnonRouter.

If any of these boundaries matters for your use case, prefer an E2EE provider for
confidentiality, treat NEAR/Venice response integrity as relay-trusting, and open
an issue or email us if you need the stronger checks prioritized.
