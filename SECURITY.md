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

### Rotating the hop-1 gateway pin

`shared/gateway-policies.json` describes AnonRouter's own confidential plane, and
it rotates on a different trigger and under a stricter rule: **the values must
never come from the gateway being pinned.** A server that could hand you the list
of builds you accept could always name itself. `scripts/capture-gateway-pins.mjs`
therefore writes an *observation* with an unresolved review checklist, and
deliberately cannot write a policy.

What has to be true before an observation becomes a pin:

1. every identity field appears in a release manifest produced and retained
   OUTSIDE the deployment, naming that exact origin, and not a preproduction one;
2. the `source` field records that manifest by SHA-256, so which document a pin
   came from stays checkable afterwards;
3. the served leaf key is observed on the wire, per hostname, and equals the one
   the quote names — the quote's claim about a key it holds is not enough on its
   own;
4. anything that could not be independently derived is written into `notes`
   rather than left to be assumed. The current entry says plainly that RTMR0 was
   not recomputed offline with `dstack-mr`, and why.

The plane's compose hash, release id and RTMR0 all move when the deployment
changes — RTMR0 moves on a resize alone, because it measures hardware
configuration. A stale hop-1 pin does not fail soft: it makes the SDK report the
live service as unverified. Rotating it is a release, not a maintenance edit, and
`shipped-pins` in both suites pins the source digest, compose hash and release id
so the change cannot arrive quietly.

## Trust model: what verification does and does not prove

This SDK is built to be honest about its own limits. The headline guarantee it
earns is **prompt confidentiality on the E2EE providers**: on `near-ai`,
`venice`, and `chutes` your request is encrypted to a key bound to the attested
enclave, and AnonRouter's relay only ever sees ciphertext. The following residual
trust boundaries are known and deliberate. Understand them before you rely on a
route.

- **Hardware signature-chain verification is available on hop 1 and requires an
  engine you install.** These packages bundle no DCAP engine, because publishing
  prebuilt binaries would mean asserting that a binary we did not build
  reproducibly is the reviewed one, and a hand-rolled JavaScript or Python
  reimplementation would be an unreviewed version of the one component whose
  failure mode is printing `hardware_verified` for a forged quote. What ships is a
  strict adapter (`@anonrouter/confidential/dcap`,
  `anonrouter_confidential.gateway.dcap`) to AnonRouter's reviewed offline engine,
  plus the Intel-signed collateral acquisition it needs. With the engine installed,
  hop 1 reaches `hardware_verified` having actually chained the quote's ECDSA
  signature to Intel's roots with an accepted TCB status. Without it, hop 1 is
  capped at `cryptographically_checked` and a policy requiring hardware
  verification fails closed with reason `quote_signature_chain` rather than
  silently accepting the weaker level.

  Two safeguards are worth knowing about. The engine's SHA-256 can be pinned, so a
  swapped binary is a refusal rather than a different answer. And the engine's own
  view of the TD (`mr_td`, the RTMRs, `report_data`) is compared against the SDK's
  independent parse of the same bytes; a "verified" verdict describing a different
  TD is refused, because a pass nobody can attribute to the quote in hand is worse
  than a failure.

- **Hop 2's ceiling is still `provider-attested`, and that is deliberate.** The
  provider TDX quote is parsed and its measurements checked against the reviewed
  pins, but the chain to the vendor roots is not completed there. Several provider
  routes run GPU enclaves whose NVIDIA NRAS chain is not available to verify, and
  chaining only the CPU quote while printing `hardware_verified` would claim more
  than was checked. A passing hop 2 therefore proves "this evidence is internally
  consistent and matches reviewed pins", not "this silicon is genuine".

- **Verifying one hop says nothing about the other.** The provider verifiers
  answer "did the upstream model provider run my request in an enclave?".
  `verifyGateway` answers "is the AnonRouter data plane I am connected to the
  exact reviewed build, in a confidential VM?". Neither implies the other, and a
  `verify()` report that skipped hop 1 says so in `gateway.requested` rather than
  letting `trusted` imply coverage it does not have.

- **A pinned policy must never come from the party it describes.** A gateway that
  could hand a client the list of builds the client accepts could always name
  itself. Gateway pins therefore ship inside the packages (or come from a policy
  you supply), never from a fetch against the gateway being verified, and an
  origin with no pin fails closed instead of falling back to what the server says.

- **Attestation proves which code ran, not that it behaves well.** Both hops
  establish that a specific measured build is running. Reviewing the source behind
  a pinned compose hash is what turns that into a reason to trust the build.

- **The confidential-plane pin shipped today is `candidate`, not `published`.**
  That plane is pre-release and its measurements move on every release, so
  resolving its pin takes an explicit opt-in. Treat a passing verdict against it
  as a development signal, not a production guarantee.

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
  outcomes, official verifier identity, exact GitHub repository, signed release
  identity, live code equality, and TLS key binding) against the fixed provider
  authority policy. In the client flow
  that document is supplied by the gateway. To verify Tinfoil independently of the
  gateway, JavaScript callers can run Tinfoil's own verifier through
  `verifyTinfoilEnclave()`; it loads the optional `tinfoil` npm dependency.
  Python callers should use Tinfoil's Python client directly for that independent
  check. The AnonRouter Python package validates the gateway-supplied document but
  does not bundle or run Tinfoil's verifier. Tinfoil is also a TEE route, so it is
  attested but not content-private from AnonRouter.

- **A collateral fetch tells Intel which platform you are verifying.** The DCAP
  engine performs no network access on purpose, so the SDK acquires the
  Intel-signed TCB info, QE identity and CRLs and hands them in. That request
  discloses the platform's FMSPC and the time to Intel. Supplying `collateral`
  yourself, from a mirror or from a cache, avoids it; the engine revalidates every
  byte under its pinned Intel root either way, so a mirror is not a party you have
  to trust.

- **`anonrouter-verify` observes TLS on its own connection.** The command compares
  the origin's leaf SPKI against the one the TD attests, but it opens its own TLS
  connection to do so, because `fetch` does not expose the certificate of the
  connection that carried the attestation request. Against a single origin
  terminating TLS inside one TD those are the same certificate, and a mismatch is
  still conclusive. Against a fleet presenting different keys per connection,
  agreement is weaker than a same-connection observation would be. The command says
  so in its output (`tlsSpki.source`) rather than leaving it to be assumed.

If any of these boundaries matters for your use case, prefer an E2EE provider for
confidentiality, treat NEAR/Venice response integrity as relay-trusting, and open
an issue or email us if you need the stronger checks prioritized.
