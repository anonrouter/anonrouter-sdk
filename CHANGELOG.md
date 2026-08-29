# Changelog

All notable changes to the AnonRouter SDKs are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
packages follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The three packages (`@anonrouter/confidential`, `@anonrouter/client`,
`anonrouter-confidential`) are versioned together, and share one set of
measurement pins and known-answer vectors, so a given version means the same
verification in both languages. They do not have to be *released* together: the
0.1.0 npm packages ship ahead of the Python one, which is still working through
PyPI onboarding. Until it lands, install the Python package from a clone.

## [0.1.0] - Unreleased

Initial public release.

### Added
- `@anonrouter/confidential` (npm): independently verify AnonRouter TEE / E2EE
  routes and run end-to-end-encrypted confidential inference for the `near-ai`,
  `venice`, and `chutes` providers, plus `tinfoil` TEE verification via the
  optional `tinfoil` dependency.
- `@anonrouter/client` (npm): thin, dependency-free client for the public
  (plaintext / TEE / private) routes over the two-request ticketed flow.
- `anonrouter-confidential` (PyPI): the Python twin of `@anonrouter/confidential`,
  sharing the same measurement pins and known-answer test vectors.
- `shared/measurements.json` reviewed measurement pins and `shared/vectors/`
  language-neutral known-answer vectors, with a cross-language parity gate.
- `shared/vectors/attestation.json`: known-answer verdict vectors covering Venice,
  Chutes, NEAR, Tinfoil, and the unknown-provider path. Each case pins the full
  verdict (status, verification level, reason, and the exact set of failed required
  checks), and both language suites must reproduce it.
- `verifyAttestation` / `verify_attestation` accept an optional `upstreamModel`
  (`upstream_model` in Python), pinning the provider-native model id the evidence
  must attest. Enclaves name themselves in provider terms rather than by
  AnonRouter's catalog id; normally the gateway reports the mapping and the SDK
  uses it, so this is only needed to pin the binding yourself or to talk to a
  gateway old enough not to report it.

### Fixed
- **Attestation verification did not work against every deployment.** Both packages
  now mint a content-free attestation ticket and present only that ticket to the
  attestation endpoint, falling back to the key-authenticated read endpoint when a
  route cannot be issued a ticket. Previously the JavaScript package used only the
  key-authenticated path, which some deployments do not serve: where attestation is
  reached through the credential-isolated relay, a request carrying an account key
  is refused there and `verifyAttestation` could only ever return an authorization
  error. The ticketed path also reports `upstream_model`, which the model binding
  needs, so this additionally fixes verification of routes whose provider-native id
  differs from the catalog id.
- **Python: confidential chat on Chutes never worked.** The inference ticket
  reserved the caller's `max_output_tokens` instead of the route's full output
  ceiling, so the gateway rejected every opaque request with
  `opaque_e2ee_requires_full_output_reservation`. The ceiling is now resolved from
  the public catalog for the exact route, matching the JavaScript package. The
  caller's limit still caps the actual generation: it travels inside the encrypted
  body, not in the ticket.
- **Python: the default HTTP timeout aborted valid Chutes requests.** A whole-body
  opaque request streams nothing, so the enclave generates the entire completion
  before the first byte arrives, which routinely exceeded the old 60 second
  default. The default is now 300 seconds with a short 10 second connect timeout.
- **Python: Tinfoil routes could not be verified at all.** `verify_attestation`
  always minted an attestation ticket, which the gateway only issues for
  E2EE-capable models, so Tinfoil failed with `model_not_e2ee`. Verification now
  uses the authenticated read endpoint, which serves TEE and E2EE routes alike.
  Verification carries no content, so there is nothing there for a ticket to
  protect.
- **Python: the Tinfoil verifier refused to run without the optional `tinfoil`
  package**, returning a failed verdict where the JavaScript package returned
  `sdk-verified` for the same document. The twins must not disagree about what the
  same evidence means. The document validation now runs in both. Shared vectors
  now cover Tinfoil so this cannot drift again.
- **Passing checks no longer carry failure text.** Several checks in both languages
  passed their failure detail unconditionally, so a passing verdict printed lines
  like `PASS instance_0_measurement_allowlist: measurements not in accepted
  allowlist`. Details are now attached only when a check actually fails.
- The Chutes certificate-possession checks no longer degrade to advisory in a Node
  ESM process. `node:crypto` is now resolved synchronously via
  `process.getBuiltinModule`, so certificate possession, certificate freshness, and
  the signed-body bindings are required and actually verified by default in Node,
  matching the Python package. Previously a verdict could read `ok` in Node while
  those three bindings went unchecked, unless the caller had separately awaited
  `enableNodeCrypto()`. A browser build still degrades only that one sub-check, as
  intended.

[0.1.0]: https://github.com/anonrouter/anonrouter-sdk/releases/tag/v0.1.0
