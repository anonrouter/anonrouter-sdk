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
- **`verifyRoute()` / `verify_route()`, the stable verdict contract.** The earlier
  `verify()` reported internal `verification_level` values, which say WHO attested
  rather than WHAT was checked, so a reader had to already know the trust model to
  rank them. Five ordered states replace that: `hardware_verified`,
  `cryptographically_checked`, `policy_matched`, `untrusted`, `unavailable`. Gate
  with `atLeast()` / `at_least()` so a threshold keeps meaning the same thing if a
  state is later inserted into the scale. `untrusted` and `unavailable` are both
  failures and deliberately distinct: "we looked and it failed" and "we could not
  look" call for different responses.
  - CROSS-BINDING is the property this adds over calling both hop verifiers.
    Each verifier only ever sees its own evidence, so neither can notice that the
    gateway attested itself perfectly while serving a different provider, model, or
    privacy class than the caller asked for. Any disagreement lands in
    `bindingMismatches` and forces `untrusted`, however strong the hops were.
- **A first-class DCAP path, so `hardware_verified` is reachable without writing
  an adapter.** `@anonrouter/confidential/dcap` and
  `anonrouter_confidential.gateway.dcap` speak the exact wire contract of
  AnonRouter's reviewed offline engine, and acquire the Intel-signed collateral it
  needs (it performs no network access, on purpose). Verified live against a real
  TDX CVM in both languages: Intel `tcb`, `qe` and `platform` statuses all
  `UpToDate`, no advisories, in about 0.8 s including the collateral fetch.
  - No engine is bundled, and the reason is written down rather than implied.
    Publishing prebuilt binaries would mean asserting that a binary we did not
    build reproducibly is the reviewed one, and a hand-rolled JavaScript or Python
    reimplementation would be an unreviewed version of the single component whose
    failure mode is printing `hardware_verified` for a forged quote.
  - The engine's SHA-256 can be pinned, so a swapped binary is a refusal rather
    than a different answer. The engine's own view of the TD is compared against
    the SDK's independent parse of the same bytes, so a "verified" verdict
    describing a different TD is refused.
  - Engine discovery keeps the rule that makes it safe: a source that is NAMED but
    unusable resolves to nothing. An explicit path that does not exist does not
    fall through to the environment, and the environment does not fall through to
    PATH.
  - `describeDcapInstallation()` / `describe_dcap_installation()` reports the
    engine that would actually run, its digest, the host's target triple, and, when
    there is none, what to install and the fact that verification stays capped
    rather than silently downgrading.
- **`anonrouter-verify`, an operator command in both ecosystems.** Prints one
  machine-readable JSON document and exits 0 only if the requested assurance was
  established, so a verdict can gate a deploy rather than only inform one. Three
  exit codes, and the third is the point: 0 met, 1 not met, 2 the command itself
  was wrong. Collapsing 2 into 1 would let a typo in a CI job read as a
  verification answer.
  - `gateway` is credential-free, enforced structurally: hop 2 is never attempted
    and the only request is the unauthenticated attestation fetch, so a caller
    cannot mint a ticket with a real key against an origin they have not verified.
  - `route` reads an API key only from an environment variable. `--api-key` is
    refused BY NAME rather than ignored, because argv is visible in the process
    table and lands in shell history.
  - It never prints a key, a ticket, request content, or the raw evidence body,
    which is ~66 KB of internal compose topology. A test asserts that by substring.
  - `doctor` reports what the machine can establish and does NOT gate: a missing
    engine is information, and exiting nonzero would make it useless in a setup
    script.
- **`shared/vectors/dcap.json`**: known-answer vectors pinning the DCAP wire
  contract. How a PCK chain and its FMSPC are read out of a quote (including a
  decoy: the same OID with a 4-byte value, which is NOT an FMSPC and would point
  the whole TCB lookup at a platform that does not exist), how Intel's signed
  documents are sliced without invalidating their signatures, and every way a
  malformed engine verdict must fail to parse rather than be coerced into a pass.
  Its expectations are stated independently of the implementation.
- **`shared/vectors/cli-contract.json`**: the command's exit codes, document shape,
  the inputs it must refuse before contacting anything, and the substrings it must
  never print.
- **`scripts/check-cli-parity.mjs`**: runs both real `anonrouter-verify`
  executables over inputs that need no network and requires the JSON they print and
  the codes they exit with to be identical.
- **`scripts/smoke-artifacts.mjs`**: builds the publishable artifacts, installs
  them into empty environments, and uses them there. Every other gate runs against
  the working tree, which says nothing about whether a `files` entry, an `exports`
  map, a `bin`, or a wheel's package data is right; those failures are invisible
  until somebody installs the thing.
- **Live-CVM negatives.** Both suites now take ONE genuine document from a real
  confidential VM and change exactly one thing, fifteen times, requiring the verdict
  to fail on the exact check that covers it: a replayed nonce, a wrong origin, a
  rewritten release id or TLS fingerprint, a flipped `report_data` or RTMR byte, the
  debug attribute set, a rewritten event digest or compose-hash payload, a supplied
  digest that does not commit to its payload, an edited manifest, a `vm_config`
  naming an OS image the hardware never measured, stale evidence, an observed
  certificate the TD did not attest, a different key provider, and platform
  measurements that do not match. A live "it verified" on its own is nearly
  worthless; a verifier that returned ok for everything would produce it too.
- **`docs/live-contract-inventory.md`**: what each live origin actually serves,
  observed read-only. Hop 1 and hop 2 are not both reachable at one origin today,
  and the SDK had no honest place saying so.
- `examples/verify-then-call.ts` and `examples/verify_then_call.py`: gate before
  sending, re-verify hop 1 at send time with a fresh nonce, and state what the
  verdict did not cover. Examples are now type-checked in both languages.

### Added (earlier in this release)
- **Verification of AnonRouter's own confidential routing plane (hop 1).**
  Previously the SDK could verify only the far end of the path: that the upstream
  provider ran a request inside an enclave. It could establish nothing about
  AnonRouter itself, so a caller had no way to know whether the data plane routing
  the request was the reviewed build, or ran in a confidential VM at all. The two
  hops are kept separate because neither implies the other.
  - `verifyGateway()` / `verify_gateway()` verify `GET /v1/gateway/attestation`
    against locally pinned measurements: report_data must equal SHA-512 of the
    canonical binding, the event log must replay to the quote's RTMRs, each RTMR3
    digest must commit to the payload printed beside it, the attested app-compose
    manifest must be the measured one and must declare private logs and
    digest-pinned images, and app id, compose hash, release, and origin must all be
    on the local allowlist.
  - `verify()` establishes both hops and reports them separately. `trusted` covers
    only the hops the call asked for, and `gateway.requested` says which way that
    went, so a report can never read as if it had covered a hop it skipped.
  - `chat({ requireGateway })` / `chat(require_gateway=...)` gate on hop 1 before
    the first authenticated call, so a failure means no ticket was spent and no
    plaintext reached the wire.
  - The DCAP chain remains a pluggable port (`chainVerifier` / `chain_verifier`).
    Without one the ceiling stays `provider-attested`, and a policy that demands
    hardware verification fails closed rather than quietly downgrading.
  - `shared/gateway-policies.json`: origin-keyed pins for the confidential plane,
    synced into both packages and covered by the parity gate. An unknown origin
    resolves nothing and fails closed. The plane shipped today is marked
    `candidate` (pre-release; its measurements move every release) and needs an
    explicit opt-in to resolve.
  - `shared/vectors/gateway-binding.json`: known-answer vectors pinning the
    canonical binding serialization and its SHA-512 digest. That digest is what a
    TD places in report_data, so a one-byte difference between the two languages,
    or against the in-TEE producer, would make a verifier reject every genuine
    quote. Both languages reproduce the vectors exactly.
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
- **The reference subprocess chain verifier did not fit AnonRouter's own engine,
  while documenting that it did.** `createSubprocessChainVerifier` wrote a bare
  quote on stdin and read a camelCase `tcbStatus`; the reviewed engine reads a JSON
  request carrying Intel collateral and prints snake_case `tcb_status`. Pointing
  one at the other produced "engine produced no usable verdict", which fails closed
  but for the wrong reason and teaches nobody anything. The generic adapters now
  document their own minimal contract and point at `./dcap` for the real engine.
- **`quote_signature_chain` could not say why it failed.** The chain verifier port
  reported only a boolean and an optional TCB status, so "the engine binary was not
  found" and "the signature is invalid" looked identical in a verdict. The outcome
  now carries a content-free detail, and both languages surface it.
- **The engine and the local policy could disagree about acceptable TCB.** The
  chain verifier is now a factory the client prepares against the exact quote it
  just fetched, and it is handed the resolved policy's `acceptableTcbStatuses`. An
  engine defaulting to `UpToDate` while the policy also accepted
  `SWHardeningNeeded` would have refused quotes the policy allowed, and the caller
  would have had no way to see why.
- **`anonrouter-verify route` reported nothing about hop 2 when hop 1 could not be
  attempted.** An origin with no shipped pin aborted the whole command. The two
  hops are separate questions and an unattemptable one must not suppress the other;
  it still cannot prop the verdict up, since the overall state is the weakest
  requested hop.
- **A client could be pointed at a plaintext origin.** `createClient` /
  `ConfidentialClient` accepted any `baseUrl`, including `http://` and URLs
  carrying a path or credentials. Over plaintext the API key travels in the clear
  and the origin a gateway quote binds cannot mean anything, which would make an
  attested route decorative. The base URL must now be a bare https origin;
  loopback http is available for local development behind an explicit
  `allowInsecureHttp` / `allow_insecure_http`.
- **`verifyAttestation` did not bind the route the gateway served.** `chat()`
  checked that the returned evidence was for the provider that was requested, but
  the verify path did not, so a substituted route surfaced as "malformed evidence"
  rather than as AnonRouter having routed elsewhere. Both the echoed provider and
  the echoed privacy class are now bound, in both languages.
- **The pin drift gate wrote the files it was checking.** `check-parity.mjs`
  imported `sync-shared.mjs`, whose top-level loop runs on import, so the
  read-only gate re-synced every copy before comparing it and could never have
  reported drift. The file map moved to `scripts/shared-files.mjs`, which has no
  side effects on import.
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
