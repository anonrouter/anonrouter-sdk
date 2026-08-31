# Release readiness for 0.1.0

What has actually been verified about this release, and what has not. Recorded
2026-08-30 against `sdk-production-readiness`.

The point of this file is the second half. A list of green checks is easy; a list
of what a green check does **not** cover is what makes the first list worth
anything.

## Gates, with exact counts

Every one of these runs in CI, and every one was run locally on the commit this
file lands with.

| Gate | Command | Result |
| --- | --- | --- |
| JS typecheck | `npm run typecheck` (in `js/`) | clean, covering `src`, `test`, `examples` and `scripts` |
| JS tests, offline | `npm test` (in `js/`) | **402 passed, 39 skipped** in `@anonrouter/confidential`; **12 passed** in `@anonrouter/client` |
| JS build | `npm run build` (in `js/`) | clean |
| End-to-end self-test | `npm run example:selftest` | PASS: venice and chutes, verify plus E2EE chat, relay saw ciphertext only |
| Python tests, offline | `pytest -q` (in `python/`) | **316 passed, 41 skipped** |
| Python types | `mypy` (in `python/`) | clean, 35 files, `src` and `examples` |
| Python lint | `ruff check .` (in `python/`) | clean |
| Measurement pin parity | `node scripts/check-parity.mjs` | all four per-package copies match `shared/` |
| Command parity | `node scripts/check-cli-parity.mjs` | 4/4 cases, both real executables, identical documents and exit codes |
| Artifact installs | `node scripts/smoke-artifacts.mjs` | **22/22**, now including that `client.images.generate` and `client.audio.speech.create` are reachable from the installed artifact in both languages |
| **Live, JS** (no engine) | `npm test` with both live origins | **437 passed, 4 skipped** |
| **Live, Python** (no engine) | `pytest -q` with both live origins | **352 passed, 5 skipped** |

The offline skips are opt-in live/platform cases. They skip with a stated reason
and never fabricate a result. Setting `ANONROUTER_LIVE_GATEWAY_ORIGIN` and
`ANONROUTER_LIVE_PUBLIC_ORIGIN` runs all but the engine-gated cases; the
remaining 4 (JS) and 5 (Python) need `ANONROUTER_DCAP_VERIFIER_BIN`.

**The engine-gated rows were not re-run for this commit.** No
`anonrouter-dcap-verifier` was available in this environment, so the
`hardware_verified` live result and the live provider-route proof recorded below
stand as **previously recorded** for 0.1.0 and are not re-asserted here. Nothing
in this commit touches the verification path; the media surface added here is a
separate code path with its own live probes, listed next.

## Ticketed media, verified

| Gate | Result |
| --- | --- |
| Wire-contract parity | `shared/vectors/media-contract.json`, 6 request cases and 8 refusals, replayed by **both** suites |
| JS media unit + negatives | **90 passed** (`js/confidential/test/media.test.ts`) |
| JS two-origin end-to-end | **11 passed** over real loopback sockets (`media-e2e.test.ts`) |
| Python media unit + negatives | **93 passed** (`python/tests/test_media.py`) |
| Python two-origin end-to-end | **12 passed** over real loopback sockets (`test_media_e2e.py`) |
| **Live media contract, JS** | **10 passed** against the real origins, credential-free, zero spend |
| **Live media contract, Python** | **10 passed**, the same probes |

The live media probes are the only live gate in this file that needs **no key and
no engine**, so they are reproducible by anyone:

```bash
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.private.anonrouter.ai \
ANONROUTER_LIVE_PUBLIC_ORIGIN=https://api.anonrouter.ai \
  npx vitest run test/live-media.test.ts     # in js/confidential
```

What they established on 2026-08-30, against production:

- `api.private.anonrouter.ai` serves **both** media routes and fails closed with
  **401 `ticket_required`** on a request carrying no ticket — including a request
  with an empty body, so the refusal happens before a body is even parsed.
- That origin answers **404** for `/v1/inference/tickets`: it does not mint, which
  is what keeps the API key off the content host by construction rather than by
  the client's good manners.
- `api.anonrouter.ai` serves **no** media content at all — **503
  `media_disabled`** for both routes — and does serve the mint, refusing an
  unauthenticated call (403 CSRF without a bearer header, 401 with a bogus one).

Two planted negatives guard the probes themselves: each suite asserts its probe
helper sends no `authorization` and no `x-anonrouter-ticket` header, so a future
edit cannot quietly make these billable.

### What the media gates do NOT cover

**No successful generation has been performed by any test in this repository.**
That needs a real inference-scoped API key and a callable `(provider, model)`
pair, and it spends money. Everything above establishes that the two-origin
exchange is shaped correctly, that both origins enforce their halves of it, and
that the client refuses rather than degrades — not that a given account can
generate a given image today. `js/confidential/examples/media.ts` and
`python/examples/media.py` perform a real generation and are deliberately not run
by CI.

## What the live run establishes

Against `https://api.private.anonrouter.ai` with the reviewed
`anonrouter-dcap-verifier` present, both languages reach **`hardware_verified`**:

- a fresh 32-byte nonce comes back inside the quote's `report_data`, which equals
  SHA-512 of the canonical binding we recomputed;
- the event log replays to the quote's RTMR0..RTMR3, with RTMR3 digests derived
  from each event's own fields rather than read out of the log;
- the quote's ECDSA signature chains to Intel's roots under the engine's pinned
  root CA, with `tcb_status`, `qe_tcb_status` and `platform_tcb_status` all
  `UpToDate` and no advisories;
- the engine's own view of `mr_td`, the RTMRs and `report_data` agrees with the
  SDK's independent parse of the same bytes;
- the leaf SPKI observed on the origin equals the one the TD attests; and
- the whole thing takes about 0.8 s including the Intel collateral fetch.

Fifteen negatives per language run against the same genuine document, each
changing exactly one field and each required to fail on the exact check that
covers it. Four more run with the engine, including a quote tampered inside the
signed body, which is refused at the **signature** and which no amount of
structural checking could catch.

## Live provider-hop proof

*Previously recorded, and not re-run for the media commit: the engine and the
inference-scoped key it needed were not available in that environment.*

Using a fresh inference-scoped key that was read from a mode-0600 temporary file
and never printed, both SDK implementations verified provider `venice`, model
`openai/gpt-oss-20b`, across the production split origins:

- the key and content-free ticket requests went only to
  `https://api.anonrouter.ai`;
- gateway/provider evidence and encrypted inference went only to
  `https://api.private.anonrouter.ai`;
- hop 1 reached **`hardware_verified`** under the shipped production pin and the
  SHA-pinned DCAP engine;
- hop 2 reached **`cryptographically_checked`**, with no binding mismatch;
- each language completed a bounded encrypted inference and decrypted `OK`;
- request instrumentation found neither the plaintext canary in a relay body nor
  an Authorization header on the confidential origin.

The first two Python inference attempts returned HTTP 503 after verification; a
diagnostic retry completed with 200 from gateway attestation, ticket minting,
provider attestation, inference ticket minting and the encrypted relay. No check
was bypassed and no plaintext fallback exists.

## What a green run does not cover

- **Hop 2's ceiling is `provider-attested` and stays there.** Several provider
  routes run GPU enclaves whose NVIDIA attestation chain is not available to
  verify. Chaining only the CPU quote and printing `hardware_verified` would claim
  more than was checked.
- **The shipped gateway pin is release-specific.** It now matches the live plane
  because the production-origin release manifest was retained independently and
  reviewed. A later deployment with a different app id, compose hash or platform
  measurement will fail closed until a new reviewed SDK policy ships.
- **No package is published.** All three 404 on their registries. The artifacts
  are built and installed into empty environments on every CI run, so what a
  registry would carry is what is being tested; publishing is an owner decision.
- **No DCAP engine is distributed with these packages**, so a user reaching
  `hardware_verified` has to install one. `anonrouter-verify doctor` says so and
  says what to do. Without it the ceiling is `cryptographically_checked` and a
  policy requiring hardware verification fails closed.
- **The reproducible engine artifact is not yet attached to a public release.**
  Two clean linux/amd64 builds in the digest-pinned Rust 1.94.1 Bookworm builder
  are byte-identical at SHA-256
  `c7d7bc21bf44a1a606e44832b6cbab1f4b74eade06743ee2324edbf396db8d67`,
  and that ELF verified a fresh live quote. Registry/release publication remains
  an owner action.
- **`anonrouter-verify` observes TLS on its own connection**, not the one that
  carried the attestation request, because `fetch` does not expose it. Conclusive
  on a mismatch; weaker than a same-connection observation on agreement. The
  output says which it was.
- **Attestation proves which code ran, not that it behaves well.** Reviewing the
  source behind a pinned compose hash is a separate act.
- **No media generation has been performed by any test.** The media gates prove
  the exchange is shaped correctly and that both origins enforce their halves;
  they do not prove a given account can generate a given image or clip today.
  That needs a real key and spends money.
- **Ticketed media is not end-to-end encrypted, and is not described as such.**
  The prompt reaches the confidential origin as plaintext. What protects it is
  the origin split (the host holding the prompt never holds the account
  credential) plus the TDX enclave the confidential plane runs in — not
  client-side encryption. E2EE chat is the surface where AnonRouter sees only
  ciphertext. Anyone reading `images.generate` on the confidential client as
  "encrypted like `chat`" is reading more than is claimed.

## One thing the suites assert that is easy to miss

There is no environment variable that weakens a verdict. Twelve plausible spellings
of an escape hatch (`ANONROUTER_INSECURE`, `ANONROUTER_SKIP_VERIFY`, `NODE_ENV=test`,
`CI=true`, and so on) are set, and the verdict for the same evidence must come out
IDENTICAL, not merely also-failing. The deliberate opt-ins are checked from the
other side: the published pin cannot be changed through the environment, a plaintext
remote origin is refused even with `allowInsecureHttp`, and the command still
refuses `--require hardware_verified` without `--dcap`.

Behavioural tests can only cover the names somebody thought to try, so there is a
structural one beside them: the four modules that decide whether a verdict passes
(`gateway/verify`, `gateway/policy`, `verify/state`, `verify/route`) may not
contain a read of the environment at all, in either language.

## Artifacts, as built

| Artifact | Size | Contents |
| --- | --- | --- |
| `anonrouter-confidential-0.1.0.tgz` | 256,205 B | `dist`, `src`, README, LICENSE |
| `anonrouter-client-0.1.0.tgz` | 9,003 B | 6 files |
| `anonrouter_confidential-0.1.0-py3-none-any.whl` | 112,223 B | package plus the measurement pins as package data |
| `anonrouter_confidential-0.1.0.tar.gz` | 233,696 B | source, tests and package data from the sdist |

`src` ships beside `dist` on purpose: this package's whole value is that you can
read what it checks, and the emitted source maps would otherwise point at files
nobody received.

## Reproducing all of it

```bash
# offline
cd js && npm ci && npm run typecheck && npm test && npm run build
cd confidential && npm run example:selftest
cd ../../python && pip install -e ".[dev,mlkem]" && pytest -q && mypy && ruff check .
cd .. && node scripts/check-parity.mjs
node scripts/check-cli-parity.mjs
node scripts/smoke-artifacts.mjs

# live, opt-in
export ANONROUTER_LIVE_GATEWAY_ORIGIN=https://api.private.anonrouter.ai
export ANONROUTER_LIVE_PUBLIC_ORIGIN=https://api.anonrouter.ai
export ANONROUTER_DCAP_VERIFIER_BIN=/path/to/anonrouter-dcap-verifier
(cd js && npm test) && (cd python && pytest -q)
```
