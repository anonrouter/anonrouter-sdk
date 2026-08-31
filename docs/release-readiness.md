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
| JS tests, offline | `npm test` (in `js/`) | **294 passed, 31 skipped** in `@anonrouter/confidential`; **6 passed** in `@anonrouter/client` |
| JS build | `npm run build` (in `js/`) | clean |
| End-to-end self-test | `npm run example:selftest` | PASS: venice and chutes, verify plus E2EE chat, relay saw ciphertext only |
| Python tests, offline | `pytest -q` (in `python/`) | **207 passed, 31 skipped** |
| Python types | `mypy` (in `python/`) | clean, 32 files, `src` and `examples` |
| Python lint | `ruff check .` (in `python/`) | clean |
| Measurement pin parity | `node scripts/check-parity.mjs` | all four per-package copies match `shared/` |
| Command parity | `node scripts/check-cli-parity.mjs` | 4/4 cases, both real executables, identical documents and exit codes |
| Artifact installs | `node scripts/smoke-artifacts.mjs` | **21/21** |
| **Live, JS** | `npm test` with a live origin and an engine | **325 passed, 0 skipped** |
| **Live, Python** | `pytest -q` with a live origin and an engine | **238 passed, 0 skipped** |

The 31 skips in each offline run are the opt-in live cases. They skip with a
stated reason and never fabricate a result. With
`ANONROUTER_LIVE_GATEWAY_ORIGIN`, `ANONROUTER_LIVE_PUBLIC_ORIGIN` and
`ANONROUTER_DCAP_VERIFIER_BIN` set, all 31 run and pass.

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

## What a green run does not cover

- **Hop 2 has never been exercised end to end.** Confirming it needs a real API
  key and a callable `(provider, model)` pair, and that is the one input an owner
  has to supply. With a fabricated key both origins answer as an unauthorized
  caller should, so "the route is absent" and "your key was refused" cannot be
  told apart from outside. Everything hop 2 does against recorded evidence is
  covered by `shared/vectors/attestation.json`.
- **Hop 2's ceiling is `provider-attested` and stays there.** Several provider
  routes run GPU enclaves whose NVIDIA attestation chain is not available to
  verify. Chaining only the CPU quote and printing `hardware_verified` would claim
  more than was checked.
- **The shipped gateway pin does not match the live plane, on purpose.** Its
  refresh was reviewed on 2026-08-29 and rejected, and reconfirmed as rejected on
  2026-08-30 after the plane's `compose_hash` moved again while `release_id` did
  not. See `reviewedRefreshAttempt` in `shared/gateway-policies.json`. Under that
  pin the live plane fails only `app_id_pinned`, `compose_hash_pinned`,
  `release_pinned` and `platform_measurements_pinned`, and the live suites assert
  that only policy checks may fail.
- **No package is published.** All three 404 on their registries. The artifacts
  are built and installed into empty environments on every CI run, so what a
  registry would carry is what is being tested; publishing is an owner decision.
- **No DCAP engine is distributed with these packages**, so a user reaching
  `hardware_verified` has to install one. `anonrouter-verify doctor` says so and
  says what to do. Without it the ceiling is `cryptographically_checked` and a
  policy requiring hardware verification fails closed.
- **The engine's build is not yet reproducible.** The digest of the binary used
  for the runs above is specific to the machine and toolchain that built it. A
  published digest an operator can pin with `expectedBinarySha256` needs the
  reproducible-build work tracked on the engine's own side.
- **`anonrouter-verify` observes TLS on its own connection**, not the one that
  carried the attestation request, because `fetch` does not expose it. Conclusive
  on a mismatch; weaker than a same-connection observation on agreement. The
  output says which it was.
- **Attestation proves which code ran, not that it behaves well.** Reviewing the
  source behind a pinned compose hash is a separate act.

## One thing the suites assert that is easy to miss

There is no environment variable that weakens a verdict. Twelve plausible spellings
of an escape hatch (`ANONROUTER_INSECURE`, `ANONROUTER_SKIP_VERIFY`, `NODE_ENV=test`,
`CI=true`, and so on) are set, and the verdict for the same evidence must come out
IDENTICAL, not merely also-failing. The deliberate opt-ins are checked from the
other side: a candidate pin does not resolve through the environment, a plaintext
remote origin is refused even with `allowInsecureHttp`, and the command still
refuses `--require hardware_verified` without `--dcap`.

Behavioural tests can only cover the names somebody thought to try, so there is a
structural one beside them: the four modules that decide whether a verdict passes
(`gateway/verify`, `gateway/policy`, `verify/state`, `verify/route`) may not
contain a read of the environment at all, in either language.

## Artifacts, as built

| Artifact | Size | Contents |
| --- | --- | --- |
| `anonrouter-confidential-0.1.0.tgz` | 255,551 B | 187 files: `dist`, `src`, README, LICENSE |
| `anonrouter-client-0.1.0.tgz` | 9,003 B | 6 files |
| `anonrouter_confidential-0.1.0-py3-none-any.whl` | 112,013 B | package plus the measurement pins as package data |
| `anonrouter_confidential-0.1.0.tar.gz` | 131,675 B | the same, from an sdist |

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
