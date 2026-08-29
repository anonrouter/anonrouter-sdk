# Contributing

Thanks for helping keep AnonRouter's confidential routes independently
verifiable. This repo is trust-critical, so the workflow leans on tests and the
cross-language parity gate. Please run them before opening a pull request.

## Prerequisites

- Node.js 22 or newer, and npm (the JS packages are npm workspaces). 22 is the
  floor because the measurement pins are imported with `with { type: "json" }`.
- Python 3.10 or newer. CI runs the test suite on 3.10, 3.11, 3.12, and 3.13.
- git.

By taking part in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## JavaScript (`js/`)

The JS packages are npm workspaces rooted at `js/`.

```bash
cd js
npm ci            # or: npm install
npm run typecheck # tsc across every workspace
npm test          # vitest across every workspace
npm run build     # tsc build across every workspace
```

To work on a single package, run its scripts directly, for example:

```bash
cd js/client
npm run typecheck && npm test && npm run build
```

### The end-to-end self-test

The unit tests cover the crypto and the verifiers, but not the client's HTTP flow.
That is covered by a self-test that runs the full verify plus E2EE chat round trip
against an in-process mock gateway. It needs no API key, no network, and spends
nothing, and it runs in CI:

```bash
cd js/confidential
npm run example:selftest
```

## Python (`python/`)

```bash
cd python
pip install -e ".[dev,mlkem]"   # dev tools + the ML-KEM extra for the Chutes route
pytest -q
mypy src
ruff check .
```

## The cross-language parity gate

The JS and Python packages must never disagree. Two things enforce that, and both
run in CI:

- The known-answer vectors in `shared/vectors/` are loaded by both languages,
  which must produce identical results in their own test suites. `attestation.json`
  is the strictest of them: it pins the whole verdict for each case, including the
  exact set of required checks that failed, so neither a one-sided verifier change
  nor a quiet downgrade of a required check to advisory can pass CI.
- The measurement pins are checked for drift by a standalone script:

```bash
node scripts/check-parity.mjs
```

Run it before you push. If it fails, a per-package copy has drifted from the
canonical pins and you need to re-sync (see below).

### Regenerating the verdict vectors

`shared/vectors/attestation.json` is generated, not hand-written. Every case is run
through the real verifier and whatever it returns is recorded, so the file always
describes actual behavior:

```bash
cd js/confidential
npm run gen:attestation-vectors   # requires openssl on PATH
```

Read the resulting diff carefully. A changed expectation is a changed security
decision, not a test fixup. If a case flips from `failed` to `ok`, or a check
disappears from `failedRequiredChecks`, say why in the pull request.

## Editing the measurement pins

The pins live in exactly one place. **Do not hand-edit the per-package copies.**

1. Edit the canonical file: `shared/measurements.json`.
2. Regenerate the per-package copies:

   ```bash
   node scripts/sync-shared.mjs
   ```

3. Commit both the canonical file and the regenerated copies together.

Any pin change is a security-policy change. Follow the rotation process in
`SECURITY.md`: verify the provider's published evidence first, add a new
immutable entry rather than mutating an old one where possible, and bump the
version string.

## Pull request checklist

- [ ] `npm run typecheck && npm test && npm run build` pass in `js/`.
- [ ] `npm run example:selftest` passes in `js/confidential/`.
- [ ] `pytest -q && mypy src && ruff check .` pass in `python/`.
- [ ] `node scripts/check-parity.mjs` passes.
- [ ] If you changed pins, you edited `shared/measurements.json`, ran
      `node scripts/sync-shared.mjs`, and followed `SECURITY.md`.
- [ ] No em dashes in user-facing copy (AnonRouter house style: use periods,
      colons, or commas).
