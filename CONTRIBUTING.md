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
mypy                            # no path: pyproject covers src and examples
ruff check .
```

## Testing against a real confidential VM

Both suites carry live tests that skip, with a stated reason, unless you point
them at a deployment. They are never silently green.

```bash
export ANONROUTER_LIVE_GATEWAY_ORIGIN=https://your-cvm.example
export ANONROUTER_LIVE_PUBLIC_ORIGIN=https://your-non-cvm.example   # optional
export ANONROUTER_DCAP_VERIFIER_BIN=/path/to/anonrouter-dcap-verifier  # optional
npm test        # in js/
pytest -q       # in python/
```

The attestation endpoint is credential-free, content-free and read-only, so
pointing these at a real deployment sends no prompt, no key and no account
identity. With the engine set, four more cases run per language and the verdict
may legitimately reach `hardware_verified`.

Most of the live suite is NEGATIVES: one genuine document, one field changed at a
time, each required to fail on the exact check that covers it. A live "it
verified" on its own is nearly worthless, because a verifier that returned ok for
everything would produce it too. If you add a check, add its negative.

## The cross-language parity gate

The JS and Python packages must never disagree. Two things enforce that, and both
run in CI:

- The known-answer vectors in `shared/vectors/` are loaded by both languages,
  which must produce identical results in their own test suites. `attestation.json`
  is the strictest of them: it pins the whole verdict for each case, including the
  exact set of required checks that failed, so neither a one-sided verifier change
  nor a quiet downgrade of a required check to advisory can pass CI.
- The measurement pins are checked for drift by a standalone script.
- Both packages ship a command called `anonrouter-verify`, and a second gate runs
  the two real executables over inputs that need no network and requires the JSON
  they print and the codes they exit with to be identical. Two commands with the
  same name that disagreed would be worse than shipping one.
- A third gate installs the actual publishable artifacts into empty environments
  and uses them there. Every other gate runs against the working tree, which says
  nothing about whether a `files` entry, an `exports` map, a `bin`, or a wheel's
  package data is right.

```bash
node scripts/check-parity.mjs      # pin copies match shared/
node scripts/check-cli-parity.mjs  # needs a built js/ and an installed python package
node scripts/smoke-artifacts.mjs   # builds, installs and exercises every artifact
```

Run the first before you push. If it fails, a per-package copy has drifted from
the canonical pins and you need to re-sync (see below).

### Regenerating the DCAP vectors

`shared/vectors/dcap.json` is generated, but unlike the verdict vectors its
expectations are stated independently of the implementation: the FMSPC is the six
bytes the generator embeds, the PCK chain is the PEM it embeds, and the engine
request and verdict shapes come from the engine's documented v1 contract.

```bash
cd js/confidential
npx tsx scripts/gen-dcap-vectors.ts
```

A changed expectation there is a changed wire contract with the reviewed DCAP
engine, not a test fixup.

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
- [ ] `pytest -q && mypy && ruff check .` pass in `python/`.
- [ ] `node scripts/check-parity.mjs` passes.
- [ ] `node scripts/check-cli-parity.mjs` passes.
- [ ] `node scripts/smoke-artifacts.mjs` passes if you touched packaging, exports,
      `files`, `bin`, package data, or anything either CLI prints.
- [ ] If you changed pins, you edited `shared/measurements.json`, ran
      `node scripts/sync-shared.mjs`, and followed `SECURITY.md`.
- [ ] No em dashes in user-facing copy (AnonRouter house style: use periods,
      colons, or commas).
