# Summary

<!-- What does this change and why? One or two sentences is fine. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Measurement pin rotation (see `SECURITY.md`)
- [ ] Documentation only
- [ ] Build, CI, or tooling

## Checklist

- [ ] `npm run typecheck && npm test && npm run build` pass in `js/`.
- [ ] `pytest -q && mypy src && ruff check .` pass in `python/`.
- [ ] `node scripts/check-parity.mjs` passes.
- [ ] `npm run example:selftest` passes in `js/confidential/` (mock gateway, no key, no spend).
- [ ] No em dashes in user-facing copy. Use periods, colons, or commas.
- [ ] No API keys, prompts, response content, or raw attestation bodies in the diff,
      the tests, or the commit messages.

## If this changes the measurement pins

- [ ] I verified the provider's published evidence first (transparency log, signed
      release, or pinned compose document), not a value asserted at request time.
- [ ] I edited `shared/measurements.json` only, then ran `node scripts/sync-shared.mjs`
      to regenerate the per-package copies.
- [ ] I added a new immutable entry rather than mutating an existing one, so
      in-flight deployments keep verifying during the rollover.
- [ ] I bumped the provider's `version` string.

## If this changes verification behavior

- [ ] The change fails closed: no route is upgraded on unverified evidence.
- [ ] The verification level is not inflated. `hardware-verified` is still never
      emitted while the vendor-root chain is unwired.
- [ ] JS and Python still agree. Cross-language behavior is covered by the shared
      vectors in `shared/vectors/` or by equivalent tests in both suites.
