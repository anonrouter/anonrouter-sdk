# npm publication status

Both `@anonrouter/confidential` and `@anonrouter/client` were published at
0.1.3 on 2026-10-15, with GitHub Actions provenance and the exact checksummed
artifacts accepted by the release's packed JavaScript/Python live gate.

The original npm upload failed with E404. Neither package had a trusted
publisher; both now trust GitHub repository `anonrouter/anonrouter-sdk`, workflow
filename `release.yml`, with no environment restriction and direct `npm publish`
permission. Both connections were validated by the successful retry of only
the failed npm job in
[release run 38802834403](https://github.com/anonrouter/anonrouter-sdk/actions/runs/38802834403).
No package bootstrap is needed. Both connections show `Valid`; the obsolete
bootstrap `NPM_TOKEN` secret was removed from GitHub after this verification.
Future releases use OIDC without a stored npm token.

The existing `v0.1.3` tag and release artifacts are immutable. Do not repeat
first-publication instructions or rebuild a published version. Future release
tags require owner approval and the release, artifact and live acceptance gates.
See [release-readiness.md](release-readiness.md) for validation and verification.

Python 0.1.3 ships as checksummed GitHub wheel/sdist assets. PyPI publication
remains disabled and requires separate owner approval and publisher setup.
