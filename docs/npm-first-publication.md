# npm publication status and owner release gate

Read-only registry checks on 2026-10-14 confirmed that both
`@anonrouter/confidential` and `@anonrouter/client` exist on npm at latest 0.1.2.
First-publication bootstrap instructions for v0.1.1 are historical and must not
be repeated for the 0.1.3 candidate. PyPI returns 404 for
`anonrouter-confidential`; its availability and publishing setup are separate.

0.1.3 is prepared locally. Do not publish, push a release tag, trigger a release
workflow, change publishing variables, or create registry credentials until the
owner explicitly gives the go. Preparing and installing local tarballs/wheels
is not registry publication.

The exact 0.1.3 publish, verification, deprecation and rollback commands are in
[release-readiness.md](release-readiness.md#publish-commands-owner-go-only).

After approval, verify the current release workflow and publisher configuration
for each ecosystem. The repository supports npm trusted publishing through
GitHub Actions OIDC, but the npm publisher settings have not been inspected in
this task. Do not infer those settings from package existence. Run the release,
artifact and provenance checks before publishing the exact reviewed artifacts.
