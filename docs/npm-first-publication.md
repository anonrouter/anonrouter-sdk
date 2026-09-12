# First npm publication

The release workflow normally publishes through npm trusted publishing: GitHub
Actions receives a short-lived OIDC identity and no registry token exists. npm
requires a package to exist before a trusted publisher can be attached, so the
first release needs one deliberately short-lived bootstrap credential.

## Owner setup before tagging

1. On npmjs.com, enable 2FA on the owner account, create or confirm the
   `anonrouter` organization, and require 2FA for organization members.
2. Create a granular npm access token that can publish public packages in the
   `anonrouter` scope, has bypass-2FA enabled, and expires as soon as npm permits.
3. In GitHub repository settings for `anonrouter/anonrouter-sdk`, add that value
   as the Actions secret `NPM_TOKEN`. Do not paste it into a shell, issue, commit,
   release note, or handoff.
4. Set the Actions repository variable `PUBLISH_NPM` to `true`.
5. Leave `PUBLISH_PYPI` absent or `false` while PyPI organization approval is
   pending.

The signed `v0.1.1` tag then runs all release gates, builds checksummed artifacts,
creates the GitHub release, and publishes both public npm packages with
provenance. The workflow refuses with a specific message if a package does not
exist and the bootstrap secret is missing.

## Immediately after the first successful publish

For **each** of `@anonrouter/client` and `@anonrouter/confidential`, configure this
trusted publisher in the package settings on npmjs.com:

- provider: GitHub Actions;
- organization or user: `anonrouter`;
- repository: `anonrouter-sdk`;
- workflow filename: `release.yml`;
- environment: none;
- allowed action: direct `npm publish`.

Then:

1. delete the GitHub Actions secret `NPM_TOKEN`;
2. revoke the bootstrap token on npmjs.com;
3. set each package's publishing access to require 2FA and disallow traditional
   tokens;
4. leave `PUBLISH_NPM=true` so later signed tags publish through OIDC;
5. verify the two npm package pages show version `0.1.1` and GitHub provenance.

The workflow passes an empty `NODE_AUTH_TOKEN` after cleanup. npm 11.5.1 or newer
detects the GitHub OIDC environment before falling back to token authentication,
so later releases need no replacement secret.
