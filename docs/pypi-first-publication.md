# First PyPI publication: anonrouter-confidential 0.1.3

Prepared 2026-10-28 after the owner reported PyPI organization approval.
The public project still returned HTTP 404 during preparation. Organization
approval alone does not create a project or configure its trusted publisher.

## Release identity

Publish `anonrouter-confidential`, imported as `anonrouter_confidential`, from
this repository. The old `anonrouter` helper under the private gateway repo's
`sdk/python` is a different package and is not this release.

Reuse the accepted [v0.1.3 release](https://github.com/anonrouter/anonrouter-sdk/releases/tag/v0.1.3)
at commit `deb7c0ec23d7f2b081eaaca71414daae69c4c42a`. Do not rebuild, retag, or
replace its assets. Its wheel description includes the historical PyPI-unpublished
status; preserve those accepted bytes and update that copy in the next release.

| Artifact | SHA-256 |
| --- | --- |
| `anonrouter_confidential-0.1.3-py3-none-any.whl` | `84af507bea0b525424871f6a06d6b4ac6e76aee7c79bd068120f80cf99f92d31` |
| `anonrouter_confidential-0.1.3.tar.gz` | `fe92b29d4892450aca5282dce768864c04989c78d20c631600449576ec86bc76` |
| `SHA256SUMS` | `b11541a1b201d49e0b005c5d5d35ab23fb180f6d2606d690c638456daa324583` |

## Preparation verification

On 2026-10-28, all seven GitHub assets matched the pinned checksum manifest.
Both released Python distributions passed strict Twine metadata checks and
separate clean installs with `connection-binding,mlkem`, `pip check`, public API
and packaged trust-root probes, CLI doctor, and rejection of an untrusted origin.
The source suite passed 582 tests with 40 live tests skipped; mypy and Ruff
passed. The repository's cross-language artifact smoke installs and shared-pin
parity passed. Actionlint 1.7.12 accepted both publication workflows.

A fresh Linux/amd64 install of the released wheel and released DCAP engine
verified `api.anonrouter.ai`: `hardware_verified`, Intel TCB `UpToDate`, signed
release-policy-v3 sequence 17, retained-connection TLS matching the attested key,
and zero failed required checks. The existing `firmware_event_log_replayed` and
`gce_instance_identity` advisory gaps remain. This was credential-free and sent
no inference. The bootstrap workflow reruns both languages' packed live gate
before publication; that new workflow has not yet been dispatched.

## Organization and GitHub setup

1. In the approved PyPI organization's **Publishing** tab, create a pending
   GitHub trusted publisher with these exact values:

   | Field | Value |
   | --- | --- |
   | PyPI project | `anonrouter-confidential` |
   | GitHub owner | `anonrouter` |
   | Repository | `anonrouter-sdk` |
   | Workflow filename | `pypi-bootstrap.yml` |
   | Environment | `pypi` |

   Create it under the organization so the organization owns the new project.
   A pending publisher does not reserve the project name. See
   [PyPI's organization publishing guidance](https://blog.pypi.org/posts/2025-11-10-trusted-publishers-coming-to-orgs/).

2. Create GitHub environment `pypi`, restrict it to `main` and release tags
   `v*`, and configure an owner reviewer if supported by the repository plan.
   Merge the preparation branch into `main` so manual dispatch is available.
   No API token or PyPI password is required.
3. Leave repository variable `PUBLISH_PYPI` unset for this bootstrap. Run
   **Publish Python 0.1.3 to PyPI** (`pypi-bootstrap.yml`) from `main`.
   This is the publication action. The workflow verifies the pinned checksum
   manifest, checks metadata, and reruns the released packed SDKs' credential-free
   live gateway gate before the environment-gated upload. It neither republishes
   npm nor changes production. A failed live gate must be investigated, never
   bypassed or solved by mutating the accepted 0.1.3 assets.

## Verify publication

Compare both PyPI JSON `urls[].digests.sha256` values to the table above:

```bash
curl --fail --silent --show-error https://pypi.org/pypi/anonrouter-confidential/0.1.3/json
python3 -m venv /tmp/anonrouter-pypi-013
/tmp/anonrouter-pypi-013/bin/python -m pip install 'anonrouter-confidential[connection-binding]==0.1.3'
/tmp/anonrouter-pypi-013/bin/python -m pip check
/tmp/anonrouter-pypi-013/bin/anonrouter-verify doctor --compact
```

Check the PyPI project's organization owner and publication provenance as well.
Record the successful run URL and registry hashes in ARK, then update the
repository's installation status. A repeated upload is deliberately an error;
do not enable `skip-existing` to conceal a partial or conflicting upload.

## Subsequent releases

Add a project trusted publisher for `anonrouter/anonrouter-sdk`, workflow
`release.yml`, environment `pypi`, then set `PUBLISH_PYPI=true`. Future annotated
version tags will publish after the existing release and live gates. Preserve
the npm publisher identity and settings. Remove the bootstrap publisher after
successful first publication; its workflow is pinned to 0.1.3 and is not a new
version release path.
