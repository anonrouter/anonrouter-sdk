# First PyPI publication: anonrouter-confidential 0.1.3.post1

Published 2026-11-06 under the `anonrouter` PyPI organization. This page records
the process. Do not rerun it for the same version.

Python's first PyPI release is `0.1.3.post1`. Its verification code matches
`v0.1.3`. The accepted 0.1.3 wheel was not published because its embedded
description was written before publication and is unfit for the PyPI page.
JavaScript stays at 0.1.3, and the v0.1.3 tag and assets are unchanged.

`pypi-bootstrap.yml` builds with pinned tools, runs a strict metadata check, then
installs the wheel into a clean environment and verifies `api.anonrouter.ai`
without credentials or inference. Only then does it upload.

## Step 1: rehearse on TestPyPI

TestPyPI is a separate site with separate accounts. On
[test.pypi.org](https://test.pypi.org), add a pending GitHub publisher:

| Field | Value |
| --- | --- |
| PyPI project | `anonrouter-confidential` |
| GitHub owner | `anonrouter` |
| Repository | `anonrouter-sdk` |
| Workflow filename | `pypi-bootstrap.yml` |
| Environment | `testpypi` |

Run the workflow with target `testpypi`. Then check the page and a real install.
The extra index supplies dependencies, which are not all on TestPyPI:

```bash
python3 -m venv /tmp/anonrouter-testpypi
/tmp/anonrouter-testpypi/bin/python -m pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  'anonrouter-confidential[connection-binding]==0.1.3.post1'
/tmp/anonrouter-testpypi/bin/python -m pip check
/tmp/anonrouter-testpypi/bin/anonrouter-verify doctor --compact
```

TestPyPI also refuses a repeated version. If the page needs a change, bump the
version to `0.1.3.post2` and rehearse again.

## Step 2: publish on PyPI

1. In the approved PyPI organization's **Publishing** tab, not the personal
   account page, add the same publisher with environment `pypi`. Create it under
   the organization so the organization owns the project. A pending publisher
   does not reserve the name.
2. Merge the rehearsed source to `main`.
3. Run the workflow from `main` with target `pypi`, passing the wheel and sdist
   hashes shown in the rehearsal's run summary. The run stops if the build differs.
4. Approve the `pypi` environment when the run pauses there.

## Verify publication

Compare `urls[].digests.sha256` from the PyPI JSON to the rehearsal hashes:

```bash
curl --fail --silent --show-error https://pypi.org/pypi/anonrouter-confidential/0.1.3.post1/json
python3 -m venv /tmp/anonrouter-pypi
/tmp/anonrouter-pypi/bin/python -m pip install 'anonrouter-confidential[connection-binding]==0.1.3.post1'
/tmp/anonrouter-pypi/bin/python -m pip check
/tmp/anonrouter-pypi/bin/anonrouter-verify doctor --compact
```

Check the organization owner and provenance on the project page. Do not enable
`skip-existing`, because a repeated upload should stay an error.

## Subsequent releases

Add a project trusted publisher for `anonrouter/anonrouter-sdk`, workflow
`release.yml`, environment `pypi`, then set `PUBLISH_PYPI=true`. Future annotated
version tags publish after the existing release and live gates. Remove the
`pypi-bootstrap.yml` publisher after the first publication.
