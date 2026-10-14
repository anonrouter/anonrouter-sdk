# Migrating from 0.1.2 to 0.1.3

## Why upgrade

Since 2026-10-14 02:37 UTC, `https://api.anonrouter.ai` has been served by Google
Cloud Intel TDX content nodes. 0.1.2 (and earlier) pins only the previous
Phala/dstack deployment, so every hop-1 (gateway) verification of
`api.anonrouter.ai` fails closed. Typically this shows up as `event_log_replays_rtmrs`,
`compose_hash_measured_in_rtmr3` and a dozen other dstack checks failing. Nothing
insecure happens; verification just cannot succeed. Hop 2 (provider attestation)
and plaintext calls are not affected by this change.

## What changes in 0.1.3

- **New trust root for `api.anonrouter.ai`.** Hop 1 is verified against the
  owner-signed release policy v3 at
  `https://anonrouter.ai/.well-known/anonrouter-content-release-v3.json`. The
  package carries the owner's two public keys, the owner root
  `10034ad2b11e9ef9f300da180a794010da369f2f14b2a896df42ceaf47077acb` and the minimum
  policy sequence 6. It carries no node image measurements: a node image approved
  by a newly signed policy needs no SDK upgrade.
- **Hop 1 for `api.anonrouter.ai` needs the bound path.** Each node behind the load
  balancer has its own per-boot TLS key, so the certificate must be read on the
  same socket that fetched the evidence. On a client created **without**
  `gatewayConnectionBinding` / `gateway_connection_binding`, these now refuse
  `api.anonrouter.ai` with `unsupported_request` ("A gcp-tdx-native policy is
  verifiable only through required gateway connection binding") **before any
  request is sent**: `verifyGateway()`, `verify()` / `verifyRoute()` with
  `gateway: true`, and `chat()` / media calls that require the gateway. In 0.1.2
  the same calls ran and returned a failed verdict.
- **Native DCAP is mandatory** for these nodes (no lower assurance exists).
- **One extra credential-free GET** per verification fetches the signed policy (no
  API key, no cookies, redirects refused). If the feed is unreachable, the last
  verified policy is reused for at most one hour. The highest sequence seen is
  stored in `~/.cache/anonrouter/gateway-policy-v1` (IndexedDB in a browser), so a
  rollback is refused across restarts. On a read-only filesystem, supply a
  `stateStore` (`state_store` in Python).
- **New verdict fields:** `instanceIdentity` / `instance_identity`
  (`verified` | `unverified` | `not-applicable`) and `gceInstance` / `gce_instance`.
  Expected advisory gaps today: `firmware_event_log_replayed`, `gce_instance_identity`.
- **CLI:** `anonrouter-verify gateway --origin https://api.anonrouter.ai --dcap`
  now verifies on the retained socket and prints `policy.origin:
  "signed-release-policy-v3"` and `tlsSpki.source: "retained-connection"`. Without
  `--dcap` the gateway hop is `unavailable`.
- **Python** has the same verification (it previously had none for GCP). Install
  with the `connection-binding` extra.
- **Phala** stays available explicitly: your own policy, or
  `gatewayPolicyUpdates: false` / `gateway_policy_updates=False` for the packaged
  Phala pin. `https://api.private.anonrouter.ai` (the Phala DNS rollback name)
  keeps its pin but is deprecated; the pin is removed when Phala is retired.

## What to do

JavaScript (Node):

```ts
import { createClient, verifyContentNode } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

// Read-only check, no API key: a fresh nonce on one retained TLS socket.
const check = await verifyContentNode();
if (check.verdict.status !== "ok") throw new Error(`gateway: ${check.verdict.reason}`);

// Inference: every operation verifies and retains its own socket.
const client = createClient({
  apiKey: process.env.ANONROUTER_API_KEY!,
  gatewayConnectionBinding: { mode: "required", verification: { chainVerifier: createAnonRouterDcapVerifier() } }
});
```

Python:

```python
from anonrouter_confidential import create_client, verify_content_node
from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

check = verify_content_node()
assert check["verdict"].status == "ok", check["verdict"].reason

client = create_client(
    api_key=KEY,
    gateway_connection_binding={"mode": "required",
                                "verification": {"chain_verifier": create_anonrouter_dcap_verifier()}},
)
```

Both need the native DCAP engine on `PATH` or in `ANONROUTER_DCAP_VERIFIER_BIN`
(see [VERIFYING.md](../VERIFYING.md#reaching-hardware_verified)). Browsers cannot
read TLS certificates or run the engine, so browser code cannot verify hop 1 for
`api.anonrouter.ai`; verify from a backend you control.

If you only call the API without hop-1 verification, nothing changes for you.

## Should 0.1.2 be deprecated on npm?

Recommendation: **yes, for `@anonrouter/confidential`, once 0.1.3 is published
and a fresh `npm install` of it has been checked.** Every earlier version fails
closed against the current production deployment, and the deprecation warning is
the only channel that reaches users who never read the changelog. It does not
remove anything, and it is reversible:

```bash
npm deprecate "@anonrouter/confidential@<0.1.3" \
  "Cannot verify api.anonrouter.ai since 2026-10-14 (GCP content nodes). Upgrade to 0.1.3: https://github.com/anonrouter/anonrouter-sdk/releases/tag/v0.1.3"
# Undo:
npm deprecate "@anonrouter/confidential@<0.1.3" ""
```

`@anonrouter/client` does not verify anything, so its 0.1.2 keeps working; do not
deprecate it.
