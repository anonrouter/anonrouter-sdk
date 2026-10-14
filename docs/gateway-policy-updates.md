# Signed gateway policy updates

JavaScript and Python 0.1.3 select the GCP release-v3 feed by default for
`https://api.anonrouter.ai`. This is an unpublished SDK candidate.
No registry publication or production change is part of this preparation.

The SDK packages the fixed USB and laptop owner public keys, deployment
`gcp-content-production`, group `release-owner-production`, owner root
`10034ad2b11e9ef9f300da180a794010da369f2f14b2a896df42ceaf47077acb`,
and minimum sequence 6 in `shared/release-policy-v3-authority.json`.
It contains no GCP node image measurements. The publication URL is
`https://anonrouter.ai/.well-known/anonrouter-content-release-v3.json`,
separate from the content API. The feed cannot replace its signing roots.
`packagedReleasePolicyV3Authority()` / `packaged_release_policy_v3_authority()`
return a copy of these anchors.
Root changes require an SDK release; approved node images do not.

Signatures establish owner approval, not proof that approved code is benign.
Native Intel DCAP, exclusively `UpToDate` TCB, nonce and origin binding,
evidence freshness and the quote-bound TLS key observed on the retained socket
remain mandatory. GCP is qualified; it needs no pilot opt-in.

## Read-only verification

Build this candidate before running it. The npm latest package is still 0.1.2.
Install/build the native verifier separately and set
`ANONROUTER_DCAP_VERIFIER_BIN` to its path, or put it on PATH.

```typescript
import { verifyContentNode } from "@anonrouter/confidential";

const result = await verifyContentNode();
console.log(result.policy.sequence, result.verdict.verificationLevel);
```

This Node-only helper sends one credential-free attestation GET with a fresh
nonce over a normally validated TLS connection. It observes the connection's
SPKI, verifies the quote on that socket, and closes it. It does not mint tickets,
send inference, or spend money. A browser cannot run the native engine or inspect
TLS certificates, and this helper refuses there.

For inference, configure required connection binding so content uses its own
retained verified socket:

```typescript
import { createClient } from "@anonrouter/confidential";
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

const client = createClient({
  apiKey,
  gatewayConnectionBinding: {
    mode: "required",
    verification: { chainVerifier: createAnonRouterDcapVerifier() }
  }
});
const result = await client.verifyGateway(); // no key or ticket sent
// Subsequent client operations independently verify and retain their own socket.
```

`createReleasePolicyV3Source()` also uses the packaged production defaults.
Callers can supply independent `trust`, `url`, `origins`, `stateStore`, `fetch`,
`refreshMs` and `maxOfflineMs` for another deployment. Custom roots remain an
explicit caller decision. Exact caller policies override feeds. The legacy
Phala source is available through `createSignedGatewayPolicySource()`; its
packaged v1 activation flag remains off. `gatewayPolicyUpdates: false` disables
automatic feed selection and uses exact caller/bundled policies.

## Release-v3 contract

The strict envelope has `protocol` (`anonrouter-content-release-envelope-v3`),
`role` (`release-policy`), `groupId`, `ownerRootSha256`, `payload`, `signatures`.
Both signatures are required in fixed order: `custodian.prod.usb`, then
`custodian.prod.laptop`. Neither v1 nor v2 is accepted by the v3 verifier.

Both sign SHA-256 of ASCII `anonrouter-content-release-v3/authority/` + role +
NUL, followed by canonical `{groupId, ownerRootSha256, payload}`. Canonical
JSON has sorted keys, printable ASCII and nonnegative safe integers.
`digest(d, v)` is SHA-256 of ASCII `anonrouter-content-node-bootstrap-v1/` +
`d` + NUL, then canonical JSON of `v`.

The payload carries `protocol`, `kind` (`content-node-release-policy`),
`deploymentId`, `sequence`, `issuedAtMs`, 1..16 measured `tuples`, sorted unique
`revokedTuples`, `revokedGenerations`, `minimumGenerationRevision`,
`maxEvidenceAgeMs` (at most five minutes), `tcbStatus` (`UpToDate`), and optionally
the backend's `tcbGrace` and the SDK-local `requireGcePzid` (boolean). It has no
expiry.

`tcbGrace` (`{statuses, advisoryIds, notAfterMs}`) is validated exactly as the
backend schema does: sorted unique statuses from the five Intel grace statuses
(never `UpToDate` or `Revoked`), 1..64 sorted unique `INTEL-XX-NNNN` advisory ids,
and `issuedAtMs < notAfterMs <= issuedAtMs + 90 days`. A policy carrying a valid
grace verifies, so publishing one does not break this SDK's feed. The SDK does
not relax its own check: a gateway quote must still be `UpToDate`, so during a
grace window nodes on a listed non-UpToDate TCB fail customer verification
closed. That is a deliberate customer-side choice; honoring the grace would be
a separate reviewed SDK change. Each tuple pins every TDX register,
TD attributes and XFAM together; exactly one complete tuple must match. Mixing
registers from different approved tuples fails. Approved and observed tuple
digests must not be revoked.

## Optional machine identity

Google C3 writes MROWNER = SHA-384 of the canonical PZID JSON
`{"instanceId":N,"numericalProjectId":N,"zone":"z"}`. The signed tuple's
`mrOwnerRule: {kind: "gce-pzid", projectNumber, zones}` carries a zero MROWNER
placeholder and is included in the tuple digest. Every other register still
matches exactly. Rule-less tuples require actual MROWNER zero (C4).

A presented `gce_pzid` must be canonical, hash to quoted MROWNER, and belong to
the rule's project/zones. Otherwise verification fails. Absence is accepted with
`instanceIdentity: "unverified"` and an unmet advisory; no project/zone claim is
established. Valid PZID reports `verified` and `gceInstance`; zero-rule tuples
report `not-applicable`.

`requireGcePzid` is **SDK-local** today. The SDK accepts `requireGcePzid: true`
in a signed payload and then requires a verified PZID, but the backend release
policy schema (`releasePolicyV3Schema`, `.strict()`), the owner signer purpose,
control, the nodes and the feed publisher all refuse unknown payload fields. The
owner therefore cannot sign it until the backend adds the field, in the same
rollout order as `tcbGrace` (control, node image, signer purpose, then a signed
policy). Until then identity stays optional, and the switch needs no SDK release
once the backend supports it.

With `requireGcePzid: true`, a matched gce-pzid tuple without a verified PZID
fails the required `gce_instance_identity` check, and so does any match on a
zero-rule tuple: a C4 node (MROWNER zero) has no PZID at all, so the switch
also excludes every C4 image. Use it only when every approved tuple is a C3
gce-pzid tuple whose image publishes `gce_pzid` (node image e4524606 does not).

## Refresh and rollback

The default source checks the feed on every resolve. Publication requests carry
no API key, cookies or body, refuse redirects, have a ten-second timeout and a
1 MiB decoded-body limit. Only verified policies are cached. Network/5xx outages
can reuse a verified policy for less than one hour after confirmation; invalid
signatures, malformed answers, 4xx, rollback, forks and revocation reversal fail
immediately. There is no fallback to bundled Phala pins after selecting v3.

A lower sequence or a changed payload at the held sequence fails. The highest
sequence and policy hash persist before acceptance under
`anonrouter.release-policy-v3/<ownerRootSha256>` using the existing atomic
Node/IndexedDB store. Dropped tuple revocations are also rejected against the
policy held in process. That revocation list is not persisted across restarts;
the durable sequence/hash still prevents replay of older approvals.

A hardware-verified identity mismatch allows one forced feed refresh and
re-verification of the same nonce/evidence/socket. It never retries paid
inference. `expiresAtMs` on a v3 approval bounds offline use, not policy lifetime.
Deleting stored checkpoints loses learned history; this is not a transparency log.

## Python and legacy Phala

Python implements the same release-v3 verification (`ReleasePolicyV3Source`,
`verify_release_policy_v3`, `verify_content_node`) and selects it by default
for `api.anonrouter.ai`. Both languages load `shared/vectors/release-policy-v3.json`
(policy and attestation cases, check by check, plus the backend's own signed
envelopes) and the PZID vectors. Retained-socket verification needs the
`connection-binding` extra (the reviewed HTTPX 0.28.1 / HTTPCore 1.0.9 pair).

`https://api.private.anonrouter.ai` keeps its packaged Phala pin while Phala is
the DNS rollback target. It is deprecated and the pin is removed when the Phala
plane is retired.

The earlier Phala v1 authority remains available explicitly. It authorizes exact
manifest-bound policies with at most seven-day expiry and two custodian
signatures over `anonrouter.gateway-policy-signature/v1\n` plus the canonical
payload string. Its independently packaged roster and security floor stay in
force. The earlier sequence-1 approval/renewal dates are historical; reverify
availability and expiry before using it.
