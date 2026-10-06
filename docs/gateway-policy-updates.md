# Signed gateway policy updates

Implemented in the unpublished 0.1.3 candidate. **Production activation is
pending.** `shared/gateway-policy-authority.json` deliberately has
`enabled: false`: an unpublished feed must not break existing SDK users.
Current default calls still use the exact bundled W8 policy. The installed gateway, signer, website, DNS, GitHub branch and registries remain
unchanged. A purpose-specific signer implementation is staged in the separate
backend branch `gateway-policy-authority-20261006`.

## Approval contract

The SDK fixes the release authority instead of requiring a package upgrade for
every compose hash. Two distinct Ed25519 signatures from the independently
packaged production custodian roster authorize a policy. The running gateway
cannot choose those keys. The proposed public publication URL is
`https://anonrouter.ai/.well-known/anonrouter/gateway-policy.json`, separate
from both confidential API origins; this file has not been published.

Automatic acceptance means trusting those custodians to approve future code.
Signatures authenticate that approval; they do not prove that the approved code
is benign. Exact caller-supplied policies remain available and always override
the feed. Root-key changes require a reviewed SDK update; this protocol does
not allow a feed to replace its own signing keys.

The envelope has exactly `schema`, `payload`, and `signatures`. `payload` is a
canonical ASCII JSON string with safe integers and fields:

```text
schema = anonrouter.gateway-policy/v1
authority = anonrouter-production-custodians/v1
sequence, issuedAtMs, expiresAtMs, manifestSha256, policy
```

Sign **exact UTF-8 bytes** of
`anonrouter.gateway-policy-signature/v1\n` followed immediately by `payload`.
Signatures are 128-character lowercase hex, each with a rostered `keyId`.
Never reuse a GCP deployment authorization, SDK tag signature, certificate or
signature over the payload's digest as this approval. The signing domain and
bytes differ. Duplicate IDs/keys, unknown signers, changed/noncanonical payloads
and insufficient signatures fail closed.

Even an authorized policy cannot disable hardware verification, in-TEE TLS,
private logs, digest-pinned images, evidence expiry, platform or KMS pins. TCB
must remain exclusively `UpToDate`; evidence age cannot exceed five minutes.
The policy source must equal the signed retained manifest digest. Every origin
must belong to the independently configured authority.

## Resolution and rollback

Publication requests carry no API key, cookies or body, refuse redirects, have
a ten-second timeout and a 256 KiB decoded-body limit. Policies refresh every
five minutes; cache reads do not extend that interval. After a
hardware-verified gateway identity mismatch, the client refreshes once and
re-verifies the same nonce-bound evidence with the new approved policy. It
does not widen an allowlist or retry paid inference.

A network/5xx outage may use a previously verified cached approval for at most
one hour, and never beyond its signed expiry. Invalid signatures, rollback,
noncanonical documents and security downgrades refuse immediately. Selecting
the signed source never silently falls back to bundled pins. Approval expiry
is rechecked after hardware verification, including the bounded refresh path.

Sequence numbers strictly increase when the payload changes, including renewal
or an intentional deployment rollback. The same sequence and exact payload may
be served again. Clients persist their highest accepted sequence and payload
hash before returning an approval. Node and Python share an atomic lock-file
format at `~/.cache/anonrouter/gateway-policy-v1`; IndexedDB provides transactional
browser storage. Storage corruption, locks or write failures refuse verification.
No credential or inference content is stored. Browser builds contain no static
Node import. File durability is tested on macOS; unsupported filesystem behavior
fails closed, and callers may supply an atomic durable store for their runtime.

A crashed file-store writer can leave a `.lock` directory. Inspect whether any
writer is still active before an operator removes that lock. Never delete or
lower the high-water mark to make a rejected release pass. A new installation
only knows the packaged minimum sequence and the signed freshness window; it
cannot reconstruct an unseen revocation history. Deleting application storage
also removes its learned sequence. This is not a transparency-log protocol.

## Client API

After activation, the packaged flag selects updates automatically for the two
known production origins when hop 1 is requested. Before activation, an explicit
opt-in is available for a signed publication canary:

```typescript
const client = createClient({ apiKey, gatewayPolicyUpdates: true });
// Hardware/TLS requirements still apply; provide the existing chain verifier
// and observed TLS SPKI to verifyGateway()/requireGateway as usual.
```

```python
client = ConfidentialClient(api_key=api_key, gateway_policy_updates=True)
```

`false` selects exact bundled/caller policies. A custom signed source can use a
caller-reviewed authority and storage. JavaScript exposes
`createSignedGatewayPolicySource`, `verifySignedGatewayPolicy`, and the optional
Node `@anonrouter/confidential/policy-state` adapter. Python exposes
`SignedGatewayPolicySource`, `verify_signed_gateway_policy`, and
`FileGatewayPolicyStateStore`. Custom stores must atomically refuse lower
sequences or a changed payload at the same sequence. Results report
`signed-release-authority`, authority, sequence, payload hash and signed expiry.

## Release tooling and activation gates

Build the SDK, then prepare from the independently retained accepted manifest
and its generated strict gateway policy:

```sh
node scripts/gateway-policy-release.mjs prepare \
  --manifest /reviewed/release-manifest.production.final.json \
  --policy /reviewed/measurement-policy.production.json \
  --sequence 1 --issued-at-ms ISSUED_MS --expires-at-ms EXPIRES_MS \
  --out /reviewed/gateway-policy.payload
```

This creates an **unsigned** payload and `.signing-bytes` file. It checks clean
finalized manifest shape, manifest hash, app, compose, release, OS and origin
agreement and the non-negotiable security floor. It does not independently
prove live hardware: the existing fresh DCAP/TLS acceptance gates must run on
that exact policy before signing. Do not label preparation as approval.

Once the approved purpose-specific signer supplies two public detached
signatures in an array of `{keyId, signature}` records:

```sh
node scripts/gateway-policy-release.mjs assemble \
  --payload /reviewed/gateway-policy.payload \
  --signatures /reviewed/gateway-policy.signatures.json \
  --out /reviewed/gateway-policy.json
node scripts/gateway-policy-release.mjs verify \
  --envelope /reviewed/gateway-policy.json
```

Assembly verifies both production origins against packaged roots and refuses
unsigned/test/development approvals. It writes a new artifact, never overwrites
an existing one, and does not publish it. Archive each policy and signatures.

**Remaining operational work:**

1. Review and install the purpose-specific signer candidate in backend branch
   `gateway-policy-authority-20261006`; see its canonical runbook
   `docs/operations/GATEWAY_POLICY_AUTHORITY.md`. The installed broker remains
   unchanged. The candidate `sign-gateway-policy` operation reads fixed public
   artifacts from the measured clean commit, retains custody/session/roster
   checks and signs only the exact policy domain. Owner installation is a
   separate gate. Agents never read private keys or activate the owner session.
   Commit the unsigned canonical payload at
   `deploy/phala/gateway-policy.approval.json` and use the reviewed backend
   `npm run gateway:policy:authorize -- --out NEW_ENVELOPE_FILE`. Preparation
   must be within five minutes of signing; there is no pre-signed approval in
   either candidate branch. Backend measurement policy flags are normalized
   only to enforce expiry and exclusively `UpToDate` TCB before comparison.
2. Obtain the first real policy approval after fresh exact-policy hardware/TLS
   acceptance. Establish monotonically increasing publication and renewal
   before the seven-day maximum signed lifetime expires. Rollback is a new
   higher-sequence approval of the retained previous release.
3. Publish the verified artifact independently. A signed JSON file under the
   public website's `.well-known/anonrouter/` path is one delivery option, but
   requires its own approved site release. Coordinate policy publication with
   gateway promotion; the single-policy protocol does not implement overlapping
   rolling releases or zero downtime.
4. Run exact packed JavaScript and Python canaries against the published feed,
   with real DCAP and observed TLS at both origins. Test refresh/revocation,
   expiry, persistent restart and rollback before activation.
5. Enable the packaged flag and set its minimum sequence to the first accepted
   publication. Publish the reviewed SDK through its existing separate gates.

These gates are necessary before saying default SDK users automatically follow
production gateway updates. Clients on older SDKs still need the migration
release. Neither automatic policy updates nor hardware verification fixes
provider outages, rate limits, metering or missing provider GPU evidence.

## Verification

Both languages consume `shared/vectors/gateway-policy-authority.json`:
synthetic public keys and signatures only, never production approval material.
CI and release gates run signature/refusal vectors, cross-language persisted
rollback tests and publication-tool preparation/refusal tests. Browser bundling
and empty-environment artifact installation are checked separately.
