# Verifying AnonRouter

How to check, from your own process, what actually protects a request. This is the
reference for `verifyRoute()` / `verify_route()`: the two hops, the five verdict
states, and what to do when a check fails.

## The two hops

A request passes through two parties. Verifying one establishes nothing about the
other, so they are separate checks with separate verdicts.

| | Question | Endpoint |
| --- | --- | --- |
| **Hop 1** AnonRouter's routing plane | Is the data plane I am connected to the exact reviewed build, in an Intel TDX confidential VM, bound to my nonce and my origin? | `GET /v1/gateway/attestation` |
| **Hop 2** the provider route | Did the model provider terminate my request inside a verified enclave running measurements I pinned? | `/v1/tee/attestation` |

A verified hop 2 says nothing about who routed the request to it. A verified hop 1
says nothing about where inference actually ran.

## One call

```ts
import { createClient, atLeast } from "@anonrouter/confidential";

const client = createClient({
  baseUrl: "https://api.anonrouter.ai",
  controlBaseUrl: "https://control.anonrouter.ai",
  apiKey: KEY
});

const verdict = await client.verifyRoute({
  model: "z-ai/glm-5.2",
  provider: "venice",
  gateway: true            // omit to skip hop 1 entirely
});

if (!atLeast(verdict.overallState, "cryptographically_checked")) {
  throw new Error(`route not established: ${verdict.reason}`);
}
```

```python
from anonrouter_confidential import create_client, at_least

with create_client(
    "https://api.anonrouter.ai",
    api_key=KEY,
    control_base_url="https://control.anonrouter.ai",
) as client:
    verdict = client.verify_route(
        model="z-ai/glm-5.2", provider="venice", gateway=True
    )
    if not at_least(verdict.overall_state, "cryptographically_checked"):
        raise SystemExit(f"route not established: {verdict.reason}")
```

## The five states

Gate with `atLeast()` / `at_least()` rather than comparing strings. It is the one
place the ordering lives, so your threshold keeps meaning the same thing if a
state is ever added to the scale.

| State | What it proves | What it does **not** prove |
| --- | --- | --- |
| `hardware_verified` | Everything below, plus the quote's signature chained to the silicon vendor's roots with an accepted TCB status. | That the measured code behaves well. Attestation names the code; reviewing it is a separate act. |
| `cryptographically_checked` | Every binding was recomputed and held: your nonce is in the quote, the event log replays to the hardware registers, each measured digest commits to the payload beside it, the identity matched your pins. | That any of it came from real silicon. Without a vendor-root chain this is internal consistency plus your pins, not proof of hardware. |
| `policy_matched` | The evidence's **claimed** identity matched your pins. | That the identity is cryptographically bound to hardware. This is the honest state for a verdict resting on a document somebody else produced. |
| `untrusted` | Nothing. A required check failed. | — |
| `unavailable` | Nothing. The hop could not be attempted: no endpoint, or nothing pinned for this origin. | — |

`untrusted` and `unavailable` are both failures and neither is stronger than the
other. They are separate because *"we looked and it failed"* and *"we could not
look"* call for different responses, and collapsing them hides which one you are
in.

### Two traps the contract closes

**A skipped hop is not a passing hop.** `verdict.trusted` covers only the hops you
asked for. With `gateway` omitted you get a verdict about the provider enclave and
nothing about the router. `verdict.gateway.requested` always says which way that
went. Read it.

**Two honest hops on the wrong route is still the wrong route.** Each hop verifier
only ever sees its own evidence, so neither can notice that the gateway attested
itself perfectly while serving a different provider, model, or privacy class than
you asked for. `verifyRoute` cross-binds them; any disagreement lands in
`bindingMismatches` and forces `untrusted`, however strong the hops were.

## What the route binding actually checks

AnonRouter mints the attestation ticket against exactly one catalog row, and the
relay echoes back everything that row bound. Each field is a separate binding
because a substitution can move one without moving the others.

| `bindingMismatches[].field` | Question | Checked when |
| --- | --- | --- |
| `provider` | Did the enclave that answered belong to the provider you named? | always |
| `requested_model` | Is the CATALOG model the one you asked for? | always — naming the model is the request |
| `model` | Is the provider-native (upstream) model the one you pinned? | only with `upstreamModel` set |
| `privacy_modality` | Was the route served under the class you pinned? | only with `privacyClass` set |

The nonce is the fifth binding and is checked inside the hop verdict, not here:
your fresh nonce must appear in the evidence, and a stale document fails
`nonce_binding`. The sixth is the ticket itself, which is single-use and expires
in about a minute, so a redeemed ticket cannot be replayed.

### The privacy class comes from the route, not the provider

`verdict.route.privacyModality` is `tee` or `e2ee`, and
`verdict.route.privacyModalitySource` says how the SDK learned it:

| Source | Meaning |
| --- | --- |
| `caller-pinned` | You passed `privacyClass`. A route served under another class is a mismatch. |
| `gateway-attested` | Read from the class bound into your single-use ticket at mint time. |
| `unestablished` | Nothing stated it. No privacy property was proved. |

`contentVisibleToAnonRouter` follows from that, and on `unestablished` it is
`true` — the weaker claim. `false` is a positive assertion that AnonRouter's build
is outside your trust set, and it is only ever made from a pin or an attested
class.

This matters because a provider is not a privacy class. AnonRouter publishes
`private` and `e2ee` rows for the same provider today, and the same model id can
be `tee` at one provider and `e2ee` at another. Pin `privacyClass` when the
distinction is what you are relying on.

## Interpreting a failure

`verdict.gateway.failedChecks` and `verdict.provider.failedChecks` name the exact
required checks that failed.

### Hop 1: the binding

| Failed check | What happened | What to do |
| --- | --- | --- |
| `binding_wellformed` | The binding object was malformed or carried an unknown field. | Treat as hostile. A verifier that ignored an unknown field would accept a digest computed over data it never inspected. |
| `report_data_binds_binding` | SHA-512 of the binding does not equal the quote's `report_data`. | The document is not internally consistent. Either it was assembled by something that is not the TD, or the SDK and gateway disagree on the binding version. Check `GATEWAY_BINDING_VERSION`. |
| `nonce_matches_request` | The quote is bound to a different nonce than you sent. | A replayed document. Never accept: this is the anti-replay control doing its job. |
| `origin_matches_connection` | The quote names an origin other than the one you connected to. | The document belongs to a different deployment. |

### Hop 1: the measurements

| Failed check | What happened | What to do |
| --- | --- | --- |
| `quote_parsed`, `quote_is_tdx` | Not a structurally valid Intel TDX quote. | The endpoint is not serving TDX evidence. |
| `quote_not_debug` | The TD has the debug bit set. | Fatal, always. A debug TD lets the host read and modify guest memory, so nothing inside it is confidential. |
| `event_log_replays_rtmrs` | The event log does not reproduce the quote's registers. | The log does not describe what the hardware measured. |
| `event_digests_commit_to_payloads` | An RTMR3 digest does not commit to the payload printed beside it. | Someone re-served a genuine quote with rewritten readable fields. |
| `compose_hash_measured_in_rtmr3` | The binding names a compose hash the hardware did not measure. | The binding is claiming a configuration that did not run. |
| `app_compose_matches_measurement` | The returned manifest is not the measured one. | The manifest is decorative; nothing in it is evidence. |
| `app_id_measured`, `instance_id_measured` | The identity in the binding is not the one measured at boot. | The TD is claiming an identity it was not provisioned with. |

### Hop 1: your policy

These mean the evidence is sound but does not match what **you** pinned. That is
usually a stale pin after a release, not an attack.

| Failed check | What to do |
| --- | --- |
| `app_id_pinned`, `compose_hash_pinned`, `release_pinned` | The deployment moved to a build you have not reviewed. Review the new release, then update your policy. Do **not** copy the values out of the response: a policy taken from the server it describes is circular. |
| `origin_pinned` | Your policy does not authorize this origin. |
| `platform_measurements_pinned`, `os_image_pinned` | The firmware or guest OS changed. Reproduce the new measurements with `dstack-mr` before pinning them. |
| `key_provider_pinned` | The CVM's keys come from a different KMS. A different key provider is a different trust domain even at the same compose hash. |
| `compose_public_logs_disabled` | The attested configuration publishes container logs. |
| `compose_images_digest_pinned` | An image is referenced by tag, so the compose hash pins something that can be repointed later. |

### Hop 1: transport and hardware

| Failed check | What to do |
| --- | --- |
| `transport_terminates_in_tee` | TLS terminates in front of the TD, so the transport is not proof of who you are talking to. Fails only when your policy sets `requireInTeeTls`. |
| `tls_certificate_bound_to_quote` | The certificate your session used is not the one the TD attested. If it appears as an **advisory** gap instead, your runtime could not observe its own certificate; a browser cannot. |
| `quote_signature_chain` | Either no DCAP engine was supplied and your policy requires one, or the engine rejected the quote. See below. |
| `tcb_status_acceptable` | The chain verified but the platform's TCB is not on your accepted list. **This can fail while `quote_signature_chain` passes**, and that is the case worth understanding: the signature is genuine and the machine holding your data has known unpatched vulnerabilities. |
| `evidence_recent` | The document is outside the age window, or carries no timestamp at all. A document that cannot be aged has not been shown to be fresh. |

## Reaching `hardware_verified`

The packages bundle **no DCAP engine**, and the reason is worth stating because it
is the same reason the rest of this SDK exists. A binary inside a package is one
you have to accept on faith. A hand-rolled JavaScript or Python reimplementation
would be worse: an unreviewed, un-cross-checked version of the single component
whose failure mode is printing `hardware_verified` for a forged quote.

What the packages ship is a strict adapter to AnonRouter's reviewed offline
engine. The engine itself has two forms and you should prefer the second:

```bash
# 1. The release asset. linux/amd64, static, SHA-256 in the release's SHA256SUMS.
curl -LO https://github.com/anonrouter/anonrouter-sdk/releases/download/v0.1.0/anonrouter-dcap-verifier-linux-amd64
chmod +x anonrouter-dcap-verifier-linux-amd64

# 2. Your own build of the same source, which is the one that means something.
#    Builds twice from clean in a digest-pinned image and fails unless the two
#    outputs are byte-identical. Compare the digest it prints with ours.
scripts/build-dcap-verifier.sh --reproduce
```

The source is in [`native/dcap-verifier`](native/dcap-verifier) under
AGPL-3.0-only (the rest of this repository is Apache-2.0; the boundary is that
directory and neither published package contains it). Put the binary on PATH or
name it in `ANONROUTER_DCAP_VERIFIER_BIN`, and hop 1 can reach
`hardware_verified`:

```ts
import { createAnonRouterDcapVerifier } from "@anonrouter/confidential/dcap";

const verdict = await client.verifyRoute({
  model, provider,
  gateway: { chainVerifier: createAnonRouterDcapVerifier() }
});
```

```python
from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

verdict = client.verify_route(
    model=..., provider=...,
    gateway={"chain_verifier": create_anonrouter_dcap_verifier()},
)
```

Check what your machine can do with `anonrouter-verify doctor`, or with
`describeDcapInstallation()` / `describe_dcap_installation()`. It reports the
engine that would actually run, its SHA-256, the host's target triple, and, when
there is none, exactly what to install.

### What the adapter does beyond spawning a process

- **It fetches the collateral the engine will not.** The engine performs no network
  access on purpose: a verifier that fetches its own trust inputs is only as
  trustworthy as whatever it reached. The SDK acquires Intel's signed TCB info, QE
  identity and CRLs, caches them to the collateral's OWN signed `nextUpdate` rather
  than a constant, and hands them in as untrusted input that the engine
  revalidates under its pinned Intel root. Supply `collateral` yourself to avoid
  the fetch entirely; a mirror is not a party you have to trust.
- **It cross-checks the engine against our own parse.** The engine echoes its view
  of `mr_td`, the RTMRs and `report_data`. A "verified" verdict describing a
  different TD is refused, because a pass nobody can attribute to the quote in hand
  is worse than a failure.
- **It can pin the engine.** Set `expectedBinarySha256` /
  `expected_binary_sha256` and a swapped binary is a refusal rather than a
  different answer.
- **It resolves the engine without substituting one.** An explicit path that does
  not exist resolves to NOTHING; it never falls through to the environment, and the
  environment never falls through to PATH.
- **It forwards your policy's accepted TCB statuses**, so the engine and the local
  policy cannot disagree about what "acceptable" means.

Everything fails closed: a missing engine, a digest mismatch, a timeout, a crash, a
non-zero exit with no verdict, non-JSON output, an oversized response, collateral
that could not be acquired, or a `verified` field that is not a real boolean. There
is no path where an error becomes a pass.

A prepared verifier is bound to the exact quote it ran on and refuses any other, so
a verdict for one quote can never be replayed onto another.

**Hop 2 is not affected by any of this.** The provider hop still caps at
`cryptographically_checked`, because several provider routes run GPU enclaves whose
NVIDIA attestation chain is not available to verify, and chaining only the CPU
quote while printing `hardware_verified` would claim more than was checked.

### Bringing your own engine

`@anonrouter/confidential/chain-verifiers` and
`anonrouter_confidential.gateway.chain_verifiers` remain for an engine you wrote.
They speak a minimal contract of their own (raw quote hex on stdin, camelCase
`tcbStatus` out), which is **not** the reviewed engine's contract. Point them at
your own wrapper, not at `anonrouter-dcap-verifier` directly. The remote variant
asks a Quote Verification Service, which is a real transfer of trust: never point
it at a service operated by the party you are verifying, which the SDK cannot
detect for you.

## Verifying from a terminal

```bash
anonrouter-verify doctor  --origin https://api.anonrouter.ai
anonrouter-verify gateway --origin https://api.anonrouter.ai \
  --policy ./reviewed-policy.json --dcap --require hardware_verified
anonrouter-verify route --origin https://api.anonrouter.ai \
  --control-origin https://control.anonrouter.ai --provider venice --model MODEL \
  --policy ./reviewed-policy.json --dcap --require cryptographically_checked
echo $?
```

| Exit | Meaning |
| --- | --- |
| 0 | The requested assurance was established. |
| 1 | It was not, including "we could not look". |
| 2 | The command or its inputs were wrong. |

Keeping 1 and 2 apart is load-bearing: if a mistyped flag exited 1, a job gating on
the exit code would read its own typo as a verification answer.

`gateway` is credential-free. `route` adds hop 2 and reads an API key only from an
environment variable; `--api-key` is refused by name, because argv is visible in
the process table and lands in shell history. Neither command prints a key, a
ticket, request content, or the raw evidence body.

## Pinning

The policy a gateway is held to must never be fetched from that gateway. A server
that could hand you the list of builds you accept could always name itself. Pins
therefore ship inside the packages, or you supply your own, and an origin with no
pin fails closed rather than falling back to the server's claim about itself.

```ts
import { loadGatewayPolicy } from "@anonrouter/confidential";
await client.verifyGateway({ policy: loadGatewayPolicy(myReviewedPolicy) });
```

Every switch in a policy is required. There are no permissive defaults, so a
truncated or hand-edited policy fails to parse rather than silently disabling a
check.

### Refreshing a pin after a release

Deployments move, and a pin that no longer matches is the system working rather
than breaking. The refresh is a review, not a copy:

```
node scripts/capture-gateway-pins.mjs https://your-cvm.example
```

That prints an **observation**, not a policy, with a `reviewChecklist` of what
must be corroborated before any of it becomes a pin. The rule it enforces is the
one that makes pinning worth doing at all: a value taken from the server it
describes proves nothing about that server.

What each field needs:

- **`app_id`, `compose_hash`, `os_image_hash`** must appear in an independently
  produced identity record **for the origin you are pinning**, not for a
  neighbouring hostname on the same machine.
- **`release_id`** is injected at deploy time and carries no measurements. It
  proves what someone set an environment variable to. Confirm it names a build
  you reviewed.
- **`mrTd`, `rtmr0..2`** should be reproduced offline with `dstack-mr` from the OS
  image and `vm_config`, not carried over and not read off the machine.
- **`tls_spki_sha256`** should be compared against the certificate actually served
  on that origin, observed by you.

The shipped production pin comes from the independently retained release manifest
with SHA-256
`46da4d4210c21ea76681ef044dd2da29d8a3a4cff135348ef9f168f6a09c6bf4`.
It binds the production origin, reviewed source, measured app-compose, image,
app/instance identity, TLS SPKI and platform measurements. The earlier rejected
refresh is retained in `shared/gateway-policies.json` as review history: it lacked
this production-origin manifest. A `release_id` is never accepted by itself;
the app id, compose hash and every platform measurement must also match.

Which origin serves what, and what each answer means, is inventoried in
[`docs/live-contract-inventory.md`](docs/live-contract-inventory.md). The short
version: both evidence hops and encrypted content stay on the confidential
origin, while `controlBaseUrl`/`--control-origin` sends only content-free ticket
and catalog operations to the public control plane.

## Testing against a real confidential VM

Both suites carry live tests that are skipped unless you point them at a
deployment:

```
export ANONROUTER_LIVE_GATEWAY_ORIGIN=https://your-cvm.example
export ANONROUTER_LIVE_PUBLIC_ORIGIN=https://your-non-cvm.example      # optional
export ANONROUTER_DCAP_VERIFIER_BIN=/path/to/anonrouter-dcap-verifier  # optional
npm test        # JS
pytest -q       # Python
```

With no origin set they skip with a stated reason and never fabricate a result;
the readiness cases still run and assert that a non-attesting deployment reports
`unavailable` rather than passing.

**Most of the live suite is negatives, and that is the point.** A live "it
verified" is nearly worthless on its own: a verifier that returned ok for
everything would produce it too. So the suite takes ONE genuine document and
changes exactly one thing at a time, fifteen times, requiring the verdict to fail
on the exact check that covers it. A replayed nonce. A wrong origin. A rewritten
release id, TLS fingerprint, event digest, compose-hash payload, or manifest. A
flipped `report_data` or RTMR byte. The debug attribute set. A `vm_config` naming
an OS image the hardware never measured. Stale evidence. An observed certificate
the TD did not attest. A different key provider. Platform measurements that do not
match.

One invariant is asserted that survives a pin refresh: under the shipped pin, only
POLICY checks may fail. If a structural or cryptographic check ever fails against
real hardware, the verifier and the hardware disagree, and that is a defect rather
than a stale allowlist.

With `ANONROUTER_DCAP_VERIFIER_BIN` set, four more cases run: the verdict reaches
`hardware_verified`; a quote tampered inside the signed body is refused at the
SIGNATURE, which no amount of structural checking could catch; a verifier prepared
for one live quote refuses another from the same machine; and a policy accepting no
status the platform can report fails at `tcb_status_acceptable` while the signature
itself is fine.

`ANONROUTER_LIVE_PUBLIC_ORIGIN` covers the other half: a deployment that does NOT
serve the contract must report `unavailable` with no failed checks, and no pin may
ship for it.

The attestation endpoint is credential-free, content-free, and read-only, so
pointing these at a real deployment sends no prompt, no key, and no account
identity.
