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

const client = createClient({ baseUrl: "https://api.anonrouter.ai", apiKey: KEY });

const verdict = await client.verifyRoute({
  model: "openai/gpt-oss-120b",
  provider: "near-ai",
  gateway: true            // omit to skip hop 1 entirely
});

if (!atLeast(verdict.overallState, "cryptographically_checked")) {
  throw new Error(`route not established: ${verdict.reason}`);
}
```

```python
from anonrouter_confidential import create_client, at_least

with create_client("https://api.anonrouter.ai", api_key=KEY) as client:
    verdict = client.verify_route(
        model="openai/gpt-oss-120b", provider="near-ai", gateway=True
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

The packages ship **no DCAP engine**. Verifying a quote's signature against Intel's
roots needs vendor collateral that cannot be vendored into a browser-safe library,
and printing `hardware_verified` for work that was never done would defeat the
purpose of the SDK. So the chain is a port you fill, and there are two maintained
adapters:

```ts
import { createSubprocessChainVerifier } from "@anonrouter/confidential/chain-verifiers";

const adapter = createSubprocessChainVerifier({ binaryPath: "/opt/dcap-verifier" });
const chainVerifier = await adapter.prepare(evidence.quote);

await client.verifyGateway({ chainVerifier });
```

- **Subprocess** (`createSubprocessChainVerifier` / `SubprocessChainVerifier`) runs
  an engine you control. The trust stays on your machine. This is the strong option.
- **Remote** (`createRemoteChainVerifier` / `RemoteChainVerifier`) asks a Quote
  Verification Service. Convenient, and a real transfer of trust: you are now
  trusting that service's answer about whether the hardware is genuine. Never point
  it at a service operated by the party you are verifying, which the SDK cannot
  detect for you.

Both fail closed. A missing binary, a timeout, a crash, a non-zero exit, non-JSON
output, an oversized response, an unreachable service, or a `verified` field that
is not a real boolean all resolve to not-verified. There is no path where an error
becomes a pass.

A prepared verifier is bound to the exact quote it ran on and refuses any other,
so a verdict for one quote can never be replayed onto another.

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

## Testing against a real confidential VM

Both suites carry live tests that are skipped unless you point them at a
deployment:

```
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://your-cvm.example npm test        # JS
ANONROUTER_LIVE_GATEWAY_ORIGIN=https://your-cvm.example pytest          # Python
```

They fetch with a fresh nonce, verify the real quote, replay the real event log,
and assert that replaying the document against a **different** nonce is refused.
With no origin set they skip with a stated reason and never fabricate a result;
the readiness cases still run and assert that a non-attesting deployment reports
`unavailable` rather than passing.

The attestation endpoint is credential-free, content-free, and read-only, so
pointing these at a real deployment sends no prompt, no key, and no account
identity.
