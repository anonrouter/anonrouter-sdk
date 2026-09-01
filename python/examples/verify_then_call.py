"""Verify first, send only if the verdict clears the bar, and re-verify at send time.

    ANONROUTER_API_KEY=ar_... python examples/verify_then_call.py

This is the shape most applications actually want, and it is three ideas rather
than one:

1. GATE BEFORE SENDING. Nothing leaves the process until the route reaches the
   state this program requires. A verdict you look at after sending is a log
   entry, not a control.

2. RE-VERIFY AT SEND TIME. ``chat(require_gateway=...)`` establishes hop 1 again,
   with a fresh nonce, before it spends a ticket or names a model. A verdict from
   thirty seconds ago is a fact about thirty seconds ago; the deployment can be
   replaced between the two calls, and the whole point of the nonce is that each
   answer covers exactly one challenge.

3. SAY WHAT WAS NOT COVERED. A trusted verdict for a call that never asked about
   hop 1 establishes the provider enclave and nothing about who routed the request
   there. This program prints that distinction instead of hiding it.

Optional env:
    ANONROUTER_BASE_URL   default https://api.anonrouter.ai
    ANONROUTER_CONTROL_URL default https://control.anonrouter.ai
    ANONROUTER_MODEL      default openai/gpt-oss-120b
    ANONROUTER_PROVIDER   default near-ai
    ANONROUTER_REQUIRE    default cryptographically_checked
    PROMPT, MAX_TOKENS

BILLABLE: the second half makes one small real inference call.

Mirrors ``js/confidential/examples/verify-then-call.ts``.
"""

from __future__ import annotations

import os
import sys

from anonrouter_confidential import (
    TRUSTED_STATES,
    at_least,
    create_client,
    describe_state,
)
from anonrouter_confidential.gateway.dcap import (
    create_anonrouter_dcap_verifier,
    describe_dcap_installation,
)

BASE_URL = os.environ.get("ANONROUTER_BASE_URL", "https://api.anonrouter.ai")
CONTROL_URL = os.environ.get("ANONROUTER_CONTROL_URL", "https://control.anonrouter.ai")
MODEL = os.environ.get("ANONROUTER_MODEL", "openai/gpt-oss-120b")
PROVIDER = os.environ.get("ANONROUTER_PROVIDER", "near-ai")
PROMPT = os.environ.get("PROMPT", "In one sentence: what does attestation prove?")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "64"))
REQUIRED = os.environ.get("ANONROUTER_REQUIRE", "cryptographically_checked")


def main() -> int:
    if REQUIRED not in TRUSTED_STATES:
        print(f"ANONROUTER_REQUIRE must be one of {', '.join(TRUSTED_STATES)}.", file=sys.stderr)
        return 2
    api_key = os.environ.get("ANONROUTER_API_KEY")
    if not api_key:
        print("Set ANONROUTER_API_KEY to your AnonRouter API key (inference scope).", file=sys.stderr)
        return 2

    # The chain verifier is what makes `hardware_verified` reachable. Supplying it
    # unconditionally is the right default: with no engine installed it fails the
    # chain check rather than silently downgrading, and a policy that does not
    # require hardware verification is unaffected either way.
    engine = describe_dcap_installation()
    gateway = {
        "chain_verifier": create_anonrouter_dcap_verifier(),
    }
    if engine.available:
        print(f"DCAP engine: {engine.binary_path}")
    else:
        print(f"DCAP engine: none installed, so hardware_verified is out of reach here ({engine.reason})")

    with create_client(BASE_URL, api_key=api_key, control_base_url=CONTROL_URL) as client:
        # ---- 1. Verify, and stop here if it does not clear the bar -----------
        verdict = client.verify_route(model=MODEL, provider=PROVIDER, gateway=gateway)

        print(f"\nroute      {verdict.route.provider}/{verdict.route.model}")
        modality_note = (
            "  (a TEE route: AnonRouter sees your plaintext to route and meter it)"
            if verdict.content_visible_to_anonrouter
            else "  (E2EE: only ciphertext reaches AnonRouter's relay)"
        )
        print(f"modality   {verdict.route.privacy_modality}{modality_note}")
        for label, hop in (("hop 1 gateway ", verdict.gateway), ("hop 2 provider", verdict.provider)):
            print(f"{label}  {hop.state if hop.requested else 'not requested'}")
            if hop.requested:
                print(f"                {describe_state(hop.state)}")
                if hop.failed_checks:
                    print(f"                failed: {', '.join(hop.failed_checks)}")
                if hop.advisory_gaps:
                    print(f"                gaps:   {', '.join(hop.advisory_gaps)}")
        print(f"overall    {verdict.overall_state}  (required: {REQUIRED})")
        for mismatch in verdict.binding_mismatches:
            print(
                f"MISMATCH   {mismatch.field_name}: asked for {mismatch.expected}, "
                f"{mismatch.source} reported {mismatch.observed}"
            )

        if not at_least(verdict.overall_state, REQUIRED):
            print(
                f"\nNOT SENDING. The route reached {verdict.overall_state}, below {REQUIRED}.",
                file=sys.stderr,
            )
            if verdict.reason:
                print(f"Reason: {verdict.reason}", file=sys.stderr)
            print(
                "See VERIFYING.md for what each failed check means and what to do about it.",
                file=sys.stderr,
            )
            return 1
        if not verdict.gateway.requested:
            # Worth saying out loud even on a pass.
            print("\nNOTE: hop 1 was not requested, so nothing here covers who routed the request.")

        # ---- 2. Send, re-verifying hop 1 at send time ------------------------
        print(f"\nOK: reached {verdict.overall_state}. Sending.")
        reply = client.chat(
            model=MODEL,
            provider=PROVIDER,
            messages=[{"role": "user", "content": PROMPT}],
            max_output_tokens=MAX_TOKENS,
            # The gate that actually protects this request. It runs BEFORE the
            # first authenticated call, so a caller who requires an attested plane
            # has not spent a ticket, or named a model, against one that is not.
            require_gateway=gateway,
        )

    print(f"\n{reply['content']}")
    if reply.get("usage"):
        print(f"\nusage: {reply['usage']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
