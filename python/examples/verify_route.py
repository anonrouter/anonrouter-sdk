"""Verify both hops and interpret the result.

    ANONROUTER_API_KEY=ar_... python examples/verify_route.py

Optional env:
    ANONROUTER_BASE_URL   default https://api.anonrouter.ai
    ANONROUTER_MODEL      default venice-uncensored
    ANONROUTER_PROVIDER   default venice

Prints what was established, what was not, and why, then exits non-zero if the
route did not meet the threshold. Attestation only: not a billable inference call.
"""

from __future__ import annotations

import os
import sys

from anonrouter_confidential import at_least, create_client, describe_state

BASE_URL = os.environ.get("ANONROUTER_BASE_URL", "https://api.anonrouter.ai")
MODEL = os.environ.get("ANONROUTER_MODEL", "venice-uncensored")
PROVIDER = os.environ.get("ANONROUTER_PROVIDER", "venice")

# The bar this program insists on. `policy_matched` would accept a verdict resting
# on a document we did not produce, which is weaker than most callers mean.
REQUIRED = "cryptographically_checked"


def main() -> int:
    api_key = os.environ.get("ANONROUTER_API_KEY")
    if not api_key:
        print("Set ANONROUTER_API_KEY to your AnonRouter API key (inference scope).", file=sys.stderr)
        return 2

    with create_client(BASE_URL, api_key=api_key) as client:
        verdict = client.verify_route(
            model=MODEL,
            provider=PROVIDER,
            # Ask about AnonRouter's own plane too. Against a deployment not
            # running in a CVM this reports `unavailable`: untrusted, not a pass.
            gateway={"allow_candidate_policy": True},
        )

    print(f"route      {verdict.route.provider}/{verdict.route.model}")
    visible = (
        "  (AnonRouter sees your plaintext on this route)"
        if verdict.content_visible_to_anonrouter
        else ""
    )
    print(f"modality   {verdict.route.privacy_modality}{visible}")
    print()

    for name, hop in (("hop 1 gateway ", verdict.gateway), ("hop 2 provider", verdict.provider)):
        print(f"{name}  {hop.state if hop.requested else 'not requested'}")
        if hop.requested:
            print(f"                {describe_state(hop.state)}")
            if hop.failed_checks:
                print(f"                failed: {', '.join(hop.failed_checks)}")
            if hop.advisory_gaps:
                print(f"                gaps:   {', '.join(hop.advisory_gaps)}")

    print()
    print(f"overall    {verdict.overall_state}")
    for m in verdict.binding_mismatches:
        # Two honestly-attested parties on the wrong route is still the wrong route.
        print(f"MISMATCH   {m.field_name}: asked for {m.expected}, {m.source} reported {m.observed}")
    if verdict.reason:
        print(f"reason     {verdict.reason}")

    if not at_least(verdict.overall_state, REQUIRED):
        print(f"\nFAILED: route did not reach {REQUIRED}.", file=sys.stderr)
        print("See VERIFYING.md for what each failed check means.", file=sys.stderr)
        return 1
    print(f"\nOK: route reached {REQUIRED}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
