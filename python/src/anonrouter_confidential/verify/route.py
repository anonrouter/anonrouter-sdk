"""verify_route(): the stable two-hop verdict.

Mirrors ``js/confidential/src/verify/route.ts``. See that file and state.py for
the reasoning; the short version is that this does three things a plain wrapper
around the two hop verifiers would not:

1. It CROSS-BINDS the hops to one route. Each hop verifier only ever sees the
   evidence for its own side, so neither can notice that the gateway attested
   itself honestly while serving a different provider, model, or privacy class
   than the caller asked for. That disagreement is invisible to both hops
   individually and is what a routing substitution looks like.
2. It reports ordered STATES rather than levels, so a threshold keeps meaning.
3. It never collapses "did not check" into "checked and passed".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .state import at_least, describe_state, is_trusted, state_for_level


@dataclass(frozen=True)
class RequestedRoute:
    """What the caller asked to be routed to. Every hop is bound back to this."""

    provider: str
    model: str
    #: ``e2ee`` means the content must stay opaque to AnonRouter.
    privacy_modality: str


@dataclass
class RouteHopVerdict:
    """One hop's outcome in the stable contract."""

    #: Whether this call asked to establish this hop at all.
    requested: bool
    state: str
    #: What this state does and does not prove.
    meaning: str
    #: The first unmet requirement, or None. Sanitized and content-free.
    reason: str | None
    #: Names of every required check that failed, in order.
    failed_checks: list[str] = field(default_factory=list)
    #: Checks that did not pass but were advisory: known, unclosed gaps.
    advisory_gaps: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "state": self.state,
            "meaning": self.meaning,
            "reason": self.reason,
            "failed_checks": list(self.failed_checks),
            "advisory_gaps": list(self.advisory_gaps),
        }


@dataclass(frozen=True)
class RouteBindingMismatch:
    """A disagreement between what was asked for and what a hop attested."""

    field_name: str
    expected: str
    observed: str
    #: Which side reported the observed value: "gateway" or "provider-evidence".
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field_name,
            "expected": self.expected,
            "observed": self.observed,
            "source": self.source,
        }


@dataclass
class RouteVerdict:
    route: RequestedRoute
    #: The weakest state across every REQUESTED hop, plus the route binding.
    overall_state: str
    trusted: bool
    reason: str | None
    gateway: RouteHopVerdict
    provider: RouteHopVerdict
    #: ANY entry forces untrusted, however strong the hops were: two honestly
    #: attested parties on the wrong route is still the wrong route.
    binding_mismatches: list[RouteBindingMismatch]
    #: True on a ``tee`` route: the gateway sees plaintext to route and meter.
    content_visible_to_anonrouter: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "route": {
                "provider": self.route.provider,
                "model": self.route.model,
                "privacy_modality": self.route.privacy_modality,
            },
            "overall_state": self.overall_state,
            "trusted": self.trusted,
            "reason": self.reason,
            "gateway": self.gateway.as_dict(),
            "provider": self.provider.as_dict(),
            "binding_mismatches": [m.as_dict() for m in self.binding_mismatches],
            "content_visible_to_anonrouter": self.content_visible_to_anonrouter,
        }


def _hop_from_checks(requested: bool, state: str, reason: str | None, checks: Any) -> RouteHopVerdict:
    entries = list(checks or [])
    return RouteHopVerdict(
        requested=requested,
        state=state,
        meaning=describe_state(state),
        reason=reason,
        failed_checks=[c.name for c in entries if c.required and not c.passed],
        advisory_gaps=[c.name for c in entries if not c.required and not c.passed],
    )


def hop_not_requested() -> RouteHopVerdict:
    """A hop that was never asked about. Not a failure, and not a pass."""
    return RouteHopVerdict(
        requested=False,
        state="unavailable",
        meaning=describe_state("unavailable"),
        reason="not requested",
    )


def hop_unavailable(reason: str) -> RouteHopVerdict:
    """A hop asked about but not attemptable (no endpoint, no pin)."""
    return RouteHopVerdict(
        requested=True,
        state="unavailable",
        meaning=describe_state("unavailable"),
        reason=reason,
    )


def gateway_hop_verdict(result: Any) -> RouteHopVerdict:
    """Project a gateway (hop 1) result into the stable contract."""
    state = state_for_level(result.verification_level) if result.status == "ok" else "untrusted"
    return _hop_from_checks(True, state, result.reason, result.checks)


def provider_hop_verdict(verdict: Any) -> RouteHopVerdict:
    """Project a provider (hop 2) verdict into the stable contract."""
    state = state_for_level(verdict.verification_level) if verdict.status == "ok" else "untrusted"
    return _hop_from_checks(True, state, verdict.reason, verdict.checks)


def assemble_route_verdict(
    *,
    route: RequestedRoute,
    gateway: RouteHopVerdict,
    provider: RouteHopVerdict,
    gateway_echo: dict[str, Any] | None = None,
    attested_upstream_model: str | None = None,
    expected_upstream_model: str | None = None,
) -> RouteVerdict:
    """Combine both hops and the route binding into one verdict.

    Pure and synchronous: the client fetches evidence and runs the hop verifiers,
    then hands the results here. Keeping the combination free of I/O is what lets
    the ordering rules be tested exhaustively.
    """
    mismatches: list[RouteBindingMismatch] = []
    echo = gateway_echo or {}

    echoed_provider = echo.get("provider")
    if isinstance(echoed_provider, str) and echoed_provider and echoed_provider != route.provider:
        mismatches.append(
            RouteBindingMismatch("provider", route.provider, echoed_provider, "gateway")
        )
    echoed_class = echo.get("privacy_class")
    if (
        isinstance(echoed_class, str)
        and echoed_class in ("tee", "e2ee")
        and echoed_class != route.privacy_modality
    ):
        mismatches.append(
            RouteBindingMismatch("privacy_modality", route.privacy_modality, echoed_class, "gateway")
        )
    # Only checked when the caller pinned an expectation. Without one there is no
    # disagreement to detect: the gateway's mapping IS the only statement of it.
    if (
        isinstance(expected_upstream_model, str)
        and expected_upstream_model
        and isinstance(attested_upstream_model, str)
        and attested_upstream_model
        and expected_upstream_model != attested_upstream_model
    ):
        mismatches.append(
            RouteBindingMismatch(
                "model", expected_upstream_model, attested_upstream_model, "provider-evidence"
            )
        )

    # The overall state is the weakest REQUESTED hop. A hop nobody asked about
    # cannot drag the verdict down, but it also cannot prop it up, which is why
    # ``gateway.requested`` stays on the result for the caller to read.
    requested_hops = [h for h in (gateway, provider) if h.requested]
    weakest = "hardware_verified"
    for hop in requested_hops:
        if not is_trusted(hop.state):
            weakest = hop.state
            break
        if is_trusted(weakest) and not at_least(hop.state, weakest):
            weakest = hop.state

    if mismatches:
        overall = "untrusted"
    elif not requested_hops:
        overall = "unavailable"
    else:
        overall = weakest

    if mismatches:
        first = mismatches[0]
        reason: str | None = (
            f"route_binding_mismatch: {first.field_name} expected {first.expected}, "
            f"{first.source} reported {first.observed}"
        )
    elif not requested_hops:
        reason = "no hop was requested"
    elif provider.requested and not is_trusted(provider.state):
        reason = f"provider: {provider.reason or provider.state}"
    elif gateway.requested and not is_trusted(gateway.state):
        reason = f"gateway: {gateway.reason or gateway.state}"
    else:
        reason = None

    return RouteVerdict(
        route=route,
        overall_state=overall,
        trusted=is_trusted(overall) and not mismatches,
        reason=reason,
        gateway=gateway,
        provider=provider,
        binding_mismatches=mismatches,
        content_visible_to_anonrouter=route.privacy_modality == "tee",
    )
