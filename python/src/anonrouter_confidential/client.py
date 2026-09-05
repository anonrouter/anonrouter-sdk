"""Thin AnonRouter confidential-inference client (httpx).

Runs the same flow as the JavaScript client in this monorepo, against the same
endpoints:

  verify -> POST /v1/inference/attestation-tickets  (Bearer auth, content-free)
         -> POST /v1/tee/attestation                (credential-free; ticket + fresh nonce)
         -> GATE on our independent verify_raw_evidence verdict
  chat   -> POST /v1/inference/tickets              (Bearer auth, e2ee + explicit ceiling)
         -> encrypted relay (credential-free single-use ticket): NEAR/Venice SSE at
            /v1/chat/completions, Chutes octet-stream at /v1/e2ee/chat/completions.

Security contract enforced here: Bearer auth only for the content-free control
requests; the relay is authenticated ONLY by the single-use ticket (never the API
key); plaintext is NEVER sent to the relay; fresh keys + a fresh nonce every call.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx
import nacl.bindings as nb
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._util import as_dict, as_list, as_str
from .crypto import chutes as chutes_crypto
from .crypto import near as near_crypto
from .crypto import venice as venice_crypto
from .errors import ConfidentialError
from .gateway.binding import GATEWAY_NONCE_HEX_LENGTH
from .gateway.policy import GatewayMeasurementPolicy, pinned_gateway_policy_for
from .gateway.verify import TdxChainVerifier, verify_gateway_attestation
from .measurements import pinned_endpoint_identity_for, pinned_measurement_policy_for
from .media import (
    DEFAULT_CONTROL_ORIGIN,
    DEFAULT_INFERENCE_ORIGIN,
    AudioApi,
    ImagesApi,
    MediaOwner,
    _MediaTransport,
)
from .route_policy import is_route_withheld_by_service, withheld_route_message
from .tdx import TDX_TEE_TYPE, match_measurement_allowlist, parse_tdx_quote
from .verify import verify_raw_evidence
from .verify.checks import hex_equal
from .verify.route import (
    RequestedRoute,
    RouteHopVerdict,
    RouteVerdict,
    assemble_route_verdict,
    gateway_hop_verdict,
    hop_not_requested,
    hop_unavailable,
    provider_hop_verdict,
)
from .verify.state import describe_state
from .verify.types import AttestationExpectations, NormalizedVerdict

_E2EE_PROVIDERS = {"near-ai", "venice", "chutes"}
#: The wire protocol each E2EE provider speaks. The provider NAME does not settle
#: it: a provider that gained a second E2EE protocol would keep echoing the same
#: name while this client encrypted to the wrong scheme, so the protocol the
#: gateway offers is checked against the one about to be spoken.
_E2EE_PROTOCOLS = {"near-ai": "near-v2", "venice": "venice-legacy", "chutes": "chutes-mlkem-v1"}
# Whole-body opaque relays: the entire request and response are one encrypted blob,
# so the gateway cannot meter them token by token and requires a ticket reserving
# the route's full output ceiling. The streaming providers are metered as they go.
_OPAQUE_E2EE_PROVIDERS = {"chutes"}
_CURVE = ec.SECP256K1()

# Client-side E2EE request surface. Kept in step with the JavaScript limits in
# js/confidential/src/transport/validation.ts.
_MAX_MESSAGE_CHARS = 128 * 1024
_MAX_TOTAL_CHARS = 256 * 1024

# Chutes instance identity shapes, matching js/confidential/src/transport/chutes.ts.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_INSTANCE_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_MLKEM_PUBLICKEY_BYTES = 1184


#: Loopback hosts, where plaintext http can be opted into for local development.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_api_origin(base_url: str, allow_insecure_http: bool) -> str:
    """Normalize and validate the API origin.

    The origin is security-relevant in its own right: a gateway quote binds the
    exact origin the client connected to, so a base_url carrying a path, a query,
    or credentials could not be compared against it, and a plaintext one could not
    be trusted to have reached the host at all. Trailing slashes are tolerated and
    stripped because they are a habit, not an ambiguity.
    """
    if not isinstance(base_url, str) or not base_url:
        raise ConfidentialError("create_client needs a base_url")
    parts = urlsplit(base_url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ConfidentialError("the base_url scheme must be https")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfidentialError("the base_url must be a bare origin: no credentials, query, or fragment")
    if parts.path not in ("", "/"):
        raise ConfidentialError(
            "the base_url must be a bare origin with no path, for example "
            "https://api.anonrouter.ai (not .../v1)"
        )
    try:
        hostname, port = parts.hostname, parts.port
    except ValueError as exc:
        raise ConfidentialError("the base_url has an invalid port") from exc
    if not hostname:
        raise ConfidentialError("the base_url must have a host")
    if scheme == "http" and not (allow_insecure_http and hostname in _LOOPBACK_HOSTS):
        # Over plaintext http the API key travels in the clear and the origin a
        # gateway quote binds cannot mean anything, so allowing it for a remote host
        # would turn an attested route into a decorative one.
        raise ConfidentialError(
            "the base_url must be https. Plaintext http is accepted only for a loopback host, "
            "and only with allow_insecure_http=True."
        )
    host = f"[{hostname}]" if ":" in hostname else hostname.lower()
    origin = f"{scheme}://{host}"
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        origin = f"{origin}:{port}"
    return origin


def _prepare_chain_verifier(
    supplied: Any,
    quote: Any,
    policy: GatewayMeasurementPolicy,
    now_ms: float,
) -> Any:
    """Resolve whichever form the caller supplied into a verifier bound to THIS quote.

    A FACTORY (anything exposing ``prepare``) does its I/O here and is handed the
    resolved policy's accepted TCB statuses, so the engine and the local policy
    cannot disagree about what "acceptable" means. An already-prepared verifier is
    passed through untouched.

    A factory that raises is turned into a refusal rather than an exception: an
    engine that could not run is a failed ``quote_signature_chain`` check, which is
    a verdict the caller can read, not a crash that loses every other check.
    """
    if supplied is None:
        return None
    prepare = getattr(supplied, "prepare", None)
    if not callable(prepare):
        return supplied
    try:
        return prepare(
            str(quote or ""),
            accepted_tcb_statuses=list(policy.acceptable_tcb_statuses),
            now_ms=now_ms,
        )
    except Exception as exc:  # noqa: BLE001 - any preparation failure is a refusal
        detail = str(exc) or "chain verifier could not be prepared"

        class _Refused:
            implementation = "unavailable"

            def verify_chain(self, quote: str, collateral: Any = None) -> tuple[bool, None, str]:
                return False, None, detail

        return _Refused()


def _gateway_option_to_kwargs(option: bool | dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalize the ``gateway`` / ``require_gateway`` option into explicit kwargs."""
    if option is None or option is False:
        return None
    if option is True:
        return {}
    if not isinstance(option, dict):
        raise ConfidentialError("the gateway option must be a bool or a dict of verify_gateway kwargs")
    return option


def create_client(
    base_url: str | None = None, api_key: str | None = None, **kwargs: Any
) -> ConfidentialClient:
    """Construct a client.

    ``base_url`` is the confidential inference origin. Split production callers
    pass ``control_base_url="https://control.anonrouter.ai"`` so API-key and
    content-free ticket operations use the control tier while both attestation
    hops and encrypted request content remain on ``base_url``.

    ``inference_base_url`` is an exact alias for ``base_url``, and with neither
    supplied both origins default to AnonRouter's production pair.
    """
    return ConfidentialClient(base_url=base_url, api_key=api_key, **kwargs)


class ConfidentialClient(MediaOwner):
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        control_base_url: str | None = None,
        inference_base_url: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 300.0,
        allow_insecure_http: bool = False,
    ) -> None:
        """``timeout`` bounds how long a single response may take to arrive.

        The default is deliberately generous. A whole-body opaque request (Chutes)
        streams nothing: the enclave generates the entire completion before any byte
        comes back, so a large generation can legitimately take minutes and a
        conventional 30 or 60 second default would abort a request the enclave was
        still working on. Connect is kept short so an unreachable gateway still
        fails fast.
        """
        # `base_url` and `inference_base_url` name the same thing. Two different
        # values is an ambiguous configuration, and the ambiguity is about where
        # prompts go, so it is refused instead of resolved by precedence.
        if (
            base_url
            and inference_base_url
            and _normalize_api_origin(base_url, allow_insecure_http)
            != _normalize_api_origin(inference_base_url, allow_insecure_http)
        ):
            raise ConfidentialError(
                "base_url and inference_base_url name the same origin and must not "
                "disagree. Set one of them."
            )
        # An ABSENT origin (None) means "use the production defaults". An origin
        # that was supplied and is empty is a misconfiguration -- an unset
        # environment variable read with a "" default is the usual way to arrive
        # here -- and quietly defaulting it would send content to production when
        # the caller believed they had configured something else.
        for name, value in (
            ("base_url", base_url),
            ("control_base_url", control_base_url),
            ("inference_base_url", inference_base_url),
        ):
            if value is not None and not value.strip():
                raise ConfidentialError(
                    f"{name} was supplied but empty. Omit it to use the default origin."
                )
        configured_inference = inference_base_url if inference_base_url is not None else base_url
        # `origin` is the canonical scheme://host[:port] a gateway quote is bound
        # against; `base_url` stays as the (identical) string used to build URLs.
        self.origin = _normalize_api_origin(
            configured_inference or DEFAULT_INFERENCE_ORIGIN, allow_insecure_http
        )
        self.base_url = self.origin
        # Preserve same-origin behaviour for custom/self-hosted deployments. Both
        # production content names, however, always use the credential-only control
        # origin unless the caller explicitly overrides it.
        implicit_control_origin = (
            DEFAULT_CONTROL_ORIGIN
            if self.origin in {DEFAULT_INFERENCE_ORIGIN, "https://api.private.anonrouter.ai"}
            else self.origin
        )
        self.control_origin = _normalize_api_origin(
            control_base_url or implicit_control_origin,
            allow_insecure_http,
        )
        self.api_key = api_key
        self._allow_insecure_http = allow_insecure_http
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=httpx.Timeout(timeout, connect=10.0))
        #: ``client.images.generate(...)`` -- ticketed image generation.
        self.images = ImagesApi(self)
        #: ``client.audio.speech.create(...)`` -- ticketed text-to-speech.
        self.audio = AudioApi(self)

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> ConfidentialClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _attest_route(
        self,
        model: str,
        provider: str,
        nonce: str | None = None,
        *,
        privacy_modality: str | None = None,
        upstream_model: str | None = None,
    ) -> dict[str, Any]:
        """Fetch evidence, resolve the route facts and verify. Does NOT raise on a
        route disagreement.

        The split from ``verify_attestation`` is what makes cross-binding work.
        A disagreement used to be raised, and ``verify_route`` catches exceptions
        and turns them into a bare "the provider hop failed" -- so the mismatch
        list stayed empty, the caller was told the enclave was bad when the real
        problem was that AnonRouter served a different route, and every
        cross-binding rule was reachable only from a hand-built test.
        """
        nonce = nonce or os.urandom(32).hex()
        attestation = self._fetch_attestation_for_route(model, provider, nonce)

        served_provider = as_str(attestation.get("provider"))
        served_model = as_str(attestation.get("model"))
        raw_evidence = attestation.get("evidence")
        upstream_model = upstream_model or as_str(attestation.get("upstream_model")) or model

        # THE MODALITY IS A PROPERTY OF THE ROUTE. A caller pin wins, because
        # pinning is how a caller says which contract they reviewed. Otherwise the
        # class the gateway bound into the single-use ticket at mint time is used:
        # a catalog fact about one row, not a guess, and what lets one SDK verify
        # a `tee` route and an `e2ee` route on the SAME provider.
        #
        # `tee` is the fallback when nobody states one, and it is conservative in
        # both directions: as a REPORT it is the weaker privacy claim, and as a
        # VERIFICATION CONTRACT it never skips a check (no verifier makes a
        # required check conditional on `e2ee`; Tinfoil makes one conditional on
        # `tee`). This used to be `"tee" if provider == "tinfoil" else "e2ee"`, a
        # hard-coded map from a provider NAME to a privacy property, which is
        # wrong the moment any provider serves two classes.
        served_class = as_str(attestation.get("privacy_class"))
        served_class = served_class if served_class in ("tee", "e2ee") else None
        modality = privacy_modality or served_class or "tee"
        modality_source = (
            "caller-pinned" if privacy_modality else "gateway-attested" if served_class else "unestablished"
        )

        expectations = self._expectations(provider, upstream_model, nonce, modality)
        verdict = verify_raw_evidence(provider, raw_evidence, expectations)
        gateway_verdict = attestation.get("attestation")
        return {
            "provider": provider,
            "model": model,
            "upstream_model": upstream_model,
            "privacy_modality": modality,
            "privacy_modality_source": modality_source,
            # THE GATEWAY'S OWN WORDS, kept separate from anything derived here.
            # Feeding a derived value back into the cross-binder compares a thing
            # to itself, which is how a check stops being a check while still
            # looking present.
            "gateway_route": {
                "provider": served_provider,
                "model": served_model,
                "upstream_model": as_str(attestation.get("upstream_model")),
                "privacy_class": served_class,
                "protocol": as_str(attestation.get("protocol")),
            },
            "verdict": verdict,
            "gateway_verdict": gateway_verdict,
            "raw_evidence": raw_evidence,
        }

    # -- public API --------------------------------------------------------
    def verify_attestation(
        self,
        model: str,
        provider: str,
        nonce: str | None = None,
        *,
        privacy_modality: str | None = None,
        upstream_model: str | None = None,
    ) -> dict[str, Any]:
        """Verify a route's attestation INDEPENDENTLY of AnonRouter's own verdict.

        Works for TEE routes as well as E2EE ones. Attestation is content-free and
        not a billable inference call.

        ``upstream_model`` pins the provider-native model id the evidence must
        attest. Normally you leave it unset: enclaves name themselves in provider
        terms rather than by AnonRouter's catalog id, and the gateway reports the
        mapping as ``upstream_model``. Set it to pin the binding yourself, or when
        talking to a gateway old enough not to report the field. An explicit value
        always wins over what the gateway says.

        ``privacy_modality`` pins the class you reviewed. Unset, the class the
        gateway bound into the ticket is used and reported as
        ``privacy_modality_source``.

        Returns a dict with ``provider``, ``model``, ``privacy_modality``,
        ``privacy_modality_source``, ``gateway_route`` (exactly what the gateway
        echoed), ``verdict`` (our NormalizedVerdict), ``gateway_verdict`` (what the
        gateway returned; never trusted alone), and ``raw_evidence``.

        Raises on a route disagreement: a single-hop caller asked about ONE route
        and did not get it, and there is no second hop here whose verdict could
        carry the nuance. ``verify_route`` reports the same facts as structured
        mismatches instead.
        """
        result = self._attest_route(
            model,
            provider,
            nonce,
            privacy_modality=privacy_modality,
            upstream_model=upstream_model,
        )
        echo = result["gateway_route"]
        if echo["provider"] and echo["provider"] != provider:
            raise ConfidentialError(
                "the attestation was bound to a different provider than the one requested"
            )
        if echo["model"] and echo["model"] != model:
            raise ConfidentialError(
                "the attestation was bound to a different model than the one requested"
            )
        if privacy_modality and echo["privacy_class"] and echo["privacy_class"] != privacy_modality:
            raise ConfidentialError(
                f"the gateway served a {echo['privacy_class']} route where {privacy_modality} was pinned"
            )
        return result

    # -- hop 1: AnonRouter's own confidential routing plane ------------------
    def verify_gateway(
        self,
        *,
        nonce: str | None = None,
        policy: GatewayMeasurementPolicy | None = None,
        allow_candidate_policy: bool = False,
        observed_tls_spki_sha256: str | None = None,
        observed_tls_spki_supplied: bool = False,
        chain_verifier: TdxChainVerifier | None = None,
    ) -> dict[str, Any]:
        """Verify AnonRouter's OWN confidential plane, independently of hop 2.

        This answers "is the data plane I am connected to the exact reviewed build
        running inside an Intel TDX confidential VM, bound to my nonce and my
        origin?". Verifying the provider's enclave says nothing about that, and
        vice versa, which is why the two are separate calls with separate verdicts.

        ``policy`` defaults to the pin this package ships for the client's origin.
        Pass ``allow_candidate_policy=True`` to accept a shipped pin whose status is
        ``candidate`` (a reviewed but pre-release plane whose measurements are
        expected to move). Supply your own policy to pin a release you reviewed.

        The request is credential-free by design: a client verifies the plane
        BEFORE it trusts the endpoint with anything, so sending a key here would
        invert the trust order.
        """
        nonce = (nonce or os.urandom(32).hex()).lower()
        if len(nonce) != GATEWAY_NONCE_HEX_LENGTH or not re.fullmatch(r"[0-9a-f]+", nonce):
            raise ConfidentialError(
                f"the gateway attestation nonce must be exactly {GATEWAY_NONCE_HEX_LENGTH} hex characters"
            )
        resolved = self._resolve_gateway_policy(policy, allow_candidate_policy)
        if resolved is None:
            # No policy means nothing to check the evidence against. Fetching it
            # anyway and reporting what it says would be reading the server's own
            # claim back to the caller.
            raise ConfidentialError(
                f"no pinned gateway policy for {self.origin}. Supply one via policy=, or pass "
                "allow_candidate_policy=True if this package ships a pre-release pin for this origin."
            )
        active, provenance = resolved
        evidence = self._fetch_gateway_evidence(nonce)
        if evidence is None:
            raise ConfidentialError(
                f"{self.origin} does not expose gateway attestation, so it cannot be shown to "
                "run inside a confidential VM"
            )
        now_ms = time.time() * 1000.0
        verdict = verify_gateway_attestation(
            evidence,
            nonce=nonce,
            origin=self.origin,
            policy=active,
            now_ms=now_ms,
            observed_tls_spki_sha256=observed_tls_spki_sha256,
            observed_tls_spki_supplied=observed_tls_spki_supplied,
            chain_verifier=_prepare_chain_verifier(
                chain_verifier, evidence.get("quote"), active, now_ms
            ),
        )
        return {
            "origin": self.origin,
            "policy": provenance,
            "verdict": verdict,
            "raw_evidence": evidence,
        }

    # -- THE STABLE CONTRACT --------------------------------------------------
    def verify_route(
        self,
        model: str,
        provider: str,
        *,
        nonce: str | None = None,
        upstream_model: str | None = None,
        privacy_class: str | None = None,
        gateway: bool | dict[str, Any] = False,
    ) -> RouteVerdict:
        """Establish the route end to end and report what actually held.

        This is the call to build on. Both hops are cross-bound to the route you
        asked for, and the result reports ordered STATES rather than a single
        boolean, so a threshold like ``at_least(v.overall_state,
        "cryptographically_checked")`` keeps meaning the same thing over time.

        The provider hop always runs. The gateway hop runs only when asked, and
        ``verdict.gateway.requested`` says which way that went, so a skipped hop
        can never be mistaken for a passing one. Any disagreement between the
        requested route and what a hop attested forces the whole verdict
        untrusted, however strong the individual hops were.
        """
        gateway_options = _gateway_option_to_kwargs(gateway)
        gateway_hop = (
            hop_not_requested() if gateway_options is None else self._gateway_route_hop(gateway_options)
        )

        attestation: dict[str, Any] | None = None
        provider_failure: str | None = None
        try:
            attestation = self._attest_route(
                model,
                provider,
                nonce,
                privacy_modality=privacy_class,
                upstream_model=upstream_model,
            )
        except ConfidentialError as exc:
            provider_failure = str(exc)

        if attestation is not None:
            provider_hop = provider_hop_verdict(attestation["verdict"])
            # THE GATEWAY'S OWN WORDS. Echoing back the modality this client just
            # derived compared a value to itself and could never fire.
            served = attestation["gateway_route"]
            echo: dict[str, Any] | None = {
                "provider": served["provider"],
                "model": served["model"],
                "privacy_class": served["privacy_class"],
            }
            attested_upstream = served["upstream_model"]
            modality = attestation["privacy_modality"]
            modality_source = attestation["privacy_modality_source"]
        else:
            provider_hop = RouteHopVerdict(
                requested=True,
                state="untrusted",
                meaning=describe_state("untrusted"),
                reason=provider_failure or "provider verification failed",
                failed_checks=[provider_failure or "provider_verification_failed"],
            )
            echo = None
            attested_upstream = None
            modality = "tee"
            modality_source = "unestablished"

        return assemble_route_verdict(
            route=RequestedRoute(
                provider=provider,
                model=model,
                privacy_modality=modality,
                privacy_modality_source=modality_source,
            ),
            gateway=gateway_hop,
            provider=provider_hop,
            gateway_echo=echo,
            attested_upstream_model=attested_upstream,
            expected_upstream_model=upstream_model,
        )

    def _gateway_route_hop(self, options: dict[str, Any]) -> RouteHopVerdict:
        """Run hop 1 and project it into the stable contract."""
        report = self._gateway_hop(options)
        if report["status"] in ("unavailable", "unpinned"):
            return hop_unavailable(str(report.get("reason") or report["status"]))
        verdict = report.get("verdict")
        if verdict is None:
            return hop_unavailable(str(report.get("reason") or "no gateway verdict"))
        return gateway_hop_verdict(verdict)

    # -- both hops (earlier report shape; prefer verify_route) ----------------
    def verify(
        self,
        model: str,
        provider: str,
        *,
        nonce: str | None = None,
        upstream_model: str | None = None,
        gateway: bool | dict[str, Any] = False,
    ) -> dict[str, Any]:
        """Verify both hops and return one report that says what it covered.

        ``gateway`` defaults to False: most deployments do not run inside a CVM
        yet, and a report that silently skipped a hop must never read as if it had
        covered one. ``report["gateway"]["requested"]`` always says which way this
        went, and ``report["trusted"]`` covers only the hops that were requested.

        Pass ``gateway=True`` for the shipped pin, or a dict of the keyword
        arguments :meth:`verify_gateway` accepts.
        """
        gateway_options = _gateway_option_to_kwargs(gateway)
        gateway_report = (
            {"requested": False, "status": "not-requested", "verification_level": None, "reason": None}
            if gateway_options is None
            else self._gateway_hop(gateway_options)
        )

        attestation = self.verify_attestation(
            model, provider, nonce, upstream_model=upstream_model
        )
        verdict: NormalizedVerdict = attestation["verdict"]
        provider_report = {
            "status": verdict.status,
            "verification_level": verdict.verification_level,
            "reason": verdict.reason,
            "verdict": verdict,
            "gateway_verdict": attestation.get("gateway_verdict"),
            "raw_evidence": attestation.get("raw_evidence"),
        }

        gateway_trusted = not gateway_report["requested"] or gateway_report["status"] == "ok"
        trusted = gateway_trusted and verdict.status == "ok"
        if not gateway_trusted:
            reason = f"gateway: {gateway_report['reason'] or gateway_report['status']}"
        elif verdict.status == "ok":
            reason = None
        else:
            reason = f"provider: {verdict.reason or 'verification_failed'}"

        modality = attestation["privacy_modality"]
        return {
            "route": {
                "provider": provider,
                "model": model,
                "upstream_model": attestation.get("upstream_model", model),
                "privacy_modality": modality,
                # The single most misunderstood fact about TEE routing, stated as a
                # fact rather than left to be inferred from a modality string.
                "content_visible_to_anonrouter": modality == "tee",
            },
            "gateway": gateway_report,
            "provider": provider_report,
            "trusted": trusted,
            "reason": reason,
        }

    def _resolve_gateway_policy(
        self, policy: GatewayMeasurementPolicy | None, allow_candidate: bool
    ) -> tuple[GatewayMeasurementPolicy, dict[str, Any]] | None:
        """Resolve the policy to hold the plane to, and say where it came from.

        A caller-supplied policy always wins. Otherwise the pin this package ships
        for THIS client's origin is used. There is deliberately no path that fetches
        a policy from the gateway: a server that could hand a client the list of
        builds the client accepts could always name itself.
        """
        if policy is not None:
            return policy, {
                "origin": "caller-supplied",
                "source": policy.source,
                "version": policy.version,
            }
        entry = pinned_gateway_policy_for(self.origin, allow_candidate=allow_candidate)
        if entry is None:
            return None
        return entry.policy, {
            "origin": "package-pinned",
            "source": entry.policy.source,
            "version": entry.policy.version,
            "status": entry.status,
        }

    def _fetch_gateway_evidence(self, nonce: str) -> dict[str, Any] | None:
        """Fetch the gateway attestation document, or None when this deployment
        does not expose the route at all (503 from a non-CVM deployment, 404 from a
        gateway too old to serve it). Both mean "this hop cannot be established
        here", which is different from "it failed"."""
        try:
            resp = self._http.get(
                self._url("/v1/gateway/attestation"),
                params={"nonce": nonce},
                headers={"accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ConfidentialError("could not reach the gateway attestation service") from exc
        if resp.status_code in (404, 503):
            return None
        self._raise_for_status(resp, "gateway attestation")
        try:
            body = resp.json()
        except ValueError as exc:
            raise ConfidentialError("the gateway attestation response could not be parsed") from exc
        if not isinstance(body, dict) or "binding" not in body or "quote" not in body:
            raise ConfidentialError(
                "the gateway attestation response did not contain a binding and a quote"
            )
        return body

    def _gateway_hop(self, options: dict[str, Any]) -> dict[str, Any]:
        """Establish hop 1 for verify()/chat(), turning every outcome into a report
        rather than an exception, so the caller decides what a status means."""
        resolved = self._resolve_gateway_policy(
            options.get("policy"), bool(options.get("allow_candidate_policy"))
        )
        if resolved is None:
            return {
                "requested": True,
                "status": "unpinned",
                "verification_level": None,
                "reason": f"no pinned gateway policy for {self.origin}",
            }
        active, provenance = resolved
        nonce = str(options.get("nonce") or os.urandom(32).hex()).lower()
        evidence = self._fetch_gateway_evidence(nonce)
        if evidence is None:
            return {
                "requested": True,
                "status": "unavailable",
                "verification_level": None,
                "reason": "this deployment does not expose gateway attestation",
                "policy": provenance,
            }
        now_ms = time.time() * 1000.0
        verdict = verify_gateway_attestation(
            evidence,
            nonce=nonce,
            origin=self.origin,
            policy=active,
            now_ms=now_ms,
            observed_tls_spki_sha256=options.get("observed_tls_spki_sha256"),
            observed_tls_spki_supplied=bool(options.get("observed_tls_spki_supplied")),
            chain_verifier=_prepare_chain_verifier(
                options.get("chain_verifier"), evidence.get("quote"), active, now_ms
            ),
        )
        return {
            "requested": True,
            "status": "ok" if verdict.status == "ok" else "failed",
            "verification_level": verdict.verification_level,
            "reason": verdict.reason,
            "policy": provenance,
            "verdict": verdict,
            "raw_evidence": evidence,
        }

    def chat(
        self,
        model: str,
        provider: str,
        messages: list[dict[str, str]],
        max_output_tokens: int,
        *,
        require_gateway: bool | dict[str, Any] = False,
    ) -> dict[str, Any]:
        """Run one browser-parity confidential inference request end to end.

        Single-turn, text-only. Fresh keys + nonce each call. Never sends plaintext
        to the relay. Gates on our own attestation verdict BEFORE minting the paid
        inference ticket.
        """
        # A ROUTE THE SERVICE WITHHOLDS FAILS HERE, before the first
        # authenticated call and long before anything is encrypted or sent. The
        # mint would refuse it anyway; refusing here turns "your ticket request
        # failed" into a sentence that names the route and says why.
        # SCOPED TO THE PRODUCTION ORIGINS, because that is what the policy
        # describes. A self-hosted deployment, a staging origin or a test double
        # has its own catalog, and refusing a route there on the strength of
        # AnonRouter's production decisions would be this SDK inventing policy
        # for somebody else's service.
        if self.origin in {
            DEFAULT_INFERENCE_ORIGIN,
            "https://api.private.anonrouter.ai",
        } and is_route_withheld_by_service(provider, model, "e2ee"):
            raise ConfidentialError(withheld_route_message(provider, model, "e2ee"))
        if provider not in _E2EE_PROVIDERS:
            raise ConfidentialError(f"provider {provider!r} has no client-opaque E2EE route")
        if not isinstance(max_output_tokens, int) or max_output_tokens <= 0:
            raise ConfidentialError("encrypted requests need a bounded output-token limit")
        # Fail visibly on an unsupported request BEFORE spending an attestation ticket.
        _validate_e2ee_messages(messages)

        # Optional HOP 1 gate. Deliberately BEFORE the first authenticated call: a
        # caller who requires AnonRouter's own plane to be attested must not have
        # spent a ticket, or named a model, against a plane that is not.
        gateway_requirement = _gateway_option_to_kwargs(require_gateway)
        if gateway_requirement is not None:
            hop = self._gateway_hop(gateway_requirement)
            if hop["status"] != "ok":
                detail = f": {hop['reason']}" if hop.get("reason") else ""
                raise ConfidentialError(
                    f"AnonRouter's own confidential plane did not verify ({hop['status']}{detail}). "
                    "Nothing was sent."
                )

        ticket = self._mint_attestation_ticket(model, provider)
        nonce = os.urandom(32).hex()
        attestation = self._fetch_attestation(ticket, nonce)
        # Every check here runs BEFORE the paid inference ticket below, so a
        # substituted route costs nothing.
        if attestation.get("provider") not in (None, provider):
            raise ConfidentialError("attestation was bound to a different provider")
        served_model = as_str(attestation.get("model"))
        if served_model and served_model != model:
            raise ConfidentialError("attestation was bound to a different model than the one requested")
        # A `tee` route has no client-opaque channel: encrypting to it would send a
        # body the enclave cannot read, on a route whose plaintext AnonRouter's
        # build handles anyway.
        if as_str(attestation.get("privacy_class")) == "tee":
            raise ConfidentialError(
                f"{provider}/{model} is served as a TEE route, which has no client-opaque "
                "encryption; verify it with verify_route() and call it as an ordinary route"
            )
        served_protocol = as_str(attestation.get("protocol"))
        expected_protocol = _E2EE_PROTOCOLS[provider]
        if served_protocol and served_protocol != expected_protocol:
            raise ConfidentialError(
                f"the gateway offered the {served_protocol} protocol where this client speaks "
                f"{expected_protocol}; nothing was encrypted or sent"
            )
        raw_evidence = attestation.get("evidence")
        upstream_model = attestation.get("upstream_model")
        if not isinstance(upstream_model, str) or not upstream_model:
            raise ConfidentialError("attestation did not name an upstream model")

        expectations = self._expectations(provider, upstream_model, nonce, "e2ee")
        verdict = verify_raw_evidence(provider, raw_evidence, expectations)
        if verdict.status != "ok":
            raise ConfidentialError(f"attestation failed independent verification: {verdict.reason}")

        # A whole-body opaque relay (Chutes) cannot be metered token by token, so the
        # gateway requires the paid ticket to reserve the route's FULL output ceiling.
        # The caller's max_output_tokens still caps the ACTUAL generation: it travels
        # in the encrypted request body, not in the ticket.
        reserved = (
            self._resolve_output_ceiling(model, provider)
            if provider in _OPAQUE_E2EE_PROVIDERS
            else max_output_tokens
        )
        inference_ticket = self._mint_inference_ticket(model, provider, reserved)
        if provider == "near-ai":
            return self._chat_near(inference_ticket, model, upstream_model, raw_evidence, messages, max_output_tokens)
        if provider == "venice":
            return self._chat_venice(inference_ticket, model, upstream_model, raw_evidence, messages, max_output_tokens)
        return self._chat_chutes(
            inference_ticket, upstream_model, raw_evidence, messages, max_output_tokens, nonce, expectations
        )

    # -- control requests --------------------------------------------------
    def _mint_attestation_ticket(self, model: str, provider: str) -> str:
        resp = self._http.post(
            self._control_url("/v1/inference/attestation-tickets"),
            headers=self._auth_headers(),
            json={"model": model, "provider": provider},
        )
        self._raise_for_status(resp, "attestation ticket")
        ticket = resp.json().get("ticket")
        if not isinstance(ticket, str) or not ticket:
            raise ConfidentialError("gateway returned an invalid attestation ticket")
        return ticket

    def _fetch_attestation_for_route(self, model: str, provider: str, nonce: str) -> dict[str, Any]:
        """Fetch raw attestation evidence for a route, for verification only.

        Two paths exist, and which one is reachable depends on how AnonRouter is
        deployed, so this tries them in the order that works most widely:

        1. Ticketed: mint a content-free attestation ticket, then present ONLY that
           ticket to the attestation endpoint. Where attestation is served by the
           credential-isolated relay, this is the only path that works: a request
           carrying an account key is refused there, by design, because that relay
           never accepts account credentials alongside a route it serves. This path
           also reports ``upstream_model``, which the model binding needs.
        2. Key-authenticated GET, for a deployment that serves this route directly.
           Attestation tickets are only issued for E2EE-capable models, so this is
           also the only path that can verify a TEE-only route such as Tinfoil.

        Neither path ever carries content, and attestation is not a billable
        inference call.
        """
        ticket: str | None = None
        try:
            ticket = self._mint_attestation_ticket(model, provider)
        except ConfidentialError:
            # In the split production architecture the account key belongs only
            # to the control origin. A failed ticket mint must therefore fail
            # closed; the legacy key-authenticated fallback below is safe only
            # when both roles are served by the same origin.
            if self.control_origin != self.origin:
                raise
            # A TEE-only route cannot be issued an attestation ticket. Fall through
            # to the key-authenticated path rather than failing hard.
            ticket = None

        if ticket is not None:
            resp = self._http.post(
                self._url("/v1/tee/attestation"),
                headers={"content-type": "application/json", "x-anonrouter-ticket": ticket},
                json={"nonce": nonce},
            )
            if resp.status_code < 400:
                return self._attestation_body(resp)
            # Fall through only on a routing/authorization mismatch; a genuine
            # attestation failure should surface as itself.
            if resp.status_code not in (401, 404):
                self._raise_for_status(resp, "attestation")
            if self.control_origin != self.origin:
                raise ConfidentialError(
                    "the confidential origin rejected the single-use attestation "
                    f"ticket with status {resp.status_code}; the API key was not sent there"
                )

        resp = self._http.get(
            self._url("/v1/tee/attestation"),
            headers={"accept": "application/json", **self._auth_headers()},
            params={"model": model, "provider": provider, "nonce": nonce},
        )
        if resp.status_code == 401 and ticket is None:
            raise ConfidentialError(
                "this deployment serves attestation only through the credential-isolated "
                "relay, which takes a single-use ticket, and "
                f"{provider}/{model} was not issued one. Attestation tickets are issued "
                "for E2EE-capable routes; a TEE-only route cannot be verified against "
                "this host."
            )
        self._raise_for_status(resp, "attestation")
        return self._attestation_body(resp)

    @staticmethod
    def _attestation_body(resp: httpx.Response) -> dict[str, Any]:
        parsed = resp.json()
        if not isinstance(parsed, dict) or "evidence" not in parsed:
            raise ConfidentialError("attestation response did not contain evidence")
        return parsed

    def _fetch_attestation(self, ticket: str, nonce: str) -> dict[str, Any]:
        # Credential-free: the single-use ticket authenticates this, never the API key.
        resp = self._http.post(
            self._url("/v1/tee/attestation"),
            headers={"content-type": "application/json", "x-anonrouter-ticket": ticket},
            json={"nonce": nonce},
        )
        self._raise_for_status(resp, "attestation")
        parsed = resp.json()
        if not isinstance(parsed, dict) or "evidence" not in parsed:
            raise ConfidentialError("attestation response did not contain evidence")
        return parsed

    def _resolve_output_ceiling(self, model: str, provider: str) -> int:
        """The route's full output ceiling, read from the public catalog.

        Only the opaque (non-streaming) transport needs this. Streaming routes are
        metered as they go and reserve exactly what the caller asked for.
        """
        resp = self._http.get(self._control_url("/v1/models"), headers=self._auth_headers())
        self._raise_for_status(resp, "model catalog")
        entry = next(
            (m for m in as_list(as_dict(resp.json()).get("data")) if as_dict(m).get("id") == model),
            None,
        )
        if entry is None:
            raise ConfidentialError(
                f"model {model!r} is not in the catalog; cannot reserve its output ceiling"
            )
        route = next(
            (
                r
                for r in as_list(as_dict(entry).get("provider_routes"))
                if as_dict(r).get("provider") == provider
            ),
            None,
        )
        ceiling = as_dict(route).get("max_output_tokens") if route is not None else None
        if not isinstance(ceiling, int):
            ceiling = as_dict(entry).get("max_output_tokens")
        if not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling <= 0:
            raise ConfidentialError(
                f"the catalog did not advertise an output ceiling for {provider}/{model}"
            )
        return ceiling

    def _mint_inference_ticket(self, model: str, provider: str, max_output_tokens: int) -> str:
        resp = self._http.post(
            self._control_url("/v1/inference/tickets"),
            headers=self._auth_headers(),
            json={
                "model": model,
                "provider": provider,
                "e2ee": True,
                "max_completion_tokens": max_output_tokens,
            },
        )
        self._raise_for_status(resp, "inference ticket")
        ticket = resp.json().get("ticket")
        if not isinstance(ticket, str) or not ticket:
            raise ConfidentialError("gateway returned an invalid inference ticket")
        return ticket

    # -- per-provider encrypted relay -------------------------------------
    def _chat_near(
        self,
        ticket: str,
        model: str,
        upstream_model: str,
        evidence: Any,
        messages: list[dict[str, str]],
        max_output_tokens: int,
    ) -> dict[str, Any]:
        model_ed_pub_hex = _evidence_str(evidence, "signing_public_key")
        seed = os.urandom(32)
        client_pub, _client_full = nb.crypto_sign_seed_keypair(seed)
        client_secret_hex = seed.hex()
        encrypted = [
            {"role": m["role"], "content": near_crypto.encrypt_field(m["content"], model_ed_pub_hex)}
            for m in messages
        ]
        body = {
            "model": model,
            "provider": "near-ai",
            "messages": encrypted,
            "max_tokens": max_output_tokens,
            "stream": True,
        }
        headers = {
            "content-type": "application/json",
            "accept": "text/event-stream",
            "x-anonrouter-ticket": ticket,
            "x-anonrouter-e2ee-provider": "near-ai",
            "x-signing-algo": "ed25519",
            "x-client-pub-key": client_pub.hex(),
            "x-encryption-version": "2",
        }
        return self._consume_sse(body, headers, lambda ct: near_crypto.decrypt(ct, client_secret_hex))

    def _chat_venice(
        self,
        ticket: str,
        model: str,
        upstream_model: str,
        evidence: Any,
        messages: list[dict[str, str]],
        max_output_tokens: int,
    ) -> dict[str, Any]:
        model_pub_hex = _evidence_str(evidence, "signing_public_key") or _evidence_str(evidence, "signing_key")
        client_private = ec.generate_private_key(_CURVE)
        client_private_hex = format(client_private.private_numbers().private_value, "064x")
        client_pub_hex = client_private.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        ).hex()
        encrypted = [
            {"role": m["role"], "content": venice_crypto.encrypt_field(m["content"], client_private_hex, model_pub_hex)}
            for m in messages
        ]
        body = {
            "model": model,
            "provider": "venice",
            "messages": encrypted,
            "max_tokens": max_output_tokens,
            "stream": True,
        }
        headers = {
            "content-type": "application/json",
            "accept": "text/event-stream",
            "x-anonrouter-ticket": ticket,
            "x-anonrouter-e2ee-provider": "venice",
            "x-venice-tee-client-pub-key": client_pub_hex,
            "x-venice-tee-model-pub-key": model_pub_hex.lower().removeprefix("0x"),
            "x-venice-tee-signing-algo": "ecdsa",
        }
        return self._consume_sse(body, headers, lambda ct: venice_crypto.decrypt(ct, client_private_hex))

    def _chat_chutes(
        self,
        ticket: str,
        upstream_model: str,
        evidence: Any,
        messages: list[dict[str, str]],
        max_output_tokens: int,
        nonce: str,
        expectations: AttestationExpectations,
    ) -> dict[str, Any]:
        # Encrypt ONLY to the ML-KEM key that report_data binds to this request's
        # nonce, independently re-verified here (not the raw e2e_instances field the
        # gateway asserts). This is the same guard the JavaScript transport applies
        # in js/confidential/src/transport/chutes.ts.
        allowlist = as_list(as_dict(expectations.measurement_policy).get("accepted"))
        instance_id, instance_nonce, instance_pubkey = _select_verified_chutes_key(
            evidence, nonce, allowlist
        )
        payload = {
            "model": upstream_model,
            "messages": messages,
            "max_tokens": max_output_tokens,
            "stream": False,
        }
        blob, response_secret_key = chutes_crypto.encrypt_request(payload, instance_pubkey)
        headers = {
            "content-type": "application/octet-stream",
            "accept": "application/octet-stream",
            "x-anonrouter-ticket": ticket,
            "x-anonrouter-e2ee-provider": "chutes",
            "x-chutes-instance-id": instance_id,
            "x-chutes-e2e-nonce": instance_nonce,
        }
        resp = self._http.post(
            self._url("/v1/e2ee/chat/completions"), headers=headers, content=blob
        )
        self._raise_for_status(resp, "encrypted inference")
        parsed = chutes_crypto.decrypt_response(resp.content, response_secret_key)
        return _normalize_completion(parsed)

    def _consume_sse(self, body: dict[str, Any], headers: dict[str, str], decrypt: Any) -> dict[str, Any]:
        content = ""
        reasoning = ""
        usage: dict[str, Any] | None = None
        finish_reason: str | None = None
        with self._http.stream(
            "POST", self._url("/v1/chat/completions"), headers=headers, json=body
        ) as resp:
            self._raise_for_status(resp, "encrypted inference")
            for frame in _iter_sse(resp.iter_lines()):
                delta = _openai_delta(frame)
                if delta.get("content"):
                    content += decrypt(delta["content"])
                if delta.get("reasoning"):
                    reasoning += decrypt(delta["reasoning"])
                if delta.get("usage"):
                    usage = delta["usage"]
                if delta.get("finish_reason"):
                    finish_reason = delta["finish_reason"]
        out: dict[str, Any] = {"content": content}
        if reasoning:
            out["reasoning"] = reasoning
        if usage:
            out["usage"] = usage
        if finish_reason:
            out["finish_reason"] = finish_reason
        return out

    # -- helpers -----------------------------------------------------------
    def _expectations(
        self, provider: str, upstream_model: str, nonce: str, modality: str
    ) -> AttestationExpectations:
        endpoint = pinned_endpoint_identity_for(provider, upstream_model) or provider
        return AttestationExpectations(
            provider=provider,
            upstream_model=upstream_model,
            endpoint_identity=endpoint,
            nonce=nonce,
            privacy_modality=modality,  # type: ignore[arg-type]
            canonical_model=upstream_model,
            route_id=f"{provider}/{upstream_model}",
            measurement_policy=pinned_measurement_policy_for(provider, upstream_model),
        )

    def _auth_headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        return headers

    # -- ticketed media ----------------------------------------------------
    def _media_transport(self) -> _MediaTransport:
        """Build the two-origin media transport, refusing a collapsed boundary.

        The check lives here rather than in ``__init__`` so a caller who only
        verifies or runs E2EE chat against a monolithic deployment keeps working
        unchanged; only a media call needs the stronger configuration.

        Why media specifically. In E2EE chat the relay receives ciphertext, so a
        single origin still never holds readable content. A media prompt is sent
        as PLAINTEXT to the inference origin, protected by the origin split and
        the enclave rather than by client-side encryption. Collapse the two
        origins and one host receives both the API key and the prompt, which is
        precisely the linkage the ticket exists to prevent. That is not a
        degraded mode worth supporting quietly; it is the absence of the feature.
        """
        if self.control_origin == self.origin:
            # The documented local-test override: a developer running both roles
            # on their own machine has no privacy boundary to collapse. This is
            # the same loopback-only escape hatch `_normalize_api_origin` already
            # documents for plaintext http, and it cannot be reached remotely.
            host = urlsplit(self.origin).hostname or ""
            if not (self._allow_insecure_http and host in _LOOPBACK_HOSTS):
                raise ConfidentialError(
                    "Ticketed media needs two distinct origins: the API key mints a ticket "
                    "at the control origin and the prompt goes to the confidential inference "
                    f"origin. Both are currently {self.origin}, so one host would receive the "
                    "key and the content together. Set control_base_url (production: "
                    f"{DEFAULT_CONTROL_ORIGIN}) alongside the confidential inference_base_url "
                    f"(production: {DEFAULT_INFERENCE_ORIGIN})."
                )
        return _MediaTransport(
            control_origin=self.control_origin,
            inference_origin=self.origin,
            api_key=self.api_key,
            http=self._http,
        )

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _control_url(self, path: str) -> str:
        """URL for content-free identity, catalog, and ticket operations."""
        return f"{self.control_origin}{path}"

    @staticmethod
    def _raise_for_status(resp: httpx.Response, what: str) -> None:
        if resp.status_code >= 400:
            raise ConfidentialError(f"{what} request failed with HTTP {resp.status_code}")


def _evidence_str(evidence: Any, key: str) -> str:
    if isinstance(evidence, dict) and isinstance(evidence.get(key), str):
        return evidence[key]
    raise ConfidentialError(f"attestation evidence is missing '{key}'")


def _validate_e2ee_messages(messages: Any) -> None:
    """Validate the encrypted-request message list (roles, text-only, size caps).

    Matches the JavaScript rules in js/confidential/src/transport/validation.ts:
    multi-turn history is accepted; tools, images, and attachments FAIL VISIBLY
    here rather than being silently sent.
    Raises ConfidentialError (never a bare KeyError) on any violation.
    """
    if not isinstance(messages, list) or len(messages) == 0:
        raise ConfidentialError("the encrypted request has no messages")
    total = 0
    user_count = 0
    for message in messages:
        if not isinstance(message, dict):
            raise ConfidentialError("each encrypted message must have a role and content")
        role = message.get("role")
        content = message.get("content")
        if role == "tool":
            raise ConfidentialError("encrypted requests do not support tool messages")
        if role not in ("user", "system", "assistant"):
            raise ConfidentialError(
                "encrypted requests accept only user, system, and assistant messages"
            )
        if not isinstance(content, str):
            raise ConfidentialError(
                "encrypted requests support text content only (no images or attachments)"
            )
        if len(content) == 0:
            raise ConfidentialError("encrypted messages cannot be empty")
        if len(content) > _MAX_MESSAGE_CHARS:
            raise ConfidentialError("an encrypted message is too long")
        total += len(content)
        if total > _MAX_TOTAL_CHARS:
            raise ConfidentialError("the encrypted request is too long")
        if role == "user":
            user_count += 1
    if user_count == 0:
        raise ConfidentialError("the encrypted request needs a user message")


def _decode_instance_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfidentialError("the enclave key encoding was invalid") from exc
    if len(decoded) != _MLKEM_PUBLICKEY_BYTES:
        raise ConfidentialError("the enclave ML-KEM key was the wrong size")
    return decoded


def _select_verified_chutes_key(
    evidence: Any, nonce: str, allowlist: Sequence[dict]
) -> tuple[str, str, bytes]:
    """Independently re-verify the selected Chutes instance and return the
    ``(instance_id, instance_nonce, ML-KEM public key bytes)`` the request may be
    sealed to.

    Mirrors the guard in js/confidential/src/transport/chutes.ts. The verifier's
    normalized verdict binds ``report_data`` to ``e2e_pubkeys[instance_id]``; the
    client, however, encrypts to ``e2e_instances[i].e2e_pubkey``. This guard closes
    that gap: it re-checks ``report_data[0:32] == sha256(nonce || e2e_pubkey)`` for
    the exact key it returns AND requires that key to equal the ``e2e_pubkeys``
    record, so a relay cannot bind one key while serving another. Fail closed.
    """
    payload = as_dict(evidence)
    instances = as_list(payload.get("e2e_instances"))
    failed = as_list(payload.get("failed_instance_ids"))
    if failed:
        raise ConfidentialError("some enclave instances failed attestation")

    selected: tuple[str, str, str] | None = None
    for candidate in instances:
        entry = as_dict(candidate)
        instance_id = as_str(entry.get("instance_id"))
        e2e_pubkey = as_str(entry.get("e2e_pubkey"))
        instance_nonce = next((n for n in as_list(entry.get("nonces")) if isinstance(n, str)), None)
        if instance_id and e2e_pubkey and instance_nonce:
            selected = (instance_id, e2e_pubkey, instance_nonce)
            break
    if selected is None:
        raise ConfidentialError("no usable enclave instance was returned")
    instance_id, e2e_pubkey, instance_nonce = selected

    if not _INSTANCE_NONCE_RE.match(instance_nonce):
        raise ConfidentialError("the enclave instance nonce was invalid")
    if not _UUID_RE.match(instance_id):
        raise ConfidentialError("the enclave instance id was invalid")

    record_key = as_str(as_dict(payload.get("e2e_pubkeys")).get(instance_id))
    if record_key is not None and record_key != e2e_pubkey:
        raise ConfidentialError("the enclave key records disagree")

    evidence_instances = as_list(payload.get("evidence"))
    instance_evidence = next(
        (as_dict(e) for e in evidence_instances if as_dict(e).get("instance_id") == instance_id),
        as_dict(evidence_instances[0]) if evidence_instances else {},
    )
    parsed = parse_tdx_quote(as_str(instance_evidence.get("quote")))
    if parsed is None:
        raise ConfidentialError("the enclave quote could not be parsed")
    if parsed.tee_type != TDX_TEE_TYPE:
        raise ConfidentialError("the enclave is not Intel TDX")
    if parsed.debug_enabled:
        raise ConfidentialError("the enclave is in debug mode")
    if match_measurement_allowlist(parsed, allowlist) is None:
        raise ConfidentialError("the enclave measurements are not on the reviewed allowlist")

    expected = hashlib.sha256((nonce + e2e_pubkey).encode("utf-8")).hexdigest()
    if not hex_equal(parsed.report_data[0:64], expected):
        raise ConfidentialError("the enclave key is not bound to this request's nonce")

    return instance_id, instance_nonce, _decode_instance_key(e2e_pubkey)


def _iter_sse(lines: Iterable[str]) -> Iterable[dict[str, Any]]:
    for line in lines:
        if not line or not line.startswith("data:"):
            continue
        data = line[len("data:") :].strip()
        if data == "[DONE]":
            break
        try:
            yield json.loads(data)
        except (ValueError, TypeError):
            continue


def _openai_delta(frame: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    choices = as_list(frame.get("choices"))
    if choices:
        choice = as_dict(choices[0])
        delta = as_dict(choice.get("delta"))
        if isinstance(delta.get("content"), str):
            out["content"] = delta["content"]
        if isinstance(delta.get("reasoning_content"), str):
            out["reasoning"] = delta["reasoning_content"]
        if isinstance(choice.get("finish_reason"), str):
            out["finish_reason"] = choice["finish_reason"]
    if isinstance(frame.get("usage"), dict):
        out["usage"] = frame["usage"]
    return out


def _normalize_completion(parsed: dict[str, Any]) -> dict[str, Any]:
    choices = as_list(parsed.get("choices"))
    choice = as_dict(choices[0]) if choices else {}
    message = as_dict(choice.get("message"))
    out: dict[str, Any] = {"content": message.get("content") if isinstance(message.get("content"), str) else ""}
    if isinstance(message.get("reasoning_content"), str):
        out["reasoning"] = message["reasoning_content"]
    if isinstance(parsed.get("usage"), dict):
        out["usage"] = parsed["usage"]
    if isinstance(choice.get("finish_reason"), str):
        out["finish_reason"] = choice["finish_reason"]
    return out


__all__ = ["ConfidentialClient", "ConfidentialError", "NormalizedVerdict", "create_client"]
