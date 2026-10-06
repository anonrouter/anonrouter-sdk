"""NEAR release authority, matching the JavaScript verifier.

GitHub, dstack image and Base RPC collateral is supplied by the measured
AnonRouter worker. This rechecks its bindings, not those authorities' network
responses independently. Neither CPU nor GPU vendor signatures are verified
here; the provider hop remains provider-attested.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, cast

from .._util import as_dict
from ..tdx import ParsedTdxQuote, parse_tdx_quote
from .checks import hex_equal


def _require(condition: Any) -> None:
    if not condition:
        raise ValueError("provider release authority did not verify")


def _hex(value: Any) -> bytes:
    _require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", value))
    return bytes.fromhex(value)


def _events(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        raw = json.loads(raw)
    _require(isinstance(raw, list) and len(raw) <= 4096)
    result = []
    for item in raw:
        _require(isinstance(item, dict))
        imr = item.get("imr")
        _require(type(imr) is int and 0 <= imr <= 3)
        result.append({
            "imr": imr,
            "event_type": item.get("event_type", -1),
            "digest": str(item.get("digest", "")).lower(),
            "event": item.get("event", ""),
            "event_payload": str(item.get("event_payload", "")).lower(),
            "preimage": item.get("preimage"),
        })
    return result


def _rtmr3_digest(event: dict[str, Any]) -> bytes:
    payload = _hex(event["event_payload"])
    preimage = event["preimage"]
    if preimage is not None:
        raw = _hex(preimage.lower())
        _require(hashlib.sha384(raw).hexdigest() == event["digest"])
        decoded = json.loads(raw)
        _require(decoded.get("name") == event["event"])
        _require(str(decoded.get("payload", "")).lower().removeprefix("0x") == event["event_payload"])
        _require("type" not in decoded or decoded["type"] == event["event_type"])
        return hashlib.sha384(raw).digest()
    kind = event["event_type"]
    _require(type(kind) is int and kind >= 0)
    raw = (kind & 0xffffffff).to_bytes(4, "little") + b":" + event["event"].encode() + b":" + payload
    digest = hashlib.sha384(raw).digest()
    _require(not event["digest"] or digest.hex() == event["digest"])
    return digest


def _replay(events: list[dict[str, Any]]) -> list[str]:
    registers = []
    for index in range(4):
        register = bytes(48)
        for event in events:
            if event["imr"] != index:
                continue
            digest = _rtmr3_digest(event) if index == 3 else _hex(event["digest"])
            digest = digest[:48].ljust(48, b"\x00")
            register = hashlib.sha384(register + digest).digest()
        registers.append(register.hex())
    return registers


def _payload(events: list[dict[str, Any]], name: str) -> str:
    matches = [e for e in events if e["event"] == name]
    _require(len(matches) == 1 and matches[0]["imr"] == 3)
    _rtmr3_digest(matches[0])
    return str(matches[0]["event_payload"])


def _canonical(value: Any, depth: int = 0) -> str:
    _require(depth <= 64)
    if value is None or type(value) is bool or isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if type(value) in {int, float}:
        _require(math.isfinite(value) and int(value) == value and abs(value) <= 2**53 - 1)
        return str(int(value))
    if isinstance(value, list):
        return "[" + ",".join(_canonical(v, depth + 1) for v in value) + "]"
    _require(isinstance(value, dict) and all(isinstance(k, str) for k in value))
    keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(_canonical(k) + ":" + _canonical(value[k], depth + 1) for k in keys) + "}"


def _fresh(record: dict[str, Any], now: float, max_age: int) -> bool:
    instant = record.get("fetchedAtMs")
    return type(instant) in {int, float} and -30000 <= now - cast(float, instant) <= max_age


def verify_near_release_authority(document: Any, quote: ParsedTdxQuote, nonce: str,
                                  policy: dict[str, Any], now: float) -> None:
    """Raise on any missing or inconsistent publication/quote binding."""
    doc = as_dict(document)
    collateral = as_dict(doc.get("anonrouter_release_collateral"))
    tcb = as_dict(as_dict(doc.get("info")).get("tcb_info"))
    compose = tcb.get("app_compose")
    _require(isinstance(compose, str) and compose)
    compose = cast(str, compose)
    compose_hash = hashlib.sha256(compose.encode()).hexdigest()
    _require(hex_equal(quote.mr_config_id, ("01" + compose_hash).ljust(96, "0")))
    events = _events(doc.get("event_log", tcb.get("event_log")))
    _require(_replay(events) == [quote.rtmr0, quote.rtmr1, quote.rtmr2, quote.rtmr3])
    _require(hex_equal(_payload(events, "compose-hash"), compose_hash))
    os_hash, app_id = _payload(events, "os-image-hash"), _payload(events, "app-id")
    _require(os_hash and app_id)
    docker_compose = json.loads(compose).get("docker_compose_file")
    _require(isinstance(docker_compose, str))
    repos = set(re.findall(r"GITHUB_REPO\s*[=:]\s*[\"']?([^\s\"'#]+)", docker_compose))
    _require(len(repos) == 1)
    repo = next(iter(repos))
    _require(repo.startswith("https://github.com/"))
    repo = repo.lower().removeprefix("https://github.com/").removesuffix(".git").rstrip("/")
    _require(repo == policy["composeRepository"])

    image = next((i for i in collateral.get("dstackImages", []) if i.get("osImageHash") == os_hash), None)
    _require(image is not None and image.get("isDev") is False
             and (image.get("prerelease") is False or policy["image"]["allowPrerelease"]))
    image = cast(dict[str, Any], image)
    _require(any(all(hex_equal(m.get(k), v) for k, v in
                    [("mrtd", quote.mr_td), ("rtmr0", quote.rtmr0), ("rtmr1", quote.rtmr1), ("rtmr2", quote.rtmr2)])
                 for m in image.get("measurements", [])))
    onchain = collateral.get("onchain", [None])[0]
    _require(isinstance(onchain, dict) and onchain.get("v") == 1
             and onchain.get("chainId") == policy["kms"]["chainId"]
             and onchain.get("kms") == policy["kms"]["kms"]
             and _fresh(onchain, now, policy["maxPublicationAgeMs"]))
    _require(onchain.get("appId") == "0x" + app_id and onchain.get("composeHash") == compose_hash
             and onchain.get("osImageHash") == os_hash and onchain.get("appRegistered") is True
             and onchain.get("composeHashAllowed") is True and onchain.get("osImageAllowed") is True)

    manager = as_dict(doc.get("compose_manager_attestation"))
    second = parse_tdx_quote(manager.get("quote"))
    actions = manager.get("actions")
    _require(second is not None and isinstance(actions, list))
    second = cast(ParsedTdxQuote, second)
    actions = cast(list[dict[str, Any]], actions)
    _require(not second.debug_enabled and all(getattr(second, k) == getattr(quote, k)
             for k in ["mr_td", "mr_config_id", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]))
    action_hash = hashlib.sha256(_canonical(actions).encode()).hexdigest()
    _require(hex_equal(second.report_data[:64], action_hash) and hex_equal(manager.get("actions_hash"), action_hash)
             and hex_equal(second.report_data[64:128], nonce))
    releases = next((r for r in collateral.get("githubReleases", [])
                     if r.get("repository") == policy["composeManagerRepository"]), None)
    _require(releases is not None and _fresh(releases, now, policy["maxPublicationAgeMs"]))

    releases = cast(dict[str, Any], releases)

    def released(component: str, digest: str) -> bool:
        return any(i.get("component") == component and i.get("digest") == digest for i in releases["images"])

    starts = [a for a in actions if a.get("action") == "compose_manager_started"]
    _require(starts)
    for action in starts:
        match = re.fullmatch(r"nearaidev/compose-manager@(sha256:[0-9a-f]{64})", str(action.get("image", "")))
        _require(match is not None and released("compose-manager", match[1]))
    for component in ["compose-manager", "compose-manager-launcher"]:
        for digest in re.findall(r"nearaidev/" + component + r"@(sha256:[0-9a-f]{64})", docker_compose):
            _require(released(component, digest))
    publication = next((r for r in collateral.get("github", []) if r.get("repository") == policy["composeRepository"]), None)
    _require(publication is not None and publication.get("v") == 1
             and _fresh(publication, now, policy["maxPublicationAgeMs"]))
    publication = cast(dict[str, Any], publication)
    claims = 0
    for action in actions:
        if not isinstance(action.get("file_sha256"), str):
            continue
        claims += 1
        commit, path, tag = str(action.get("commit", "")).lower(), action.get("file", ""), action.get("tag")
        _require((tag is not None and publication["tags"].get(tag) == commit)
                 or commit in publication["defaultBranchAncestors"])
        file = next((f for f in publication["files"] if f.get("commit") == commit and f.get("path") == path), None)
        _require(file is not None and file.get("sha256") is not None
                 and file["sha256"] == action["file_sha256"].lower())
    _require(claims > 0 and any(a.get("action") == "compose_up" for a in actions))


def verify_near_gpu_evidence(raw: Any, nonce: str) -> None:
    """Require nonce-bound, well-formed GPU evidence; not vendor signatures."""
    _require(isinstance(raw, str) and raw)
    document = json.loads(raw)
    entries = document.get("evidence_list")
    _require(isinstance(entries, list) and 0 < len(entries) <= 64)
    _require(hex_equal(document.get("nonce"), nonce))
    for entry in entries:
        _require(isinstance(entry, dict) and isinstance(entry.get("certificate"), str) and entry["certificate"]
                 and isinstance(entry.get("evidence"), str) and entry["evidence"] and hex_equal(entry.get("nonce"), nonce))
