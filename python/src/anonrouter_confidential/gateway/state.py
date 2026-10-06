"""Durable cross-process policy high-water marks; public metadata only."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from .policy import GatewayPolicyError


class FileGatewayPolicyStateStore:
    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = Path(directory) if directory is not None else (
            Path.home() / ".cache" / "anonrouter" / "gateway-policy-v1"
        )

    def __call__(self, authority: str, checkpoint: dict[str, Any]) -> None:
        checkpoint = {"sequence": checkpoint["sequence"], "payloadSha256": checkpoint["payloadSha256"]}
        if (type(checkpoint["sequence"]) is not int or checkpoint["sequence"] < 1
                or not isinstance(checkpoint["payloadSha256"], str)
                or len(checkpoint["payloadSha256"]) != 64
                or any(c not in "0123456789abcdef" for c in checkpoint["payloadSha256"])):
            raise GatewayPolicyError("invalid gateway policy checkpoint")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise GatewayPolicyError("unsafe gateway policy state directory")
        path = self.directory / (hashlib.sha256(authority.encode()).hexdigest() + ".json")
        lock = Path(str(path) + ".lock")
        deadline = time.monotonic() + 10
        while True:
            try:
                lock.mkdir(mode=0o700)
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise GatewayPolicyError("gateway policy state locked/unavailable") from None
                time.sleep(0.025)
        try:
            try:
                previous = json.loads(path.read_text())
            except FileNotFoundError:
                previous = None
            except ValueError:
                raise GatewayPolicyError("invalid gateway policy state file") from None
            if previous is not None:
                if (not isinstance(previous, dict) or type(previous.get("sequence")) is not int
                        or previous["sequence"] < 1
                        or not isinstance(previous.get("payloadSha256"), str)
                        or len(previous["payloadSha256"]) != 64
                        or any(c not in "0123456789abcdef" for c in previous["payloadSha256"])):
                    raise GatewayPolicyError("invalid stored gateway policy checkpoint")
                if (checkpoint["sequence"] < previous["sequence"] or (
                        checkpoint["sequence"] == previous["sequence"]
                        and checkpoint["payloadSha256"] != previous["payloadSha256"])):
                    raise GatewayPolicyError("gateway policy rollback or conflicting persisted sequence")
                if checkpoint["sequence"] == previous["sequence"]:
                    return
            temp = Path(str(path) + "." + secrets.token_hex(12) + ".tmp")
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as file:
                    file.write(json.dumps(checkpoint, separators=(",", ":")) + "\n")
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temp, path)
                fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                temp.unlink(missing_ok=True)
        finally:
            lock.rmdir()
