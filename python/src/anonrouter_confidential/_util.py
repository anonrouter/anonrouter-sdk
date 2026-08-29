"""Tiny typed narrowing helpers used across the verifiers and client."""

from __future__ import annotations

from typing import Any


def as_dict(value: Any) -> dict[str, Any]:
    """Return ``value`` when it is a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    """Return ``value`` when it is a list, otherwise an empty list."""
    return value if isinstance(value, list) else []


def as_str(value: Any) -> str | None:
    """Return ``value`` when it is a str, otherwise None."""
    return value if isinstance(value, str) else None
