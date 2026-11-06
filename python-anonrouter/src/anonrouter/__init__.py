"""AnonRouter for Python.

This package exposes the main entry points of ``anonrouter-confidential`` under
the shorter ``anonrouter`` name.
"""

from __future__ import annotations

from anonrouter_confidential import (
    ConfidentialClient,
    ConfidentialError,
    at_least,
    create_client,
    verify_content_node,
)
from anonrouter_confidential.gateway.dcap import create_anonrouter_dcap_verifier

__version__ = "0.1.0"

__all__ = [
    "ConfidentialClient",
    "ConfidentialError",
    "__version__",
    "at_least",
    "create_anonrouter_dcap_verifier",
    "create_client",
    "verify_content_node",
]
