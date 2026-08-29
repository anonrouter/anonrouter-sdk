"""Provider E2EE crypto primitives (NEAR, Venice, Chutes).

Each module owns exactly the wire layout, HKDF info string, and AEAD its provider
speaks, matching the JavaScript transports byte for byte. The shared known-answer
vectors in ``shared/vectors/`` are decrypted by both languages and must produce
identical results, so the two implementations cannot quietly drift apart.
"""

from . import chutes, near, venice

__all__ = ["chutes", "near", "venice"]
