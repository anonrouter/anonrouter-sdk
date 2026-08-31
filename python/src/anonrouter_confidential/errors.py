"""The package's error base, in its own module so every layer can share it.

Split out of ``client.py`` because ``media.py`` needs to raise a subclass of it
and ``client.py`` imports ``media.py``: leaving the base in the client would make
that a circular import, and the alternative -- a media error that is NOT a
``ConfidentialError`` -- would silently break ``except ConfidentialError`` for
exactly the callers who wrote it to catch everything this SDK can raise.

Mirrors ``js/confidential/src/errors.ts``, where ``MediaError extends
ConfidentialError`` for the same reason.

Messages here may be surfaced to a UI and logged, so they MUST be content-free:
never embed a private key, shared secret, ciphertext, plaintext prompt or
response, nonce, or raw evidence body.
"""

from __future__ import annotations


class ConfidentialError(RuntimeError):
    """Any failure in the confidential-inference flow (fail closed)."""
