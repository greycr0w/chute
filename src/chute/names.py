"""Subdomain label rules + generation, shared by the client and the server.

A tunnel's public name is one DNS label under the server's base domain
(``<label>.chute.sh``). Keeping the rules in one place means the SDK
can reject a bad label instantly *and* the server enforces the same thing as the
authority -- defense in depth, no drift.
"""

from __future__ import annotations

import re
import secrets

# A single DNS label: 1-63 chars, lowercase alnum + hyphen, no leading/trailing
# hyphen. (We lowercase before checking; DNS is case-insensitive.)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Alphabet for auto-generated labels: lowercase alnum minus look-alikes
# (no l/o/0/1) so a label is easy to read back off a screen or a log line.
_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"


def valid_label(label: str) -> bool:
    """True if *label* is a usable single DNS label."""
    return isinstance(label, str) and _LABEL_RE.fullmatch(label) is not None


def random_label(length: int = 8) -> str:
    """A fresh, unpredictable, DNS-safe label (e.g. ``k7m2pq9w``)."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))
