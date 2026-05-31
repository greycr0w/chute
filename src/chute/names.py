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

# Wordlists for friendly, ngrok-style labels (``swift-amber-otter``). All entries
# are lowercase a-z only, so any combination is a valid DNS label well under the
# 63-char cap. Keep them wholesome and unambiguous: a label may be read aloud,
# typed from memory, or copied off a terminal.
_ADJECTIVES = (
    "amber",
    "ancient",
    "autumn",
    "azure",
    "bold",
    "brave",
    "bright",
    "brisk",
    "calm",
    "clever",
    "cobalt",
    "cosmic",
    "cozy",
    "crimson",
    "crisp",
    "curious",
    "daring",
    "deft",
    "eager",
    "early",
    "easy",
    "electric",
    "emerald",
    "fancy",
    "fleet",
    "fluffy",
    "fresh",
    "gentle",
    "giddy",
    "golden",
    "grand",
    "happy",
    "hazel",
    "humble",
    "indigo",
    "ivory",
    "jade",
    "jolly",
    "keen",
    "kind",
    "lively",
    "lucky",
    "lunar",
    "mellow",
    "merry",
    "mighty",
    "misty",
    "neat",
    "nimble",
    "noble",
    "olive",
    "plucky",
    "polar",
    "proud",
    "quick",
    "quiet",
    "rapid",
    "ruby",
    "rustic",
    "sandy",
    "scarlet",
    "shiny",
    "silent",
    "silver",
    "sleek",
    "snappy",
    "snowy",
    "solar",
    "spry",
    "stellar",
    "sunny",
    "swift",
    "teal",
    "tidy",
    "tiny",
    "vivid",
    "witty",
    "zany",
    "zesty",
)
_NOUNS = (
    "acorn",
    "anchor",
    "aspen",
    "badger",
    "beacon",
    "birch",
    "bison",
    "bloom",
    "brook",
    "cedar",
    "cobra",
    "comet",
    "coral",
    "cove",
    "crane",
    "delta",
    "dune",
    "eagle",
    "ember",
    "falcon",
    "fern",
    "finch",
    "fjord",
    "flint",
    "fox",
    "gecko",
    "glade",
    "harbor",
    "hawk",
    "heron",
    "ivy",
    "koala",
    "lark",
    "lemur",
    "lichen",
    "lotus",
    "lynx",
    "maple",
    "marsh",
    "meadow",
    "moose",
    "moth",
    "otter",
    "owl",
    "panda",
    "peak",
    "pebble",
    "pine",
    "prairie",
    "quail",
    "quartz",
    "raven",
    "reef",
    "ridge",
    "river",
    "robin",
    "sage",
    "sparrow",
    "spruce",
    "stork",
    "stream",
    "summit",
    "swan",
    "thorn",
    "tiger",
    "topaz",
    "vale",
    "willow",
    "wolf",
    "wren",
    "yak",
    "zephyr",
)


def valid_label(label: str) -> bool:
    """True if *label* is a usable single DNS label."""
    return isinstance(label, str) and _LABEL_RE.fullmatch(label) is not None


def random_label(length: int = 8) -> str:
    """A fresh, unpredictable, DNS-safe label (e.g. ``k7m2pq9w``)."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def random_phrase() -> str:
    """A friendly, easily-typed label like ``swift-amber-otter``.

    Two distinct adjectives + a noun (~440k combinations). The server retries on
    the rare collision and frees the name the moment the agent disconnects, so
    the space recycles. Always a valid DNS label (lowercase words, well < 63 chars).
    """
    first = secrets.choice(_ADJECTIVES)
    second = secrets.choice(_ADJECTIVES)
    while second == first:
        second = secrets.choice(_ADJECTIVES)
    return f"{first}-{second}-{secrets.choice(_NOUNS)}"
