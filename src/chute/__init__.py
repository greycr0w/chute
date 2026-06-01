"""chute -- a tiny, self-hosted, zero-maintenance tunnel (your own ngrok).

Public API::

    from chute import Tunnel

    with Tunnel(server="vps.example.com", token="...", local_port=8000) as t:
        print(t.public_url)
        t.wait()
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .client import Tunnel
from .server import Server

try:
    # Single source of truth: the version declared in pyproject.toml and baked
    # into the installed package metadata. No hardcoded string to drift.
    __version__ = version("chute")
except PackageNotFoundError:  # imported from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["Server", "Tunnel", "__version__"]
