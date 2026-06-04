"""Socket-level relay helpers shared by the server and agent."""

from __future__ import annotations

import asyncio
import contextlib
import socket

_KEEPALIVE_IDLE = 60
_KEEPALIVE_INTERVAL = 10
_KEEPALIVE_COUNT = 3


def enable_tcp_keepalive(writer: asyncio.StreamWriter) -> None:
    """Enable TCP keepalive on a stream socket.

    This is intentionally OS-level liveness only: it reaps a peer that vanished
    without FIN/RST, but it does not treat a live, quiet socket as unhealthy.
    """
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    with contextlib.suppress(AttributeError, OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):  # Linux / some Windows builds
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, _KEEPALIVE_IDLE)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTERVAL)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, _KEEPALIVE_COUNT)
