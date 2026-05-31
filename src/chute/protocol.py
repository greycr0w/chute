"""Binary frame protocol for chute's multiplexed control channel.

Each frame travels as a single WebSocket *binary* message, so the WebSocket
message boundary gives us framing for free -- no length prefixes to parse.
A frame is a 5-byte prefix plus an arbitrary payload::

    +--------+------------------+--------------+
    | type   | stream_id        | payload      |
    | 1 byte | 4 bytes (BE u32) | 0..N bytes   |
    +--------+------------------+--------------+

Only the *server* opens streams (one per inbound public connection), so the
server allocates every stream id and there is no id-collision negotiation.
"""

from __future__ import annotations

import struct

# Frame types -----------------------------------------------------------------
OPEN = 0x01  # server -> agent: open a stream; agent dials the local target
DATA = 0x02  # both ways: stream payload bytes
EOF = 0x03  # both ways: half-close (sender will write no more on this stream)
RESET = 0x04  # both ways: abort this stream immediately

_PREFIX = struct.Struct("!BI")
PREFIX_SIZE = _PREFIX.size  # 5 bytes


def encode(frame_type: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Serialise one frame into a single bytes object."""
    return _PREFIX.pack(frame_type, stream_id) + payload


def decode(message: bytes) -> tuple[int, int, bytes]:
    """Split one received binary message into (type, stream_id, payload).

    Raises ``ValueError`` on a frame shorter than the 5-byte prefix so the caller
    can drop the bad frame instead of letting ``struct.error`` tear down the
    whole multiplexed connection.
    """
    if len(message) < PREFIX_SIZE:
        raise ValueError(f"short frame: {len(message)} bytes (need >= {PREFIX_SIZE})")
    frame_type, stream_id = _PREFIX.unpack_from(message)
    return frame_type, stream_id, message[PREFIX_SIZE:]
