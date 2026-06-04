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

**Protocol version** is negotiated out-of-band in the JSON hello/ready (not in the
binary prefix): both peers must agree before any binary frame flows, so a new
frame type (e.g. WINDOW_UPDATE) can be added without an old peer silently
no-op'ing it.
"""

from __future__ import annotations

import struct

# Wire/behavioral protocol version, negotiated in the hello/ready handshake. Bump
# when the frame set or framing semantics change incompatibly. A peer that does
# not speak this exact version is refused with a clean close (see server/client),
# because flow control requires *both* ends to honor windows -- a mixed pair would
# stall or overflow rather than fail cleanly.
#   v2: credit-window flow control (WINDOW_UPDATE).
#   v3: graceful drain (GOAWAY).
#   v4: negotiated mux flow window in the JSON hello/ready handshake.
VERSION = 4

# Frame types -----------------------------------------------------------------
OPEN = 0x01  # server -> agent: open a stream; agent dials the local target
DATA = 0x02  # both ways: stream payload bytes
EOF = 0x03  # both ways: half-close (sender will write no more on this stream)
RESET = 0x04  # both ways: abort this stream immediately
WINDOW_UPDATE = 0x05  # both ways: grant the peer N more bytes of send credit
GOAWAY = 0x06  # both ways, stream id 0: sender is draining -- it will open no new
# streams and will close the connection once in-flight streams finish.

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
