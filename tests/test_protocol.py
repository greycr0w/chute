"""Unit tests for the wire protocol -- pure logic, no network."""

from __future__ import annotations

import pytest

from chute import protocol


@pytest.mark.parametrize(
    "ftype,sid,payload",
    [
        (protocol.OPEN, 1, b""),
        (protocol.DATA, 42, b"hello world"),
        (protocol.EOF, 7, b""),
        (protocol.RESET, 2**32 - 1, b""),
        (protocol.DATA, 0, b"\x00\xff" * 1000),
    ],
)
def test_round_trip(ftype: int, sid: int, payload: bytes) -> None:
    encoded = protocol.encode(ftype, sid, payload)
    assert protocol.decode(encoded) == (ftype, sid, payload)


def test_prefix_size() -> None:
    assert protocol.PREFIX_SIZE == 5
    assert len(protocol.encode(protocol.DATA, 1, b"abc")) == 5 + 3
