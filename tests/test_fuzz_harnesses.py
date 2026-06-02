from __future__ import annotations

from fuzz import _targets
from fuzz.run_atheris import FUZZERS


def test_protocol_decode_fuzz_target_contract() -> None:
    _targets.check_protocol_decode(b"")
    _targets.check_protocol_decode(b"abcdepayload")


def test_request_head_fuzz_target_contract() -> None:
    _targets.check_request_head(b"GET / HTTP/1.1\r\nHost: alpha.chute.sh\r\n\r\n")
    _targets.check_request_head(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
    _targets.check_request_head(b"GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n")


def test_host_label_fuzz_target_contract() -> None:
    _targets.check_host_label(b"alpha.chute.sh")
    _targets.check_host_label(b"chute.sh")
    _targets.check_host_label(b"bad..alpha.chute.sh")
    _targets.check_host_label(b"\xff")


def test_mux_frame_fuzz_target_contract() -> None:
    _targets.check_mux_frames(b"")
    _targets.check_mux_frames(b"open-data-eof-reset-goaway-window" * 4)


def test_all_atheris_targets_are_registered() -> None:
    assert set(FUZZERS) == {"host_label", "mux_frames", "protocol_decode", "request_head"}
