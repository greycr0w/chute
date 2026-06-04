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


def test_policy_json_fuzz_target_contract() -> None:
    _targets.check_policy_json(
        b"""
        {
          "schema_version": 1,
          "credentials": [
            {
              "credential_id": "cred-a",
              "token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "account_id": "acct-a",
              "allowed_label": "dev",
              "budget": {"max_visitors": 1},
              "lease_seconds": 30
            }
          ]
        }
        """
    )
    _targets.check_policy_json(
        b"""
        {
          "schema_version": 1,
          "credentials": [
            {
              "credential_id": "cred-a",
              "token_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "account_id": "acct-a"
            }
          ],
          "policy_version": 1,
          "revoke_lease_ids": ["same"],
          "lease_revocations": [{"lease_id": "same", "action": "close"}]
        }
        """
    )
    _targets.check_policy_json(b"\xff")
    _targets.check_policy_json(b"{not json")


def test_all_atheris_targets_are_registered() -> None:
    assert set(FUZZERS) == {
        "host_label",
        "mux_frames",
        "policy_json",
        "protocol_decode",
        "request_head",
    }
