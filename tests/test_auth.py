"""The Authorizer seam. Pure unit tests -- no server, no sockets."""

import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from chute.auth import (
    UNLIMITED_TUNNELS,
    Authorizer,
    AuthRequest,
    AuthResult,
    StaticTokenAuthorizer,
)
from chute.control import StaticPolicyControlPlane
from chute.events import (
    DEFAULT_JSONL_EVENT_LOG_BACKUPS,
    DEFAULT_JSONL_EVENT_LOG_MAX_BYTES,
    JsonlEventSink,
)


def _write_policy_file(path, token: str = "s3cret") -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "credentials": [
                    {
                        "credential_id": "cred",
                        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                        "account_id": "acct",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _request(
    token: str,
    requested_subdomain: str | None = None,
    agent_ip: str | None = None,
    *,
    scheme: str = "https",
    protocol_version: int = 3,
) -> AuthRequest:
    return AuthRequest(
        token=token,
        requested_subdomain=requested_subdomain,
        agent_ip=agent_ip,
        scheme=scheme,
        protocol_version=protocol_version,
    )


async def test_static_authorizer_accepts_the_configured_token():
    auth = StaticTokenAuthorizer("s3cret")
    result = await auth.authenticate(_request("s3cret"))
    assert isinstance(result, AuthResult)
    assert result.account_id == "0"
    assert result.max_tunnels == UNLIMITED_TUNNELS
    assert result.allowed_label is None


async def test_static_authorizer_rejects_wrong_or_empty_token():
    auth = StaticTokenAuthorizer("s3cret")
    assert await auth.authenticate(_request("nope")) is None
    assert await auth.authenticate(_request("")) is None
    assert await auth.authenticate(_request("S3CRET")) is None  # case-sensitive


def test_static_authorizer_rejects_empty_configured_token() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        StaticTokenAuthorizer("")


async def test_static_authorizer_rejects_non_ascii_token_without_crashing():
    # A non-ASCII token must be a clean reject, not a TypeError: hmac.compare_digest
    # raises on a non-ASCII *str*, and the server's blanket except would mistake that
    # crash for "authorizer unavailable" (retryable 1013) and skip the failed-auth
    # limiter. Comparing as bytes makes it a normal rejection (F7).
    auth = StaticTokenAuthorizer("s3cret")
    assert await auth.authenticate(_request("naïve-tøken")) is None
    assert await auth.authenticate(_request("\U0001f4a9", "sub", "203.0.113.1")) is None
    # and a valid token still works after the byte change
    assert (await auth.authenticate(_request("s3cret"))).account_id == "0"


async def test_static_authorizer_ignores_subdomain_and_ip():
    # A single shared token grants the same thing regardless of requested name/IP;
    # label assignment still happens downstream in the relay.
    auth = StaticTokenAuthorizer("s3cret")
    result = await auth.authenticate(_request("s3cret", "myapp", "203.0.113.9"))
    assert result is not None and result.account_id == "0"


async def test_static_authorizer_satisfies_the_authorizer_protocol():
    assert isinstance(StaticTokenAuthorizer("x"), Authorizer)


def test_authresult_is_frozen():
    result = AuthResult(account_id="0")
    with pytest.raises(FrozenInstanceError):
        result.account_id = "1"


def test_authresult_defaults_are_single_tenant_shaped():
    result = AuthResult(account_id="7")
    assert result.max_tunnels == UNLIMITED_TUNNELS
    assert result.allowed_label is None
    assert result.credential_id is None


# --------------------------------------------------------------------------- #
# CHUTE_AUTHORIZER import-string knob
#
# The import-strings below target *this* module (pytest's prepend import mode puts
# the tests dir on sys.path, so "test_auth" is importable by name).
# --------------------------------------------------------------------------- #


class _DummyAuthorizer:
    async def authenticate(self, request):
        return None


_DUMMY_INSTANCE = _DummyAuthorizer()
_NOT_AN_AUTHORIZER = object()  # no authenticate method


class _DummyEventSink:
    async def tunnel_opened(self, event):
        return None

    async def tunnel_closed(self, event):
        return None

    async def visitor_opened(self, event):
        return None

    async def visitor_closed(self, event):
        return None

    async def auth_rejected(self, event):
        return None

    async def visitor_rejected(self, event):
        return None

    async def relay_stats(self, event):
        return None


_DUMMY_EVENT_SINK = _DummyEventSink()
_NOT_AN_EVENT_SINK = object()


class _DummyControlPlane:
    async def admit_tunnel(self, request):
        return None

    async def renew_lease(self, request):
        return None

    async def poll_policy_updates(self, request):
        return None


_DUMMY_CONTROL_PLANE = _DummyControlPlane()
_NOT_A_CONTROL_PLANE = object()


def _make_dummy_authorizer():
    return _DummyAuthorizer()


def _make_dummy_event_sink():
    return _DummyEventSink()


def _make_dummy_control_plane():
    return _DummyControlPlane()


def test_build_authorizer_absent_returns_none(monkeypatch):
    from chute.cli import _build_authorizer

    monkeypatch.delenv("CHUTE_AUTHORIZER", raising=False)
    assert _build_authorizer("tok") is None


def test_build_authorizer_calls_a_factory(monkeypatch):
    from chute.cli import _build_authorizer

    monkeypatch.setenv("CHUTE_AUTHORIZER", "test_auth:_make_dummy_authorizer")
    assert isinstance(_build_authorizer("tok"), _DummyAuthorizer)


def test_build_authorizer_uses_an_instance_as_is(monkeypatch):
    from chute.cli import _build_authorizer

    monkeypatch.setenv("CHUTE_AUTHORIZER", "test_auth:_DUMMY_INSTANCE")
    assert _build_authorizer("tok") is _DUMMY_INSTANCE


def test_build_authorizer_rejects_bad_format(monkeypatch):
    from chute.cli import _build_authorizer

    monkeypatch.setenv("CHUTE_AUTHORIZER", "no_colon_here")
    with pytest.raises(SystemExit):
        _build_authorizer("tok")


def test_build_authorizer_rejects_unimportable(monkeypatch):
    from chute.cli import _build_authorizer

    monkeypatch.setenv("CHUTE_AUTHORIZER", "test_auth:does_not_exist")
    with pytest.raises(SystemExit):
        _build_authorizer("tok")


def test_build_authorizer_rejects_non_authorizer(monkeypatch):
    from chute.cli import _build_authorizer

    monkeypatch.setenv("CHUTE_AUTHORIZER", "test_auth:_NOT_AN_AUTHORIZER")
    with pytest.raises(SystemExit):
        _build_authorizer("tok")


def test_build_control_plane_absent_returns_none(monkeypatch):
    from chute.cli import _build_control_plane

    monkeypatch.delenv("CHUTE_CONTROL_PLANE", raising=False)
    monkeypatch.delenv("CHUTE_POLICY_FILE", raising=False)
    assert _build_control_plane() is None


def test_build_control_plane_uses_static_policy_file(tmp_path, monkeypatch):
    from chute.cli import _build_control_plane

    policy_file = tmp_path / "policy.json"
    _write_policy_file(policy_file)
    monkeypatch.delenv("CHUTE_CONTROL_PLANE", raising=False)
    monkeypatch.setenv("CHUTE_POLICY_FILE", str(policy_file))

    control_plane = _build_control_plane()

    assert isinstance(control_plane, StaticPolicyControlPlane)


def test_build_control_plane_rejects_policy_file_and_import_hook(tmp_path, monkeypatch):
    from chute.cli import _build_control_plane

    policy_file = tmp_path / "policy.json"
    _write_policy_file(policy_file)
    monkeypatch.setenv("CHUTE_POLICY_FILE", str(policy_file))
    monkeypatch.setenv("CHUTE_CONTROL_PLANE", "test_auth:_make_dummy_control_plane")

    with pytest.raises(SystemExit):
        _build_control_plane()


def test_build_control_plane_calls_a_factory(monkeypatch):
    from chute.cli import _build_control_plane

    monkeypatch.delenv("CHUTE_POLICY_FILE", raising=False)
    monkeypatch.setenv("CHUTE_CONTROL_PLANE", "test_auth:_make_dummy_control_plane")
    assert isinstance(_build_control_plane(), _DummyControlPlane)


def test_build_control_plane_uses_an_instance_as_is(monkeypatch):
    from chute.cli import _build_control_plane

    monkeypatch.setenv("CHUTE_CONTROL_PLANE", "test_auth:_DUMMY_CONTROL_PLANE")
    assert _build_control_plane() is _DUMMY_CONTROL_PLANE


def test_build_control_plane_rejects_bad_format(monkeypatch):
    from chute.cli import _build_control_plane

    monkeypatch.setenv("CHUTE_CONTROL_PLANE", "no_colon_here")
    with pytest.raises(SystemExit):
        _build_control_plane()


def test_build_control_plane_rejects_unimportable(monkeypatch):
    from chute.cli import _build_control_plane

    monkeypatch.setenv("CHUTE_CONTROL_PLANE", "test_auth:does_not_exist")
    with pytest.raises(SystemExit):
        _build_control_plane()


def test_build_control_plane_rejects_non_control_plane(monkeypatch):
    from chute.cli import _build_control_plane

    monkeypatch.setenv("CHUTE_CONTROL_PLANE", "test_auth:_NOT_A_CONTROL_PLANE")
    with pytest.raises(SystemExit):
        _build_control_plane()


def test_build_event_sink_absent_returns_none(monkeypatch):
    from chute.cli import _build_event_sink

    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.delenv("CHUTE_EVENT_LOG_FILE", raising=False)
    monkeypatch.delenv("CHUTE_EVENT_LOG_MAX_BYTES", raising=False)
    monkeypatch.delenv("CHUTE_EVENT_LOG_BACKUPS", raising=False)
    assert _build_event_sink() is None


def test_build_event_sink_uses_jsonl_event_log_file(tmp_path, monkeypatch):
    from chute.cli import _build_event_sink

    event_log = tmp_path / "events.jsonl"
    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.setenv("CHUTE_EVENT_LOG_FILE", str(event_log))

    sink = _build_event_sink()

    assert isinstance(sink, JsonlEventSink)
    assert sink.max_bytes == DEFAULT_JSONL_EVENT_LOG_MAX_BYTES
    assert sink.backup_count == DEFAULT_JSONL_EVENT_LOG_BACKUPS


def test_build_event_sink_uses_jsonl_rotation_settings(tmp_path, monkeypatch):
    from chute.cli import _build_event_sink

    event_log = tmp_path / "events.jsonl"
    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.setenv("CHUTE_EVENT_LOG_FILE", str(event_log))
    monkeypatch.setenv("CHUTE_EVENT_LOG_MAX_BYTES", "12345")
    monkeypatch.setenv("CHUTE_EVENT_LOG_BACKUPS", "7")

    sink = _build_event_sink()

    assert isinstance(sink, JsonlEventSink)
    assert sink.max_bytes == 12345
    assert sink.backup_count == 7


def test_build_event_sink_can_disable_jsonl_rotation(tmp_path, monkeypatch):
    from chute.cli import _build_event_sink

    event_log = tmp_path / "events.jsonl"
    monkeypatch.delenv("CHUTE_EVENT_SINK", raising=False)
    monkeypatch.setenv("CHUTE_EVENT_LOG_FILE", str(event_log))
    monkeypatch.setenv("CHUTE_EVENT_LOG_MAX_BYTES", "off")

    sink = _build_event_sink()

    assert isinstance(sink, JsonlEventSink)
    assert sink.max_bytes is None


def test_build_event_sink_rejects_event_log_file_and_import_hook(tmp_path, monkeypatch):
    from chute.cli import _build_event_sink

    event_log = tmp_path / "events.jsonl"
    monkeypatch.setenv("CHUTE_EVENT_LOG_FILE", str(event_log))
    monkeypatch.setenv("CHUTE_EVENT_SINK", "test_auth:_make_dummy_event_sink")

    with pytest.raises(SystemExit):
        _build_event_sink()


def test_build_event_sink_calls_a_factory(monkeypatch):
    from chute.cli import _build_event_sink

    monkeypatch.delenv("CHUTE_EVENT_LOG_FILE", raising=False)
    monkeypatch.setenv("CHUTE_EVENT_SINK", "test_auth:_make_dummy_event_sink")
    assert isinstance(_build_event_sink(), _DummyEventSink)


def test_build_event_sink_custom_sink_ignores_jsonl_rotation_env(monkeypatch):
    from chute.cli import _build_event_sink

    monkeypatch.delenv("CHUTE_EVENT_LOG_FILE", raising=False)
    monkeypatch.setenv("CHUTE_EVENT_SINK", "test_auth:_make_dummy_event_sink")
    monkeypatch.setenv("CHUTE_EVENT_LOG_MAX_BYTES", "bad")

    assert isinstance(_build_event_sink(), _DummyEventSink)


def test_build_event_sink_uses_an_instance_as_is(monkeypatch):
    from chute.cli import _build_event_sink

    monkeypatch.setenv("CHUTE_EVENT_SINK", "test_auth:_DUMMY_EVENT_SINK")
    assert _build_event_sink() is _DUMMY_EVENT_SINK


def test_build_event_sink_rejects_bad_format(monkeypatch):
    from chute.cli import _build_event_sink

    monkeypatch.setenv("CHUTE_EVENT_SINK", "no_colon_here")
    with pytest.raises(SystemExit):
        _build_event_sink()


def test_build_event_sink_rejects_non_sink(monkeypatch):
    from chute.cli import _build_event_sink

    monkeypatch.setenv("CHUTE_EVENT_SINK", "test_auth:_NOT_AN_EVENT_SINK")
    with pytest.raises(SystemExit):
        _build_event_sink()
