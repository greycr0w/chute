"""The Authorizer seam. Pure unit tests -- no server, no sockets."""

from dataclasses import FrozenInstanceError

import pytest

from chute.auth import UNLIMITED_TUNNELS, Authorizer, AuthResult, StaticTokenAuthorizer


async def test_static_authorizer_accepts_the_configured_token():
    auth = StaticTokenAuthorizer("s3cret")
    result = await auth.authenticate("s3cret", None, None)
    assert isinstance(result, AuthResult)
    assert result.account_id == "0"
    assert result.max_tunnels == UNLIMITED_TUNNELS
    assert result.allowed_label is None


async def test_static_authorizer_rejects_wrong_or_empty_token():
    auth = StaticTokenAuthorizer("s3cret")
    assert await auth.authenticate("nope", None, None) is None
    assert await auth.authenticate("", None, None) is None
    assert await auth.authenticate("S3CRET", None, None) is None  # case-sensitive


async def test_static_authorizer_ignores_subdomain_and_ip():
    # A single shared token grants the same thing regardless of requested name/IP;
    # label assignment still happens downstream in the relay.
    auth = StaticTokenAuthorizer("s3cret")
    result = await auth.authenticate("s3cret", "myapp", "203.0.113.9")
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


# --------------------------------------------------------------------------- #
# CHUTE_AUTHORIZER import-string knob
#
# The import-strings below target *this* module (pytest's prepend import mode puts
# the tests dir on sys.path, so "test_auth" is importable by name).
# --------------------------------------------------------------------------- #


class _DummyAuthorizer:
    async def authenticate(self, token, requested_subdomain, agent_ip):
        return None


_DUMMY_INSTANCE = _DummyAuthorizer()
_NOT_AN_AUTHORIZER = object()  # no authenticate method


def _make_dummy_authorizer():
    return _DummyAuthorizer()


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
