"""Control-plane primitives.

These tests are deliberately socket-free: the control-plane seam should be a
small policy adapter, not part of the visitor data path.
"""

import datetime as _dt
import hashlib
import json
import os
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import chute.control as control_module
from chute.auth import AuthResult, Budget, StaticTokenAuthorizer
from chute.control import (
    AccountBudgetUpdate,
    AuthorizerControlPlane,
    ControlPlane,
    LeaseRenewalRequest,
    LeaseRevocation,
    PolicyUpdate,
    PolicyUpdateRequest,
    StaticPolicyControlPlane,
    StaticTokenControlPlane,
    TunnelAdmission,
    TunnelAdmissionRequest,
    TunnelLease,
    validate_static_policy_file,
)
from chute.server import Server

ROOT = Path(__file__).resolve().parents[1]


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _write_policy(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)


def _policy(token: str = "s3cret", *, lease_seconds: int | None = None) -> dict:
    credential: dict[str, object] = {
        "credential_id": "cred-1",
        "token_sha256": _token_hash(token),
        "account_id": "acct",
        "max_tunnels": 2,
        "allowed_label": "api",
        "budget": {
            "max_visitors": 7,
            "max_reconnects_per_min": 3,
            "max_bytes_per_sec": 1024,
            "max_buffered_bytes": 2048,
        },
    }
    if lease_seconds is not None:
        credential["lease_seconds"] = lease_seconds
    return {"schema_version": 1, "credentials": [credential]}


def _request(token: str = "s3cret") -> TunnelAdmissionRequest:
    return TunnelAdmissionRequest(
        token=token,
        requested_subdomain="api",
        agent_ip="203.0.113.5",
        scheme="https",
        protocol_version=3,
    )


def _renewal_request() -> LeaseRenewalRequest:
    return LeaseRenewalRequest(
        lease_id="lease-1",
        account_id="acct",
        credential_id="cred",
        label="api",
        connection_id="conn",
        generation=7,
        expires_at=_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=30),
    )


def _policy_request() -> PolicyUpdateRequest:
    return PolicyUpdateRequest(
        current_version=3,
        active_lease_count=2,
        active_lease_ids=("lease-1", "lease-2"),
    )


class _RecordingAuthorizer:
    def __init__(self, result: AuthResult | None) -> None:
        self.result = result
        self.requests = []

    async def authenticate(self, request):
        self.requests.append(request)
        return self.result


async def test_static_token_control_plane_admits_the_configured_token():
    cp = StaticTokenControlPlane("s3cret")
    admission = await cp.admit_tunnel(_request("s3cret"))

    assert isinstance(cp, ControlPlane)
    assert isinstance(admission, TunnelAdmission)
    assert admission.account_id == "0"
    assert admission.credential_id is None
    assert admission.lease.lease_id
    assert admission.lease.expires_at is None
    assert admission.budget == Budget()


async def test_static_token_control_plane_rejects_wrong_token():
    cp = StaticTokenControlPlane("s3cret")
    assert await cp.admit_tunnel(_request("wrong")) is None


async def test_static_token_control_plane_renewal_returns_non_expiring_lease():
    cp = StaticTokenControlPlane("s3cret")
    renewed = await cp.renew_lease(_renewal_request())

    assert isinstance(renewed, TunnelLease)
    assert renewed.lease_id == "lease-1"
    assert renewed.account_id == "acct"
    assert renewed.credential_id == "cred"
    assert renewed.generation == 7
    assert renewed.expires_at is None


async def test_static_token_control_plane_policy_poll_is_noop():
    cp = StaticTokenControlPlane("s3cret")

    assert await cp.poll_policy_updates(_policy_request()) is None


async def test_authorizer_control_plane_preserves_structured_request_and_result():
    budget = Budget(max_visitors=7)
    auth = AuthResult(
        account_id="acct",
        max_tunnels=3,
        allowed_label="api",
        budget=budget,
        credential_id="cred",
    )
    authorizer = _RecordingAuthorizer(auth)
    cp = AuthorizerControlPlane(authorizer)

    admission = await cp.admit_tunnel(_request("tok"))

    assert authorizer.requests[0].token == "tok"
    assert authorizer.requests[0].requested_subdomain == "api"
    assert authorizer.requests[0].agent_ip == "203.0.113.5"
    assert admission is not None
    assert admission.account_id == "acct"
    assert admission.max_tunnels == 3
    assert admission.allowed_label == "api"
    assert admission.budget is budget
    assert admission.credential_id == "cred"


async def test_static_policy_control_plane_admits_hashed_token_policy(tmp_path: Path):
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy())
    cp = StaticPolicyControlPlane(policy_file)

    admission = await cp.admit_tunnel(_request("s3cret"))

    assert isinstance(cp, ControlPlane)
    assert isinstance(admission, TunnelAdmission)
    assert admission.account_id == "acct"
    assert admission.credential_id == "cred-1"
    assert admission.max_tunnels == 2
    assert admission.allowed_label == "api"
    assert admission.budget.max_visitors == 7
    assert admission.budget.max_reconnects_per_min == 3
    assert admission.budget.max_bytes_per_sec == 1024
    assert admission.budget.max_buffered_bytes == 2048
    assert admission.lease.expires_at is None
    assert await cp.admit_tunnel(_request("wrong")) is None


async def test_static_policy_control_plane_normalizes_allowed_label(tmp_path: Path):
    policy_file = tmp_path / "policy.json"
    data = _policy()
    data["credentials"][0]["allowed_label"] = "API"  # type: ignore[index]
    _write_policy(policy_file, data)
    cp = StaticPolicyControlPlane(policy_file)

    admission = await cp.admit_tunnel(_request("s3cret"))

    assert admission is not None
    assert admission.allowed_label == "api"


async def test_static_policy_control_plane_renews_finite_leases_and_revokes_removed_credential(
    tmp_path: Path,
):
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy(lease_seconds=60))
    cp = StaticPolicyControlPlane(policy_file)

    admission = await cp.admit_tunnel(_request("s3cret"))
    assert admission is not None
    assert admission.lease.expires_at is not None

    renewed = await cp.renew_lease(
        LeaseRenewalRequest(
            lease_id=admission.lease.lease_id,
            account_id=admission.account_id,
            credential_id=admission.credential_id,
            label="api",
            connection_id="conn",
            generation=0,
            expires_at=admission.lease.expires_at,
        )
    )

    assert renewed is not None
    assert renewed.lease_id == admission.lease.lease_id
    assert renewed.account_id == "acct"
    assert renewed.credential_id == "cred-1"
    assert renewed.generation == 1
    assert renewed.expires_at is not None
    assert renewed.expires_at > _dt.datetime.now(_dt.UTC)

    _write_policy(policy_file, _policy("new", lease_seconds=60))
    assert (
        await cp.renew_lease(
            LeaseRenewalRequest(
                lease_id=admission.lease.lease_id,
                account_id=admission.account_id,
                credential_id=admission.credential_id,
                label="api",
                connection_id="conn",
                generation=1,
                expires_at=renewed.expires_at,
            )
        )
        is None
    )

    admission = await cp.admit_tunnel(_request("new"))
    assert admission is not None
    assert admission.lease.expires_at is not None

    _write_policy(
        policy_file, {"schema_version": 1, "credentials": [_policy("new")["credentials"][0]]}
    )
    assert (
        await cp.renew_lease(
            LeaseRenewalRequest(
                lease_id=admission.lease.lease_id,
                account_id=admission.account_id,
                credential_id=admission.credential_id,
                label="api",
                connection_id="conn",
                generation=1,
                expires_at=renewed.expires_at,
            )
        )
        is None
    )


async def test_static_policy_control_plane_prunes_inactive_finite_leases(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy(lease_seconds=60))
    cp = StaticPolicyControlPlane(policy_file)

    active = await cp.admit_tunnel(_request())
    stale = await cp.admit_tunnel(_request())
    assert active is not None and active.lease.expires_at is not None
    assert stale is not None and stale.lease.expires_at is not None

    await cp.poll_policy_updates(
        PolicyUpdateRequest(current_version=0, active_lease_ids=(active.lease.lease_id,))
    )

    assert (
        await cp.renew_lease(
            LeaseRenewalRequest(
                lease_id=stale.lease.lease_id,
                account_id=stale.account_id,
                credential_id=stale.credential_id,
                label="api",
                connection_id="stale-conn",
                generation=0,
                expires_at=stale.lease.expires_at,
            )
        )
        is None
    )
    assert (
        await cp.renew_lease(
            LeaseRenewalRequest(
                lease_id=active.lease.lease_id,
                account_id=active.account_id,
                credential_id=active.credential_id,
                label="api",
                connection_id="active-conn",
                generation=0,
                expires_at=active.lease.expires_at,
            )
        )
        is not None
    )


async def test_static_policy_control_plane_polls_versioned_policy_update(tmp_path: Path):
    policy_file = tmp_path / "policy.json"
    data = _policy()
    data.update(
        {
            "policy_version": 4,
            "revoke_lease_ids": ["legacy-lease"],
            "lease_revocations": [{"lease_id": "close-lease", "action": "close"}],
            "account_budgets": [
                {
                    "account_id": "acct",
                    "budget": {"max_visitors": 1, "max_buffered_bytes": 4096},
                }
            ],
        }
    )
    _write_policy(policy_file, data)
    cp = StaticPolicyControlPlane(policy_file)

    update = await cp.poll_policy_updates(_policy_request())

    assert isinstance(update, PolicyUpdate)
    assert update.version == 4
    assert update.revoke_lease_ids == ("legacy-lease",)
    assert update.lease_revocations == (LeaseRevocation("close-lease", action="close"),)
    assert update.account_budgets[0].account_id == "acct"
    assert update.account_budgets[0].budget.max_visitors == 1
    assert update.account_budgets[0].budget.max_buffered_bytes == 4096
    assert (
        await cp.poll_policy_updates(PolicyUpdateRequest(current_version=4, active_lease_ids=()))
        is None
    )


def test_validate_static_policy_file_accepts_valid_private_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy())

    validate_static_policy_file(policy_file)


def test_static_policy_control_plane_rejects_duplicate_policy_update_entries(
    tmp_path: Path,
) -> None:
    policy_file = tmp_path / "policy.json"

    data = _policy()
    data.update({"policy_version": 1, "revoke_lease_ids": ["lease-1", "lease-1"]})
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="revoke_lease_ids.*duplicates"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data.update(
        {
            "policy_version": 1,
            "lease_revocations": [
                {"lease_id": "lease-1", "action": "drain"},
                {"lease_id": "lease-1", "action": "close"},
            ],
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="lease_revocations.*duplicate"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data.update(
        {
            "policy_version": 1,
            "revoke_lease_ids": ["lease-1"],
            "lease_revocations": [{"lease_id": "lease-1", "action": "close"}],
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="across revoke_lease_ids and lease_revocations"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data.update(
        {
            "policy_version": 1,
            "account_budgets": [
                {"account_id": "acct", "budget": {"max_visitors": 1}},
                {"account_id": "acct", "budget": {"max_visitors": 2}},
            ],
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="account_budgets.*duplicate"):
        StaticPolicyControlPlane(policy_file)


def test_static_policy_control_plane_validates_reserved_label_ownership(
    tmp_path: Path,
) -> None:
    policy_file = tmp_path / "policy.json"

    data = _policy()
    data["credentials"].append(  # type: ignore[union-attr]
        {
            **_policy("rotated")["credentials"][0],
            "credential_id": "cred-2",
            "token_sha256": _token_hash("rotated"),
        }
    )
    _write_policy(policy_file, data)
    validate_static_policy_file(policy_file)

    data = _policy()
    data["credentials"].append(  # type: ignore[union-attr]
        {
            **_policy("other")["credentials"][0],
            "credential_id": "cred-2",
            "token_sha256": _token_hash("other"),
            "account_id": "other-acct",
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="allowed_label.*multiple accounts"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data["credentials"][0]["allowed_label"] = "bad_label"  # type: ignore[index]
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="valid hostname label"):
        StaticPolicyControlPlane(policy_file)


async def test_static_policy_control_plane_keeps_last_good_on_malformed_live_reload(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy())
    cp = StaticPolicyControlPlane(policy_file)

    policy_file.write_text("{not-json", encoding="utf-8")
    policy_file.chmod(0o600)

    old_admission = await cp.admit_tunnel(_request("s3cret"))

    assert old_admission is not None
    assert old_admission.credential_id == "cred-1"
    assert "keeping last-good policy" in caplog.text

    _write_policy(policy_file, _policy("new-token"))

    assert await cp.admit_tunnel(_request("s3cret")) is None
    new_admission = await cp.admit_tunnel(_request("new-token"))
    assert new_admission is not None
    assert new_admission.credential_id == "cred-1"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
async def test_static_policy_control_plane_keeps_last_good_on_permissive_live_reload(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy())
    cp = StaticPolicyControlPlane(policy_file)

    policy_file.write_text(json.dumps(_policy("new-token")), encoding="utf-8")
    policy_file.chmod(0o644)

    old_admission = await cp.admit_tunnel(_request("s3cret"))

    assert old_admission is not None
    assert await cp.admit_tunnel(_request("new-token")) is None
    assert "keeping last-good policy" in caplog.text

    policy_file.chmod(0o600)
    recovered = await cp.admit_tunnel(_request("new-token"))
    assert recovered is not None


def test_static_policy_control_plane_rejects_oversized_policy_file(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(" " * (control_module._MAX_POLICY_FILE_BYTES + 1), encoding="utf-8")
    policy_file.chmod(0o600)

    with pytest.raises(ValueError, match="too large"):
        StaticPolicyControlPlane(policy_file)


def test_static_policy_control_plane_rejects_oversized_policy_sections(
    tmp_path: Path,
) -> None:
    policy_file = tmp_path / "policy.json"

    data = _policy()
    data["credentials"] = [{} for _ in range(control_module._MAX_POLICY_CREDENTIALS + 1)]
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="credentials.*at most"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data.update(
        {
            "policy_version": 1,
            "revoke_lease_ids": [
                f"lease-{index}" for index in range(control_module._MAX_POLICY_REVOKE_LEASE_IDS + 1)
            ],
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="revoke_lease_ids.*at most"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data.update(
        {
            "policy_version": 1,
            "lease_revocations": [
                {"lease_id": f"lease-{index}"}
                for index in range(control_module._MAX_POLICY_LEASE_REVOCATIONS + 1)
            ],
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="lease_revocations.*at most"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    data.update(
        {
            "policy_version": 1,
            "account_budgets": [
                {"account_id": f"acct-{index}", "budget": {}}
                for index in range(control_module._MAX_POLICY_ACCOUNT_BUDGETS + 1)
            ],
        }
    )
    _write_policy(policy_file, data)
    with pytest.raises(ValueError, match="account_budgets.*at most"):
        StaticPolicyControlPlane(policy_file)


async def test_static_policy_control_plane_uses_cached_policy_when_file_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    policy_file = tmp_path / "policy.json"
    _write_policy(policy_file, _policy())
    cp = StaticPolicyControlPlane(policy_file)

    def fail_reparse(_text: str, _path: Path):
        raise AssertionError("unchanged policy file was reparsed")

    monkeypatch.setattr(control_module, "_parse_static_policy_text", fail_reparse)

    admission = await cp.admit_tunnel(_request("s3cret"))

    assert admission is not None
    assert admission.account_id == "acct"


async def test_static_policy_control_plane_rejects_permissive_or_plaintext_policy(
    tmp_path: Path,
):
    policy_file = tmp_path / "policy.json"
    data = _policy()
    data["credentials"][0]["token"] = "plaintext"  # type: ignore[index]
    _write_policy(policy_file, data)

    with pytest.raises(ValueError, match="unknown keys"):
        StaticPolicyControlPlane(policy_file)

    data = _policy()
    _write_policy(policy_file, data)
    policy_file.chmod(0o644)
    with pytest.raises(ValueError, match="chmod 600"):
        StaticPolicyControlPlane(policy_file)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink behavior only")
def test_static_policy_control_plane_rejects_symlink_policy_file(tmp_path: Path) -> None:
    target = tmp_path / "target-policy.json"
    link = tmp_path / "policy.json"
    _write_policy(target, _policy())
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        StaticPolicyControlPlane(link)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_static_policy_control_plane_rejects_world_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)
    policy_file = parent / "policy.json"
    _write_policy(policy_file, _policy())

    with pytest.raises(ValueError, match="world-writable"):
        StaticPolicyControlPlane(policy_file)


def test_tunnel_admission_can_project_to_auth_result_for_compatibility():
    admission = TunnelAdmission.from_auth_result(
        AuthResult(
            account_id="acct",
            max_tunnels=2,
            allowed_label="api",
            budget=Budget(max_visitors=5),
            credential_id="cred",
        ),
        lease_id="lease-1",
    )

    auth = admission.to_auth_result()

    assert admission.lease.lease_id == "lease-1"
    assert auth.account_id == "acct"
    assert auth.max_tunnels == 2
    assert auth.allowed_label == "api"
    assert auth.budget.max_visitors == 5
    assert auth.credential_id == "cred"


def test_tunnel_admission_is_frozen():
    admission = TunnelAdmission.from_auth_result(AuthResult(account_id="acct"))
    with pytest.raises(FrozenInstanceError):
        admission.max_tunnels = 1


def test_policy_update_primitives_are_frozen():
    update = PolicyUpdate(
        version=4,
        revoke_lease_ids=("lease-1",),
        account_budgets=(AccountBudgetUpdate("acct", Budget(max_visitors=1)),),
        lease_revocations=(LeaseRevocation("lease-2", action="close"),),
    )

    assert update.version == 4
    assert update.revoke_lease_ids == ("lease-1",)
    assert update.account_budgets[0].budget.max_visitors == 1
    assert update.lease_revocations[0].lease_id == "lease-2"
    assert update.lease_revocations[0].action == "close"
    with pytest.raises(FrozenInstanceError):
        update.version = 5


def test_budget_docs_do_not_advertise_enforced_fields_as_reserved():
    surfaces = "\n".join(
        (ROOT / path).read_text()
        for path in (
            "README.md",
            "CHANGELOG.md",
            "AUDIT.md",
            "docs/PROTOCOL.md",
            "docs/CONTROL-PLANE.md",
            "src/chute/auth.py",
        )
    )
    stale_claim = re.compile(
        r"(max_visitors|max_reconnects_per_min|max_bytes_per_sec|max_buffered_bytes)"
        r"(?:(?!\n\n).){0,220}not enforced|"
        r"not enforced(?:(?!\n\n).){0,220}"
        r"(max_visitors|max_reconnects_per_min|max_bytes_per_sec|max_buffered_bytes)|"
        r"reserved(?:(?!\n\n).){0,220}not enforced",
        re.IGNORECASE | re.DOTALL,
    )

    assert not stale_claim.search(surfaces)
    for field in (
        "max_visitors",
        "max_reconnects_per_min",
        "max_bytes_per_sec",
        "max_buffered_bytes",
    ):
        assert field in surfaces


def test_control_plane_docs_define_guarantees_matrix():
    control_doc = (ROOT / "docs" / "CONTROL-PLANE.md").read_text()
    readme = (ROOT / "README.md").read_text()
    security = (ROOT / "SECURITY.md").read_text()

    assert "## Guarantees matrix" in control_doc
    assert "Guaranteed by chute core" in control_doc
    assert "Owned outside chute core" in control_doc
    assert "Not guaranteed" in control_doc

    for phrase in (
        "pending-label reservation",
        "one request per upstream connection",
        "detached in-flight streams after a policy update",
        "Host-global memory caps",
        "Compliance-grade audit by default",
        "No remote control-plane call on the visitor hot path",
        "Proof that an external firewall is correct",
        "HA, multi-node seamless failover",
    ):
        assert phrase in control_doc

    for surface in (readme, security):
        assert "docs/CONTROL-PLANE.md#guarantees-matrix" in surface


def test_budget_update_docs_cover_detached_in_flight_work():
    surfaces = {
        "docs/CONTROL-PLANE.md": (ROOT / "docs" / "CONTROL-PLANE.md").read_text(),
        "docs/PROTOCOL.md": (ROOT / "docs" / "PROTOCOL.md").read_text(),
    }

    for path, text in surfaces.items():
        assert "detached in-flight" in text, path
        assert re.search(r"local account\s+budget", text), path
    assert "replace live account budgets" not in surfaces["docs/PROTOCOL.md"]


def test_protocol_docs_state_keepalive_detection_window():
    protocol_doc = (ROOT / "docs" / "PROTOCOL.md").read_text()

    assert "**Protocol version:** 4" in protocol_doc
    assert "if `v != 4`" in protocol_doc
    assert "ping_interval = 20s" in protocol_doc
    assert "ping_timeout = 20s" in protocol_doc
    assert "up to about\n  40s" in protocol_doc
    assert "reconnect backoff" in protocol_doc


def test_event_sink_docs_state_bounded_queue_and_required_open_gate():
    surfaces = {
        "README.md": (ROOT / "README.md").read_text(),
        "docs/PROTOCOL.md": (ROOT / "docs" / "PROTOCOL.md").read_text(),
        "docs/CONTROL-PLANE.md": (ROOT / "docs" / "CONTROL-PLANE.md").read_text(),
    }

    for path, text in surfaces.items():
        assert "CHUTE_EVENT_LOG_FILE" in text, path
        assert "CHUTE_EVENT_LOG_MAX_BYTES" in text, path
        assert "CHUTE_EVENT_LOG_BACKUPS" in text, path
        assert "JsonlEventSink" in text or "JSONL" in text, path
        assert "owned" in text, path
        assert "rotat" in text.lower(), path
        assert "metadata-sensitive" in text, path
        assert "CHUTE_REQUIRE_EVENT_SINK" in text, path
        assert "bounded" in text and "queue" in text, path
        assert re.search(r"retr(y|ied)", text), path
        assert "visitor" in text and ("hot" in text or "admission" in text), path
        assert "tunnel_opened" in text or "tunnel-open" in text, path
        assert "depth" in text and "drop" in text, path
        assert "generated" in text and "counter" in text, path
        assert "pool" in text and "capacity" in text, path
        assert "busy" in text and "limit" in text, path
        assert "policy" in text and "lease" in text, path
        assert "rejected" in text and "renewal" in text, path
        assert "log" in text and ("metric" in text or "/metrics" in text), path
        assert "relay stat" in text.lower() or "relay_stats" in text, path


def test_control_plane_docs_state_revocation_actions():
    surfaces = {
        "README.md": (ROOT / "README.md").read_text(),
        "docs/PROTOCOL.md": (ROOT / "docs" / "PROTOCOL.md").read_text(),
        "docs/CONTROL-PLANE.md": (ROOT / "docs" / "CONTROL-PLANE.md").read_text(),
        "AUDIT.md": (ROOT / "AUDIT.md").read_text(),
    }

    for path, text in surfaces.items():
        assert "LeaseRevocation" in text, path
        assert "drain" in text and "close" in text, path
        assert "last-good" in text or "last good" in text, path
    assert "lease-id index" in surfaces["docs/CONTROL-PLANE.md"]


def test_control_plane_docs_state_static_policy_file():
    surfaces = {
        "README.md": (ROOT / "README.md").read_text(),
        "docs/PROTOCOL.md": (ROOT / "docs" / "PROTOCOL.md").read_text(),
        "docs/CONTROL-PLANE.md": (ROOT / "docs" / "CONTROL-PLANE.md").read_text(),
    }

    for path, text in surfaces.items():
        assert "CHUTE_POLICY_FILE" in text, path
        assert "StaticPolicyControlPlane" in text or "file-backed" in text, path
        assert "non-symlink" in text, path
        assert "owned" in text and "root" in text, path
        assert "group-" in text, path
        assert "world-writable" in text, path
        assert "cached" in text or "fingerprint" in text, path
        assert "last-good" in text or "last good" in text, path
        assert "validate-policy" in text, path
        assert "allowed_label" in text, path
        assert "multiple accounts" in text, path

    control_doc = surfaces["docs/CONTROL-PLANE.md"]
    assert "chuted gen-token --token-file" in control_doc
    assert "chuted hash-token --token-file" in control_doc
    assert "chuted validate-policy --policy-file" in control_doc
    assert "--token-file" in control_doc and "CHUTE_TOKEN_FILE" in control_doc
    assert "chmod 600" in control_doc
    assert "token_sha256" in control_doc
    assert "schema_version" in control_doc
    assert "Unknown keys are rejected" in control_doc


def test_docs_distinguish_authorizer_from_full_control_plane():
    surfaces = {
        "README.md": (ROOT / "README.md").read_text(),
        "docs/CONTROL-PLANE.md": (ROOT / "docs" / "CONTROL-PLANE.md").read_text(),
    }

    for path, text in surfaces.items():
        assert "CHUTE_AUTHORIZER" in text, path
        assert "admission-only" in text, path
        assert "not" in text and "deprecated" in text, path
        assert "CHUTE_CONTROL_PLANE" in text, path
        assert "finite lease" in text or "finite leases" in text, path
        assert "revocation" in text, path


def test_server_rejects_ambiguous_control_plane_and_authorizer():
    with pytest.raises(ValueError, match="control_plane or authorizer"):
        Server(
            token="secret",
            control_plane=StaticTokenControlPlane("secret"),
            authorizer=StaticTokenAuthorizer("secret"),
        )
