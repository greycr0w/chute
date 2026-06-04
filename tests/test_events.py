import datetime as _dt
import json
import os
from pathlib import Path

import pytest

import chute.events as events_module
from chute.events import JsonlEventSink, TunnelOpenedEvent, VisitorRejectedEvent


def _visitor_rejected_event(reason: str = "no_tunnel") -> VisitorRejectedEvent:
    return VisitorRejectedEvent(
        reason=reason,
        label=None,
        account_id=None,
        credential_id=None,
        host="missing.example.test",
        visitor_ip="198.51.100.2",
        at=_dt.datetime(2026, 6, 3, 12, 1, tzinfo=_dt.UTC),
    )


async def test_jsonl_event_sink_writes_structured_owner_only_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    sink = JsonlEventSink(path)
    event = TunnelOpenedEvent(
        connection_id="conn",
        label="api",
        account_id="acct",
        credential_id="cred",
        scheme="https",
        public_url="https://api.example.test/",
        agent_ip="203.0.113.10",
        requested_subdomain="api",
        at=_dt.datetime(2026, 6, 3, 12, 0, tzinfo=_dt.UTC),
        lease_id="lease-api",
    )

    await sink.tunnel_opened(event)

    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record == {
        "type": "tunnel_opened",
        "event": {
            "connection_id": "conn",
            "label": "api",
            "account_id": "acct",
            "credential_id": "cred",
            "scheme": "https",
            "public_url": "https://api.example.test/",
            "agent_ip": "203.0.113.10",
            "requested_subdomain": "api",
            "at": "2026-06-03T12:00:00+00:00",
            "lease_id": "lease-api",
        },
    }


async def test_jsonl_event_sink_appends_multiple_event_types(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    sink = JsonlEventSink(path)

    await sink.visitor_rejected(_visitor_rejected_event())
    await sink.visitor_rejected(
        VisitorRejectedEvent(
            reason="visitor_limit",
            label="api",
            account_id="acct",
            credential_id="cred",
            host="api.example.test",
            visitor_ip="198.51.100.3",
            at=_dt.datetime(2026, 6, 3, 12, 2, tzinfo=_dt.UTC),
        )
    )

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [record["type"] for record in records] == ["visitor_rejected", "visitor_rejected"]
    assert records[0]["event"]["host"] == "missing.example.test"
    assert records[1]["event"]["account_id"] == "acct"


async def test_jsonl_event_sink_rotates_with_owner_only_backups(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    sink = JsonlEventSink(path, max_bytes=1, backup_count=2)

    for index in range(4):
        await sink.visitor_rejected(_visitor_rejected_event(f"reject-{index}"))

    active = json.loads(path.read_text(encoding="utf-8"))
    first_backup = json.loads((tmp_path / "events.jsonl.1").read_text(encoding="utf-8"))
    second_backup = json.loads((tmp_path / "events.jsonl.2").read_text(encoding="utf-8"))

    assert active["event"]["reason"] == "reject-3"
    assert first_backup["event"]["reason"] == "reject-2"
    assert second_backup["event"]["reason"] == "reject-1"
    assert not (tmp_path / "events.jsonl.3").exists()
    if os.name != "nt":
        for rotated in (path, tmp_path / "events.jsonl.1", tmp_path / "events.jsonl.2"):
            assert rotated.stat().st_mode & 0o077 == 0


async def test_jsonl_event_sink_rotation_can_be_disabled(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    sink = JsonlEventSink(path, max_bytes=1, backup_count=0)

    for index in range(3):
        await sink.visitor_rejected(_visitor_rejected_event(f"reject-{index}"))

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [record["event"]["reason"] for record in records] == [
        "reject-0",
        "reject-1",
        "reject-2",
    ]
    assert not (tmp_path / "events.jsonl.1").exists()


def test_jsonl_event_sink_rejects_permissive_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("", encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(ValueError, match="chmod 600"):
        JsonlEventSink(path)


def test_jsonl_event_sink_rejects_missing_parent(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="parent"):
        JsonlEventSink(tmp_path / "missing" / "events.jsonl")


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_jsonl_event_sink_rejects_world_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "public"
    parent.mkdir()
    parent.chmod(0o777)

    with pytest.raises(ValueError, match="group- or world-writable"):
        JsonlEventSink(parent / "events.jsonl")


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_jsonl_event_sink_rejects_group_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o775)

    with pytest.raises(ValueError, match="group- or world-writable"):
        JsonlEventSink(parent / "events.jsonl")


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner checks only")
def test_jsonl_event_sink_rejects_parent_not_owned_by_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_euid = os.geteuid()
    monkeypatch.setattr(events_module.os, "geteuid", lambda: real_euid + 1)

    with pytest.raises(ValueError, match="parent .* owned by this user"):
        JsonlEventSink(tmp_path / "events.jsonl")


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner checks only")
def test_jsonl_event_sink_rejects_existing_file_not_owned_by_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("", encoding="utf-8")
    path.chmod(0o600)
    real_euid = os.geteuid()
    monkeypatch.setattr(events_module.JsonlEventSink, "_validate_parent_dir", lambda _self: None)
    monkeypatch.setattr(events_module.os, "geteuid", lambda: real_euid + 1)

    with pytest.raises(ValueError, match="must be owned by this user"):
        JsonlEventSink(path)


def test_jsonl_event_sink_rejects_invalid_rotation_config(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        JsonlEventSink(tmp_path / "events.jsonl", max_bytes=-1)
    with pytest.raises(ValueError, match="backup_count"):
        JsonlEventSink(tmp_path / "events.jsonl", backup_count=-1)
