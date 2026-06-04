from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import chute._files as private_files
from chute._files import read_private_text_file, write_new_private_text_file


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory fsync behavior only")
def test_write_new_private_text_file_fsyncs_file_and_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fsynced: list[str] = []

    def fake_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        fsynced.append("dir" if stat.S_ISDIR(mode) else "file")

    monkeypatch.setattr(private_files.os, "fsync", fake_fsync)

    token_file = tmp_path / "token"
    write_new_private_text_file(token_file, "secret-token", "token file")

    assert token_file.read_text(encoding="utf-8") == "secret-token\n"
    assert fsynced == ["file", "dir"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_read_private_text_file_rejects_group_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    token_file = parent / "token"
    token_file.write_text("secret-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    parent.chmod(0o775)

    with pytest.raises(ValueError, match="group- or world-writable"):
        read_private_text_file(token_file, "token file")


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_write_new_private_text_file_rejects_group_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o775)

    with pytest.raises(ValueError, match="group- or world-writable"):
        write_new_private_text_file(parent / "token", "secret-token", "token file")


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="POSIX owner checks only; root-owned parents are trusted",
)
def test_read_private_text_file_rejects_parent_not_owned_by_user_or_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    real_euid = os.geteuid()
    monkeypatch.setattr(private_files.os, "geteuid", lambda: real_euid + 1)

    with pytest.raises(ValueError, match="parent .* owned by this user or root"):
        read_private_text_file(token_file, "token file")


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner checks only")
def test_read_private_text_file_rejects_file_not_owned_by_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n", encoding="utf-8")
    token_file.chmod(0o600)
    real_euid = os.geteuid()
    monkeypatch.setattr(private_files, "_validate_parent", lambda _path, _name: None)
    monkeypatch.setattr(private_files.os, "geteuid", lambda: real_euid + 1)

    with pytest.raises(ValueError, match="must be owned by this user"):
        read_private_text_file(token_file, "token file")
