"""Small secure-file helpers for local secret/config surfaces."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

PrivateFileFingerprint = tuple[int, int, int, int, int]
_UNSUPPORTED_DIR_FSYNC_ERRNOS = tuple(
    value
    for value in (
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)

__all__ = [
    "PrivateFileFingerprint",
    "PrivateTextFile",
    "read_private_text_file",
    "read_private_text_file_snapshot",
    "write_new_private_text_file",
]


@dataclass(frozen=True, slots=True)
class PrivateTextFile:
    text: str
    fingerprint: PrivateFileFingerprint


def read_private_text_file(raw_path: str | os.PathLike[str], name: str) -> str:
    return read_private_text_file_snapshot(raw_path, name).text


def read_private_text_file_snapshot(
    raw_path: str | os.PathLike[str],
    name: str,
    *,
    max_bytes: int | None = None,
) -> PrivateTextFile:
    """Read a 0600 current-user-owned regular file without following the final symlink.

    This protects local token/policy files from the common "checked one path,
    opened another" footgun while keeping the rule simple for operators: put
    sensitive chute files in a private directory and make the file owner-only.
    """

    path = Path(raw_path).expanduser()
    _validate_parent(path, name)
    _validate_lstat(path, name)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{name} {path} must not be a symlink") from None
        raise ValueError(f"{name} {path} is not readable: {exc}") from None
    try:
        first = _validate_fstat(fd, path, name)
        if max_bytes is not None and first[2] > max_bytes:
            raise ValueError(f"{name} {path} is too large; max {max_bytes} bytes")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            text = handle.read(max_bytes + 1 if max_bytes is not None else -1)
            if max_bytes is not None and len(text) > max_bytes:
                raise ValueError(f"{name} {path} is too large; max {max_bytes} bytes")
            second = _validate_fstat(handle.fileno(), path, name)
        if second != first:
            raise ValueError(f"{name} {path} changed while being read")
        return PrivateTextFile(text=text, fingerprint=second)
    finally:
        if fd >= 0:
            os.close(fd)


def write_new_private_text_file(
    raw_path: str | os.PathLike[str],
    text: str,
    name: str,
) -> None:
    """Create and durably flush a new 0600 current-user-owned regular text file."""

    path = Path(raw_path).expanduser()
    _validate_parent(path, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise ValueError(f"{name} {path} already exists") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{name} {path} must not be a symlink") from None
        raise ValueError(f"{name} {path} is not writable: {exc}") from None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        _validate_fstat(fd, path, name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            try:
                handle.write(text)
                if not text.endswith("\n"):
                    handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                raise ValueError(f"{name} {path} is not writable: {exc}") from None
        _fsync_parent_dir(path, name)
    finally:
        if fd >= 0:
            os.close(fd)


def _fsync_parent_dir(path: Path, name: str) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path.parent, flags)
    except OSError as exc:
        if exc.errno in _UNSUPPORTED_DIR_FSYNC_ERRNOS:
            return
        raise ValueError(f"{name} parent {path.parent} is not flushable: {exc}") from None
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno in _UNSUPPORTED_DIR_FSYNC_ERRNOS:
                return
            raise ValueError(f"{name} parent {path.parent} is not flushable: {exc}") from None
    finally:
        os.close(fd)


def _validate_parent(path: Path, name: str) -> None:
    parent = path.parent
    try:
        st = parent.stat()
    except OSError as exc:
        raise ValueError(f"{name} parent {parent} is not readable: {exc}") from None
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{name} parent {parent} must be a directory")
    if os.name != "nt" and st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{name} parent {parent} must not be group- or world-writable")
    if os.name != "nt" and st.st_uid not in (0, os.geteuid()):
        raise ValueError(f"{name} parent {parent} must be owned by this user or root")


def _validate_lstat(path: Path, name: str) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise ValueError(f"{name} {path} is not readable: {exc}") from None
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{name} {path} must not be a symlink")
    _validate_stat(st, path, name)


def _validate_fstat(fd: int, path: Path, name: str) -> PrivateFileFingerprint:
    try:
        st = os.fstat(fd)
    except OSError as exc:
        raise ValueError(f"{name} {path} is not readable: {exc}") from None
    _validate_stat(st, path, name)
    return _fingerprint(st)


def _validate_stat(st: os.stat_result, path: Path, name: str) -> None:
    mode = st.st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"{name} {path} must be a regular file")
    if os.name != "nt" and st.st_uid != os.geteuid():
        raise ValueError(f"{name} {path} must be owned by this user")
    if os.name != "nt" and mode & 0o077:
        raise ValueError(f"{name} {path} must be readable only by its owner (chmod 600)")


def _fingerprint(st: os.stat_result) -> PrivateFileFingerprint:
    return (
        st.st_dev,
        st.st_ino,
        st.st_size,
        st.st_mtime_ns,
        stat.S_IMODE(st.st_mode),
    )
