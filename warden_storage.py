"""POSIX trust checks for the Warden control policy and its SQLite audit files."""

from collections import deque
import os
from pathlib import Path
import sqlite3
import stat


MAX_POLICY = 1024 * 1024
_SIDECARS = ("-journal", "-wal", "-shm")


def trusted_path(path):
    """Resolve only trusted directory entries. A sticky shared ancestor may contain a private directory."""
    path = Path(path).absolute()
    parent = path.parent
    parts = deque(parent.parts[1:])
    current = Path(parent.anchor)
    links = 0
    owners = {0, os.geteuid()}
    while parts:
        name = parts.popleft()
        if name == "..":
            current = current.parent
            continue
        candidate = current / name
        info = candidate.lstat()
        if info.st_uid not in owners:
            raise PermissionError("控制服务路径经过其他账户拥有的目录")
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40:
                raise PermissionError("控制服务路径中的符号链接过多")
            target = candidate.readlink()
            if target.is_absolute():
                current = Path(target.anchor)
                parts.extendleft(reversed(target.parts[1:]))
            else:
                parts.extendleft(reversed(target.parts))
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise NotADirectoryError(candidate)
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise PermissionError("控制服务路径经过其他账户可写的目录")
        current = candidate
    if current.stat().st_mode & 0o022:
        # A shared directory could pre-create a SQLite sidecar or an administration lock.
        raise PermissionError("策略和审计文件须放在其他账户不可写的目录")
    return current / path.name


def _file(info, *, private):
    mask = 0o077 if private else 0o022
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & mask):
        raise PermissionError("控制服务文件类型、属主或权限不安全")


def read_policy_bytes(path):
    path = trusted_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(fd)
        _file(info, private=False)
        raw = source.read(MAX_POLICY + 1)
        if len(raw) > MAX_POLICY:
            raise ValueError("控制策略超过 1 MiB")
        return raw, info


def open_policy_lock(path):
    fd = os.open(str(path) + ".admin.lock",
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, 0o600)
    try:
        _file(os.fstat(fd), private=True)
        return os.fdopen(fd, "r+b")
    except BaseException:
        os.close(fd)
        raise


def open_audit(path, *, create=False, readonly=False):
    """Only the control server creates the main DB. Validate sidecars before SQLite can open them."""
    path = trusted_path(path)
    sidecar_found = False
    for suffix in _SIDECARS:
        try:
            info = path.with_name(path.name + suffix).lstat()
        except FileNotFoundError:
            continue  # SQLite may remove a transient journal concurrently.
        _file(info, private=True)
        sidecar_found = True
    try:
        info = path.lstat()
    except FileNotFoundError:
        if sidecar_found:
            raise PermissionError("缺少审计主库，但目录中仍有 SQLite 副文件") from None
        if not create:
            raise
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass  # A concurrent authorized starter may have initialized it.
        else:
            os.close(fd)
        info = path.lstat()
    _file(info, private=True)
    mode = "ro" if readonly else "rw"
    return sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True, timeout=2)
