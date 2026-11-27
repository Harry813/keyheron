"""Encrypted upstream credentials. Only the trusted launcher may hold an unlocked Store."""

import base64
from contextlib import closing, contextmanager
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import tempfile

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:
    raise RuntimeError("加密凭据库需要安装 requirements-credentials.txt 中的依赖") from None


_PREFIX = b"KeyHeron/v1/"
_MAX_BYTES = 16384


def reference(env, name):
    if (env not in ("DEV", "STG", "PROD") or not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name)):
        raise ValueError("无效的环境或凭据名称")
    return f"{env}/{name}"


def _derive(passphrase, salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=131072).derive(passphrase)


@contextmanager
def _database(path, write=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
            or info.st_uid not in (0, os.geteuid())):
        raise ValueError("凭据库须为受信账户独占的普通文件")
    mode = "rw" if write else "ro"
    try:
        with closing(sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True, timeout=5)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            if write:
                db.commit()
    except sqlite3.Error:
        raise ValueError("加密凭据库无法读取或写入") from None


def _meta(db):
    row = db.execute("SELECT version, salt, nonce, verifier FROM vault_meta WHERE id=1").fetchone()
    if (row is None or row[0] != 1 or not all(isinstance(v, bytes) for v in row[1:])
            or tuple(map(len, row[1:])) != (16, 12, 16)):
        raise ValueError("加密凭据库格式无效")
    return row


def initialize(path, passphrase: bytes) -> None:
    if not isinstance(passphrase, bytes) or len(passphrase) < 16:
        raise ValueError("新凭据库的主口令至少需要 16 字节")
    path = Path(path).absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.path.lexists(path):
        raise FileExistsError("凭据库已存在")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    master = _derive(passphrase, salt)
    verifier = AESGCM(master).encrypt(nonce, b"", _PREFIX + b"check\0" + salt)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".keyheron-init-")
    tmp = Path(name)
    os.close(fd)
    try:
        with _database(tmp, write=True) as db:
            db.execute("""CREATE TABLE vault_meta (
                id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL,
                salt BLOB NOT NULL, nonce BLOB NOT NULL, verifier BLOB NOT NULL)""")
            db.execute("""CREATE TABLE vault_credentials (
                ref TEXT PRIMARY KEY NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)""")
            db.execute("INSERT INTO vault_meta VALUES (1,1,?,?,?)", (salt, nonce, verifier))
        # Publish a complete 0600 file atomically; another initializer wins without being overwritten.
        os.link(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def vault_identity(path):
    """The vault header stays stable when individual credential entries rotate."""
    with _database(Path(path).absolute()) as db:
        return _meta(db)


def unlock(path, passphrase: bytes):
    if not isinstance(passphrase, bytes) or not passphrase:
        raise ValueError("需要凭据库主口令")
    path = Path(path).absolute()
    metadata = vault_identity(path)
    _, salt, nonce, verifier = metadata
    master = _derive(passphrase, salt)
    try:
        AESGCM(master).decrypt(nonce, verifier, _PREFIX + b"check\0" + salt)
    except InvalidTag:
        raise ValueError("主口令或凭据库认证失败") from None
    return Store(path, metadata, master)


class _Binding(dict):
    # json.dumps() deliberately retains the key for the private pipe to the trusted core.
    def __repr__(self):
        return "<private credential binding>"


def _check_store(db, metadata):
    if _meta(db) != metadata:
        raise ValueError("凭据库身份已改变，请重新解锁")


def _entry(path, metadata, ref):
    with _database(path) as db:
        _check_store(db, metadata)
        row = db.execute("""SELECT nonce, ciphertext FROM vault_credentials
            WHERE ref=? AND typeof(nonce)='blob' AND length(nonce)=12
                AND typeof(ciphertext)='blob' AND length(ciphertext) BETWEEN 17 AND 16400""", (ref,)).fetchone()
    if row is None:
        raise ValueError("凭据不存在或格式无效")
    return row


class Store:
    def __init__(self, path, metadata, master):
        self._path = path
        self._metadata = metadata
        self._master = master

    def _key_and_aad(self, ref):
        identity = self._metadata[1] + b"\0" + ref.encode("ascii")
        key = hmac.digest(self._master, _PREFIX + b"key\0" + identity, "sha256")
        return key, _PREFIX + b"credential\0" + identity

    def put(self, env, name, value: bytes) -> None:
        ref = reference(env, name)
        if not isinstance(value, bytes) or not 1 <= len(value) <= _MAX_BYTES:
            raise ValueError("凭据长度须为 1 至 16384 字节")
        key, aad = self._key_and_aad(ref)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, value, aad)
        with _database(self._path, write=True) as db:
            _check_store(db, self._metadata)
            db.execute("""INSERT INTO vault_credentials(ref, nonce, ciphertext) VALUES (?,?,?)
                       ON CONFLICT(ref) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext""",
                       (ref, nonce, ciphertext))

    def reader(self, env, name):
        """Hand off a rotating single-entry reader without retaining the vault master key."""
        ref = reference(env, name)
        key, aad = self._key_and_aad(ref)
        path, metadata = self._path, self._metadata

        def read():
            nonce, ciphertext = _entry(path, metadata, ref)
            try:
                return AESGCM(key).decrypt(nonce, ciphertext, aad)
            except InvalidTag:
                raise ValueError("凭据密文认证失败") from None

        return read

    def get(self, env, name) -> bytes:
        return self.reader(env, name)()

    def binding(self, env, name) -> dict:
        ref = reference(env, name)
        _entry(self._path, self._metadata, ref)
        key, _ = self._key_and_aad(ref)
        return _Binding(db=str(self._path), ref=ref, salt=base64.b64encode(self._metadata[1]).decode("ascii"),
                        key=base64.b64encode(key).decode("ascii"))
