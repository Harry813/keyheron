"""Operator-only input for the encrypted credential store."""

import getpass
import hmac
import os
from pathlib import Path
import stat
import sys
import warnings


MAX_PASSPHRASE = 4096
MAX_SECRET = 16384


def register(subparsers):
    parser = subparsers.add_parser("secrets", help="管理加密凭据库")
    commands = parser.add_subparsers(dest="secret_command", required=True)
    init = commands.add_parser("init", help="初始化新的加密凭据库")
    put = commands.add_parser("put", help="写入或更新一个环境的凭据")
    for command in (init, put):
        command.add_argument("--store", type=Path, required=True, help="加密凭据库路径")
        command.add_argument("--passphrase-file", type=Path, help="可信宿主提供的私有解锁口令文件")
    put.add_argument("--env", choices=("DEV", "STG", "PROD"), required=True)
    put.add_argument("--name", required=True, help="策略引用的凭据名称")
    put.add_argument("--stdin", action="store_true", help="从管道或重定向文件读取一个凭据")


def _hidden(prompt):
    # getpass prefers /dev/tty. Make an echo-enabled fallback fail before it reads input.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt).encode("utf-8")
        except (getpass.GetPassWarning, EOFError, UnicodeError):
            raise ValueError("需要支持无回显输入的终端，或指定私有文件或管道") from None


def _read_text(stream, maximum):
    # Preserve spaces and intentional content; remove one transport line ending.
    raw = stream.read(maximum + 3)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    else:
        raw = raw.removesuffix(b"\n")
    if not 1 <= len(raw) <= maximum or b"\0" in raw:
        raise ValueError("输入内容为空、含空字符或超出长度限制")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("输入内容必须使用 UTF-8 编码") from None
    return raw


def load_passphrase(passphrase_file=None, *, confirm=False):
    if passphrase_file is None:
        value = _hidden("凭据库解锁口令：")
        if not 1 <= len(value) <= MAX_PASSPHRASE or b"\0" in value:
            raise ValueError("解锁口令为空、含空字符或超出长度限制")
        if confirm and not hmac.compare_digest(value, _hidden("再次输入解锁口令：")):
            raise ValueError("两次输入的解锁口令不同")
    else:
        fd = os.open(passphrase_file, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}):
                raise ValueError("解锁口令文件须属于当前账户或 root，权限为 0400 或 0600")
            value = _read_text(source, MAX_PASSPHRASE)
    if confirm and len(value) < 16:
        raise ValueError("新凭据库的解锁口令至少需要 16 个 UTF-8 字节")
    return value


def run(args):
    from credential_store import initialize, unlock

    creating = args.secret_command == "init"
    passphrase = load_passphrase(args.passphrase_file, confirm=creating)
    if creating:
        initialize(args.store, passphrase)
        print("加密凭据库已初始化。")
        return 0
    store = unlock(args.store, passphrase)
    if args.stdin:
        if sys.stdin.isatty():
            raise ValueError("--stdin 需要管道或文件重定向；交互输入请省略此参数")
        value = _read_text(sys.stdin.buffer, MAX_SECRET)
    else:
        value = _hidden("需要保存的上游凭据：")
        if not 1 <= len(value) <= MAX_SECRET or b"\0" in value:
            raise ValueError("凭据为空、含空字符或超出长度限制")
    store.put(args.env, args.name, value)
    print("凭据已加密保存。")
    return 0
