"""Trusted target configuration for native database sessions."""

import os
import re
import ssl
import stat


PORTS = {"postgresql": 5432, "mysql": 3306, "sqlserver": 1433}


def upstream_tls(target):
    # Keep host environment settings such as SSLKEYLOGFILE away from database secrets.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if target.get("ca_file"):
        ctx.load_verify_locations(cafile=target["ca_file"])
    else:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return ctx


def targets(entries, base):
    if not isinstance(entries, dict) or not entries:
        raise ValueError("databases 需要至少一个命名目标")
    required = {"engine", "host", "database", "user"}
    allowed = required | {"port", "max_ttl", "ca_file", "password_file", "password_ref"}
    result = {}
    for alias, config in entries.items():
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", alias):
            raise ValueError("数据库别名无效")
        if not isinstance(config, dict) or not required <= config.keys() <= allowed:
            raise ValueError(f"{alias} 的数据库配置字段不完整或无法识别")
        source = {"password_file", "password_ref"} & config.keys()
        if len(source) != 1:
            raise ValueError(f"{alias} 需要唯一的数据库口令来源")
        target = config.copy()
        for key in required | source | ({"ca_file"} & target.keys()):
            value = target[key]
            if not isinstance(value, str) or not value.strip() or not value.isprintable():
                raise ValueError(f"{alias} 的 {key} 应为非空文本")
        if target["engine"] not in PORTS:
            raise ValueError(f"{alias} 的数据库类型不受支持")
        if not re.fullmatch(r"[A-Za-z0-9:.\-]+", target["host"]):
            raise ValueError(f"{alias} 的 host 需要 DNS 主机名或 IP 地址")
        for key, default, limit in (("port", PORTS[target["engine"]], 65535), ("max_ttl", 300, 900)):
            value = target.setdefault(key, default)
            if type(value) is not int or not 1 <= value <= limit:
                raise ValueError(f"{alias} 的 {key} 应在 1 至 {limit} 之间")
        for key in ("password_file", "ca_file"):
            if key in target:
                target[key] = str(base / target[key])
        result[alias] = target
    return result


def read_password(target):
    if "password_ref" in target:
        raw = target["_read_secret"]()
    else:
        raw = _read_private_file(target["password_file"])
    if len(raw) > 8192:
        raise ValueError("数据库凭据超出大小限制")
    password = raw.decode()
    if "password_ref" not in target:
        password = password.removesuffix("\n").removesuffix("\r")
    if not password or "\0" in password:
        raise ValueError("数据库凭据为空或格式无效")
    return password


def _read_private_file(path):
    # Check the opened inode so secret managers can rotate the file atomically.
    fd = os.open(path, os.O_NONBLOCK | os.O_RDONLY)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid not in {0, os.geteuid()}):
            raise ValueError("数据库凭据须来自受信账户独占的文件")
        return source.read(8193)
