"""Trusted Warden adapter for the versioned Rust plugin runtime."""

import asyncio
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from warden_control import _object
from warden_storage import trusted_path
from web_demo import ROOT, core_binary


def add_runtime_arguments(parser):
    parser.add_argument("--plugin-manifest", type=Path, action="append", default=[],
                        help="管理员部署的 v1 插件清单，可重复指定")
    parser.add_argument("--core", type=Path, help="同版本的受信 Rust 核心")


def trusted_json(path, limit=1024 * 1024):
    fd = os.open(trusted_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o022):
            raise ValueError("插件配置须由管理员或当前账户拥有，且其他用户不可修改")
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("插件配置超出大小限制")
        return json.loads(data, object_pairs_hook=_object)


class PluginRuntime:
    def __init__(self, manifests=(), core=None):
        if len(manifests) > 64:
            raise ValueError("最多允许 64 个外部插件")
        built = ROOT / "rust-core" / "target" / "release" / "agent-access-core"
        self.binary = core_binary(core or (built if built.is_file() else None))
        self.manifests = [trusted_json(p, 4096) for p in manifests]
        plugins = self.call({"op": "catalog"})
        self.plugins = {p["id"]: p for p in plugins}
        self.actions = {p["id"]: p["action"] for p in plugins if not p["legacy"]}

    def _request(self, command):
        body = json.dumps({"api_version": 1, "manifests": self.manifests, "command": command},
                          default=os.fspath, allow_nan=False).encode()
        if len(body) > 512 * 1024:
            raise ValueError("插件请求过大")
        return body

    @staticmethod
    def _result(returncode, data):
        if returncode or not data or len(data) > 2 * 1024 * 1024:
            raise RuntimeError("Rust 插件核心不可用，请重新构建或用 --core 指定同版本程序")
        reply = json.loads(data, object_pairs_hook=_object)
        if isinstance(reply, dict) and set(reply) == {"result"}:
            return reply["result"]
        if reply == {"error": "denied"}:
            raise PermissionError("Rust 核心拒绝插件操作")
        if reply == {"error": "invalid"}:
            raise ValueError("Rust 核心拒绝了插件清单或资源配置")
        raise RuntimeError("插件执行未完成")

    def call(self, command):
        try:
            result = subprocess.run([self.binary, "plugins-v1"], input=self._request(command),
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3,
                                    env={"PATH": os.defpath})
        except subprocess.TimeoutExpired:
            raise RuntimeError("Rust 插件核心响应超时") from None
        return self._result(result.returncode, result.stdout)

    async def read(self, request, grant, spec, deadline):
        timeout_ms = min(10_000, int((deadline - time.monotonic()) * 1000))
        if timeout_ms < 1:
            raise PermissionError("插件授权已到期")
        payload = self._request({"op": "read", "request": request, "grant": grant,
                                 "target": spec, "timeout_ms": timeout_ms})
        proc = await asyncio.create_subprocess_exec(
            self.binary, "plugins-v1", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env={"PATH": os.defpath})
        try:
            async with asyncio.timeout(timeout_ms / 1000):
                data, _ = await proc.communicate(payload)
            return self._result(proc.returncode, data)
        finally:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.communicate()
