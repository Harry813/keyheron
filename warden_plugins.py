"""Trusted, task-scoped Warden connectors. Agent inputs select names, never destinations."""

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from agent_access import load_config, unlock_policy_store
from dbproxy import read_password
from plugin_runtime import PluginRuntime, trusted_json
from dbproxy.session import database_audit, run_session
from warden_control import FIELDS, valid_id


DB_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MAX_SESSIONS = 16
CHECK_INTERVAL = 1.0


def _gitlab_paths(spec):
    fields = {"origin", "project", "iid", "token_file"}
    if not fields <= spec.keys() <= fields | {"ca_file"}:
        raise ValueError("GitLab 资源需要 origin、project、iid 和 token_file")
    if any(type(spec[k]) is not int or spec[k] <= 0 for k in ("project", "iid")):
        raise ValueError("GitLab 项目和 MR 需要正整数 ID")
    if not isinstance(spec["origin"], str) or not spec["origin"].isprintable():
        raise ValueError("GitLab 需要固定的 HTTPS origin")
    origin = urlsplit(spec["origin"])
    if (origin.scheme != "https" or not origin.hostname or origin.username is not None
            or origin.password is not None or origin.path not in ("", "/")
            or origin.query or origin.fragment or origin.port == 0):
        raise ValueError("GitLab 需要固定的 HTTPS origin")
    return {"token_file", "ca_file"} & spec.keys()


def _database_paths(spec):
    if (spec.keys() != {"config", "env", "target"} or spec["env"] not in ("DEV", "STG", "PROD")
            or not isinstance(spec["target"], str) or not DB_TARGET.fullmatch(spec["target"])):
        raise ValueError("数据库资源需要 config、env 和固定 target")
    return {"config"}


def _json_paths(spec):
    fields = {"origin", "path", "fields"}
    if not fields <= spec.keys() <= fields | {"token_file", "ca_file"}:
        raise ValueError("HTTPS JSON 资源需要 origin、path 和 fields")
    return {"token_file", "ca_file"} & spec.keys()


def _load_catalog(path, runtime):
    base = path.absolute().parent
    catalog = trusted_json(path)
    if not isinstance(catalog, dict) or catalog.keys() - runtime.plugins.keys():
        raise ValueError("连接器目录含有未知插件")
    for name, resources in catalog.items():
        if not isinstance(resources, dict):
            raise ValueError("连接器资源应为命名对象")
        for alias, spec in resources.items():
            if not valid_id(alias) or not isinstance(spec, dict):
                raise ValueError("连接器资源名或配置无效")
            plugin = runtime.plugins[name]
            if plugin["native_stream"]:
                paths = _database_paths(spec)
            elif plugin["driver"] == "gitlab":
                paths = _gitlab_paths(spec)
            elif plugin["driver"] == "https-json":
                paths = _json_paths(spec)
            else:
                raise ValueError("当前 Warden 不支持此驱动")
            for key in paths:
                if not isinstance(spec[key], str) or not spec[key].strip():
                    raise ValueError("连接器资源需要非空文件路径")
                spec[key] = base / spec[key]
    return catalog


def _database_target(spec, runtime, request, grant):
    policy = load_config(spec["config"], database=True, read_json=trusted_json)
    target = policy["environments"][spec["env"]][spec["target"]]
    # Check the same target object passed to the broker, before touching its credentials.
    plan = runtime.call({"op": "open_database", "request": request, "grant": grant,
                         "actual_engine": target["engine"]})
    if plan != {"driver": target["engine"]}:
        raise PermissionError("数据库目标与授权的引擎不匹配")
    if "password_ref" in target:
        if not policy.get("credential_store", {}).get("passphrase_file"):
            raise ValueError("无人值守的 Warden 需要凭据库解锁文件")
        target["_read_secret"] = unlock_policy_store(policy).reader(spec["env"], target["password_ref"])
    read_password(target)
    if target.get("ca_file") and not Path(target["ca_file"]).is_file():
        raise ValueError("数据库 CA 文件不可用")
    return target, policy["identities"]["applicant"]


@dataclass
class _DatabaseSession:
    operation: tuple
    stop: asyncio.Event
    ready: asyncio.Future
    worker: asyncio.Task


class PluginHost:
    def __init__(self, config_path, state_dir, task, authorize, event, runtime=None):
        self.runtime = runtime or PluginRuntime()
        self.catalog = _load_catalog(Path(config_path), self.runtime)
        self.state_dir = Path(state_dir).resolve()
        self.task = task
        self.authorize = authorize
        self.event = event
        self.sessions = {}
        self.running = False

    async def __aenter__(self):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Warden 状态目录须由当前账户独占")
        self.running = True
        return self

    async def __aexit__(self, *_):
        self.running = False
        sessions = list(self.sessions.values())
        for session in sessions:
            session.stop.set()
        await asyncio.gather(*(session.worker for session in sessions), return_exceptions=True)

    def available(self, connector, action, resource):
        plugin = self.runtime.plugins.get(connector)
        return bool(plugin and plugin["action"] == action and resource in self.catalog.get(connector, {}))

    async def _grant(self, operation):
        started = time.monotonic()
        grant = await asyncio.to_thread(self.authorize, self.task, *operation)
        expected = dict(zip(FIELDS, (self.task, *operation)))
        ttl = grant.get("ttl")
        if (grant.get("scope") != expected or type(ttl) is not int or not 1 <= ttl <= 900
                or started + ttl <= time.monotonic()):
            raise PermissionError("操作未获有效授权")
        return started + ttl, grant["scope"]

    async def _event(self, operation, result):
        await asyncio.to_thread(self.event, self.task, *operation, result)

    async def invoke(self, connector, action, resource):
        operation = (connector, action, resource)
        if not self.running:
            raise RuntimeError("连接器服务未启动")
        deadline, grant = await self._grant(operation)
        try:
            if not self.available(*operation):
                raise PermissionError("Warden 未配置此连接器操作")
            spec = self.catalog[connector][resource]
            async with asyncio.timeout(deadline - time.monotonic()):
                request = dict(zip(FIELDS, (self.task, *operation)))
                if self.runtime.plugins[connector]["native_stream"]:
                    return await self._open_database(operation, spec, deadline, request, grant)
                result = await self.runtime.read(request, grant, spec, deadline)
                await self._grant(operation)
                await self._event(operation, "succeeded")
                return result
        except Exception as exc:
            with suppress(Exception):
                await self._event(operation, "failed")
            if isinstance(exc, PermissionError):
                raise PermissionError("操作未获授权") from None
            raise RuntimeError("连接器操作未完成") from None

    async def _watch(self, operation, deadline, stop):
        try:
            while not stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(CHECK_INTERVAL, remaining))
                async with asyncio.timeout(min(CHECK_INTERVAL, deadline - time.monotonic())):
                    renewed_deadline, _ = await self._grant(operation)
                    deadline = min(deadline, renewed_deadline)
        except Exception:
            # Denial, timeout and control-plane failure all terminate the live native stream.
            pass
        finally:
            stop.set()

    async def _open_database(self, operation, spec, deadline, request, grant):
        if not self.running or len(self.sessions) >= MAX_SESSIONS:
            raise RuntimeError("数据库会话不可用")
        session_id = uuid.uuid4().hex
        stop = asyncio.Event()
        ready = asyncio.get_running_loop().create_future()
        serving = asyncio.create_task(self._serve_database(operation, spec, session_id, stop, ready, deadline, request, grant))
        self.sessions[session_id] = _DatabaseSession(operation, stop, ready, serving)
        try:
            done, _ = await asyncio.wait((ready, serving), return_when=asyncio.FIRST_COMPLETED)
            if serving in done:
                await serving
                raise RuntimeError("数据库会话已结束")
            result = dict(ready.result())
            await self._event(operation, "succeeded")
            if stop.is_set() or serving.done():
                raise RuntimeError("数据库会话已结束")
            return result
        except BaseException:
            stop.set()
            await asyncio.gather(serving, return_exceptions=True)
            raise

    async def _serve_database(self, operation, spec, session_id, stop, ready, deadline, request, grant):
        watch = asyncio.create_task(self._watch(operation, deadline, stop))
        try:
            target, actor = await asyncio.to_thread(_database_target, spec, self.runtime, request, grant)
            ttl = min(target["max_ttl"], deadline - time.monotonic())
            if stop.is_set() or ttl <= 0:
                return

            def publish(info):
                result = {**info, "session_id": session_id}
                for field, public in (("ca_file", "ca_pem"), ("server_certificate", "server_certificate_pem")):
                    if field in result:
                        result[public] = Path(result.pop(field)).read_text()
                ready.set_result(result)

            with (tempfile.TemporaryDirectory(prefix="db-", dir=self.state_dir) as temporary,
                  database_audit(self.state_dir / "db-events.sqlite3", session_id, self.task, actor,
                                 spec["env"], spec["target"], target["engine"]) as record):
                await run_session(target, ttl, Path(temporary), record, stop, on_ready=publish)
        finally:
            stop.set()
            watch.cancel()
            await asyncio.gather(watch, return_exceptions=True)
            try:
                if ready.done():
                    with suppress(Exception):
                        await self._event(operation, "closed")
            finally:
                self.sessions.pop(session_id, None)

    async def open_database_stream(self, descriptor):
        session_id = descriptor["session_id"]
        session = self.sessions.get(session_id)
        if not session or session.stop.is_set() or not session.ready.done():
            raise PermissionError("数据库会话已结束")
        try:
            await self._grant(session.operation)
        except Exception:
            session.stop.set()
            raise
        if session.stop.is_set():
            raise PermissionError("数据库会话已结束")
        port = session.ready.result()["port"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        if self.sessions.get(session_id) is not session or session.stop.is_set():
            writer.close()
            await writer.wait_closed()
            raise PermissionError("数据库会话已结束")
        return reader, writer

    async def close_database(self, descriptor):
        session = self.sessions.get(descriptor["session_id"])
        if session:
            session.stop.set()
            await asyncio.shield(session.worker)

    async def wait_database_closed(self, descriptor):
        session = self.sessions.get(descriptor["session_id"])
        if session:
            await session.stop.wait()
