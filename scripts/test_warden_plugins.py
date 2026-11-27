"""Connector grants, fixed GitLab destination and revocation of native database streams."""

import asyncio
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dbproxy.session import local_tls
from warden_client import serve_one_database
from warden_control import ControlBusy
from warden_plugins import PluginHost


class WardenPlugins(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.secret = self.root / "secret"
        self.secret.write_text("synthetic-secret\n")
        self.secret.chmod(0o600)
        self.target = {"host": "localhost", "engine": "mysql", "database": "orders", "user": "reporter",
                       "password_file": "secret", "max_ttl": 20}
        (self.root / "db.json").write_text(json.dumps({
            "version": 1, "task": "db-diagnostics", "identities": {"applicant": "operator", "approver": "owner"},
            "environments": {"DEV": {"databases": {"orders-mysql": self.target}}}
        }))
        self.config = {"mysql": {"orders": {"config": "db.json", "env": "DEV", "target": "orders-mysql"}}}
        self.events = []
        self.allowed = True

    def grant(self, task, connector, action, resource):
        if not self.allowed:
            raise PermissionError
        return {"scope": dict(task=task, connector=connector, action=action, resource=resource), "ttl": 30}

    def host(self):
        path = self.root / "plugins.json"
        path.write_text(json.dumps(self.config))
        return PluginHost(path, self.root / "warden", "review", self.grant,
                          lambda *args: self.events.append(args))

    def test_catalog_uses_control_names_and_rejects_duplicate_keys(self):
        alias = "orders:" + "a" * 120
        self.config["mysql"][alias] = self.config["mysql"].pop("orders")
        self.assertTrue(self.host().available("mysql", "connect", alias))
        path = self.root / "duplicate.json"
        path.write_text('{"database":{},"database":{}}')
        with self.assertRaises(ValueError):
            PluginHost(path, self.root / "warden", "review", self.grant, lambda *_: None)

    async def test_writable_catalog_or_target_cannot_supply_credentials(self):
        path = self.root / "plugins.json"
        path.write_text(json.dumps(self.config))
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            PluginHost(path, self.root / "warden", "review", self.grant, lambda *_: None)
        path.chmod(0o600)
        (self.root / "db.json").chmod(0o666)
        with patch("warden_plugins.read_password") as read:
            async with self.host() as host:
                with self.assertRaises(RuntimeError):
                    await host.invoke("mysql", "connect", "orders")
            read.assert_not_called()

    async def test_ungranted_and_unknown_do_not_use_upstream(self):
        with patch("warden_plugins._database_target") as prepare:
            async with self.host() as host:
                self.assertTrue(host.available("mysql", "connect", "orders"))
                for action, resource in (("exec", "orders"), ("connect", "other")):
                    self.assertFalse(host.available("mysql", action, resource))
                    with self.assertRaises(PermissionError):
                        await host.invoke("mysql", action, resource)
                self.allowed = False
                with self.assertRaises(PermissionError):
                    await host.invoke("mysql", "connect", "orders")
                prepare.assert_not_called()

    async def test_engine_grants_are_independent_even_for_the_same_alias(self):
        engines = ("postgresql", "mysql", "sqlserver")
        db_file = self.root / "db.json"
        db_config = json.loads(db_file.read_text())
        targets = db_config["environments"]["DEV"]["databases"]
        runtime = self.host().runtime
        for engine in engines:
            target = f"orders-{engine}"
            targets[target] = {**self.target, "engine": engine}
            self.config[engine] = {"orders": {"config": "db.json", "env": "DEV", "target": target}}
            self.assertEqual(runtime.actions[engine], "connect")
            self.assertTrue(runtime.plugins[engine]["native_stream"])
        db_file.write_text(json.dumps(db_config))
        self.assertFalse(runtime.plugins["gitlab"]["native_stream"])
        self.assertNotIn("database", runtime.actions)
        self.assertTrue(runtime.plugins["database"]["native_stream"])

        async def session(target, ttl, directory, record, stop, *, on_ready):
            on_ready({"engine": target["engine"]})
            await stop.wait()

        def grant(task, connector, action, resource):
            if (task, connector, action, resource) != ("review", allowed, "connect", "orders"):
                raise PermissionError
            return {"scope": dict(task=task, connector=connector, action=action, resource=resource), "ttl": 10}

        with patch("warden_plugins.run_session", side_effect=session) as broker:
            async with self.host() as host:
                host.authorize = grant
                for allowed in engines:
                    for requested in engines:
                        if requested == allowed:
                            descriptor = await host.invoke(allowed, "connect", "orders")
                            self.assertEqual(descriptor["engine"], allowed)
                            await host.close_database(descriptor)
                        else:
                            with self.assertRaises(PermissionError):
                                await host.invoke(requested, "connect", "orders")
                allowed = "database"
                with self.assertRaises(PermissionError):
                    await host.invoke("database", "connect", "orders")
            self.assertEqual(broker.await_count, 3)

        self.config["database"] = self.config["mysql"]
        async with self.host() as host:
            host.authorize = grant
            with self.assertRaises(PermissionError):
                await host.invoke("mysql", "connect", "orders")
            legacy = await host.invoke("database", "connect", "orders")
            self.assertEqual(legacy["engine"], "mysql")
            await host.close_database(legacy)

    async def test_changed_engine_is_denied_before_credentials_or_listener(self):
        async with self.host() as host:
            # The Warden keeps its catalog while the operator replaces the target policy.
            db_file = self.root / "db.json"
            config = json.loads(db_file.read_text())
            target = config["environments"]["DEV"]["databases"]["orders-mysql"]
            target["engine"] = "postgresql"
            del target["password_file"]
            target["password_ref"] = "new-role"
            config["credential_store"] = {"path": "vault", "passphrase_file": "unlock"}
            db_file.write_text(json.dumps(config))
            with (patch("warden_plugins.read_password") as password,
                  patch("warden_plugins.unlock_policy_store") as unlock,
                  patch("warden_plugins.run_session") as broker):
                with self.assertRaises(PermissionError):
                    await host.invoke("mysql", "connect", "orders")
                password.assert_not_called()
                unlock.assert_not_called()
                broker.assert_not_called()
            self.assertFalse(host.sessions)
            self.assertEqual(self.events, [("review", "mysql", "connect", "orders", "failed")])

    async def test_revoke_open_stream_and_release(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()

        async with await asyncio.start_server(echo, "127.0.0.1", 0) as upstream:
            async def login(reader, writer, target, password):
                self.assertEqual(await reader.readline(), password.encode() + b"\n")
                return await asyncio.open_connection("127.0.0.1", upstream.sockets[0].getsockname()[1])

            with patch("dbproxy.mysql.authenticate", login), patch("warden_plugins.CHECK_INTERVAL", 0.1):
                async with self.host() as host:
                    info = await host.invoke("mysql", "connect", "orders")
                    self.assertNotIn("synthetic-secret", json.dumps(info))
                    self.assertFalse(list(self.root.rglob("connection.json")))
                    with patch("warden_plugins.MAX_SESSIONS", 1), self.assertRaises(RuntimeError):
                        await host.invoke("mysql", "connect", "orders")
                    host.session_grant = self.grant
                    actual_port = info["port"]
                    info.update(port=1, host="untrusted.invalid")
                    reader, writer = await host.open_database_stream(info)
                    def ordinary_busy(*_):
                        raise ControlBusy("ordinary budget exhausted")

                    host.authorize = ordinary_busy
                    with self.assertRaises(ControlBusy):
                        await host.open_database_stream(info)
                    self.assertFalse(host.sessions[info["session_id"]].stop.is_set())
                    ping = b"\x01\x00\x00\x00\x0e"  # Classic COM_PING frame
                    writer.write(info["password"].encode() + b"\n" + ping)
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(len(ping)), 2), ping)
                    self.allowed = False
                    self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
                    writer.close()
                    await writer.wait_closed()
                    with self.assertRaises(PermissionError):
                        await host.open_database_stream(info)
                    with self.assertRaises(OSError):
                        await asyncio.open_connection("127.0.0.1", actual_port)
                    await host.close_database(info)
        self.assertIn(("review", "mysql", "connect", "orders", "succeeded"), self.events)
        self.assertIn(("review", "mysql", "connect", "orders", "closed"), self.events)
        with closing(sqlite3.connect(self.root / "warden" / "db-events.sqlite3")) as db:
            actions = db.execute("SELECT action FROM database_events WHERE task='review'").fetchall()
            self.assertIn(("connect",), actions)
            self.assertIn(("close",), actions)

    async def test_no_descriptor_if_audit_fails(self):
        async with self.host() as host:
            def broken_event(*args):
                raise OSError("internal-only")
            host.event = broken_event
            with self.assertRaisesRegex(RuntimeError, "^连接器操作未完成$"):
                await host.invoke("mysql", "connect", "orders")
            self.assertFalse(host.sessions)

    async def test_full_watchdog_pool_keeps_allowed_sessions_and_observes_revocation(self):
        seen = set()
        lock = threading.Lock()
        all_checked = threading.Event()
        revoke_first = threading.Event()
        stops = [asyncio.Event() for _ in range(16)]

        def check(task, connector, action, resource):
            time.sleep(0.35)  # Normal request; four batches take longer than one check timeout.
            if resource == "orders-0" and revoke_first.is_set():
                raise PermissionError
            with lock:
                seen.add(resource)
                if len(seen) == len(stops):
                    all_checked.set()
            return self.grant(task, connector, action, resource)

        async with self.host() as host:
            host.session_grant = check
            deadline = time.monotonic() + 15
            watches = [asyncio.create_task(host._watch(("mysql", "connect", f"orders-{i}"), deadline, stop))
                       for i, stop in enumerate(stops)]
            try:
                self.assertTrue(await asyncio.to_thread(all_checked.wait, 6))
                self.assertFalse(any(stop.is_set() for stop in stops))
                revoke_first.set()
                await asyncio.wait_for(stops[0].wait(), 4)
                self.assertFalse(any(stop.is_set() for stop in stops[1:]))
            finally:
                for watch in watches:
                    watch.cancel()
                await asyncio.gather(*watches, return_exceptions=True)

    async def test_slow_checks_time_out_and_queued_session_keeps_its_absolute_deadline(self):
        release = threading.Event()
        calls = []
        lock = threading.Lock()

        def blocked(task, connector, action, resource):
            with lock:
                calls.append(resource)
            release.wait(4)
            return self.grant(task, connector, action, resource)

        with patch("warden_plugins.CHECK_INTERVAL", 0.4):
            async with self.host() as host:
                host.session_grant = blocked
                now = time.monotonic()
                stops = [asyncio.Event() for _ in range(5)]
                watches = [asyncio.create_task(host._watch(("mysql", "connect", f"orders-{i}"),
                                                now + (0.6 if i == 4 else 5), stop))
                           for i, stop in enumerate(stops)]
                try:
                    await asyncio.wait_for(stops[4].wait(), 2)
                    self.assertFalse(any(stop.is_set() for stop in stops[:4]))
                    await asyncio.wait_for(asyncio.gather(*watches), 1)
                    self.assertCountEqual(calls, [f"orders-{i}" for i in range(4)])
                finally:
                    release.set()
                    for watch in watches:
                        watch.cancel()
                    await asyncio.gather(*watches, return_exceptions=True)

    async def test_idle_client_removes_descriptor_when_warden_closes(self):
        local_sock, peer_sock = socket.socketpair()
        remote = await asyncio.open_connection(sock=local_sock)
        _, peer = await asyncio.open_connection(sock=peer_sock)
        ready = asyncio.get_running_loop().create_future()
        expires = datetime.now(timezone.utc) + timedelta(seconds=30)
        bridge = asyncio.create_task(serve_one_database(remote, {"expires_at": expires.isoformat()}, ready.set_result))
        try:
            path = await asyncio.wait_for(ready, 2)
            self.assertTrue(path.is_file())
            peer.close()
            await peer.wait_closed()
            with self.assertRaisesRegex(ConnectionError, "数据库会话已关闭"):
                await asyncio.wait_for(bridge, 2)
            self.assertFalse(path.exists())
        finally:
            bridge.cancel()
            await asyncio.gather(bridge, return_exceptions=True)
            peer.close()
            remote[1].close()
            await remote[1].wait_closed()

    async def test_gitlab_withholds_results_after_revocation(self):
        self.config["gitlab"] = {"mr": {"origin": "https://example.test", "project": 1,
                                        "iid": 3, "token_file": "secret"}}

        async def in_flight(*_):
            self.allowed = False
            return {"title": "confidential"}

        async with self.host() as host:
            with patch.object(host.runtime, "read", in_flight):
                with self.assertRaises(PermissionError):
                    await host.invoke("gitlab", "read", "mr")
        self.assertEqual(self.events, [("review", "gitlab", "read", "mr", "failed")])

    async def test_gitlab_exact_path_only_and_never_follow_redirect(self):
        context, ca = await asyncio.to_thread(local_tls, self.root)
        requests = []
        status = 302
        body = b""
        async def endpoint(reader, writer):
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(f"HTTP/1.1 {status} Test\r\nLocation: /unexpected\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
            await writer.drain()
            writer.close()

        async with await asyncio.start_server(endpoint, "127.0.0.1", 0, ssl=context) as upstream:
            port = upstream.sockets[0].getsockname()[1]
            self.config["gitlab"] = {"mr": {"origin": f"https://127.0.0.1:{port}", "token_file": "secret",
                                            "ca_file": str(ca), "project": 12, "iid": 42}}
            async with self.host() as host:
                with self.assertRaisesRegex(RuntimeError, "^连接器操作未完成$"):
                    await host.invoke("gitlab", "read", "mr")
                self.assertEqual(len(requests), 1)
                status = 200
                body = b'{"project_id":12,"iid":42,"title":"Review","internal_only":true}'
                self.assertEqual(await host.invoke("gitlab", "read", "mr"),
                                 {"project_id": 12, "iid": 42, "title": "Review"})
                self.assertEqual(len(requests), 2)
                self.assertIn(b"GET /api/v4/projects/12/merge_requests/42 HTTP/1.1", requests[0])
                self.assertIn(b"private-token: synthetic-secret\r\n", requests[0].lower())
                body = json.dumps({"project_id": 12, "iid": 42, "title": "x" * (1024 * 1024)}).encode()
                with self.assertRaises(RuntimeError):
                    await host.invoke("gitlab", "read", "mr")
                body = b'{"project_id":42,"iid":42}'
                with self.assertRaises(RuntimeError):
                    await host.invoke("gitlab", "read", "mr")
                body = br'{"project_id":12,"iid":42,"title":"synthetic-\u0073ecret"}'
                with self.assertRaisesRegex(RuntimeError, "^连接器操作未完成$"):
                    await host.invoke("gitlab", "read", "mr")
                self.secret.chmod(0o644)
                before = len(requests)
                with self.assertRaises(RuntimeError):
                    await host.invoke("gitlab", "read", "mr")
                self.assertEqual(len(requests), before)
                self.assertNotIn("synthetic-secret", str(self.events))


if __name__ == "__main__":
    unittest.main()
