"""Sandbox client lifecycle checks with a task Unix socket and synthetic database credentials."""
import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warden_client


@asynccontextmanager
async def fixture():
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        path = Path(tmp, "warden.sock")
        seen = asyncio.Queue()
        ended = asyncio.Queue()
        close_stream = asyncio.Event()
        workers = set()
        secret = "synthetic-local-session-secret"

        async def client(reader, writer):
            scope = None
            try:
                request = json.loads(await reader.readline())
                scope = request.get("resource", request.get("op"))
                await seen.put(scope)
                if scope == "hang":
                    await reader.read()
                    return
                if scope == "invalid":
                    writer.write(b'{"result":')
                    return
                if scope == "denied":
                    reply = {"error": "任务未获此连接器操作的授权"}
                elif scope == "list":
                    reply = {"result": [{"connector": "mysql"}]}
                elif scope == "describe":
                    reply = {"result": {"id": request["connector"]}}
                elif request["action"] == "read":
                    reply = {"result": {"descriptor_path": "ordinary data", "handle": "ordinary field"}}
                else:
                    expires = datetime.now(timezone.utc) + timedelta(seconds=20)
                    reply = {"result": {"user": "keyheron", "password": secret, "expires_at": expires.isoformat()}}
                    if request["connector"] != "database":
                        reply["transport"] = "database-stream"
                writer.write(json.dumps(reply).encode() + b"\n")
                await writer.drain()
                if request.get("action") == "connect":
                    async def native():
                        if await reader.read(1) == b"\x01":
                            data = await reader.read(128)
                            if data:
                                writer.write(data)
                                await writer.drain()
                            await reader.read()
                    stream = asyncio.create_task(native())
                    revoke = asyncio.create_task(close_stream.wait())
                    try:
                        await asyncio.wait((stream, revoke), return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        for task in (stream, revoke):
                            task.cancel()
                        await asyncio.gather(stream, revoke, return_exceptions=True)
            finally:
                writer.close()
                with suppress(ConnectionError):
                    await writer.wait_closed()
                await ended.put(scope)

        def accept(reader, writer):
            worker = asyncio.create_task(client(reader, writer))
            workers.add(worker)
            worker.add_done_callback(workers.discard)

        async with await asyncio.start_unix_server(accept, path) as server:
            try:
                yield path, seen, ended, close_stream, secret
            finally:
                server.close()
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)


class ConnectorSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_and_errors_across_multiple_calls(self):
        async with fixture() as (sock, _, _, _, _):
            async with warden_client.ConnectorSession(sock) as session:
                self.assertEqual(await session.list(), [{"connector": "mysql"}])
                self.assertEqual(await session.describe("mysql"), {"id": "mysql"})
                expected = {"descriptor_path": "ordinary data", "handle": "ordinary field"}
                self.assertEqual(await session.invoke("service", "read", "json"), expected)
                with self.assertRaises(RuntimeError):
                    await session.invoke("service", "read", "denied")
                with self.assertRaises(ConnectionError):
                    await session.invoke("service", "read", "invalid")
            with self.assertRaises(RuntimeError):
                await session.list()

    async def test_multi_session_limit_opaque_handles_and_explicit_close(self):
        async with fixture() as (sock, _, ended, _, secret):
            with patch.object(warden_client, "MAX_CONNECTIONS", 2):
                async with warden_client.ConnectorSession(sock) as session:
                    first, second = await asyncio.gather(session.invoke("database", "connect", "legacy"),
                                                         session.invoke("mysql", "connect", "mysql"))
                    self.assertNotEqual(first["handle"], second["handle"])
                    for info in (first, second):
                        self.assertEqual(set(info), {"descriptor_path", "expires_at", "handle"})
                        self.assertNotIn(secret, json.dumps(info))
                        path = Path(info["descriptor_path"])
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                        self.assertEqual(json.loads(path.read_bytes())["password"], secret)
                    with self.assertRaises(RuntimeError):
                        await session.invoke("mysql", "connect", "extra")
                    with self.assertRaises(ValueError):
                        await session.close_connection(first["descriptor_path"])
                    self.assertTrue(Path(first["descriptor_path"]).exists())
                    await asyncio.gather(session.close_connection(first["handle"]), session.close_connection(first["handle"]))
                    self.assertFalse(Path(first["descriptor_path"]).exists())
                    self.assertTrue(Path(second["descriptor_path"]).exists())
                self.assertFalse(Path(second["descriptor_path"]).exists())
                observed = {await asyncio.wait_for(ended.get(), 2) for _ in range(3)}
                self.assertEqual(observed, {"legacy", "mysql", "extra"})

    async def test_live_revocation_removes_file_and_disconnects_sql_client(self):
        async with fixture() as (sock, _, _, revoke, _):
            async with warden_client.ConnectorSession(sock) as session:
                info = await session.invoke("mysql", "connect", "db")
                descriptor = Path(info["descriptor_path"])
                native = json.loads(descriptor.read_bytes())
                reader, writer = await asyncio.open_connection(native["host"], native["port"])
                try:
                    writer.write(b"hello")
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 2), b"hello")
                    revoke.set()
                    self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
                finally:
                    writer.close()
                    await writer.wait_closed()
                async with asyncio.timeout(2):
                    while descriptor.exists():
                        await asyncio.sleep(.005)
                with self.assertRaises(OSError):
                    await asyncio.open_connection(native["host"], native["port"])

    async def test_cancel_and_context_exit_close_outstanding_requests(self):
        async with fixture() as (sock, seen, ended, _, _):
            async with warden_client.ConnectorSession(sock) as session:
                first = asyncio.create_task(session.invoke("slow", "read", "hang"))
                await asyncio.wait_for(seen.get(), 2)
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                await asyncio.wait_for(ended.get(), 2)
                pending = asyncio.create_task(session.invoke("slow", "read", "hang"))
                await asyncio.wait_for(seen.get(), 2)
            with self.assertRaises(asyncio.CancelledError):
                await pending
            await asyncio.wait_for(ended.get(), 2)

    async def test_explicit_close_unpublishes_before_waiting_for_warden_eof(self):
        closing = asyncio.Event()
        release = asyncio.Event()
        async def warden(reader, writer):
            try:
                await reader.readline()
                expires = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
                writer.write(json.dumps({"result": {"expires_at": expires},
                                         "transport": "database-stream"}).encode() + b"\n")
                await writer.drain()
                self.assertEqual(await reader.read(1), b"")
                closing.set()
                await release.wait()
            finally:
                writer.close()
                await writer.wait_closed()

        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            socket_path = Path(tmp, "task.sock")
            async with await asyncio.start_unix_server(warden, socket_path):
                async with warden_client.ConnectorSession(socket_path) as session:
                    result = await session.invoke("postgresql", "connect", "orders")
                    closed = asyncio.create_task(session.close_connection(result["handle"]))
                    try:
                        await asyncio.wait_for(closing.wait(), 1)
                        self.assertFalse(Path(result["descriptor_path"]).exists())
                        self.assertFalse(closed.done())
                    finally:
                        release.set()
                        await asyncio.wait_for(closed, 1)


if __name__ == "__main__":
    unittest.main()
