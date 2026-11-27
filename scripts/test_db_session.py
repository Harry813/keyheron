"""Regression checks for policy selection, credential handoff and live socket revocation."""

import asyncio
from contextlib import redirect_stdout, suppress
import io
import json
import os
from pathlib import Path
import sys
import ssl
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_access import load_config
from dbproxy import read_password, upstream_tls
from dbproxy.session import run_session


class DatabaseSession(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        secret = self.root / "secret"
        secret.write_text("fixture-upstream-credential\n")
        secret.chmod(0o600)
        self.target = dict(engine="mysql", host="localhost", port=3306, user="reader",
                           database="orders", password_file=str(secret))

    def test_mixed_policy(self):
        source = Path(__file__).resolve().parents[1] / "examples/github-readonly.json"
        cfg = json.loads(source.read_text())
        api = cfg["environments"]["DEV"]
        api["credential_files"] = {key: "secret" for key in api.pop("credential_refs")}
        profiles = {"orders": {**self.target, "password_file": "secret"}}
        cfg["environments"] = {"DEV": {**api, "databases": profiles}, "STG": {"databases": profiles}}
        path = self.root / "policy.json"
        path.write_text(json.dumps(cfg))
        https = load_config(path)["environments"]
        self.assertEqual(list(https), ["DEV"])
        self.assertNotIn("databases", https["DEV"])
        dbs = load_config(path, database=True)["environments"]
        self.assertEqual(set(dbs), {"DEV", "STG"})
        self.assertEqual(dbs["DEV"]["orders"]["max_ttl"], 300)
        self.assertEqual(read_password(dbs["DEV"]["orders"]), "fixture-upstream-credential")
        Path(self.target["password_file"]).chmod(0o644)
        with self.assertRaises(ValueError):
            read_password(self.target)

    def test_credentials_never_enable_tls_key_logging(self):
        keylog = self.root / "tls.keys"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
            ctx = upstream_tls(self.target)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertIsNone(ctx.keylog_filename)
        self.assertFalse(keylog.exists())

    async def check_close(self, *, expire):
        loop = asyncio.get_running_loop()
        ended = loop.create_future()

        async def echo(reader, writer):
            try:
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                ended.set_result(None)

        async with await asyncio.start_server(echo, "127.0.0.1", 0) as upstream:
            async def login(reader, writer, target, password):
                self.assertEqual(await reader.readline(), password.encode() + b"\n")
                return await asyncio.open_connection("127.0.0.1", upstream.sockets[0].getsockname()[1])

            stop = asyncio.Event()
            records = []
            descriptor = self.root / "connection.json"
            with patch("dbproxy.mysql.authenticate", login), redirect_stdout(io.StringIO()):
                serving = asyncio.create_task(run_session(
                    self.target, 1 if expire else 20, self.root,
                    lambda *event: records.append(event), stop))
                try:
                    async with asyncio.timeout(3):
                        while not descriptor.is_file():
                            await asyncio.sleep(0.01)
                    content = descriptor.read_text()
                    self.assertNotIn("fixture-upstream-credential", content)
                    self.assertNotIn(self.target["password_file"], content)
                    self.assertEqual(descriptor.stat().st_mode & 0o777, 0o600)
                    info = json.loads(content)
                    reader, writer = await asyncio.open_connection(info["host"], info["port"])
                    ping = b"\x01\x00\x00\x00\x0e"  # Classic COM_PING frame
                    writer.write(info["password"].encode() + b"\n" + ping)
                    await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(len(ping)), 2), ping)
                    if not expire:
                        stop.set()
                    await asyncio.wait_for(serving, 3)
                    self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
                    await asyncio.wait_for(ended, 1)
                    writer.close()
                    with self.assertRaises(OSError):
                        await asyncio.open_connection(info["host"], info["port"])
                finally:
                    stop.set()
                    with suppress(asyncio.CancelledError):
                        await serving
            self.assertIn(("connect", "allowed"), records)
            self.assertEqual(records[-1], ("expire" if expire else "close", "closed"))

    async def test_expiry_closes_both_peers(self):
        await self.check_close(expire=True)

    async def test_revocation_closes_both_peers(self):
        await self.check_close(expire=False)


if __name__ == "__main__":
    unittest.main()
