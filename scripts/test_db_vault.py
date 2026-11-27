"""Encrypted credential handoff at the native database session boundary."""

import asyncio
from contextlib import closing, redirect_stdout, suppress
import importlib
import io
import json
from pathlib import Path
import sqlite3
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_access import load_config
from credential_store import initialize, unlock
from dbproxy.session import serve_database


class DatabaseVault(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.phrase = b"synthetic vault unlock secret"
        self.vault = self.root / "vault" / "store.db"
        initialize(self.vault, self.phrase)
        self.store = unlock(self.vault, self.phrase)
        key_file = self.root / "unlock"
        key_file.write_bytes(self.phrase)
        key_file.chmod(0o600)
        self.original, self.updated = b"synthetic-db-password-1", b"synthetic-db-password-2"
        self.store.put("DEV", "login", self.original)
        self.store.put("PROD", "login", b"synthetic-other-environment")
        target = {"host": "localhost", "database": "orders", "user": "db_reader", "password_ref": "login"}
        policy = {"version": 1, "task": "db-vault", "identities": {"applicant": "agent", "approver": "owner"},
                  "credential_store": {"path": "vault/store.db", "passphrase_file": "unlock"},
                  "environments": {"DEV": {"databases": {
                      engine: dict(target, engine=engine) for engine in ("postgresql", "mysql", "sqlserver")
                  }}}}
        path = self.root / "policy.json"
        path.write_text(json.dumps(policy))
        self.policy = load_config(path, database=True)
        self.args = SimpleNamespace(env="DEV", target="mysql", ttl=20, state_dir=self.root / "state")

    async def test_wrong_unlock_creates_no_session(self):
        (self.root / "unlock").write_bytes(b"wrong synthetic passphrase")
        with self.assertRaises(ValueError):
            await serve_database(self.policy, self.args)
        self.assertFalse(self.args.state_dir.exists())

    async def native_session(self, engine):
        self.args.target = engine
        adapter = importlib.import_module("dbproxy." + engine)
        captured = []

        # Substitute only the wire authentication. The real adapter's credential
        # reader, session, rotating vault record, descriptor and audit are exercised.
        async def login(reader, writer, target, password):
            if (await reader.readline()).rstrip(b"\n") != password.encode():
                raise ValueError("fixture: bad local password")
            captured.append(adapter.read_password(target).encode())
            return await asyncio.open_connection("127.0.0.1", upstream.sockets[0].getsockname()[1])

        async def reply(reader, writer):
            try:
                await reader.readexactly(5 if engine == "mysql" else 1)
                writer.write(b"1")
                await writer.drain()
            finally:
                writer.close()

        output = io.StringIO()
        async with await asyncio.start_server(reply, "127.0.0.1", 0) as upstream:
            with patch.object(adapter, "authenticate", login), redirect_stdout(output):
                serving = asyncio.create_task(serve_database(self.policy, self.args))
                try:
                    async with asyncio.timeout(8):
                        while not (files := list(self.args.state_dir.glob("session-*/connection.json"))):
                            if serving.done():
                                await serving
                            await asyncio.sleep(0.01)
                    descriptor, = files
                    raw = descriptor.read_bytes()
                    info = json.loads(raw)
                    client_tls = ssl.create_default_context(cafile=info["ca_file"]) if "ca_file" in info else None

                    async def query():
                        reader, writer = await asyncio.open_connection(info["host"], info["port"], ssl=client_tls)
                        try:
                            query_bytes = b"\x01\x00\x00\x00\x0e" if engine == "mysql" else b"?"
                            writer.write(info["password"].encode() + b"\n" + query_bytes)
                            await writer.drain()
                            return await asyncio.wait_for(reader.read(1), 2)
                        finally:
                            writer.close()

                    self.assertEqual(await query(), b"1")
                    self.store.put("DEV", "login", self.updated)
                    self.assertEqual(await query(), b"1")
                    with closing(sqlite3.connect(self.vault)) as db, db:
                        db.execute("UPDATE vault_credentials SET ciphertext=zeroblob(length(ciphertext)) WHERE ref='DEV/login'")
                    self.assertEqual(await query(), b"")
                    self.assertEqual(captured, [self.original, self.updated])
                finally:
                    serving.cancel()
                    with suppress(asyncio.CancelledError):
                        await serving
        self.assertFalse(descriptor.exists())
        audit = self.args.state_dir / "db-events.sqlite3"
        with closing(sqlite3.connect(audit)) as db:
            events = db.execute("SELECT action,result FROM database_events ORDER BY id").fetchall()
        self.assertEqual(events.count(("connect", "allowed")), 2)
        self.assertIn(("login", "failed"), events)
        for secret in (self.original, self.updated, self.phrase):
            for contents in (raw, output.getvalue().encode(), audit.read_bytes(), self.vault.read_bytes()):
                self.assertNotIn(secret, contents)

    async def test_postgresql_session(self):
        await self.native_session("postgresql")

    async def test_mysql_session(self):
        await self.native_session("mysql")

    async def test_sqlserver_session(self):
        await self.native_session("sqlserver")


if __name__ == "__main__":
    unittest.main()
