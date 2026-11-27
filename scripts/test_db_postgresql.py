"""Exercise the native PostgreSQL login against a TLS/SCRAM protocol fixture."""

import asyncio
from pathlib import Path
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scramp import ScramMechanism
from dbproxy.postgresql import authenticate
from verify_external import make_ca


def frame(kind, body):
    return kind + struct.pack("!I", len(body) + 4) + body


async def packet(reader, *, typed=True):
    kind = await reader.readexactly(1) if typed else b""
    size, = struct.unpack("!I", await reader.readexactly(4))
    return kind, await reader.readexactly(size - 4)


class PostgreSQLTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        make_ca(root / "tls")
        secret = root / "password"
        secret.write_text("upstream-fixture-password\n")
        secret.chmod(0o600)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(root / "tls/server.pem", root / "tls/server.key")
        self.attempts = 0
        self.started = b""
        self.invalid_proof = False
        upstream = await self.listen(self.upstream)
        self.target = {"user": "service_reader", "database": "orders", "host": "localhost",
                       "port": upstream, "password_file": str(secret), "ca_file": str(root / "tls/root.pem")}
        self.proxy_port = await self.listen(self.proxy)

    async def listen(self, callback):
        server = await asyncio.start_server(callback, "127.0.0.1", 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        return server.sockets[0].getsockname()[1]

    async def upstream(self, reader, writer):
        self.attempts += 1
        try:
            self.assertEqual(await packet(reader, typed=False), (b"", struct.pack("!I", 80877103)))
            writer.write(b"S")
            await writer.drain()
            await writer.start_tls(self.tls)
            _, self.started = await packet(reader, typed=False)
            mechanism = ScramMechanism("SCRAM-SHA-256")
            auth_info = mechanism.make_auth_info("upstream-fixture-password")
            auth = mechanism.make_server(lambda user: auth_info if user == "service_reader" else None)
            writer.write(frame(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\0\0"))
            _, data = await packet(reader)
            _, response = data.split(b"\0", 1)
            auth.set_client_first(response[4:].decode())
            writer.write(frame(b"R", struct.pack("!I", 11) + auth.get_server_first().encode()))
            _, data = await packet(reader)
            auth.set_client_final(data.decode())
            proof = auth.get_server_final().encode()
            if self.invalid_proof:
                proof = b"v=AAAA"
            writer.write(frame(b"R", struct.pack("!I", 12) + proof))
            writer.write(frame(b"R", struct.pack("!I", 0)))
            writer.write(frame(b"K", b"private!"))
            writer.write(frame(b"S", b"client_encoding\0UTF8\0"))
            writer.write(frame(b"Z", b"I"))
            self.assertEqual(await packet(reader), (b"Q", b"SELECT 1\0"))
            writer.write(frame(b"C", b"SELECT 1\0"))
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass  # The client closes when a certificate or SCRAM proof is invalid.
        finally:
            writer.close()

    async def proxy(self, reader, writer):
        upstream = None
        try:
            other, upstream = await authenticate(reader, writer, self.target, "session-test")
            kind, sql = await packet(reader)
            upstream.write(frame(kind, sql))
            kind, response = await packet(other)
            writer.write(frame(kind, response))
            await writer.drain()
        except PermissionError:
            pass
        finally:
            if upstream:
                upstream.close()
            writer.close()

    async def login(self, password):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        self.addCleanup(writer.close)
        writer.write(frame(b"", struct.pack("!I", 80877103)))
        self.assertEqual(await reader.readexactly(1), b"N")
        writer.write(frame(b"", struct.pack("!I", (3 << 16) + 2) + b"user\0keyheron\0database\0orders\0options\0opaque\0\0"))
        self.assertEqual(await packet(reader), (b"v", struct.pack("!II", 3 << 16, 0)))
        self.assertEqual(await packet(reader), (b"R", struct.pack("!I", 3)))
        writer.write(frame(b"p", password + b"\0"))
        return reader, writer

    async def test_sql_with_fixed_upstream_identity(self):
        reader, writer = await self.login(b"session-test")
        self.assertEqual(await packet(reader), (b"R", struct.pack("!I", 0)))
        self.assertEqual(await packet(reader), (b"S", b"client_encoding\0UTF8\0"))
        self.assertEqual(await packet(reader), (b"Z", b"I"))
        self.assertIn(b"user\0service_reader\0database\0orders\0", self.started)
        self.assertNotIn(b"opaque", self.started)
        writer.write(frame(b"Q", b"SELECT 1\0"))
        self.assertEqual(await packet(reader), (b"C", b"SELECT 1\0"))

    async def test_wrong_session_password(self):
        reader, _ = await self.login(b"wrong")
        self.assertEqual((await packet(reader))[0], b"E")
        self.assertEqual(self.attempts, 0)

    async def test_wrong_certificate_hostname(self):
        self.target["host"] = "127.0.0.1"
        reader, _ = await self.login(b"session-test")
        kind, body = await packet(reader)
        self.assertEqual(kind, b"E")
        self.assertNotIn(b"upstream-fixture-password", body)
        self.assertEqual(self.started, b"")

    async def test_upstream_authentication_must_finish_before_client_success(self):
        self.invalid_proof = True
        reader, _ = await self.login(b"session-test")
        kind, body = await packet(reader)
        self.assertEqual(kind, b"E")
        self.assertNotIn(b"v=", body)


if __name__ == "__main__":
    unittest.main()
