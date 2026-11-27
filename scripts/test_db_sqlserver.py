"""Exercise SQL authentication through both TLS legs against an isolated TDS fixture."""

import asyncio
from pathlib import Path
import secrets
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dbproxy import sqlserver as tds
from verify_external import make_ca


def token(kind, value):
    return bytes([kind]) + struct.pack("<H", len(value)) + value


def login_ack():
    name = "Microsoft SQL Server".encode("utf-16-le")
    version = bytes.fromhex("01 08 00 00 00")
    return token(0xad, version + bytes([len(name) // 2]) + name + bytes([16, 0, 3, 232]))


DONE = b"\xfd" + bytes(12)


class SqlServerTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        make_ca(root / "ca")
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.set_alpn_protocols([tds.ALPN])
        self.tls.load_cert_chain(root / "ca/server.pem", root / "ca/server.key")
        self.ca_file = str(root / "ca/root.pem")
        self.upstream_secret = secrets.token_hex(32)
        self.session_password = secrets.token_hex(32)
        secret_file = root / "secret"
        secret_file.write_text(self.upstream_secret)
        secret_file.chmod(0o600)
        self.target = dict(user="reports_reader", host="localhost", database="reports",
                           ca_file=self.ca_file, password_file=str(secret_file))
        self.seen = []
        self.failures = []
        self.proxy_errors = []
        self.login_reply = login_ack() + DONE

    async def _listen(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=self.tls)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        return server.sockets[0].getsockname()[1]

    async def asyncSetUp(self):
        async def upstream(reader, writer):
            try:
                self.assertEqual(writer.get_extra_info("ssl_object").selected_alpn_protocol(), tds.ALPN)
                await tds._receive(reader, tds.PRELOGIN)
                await tds._send(writer, tds.REPLY, tds._prelogin())
                login = await tds._receive(reader, tds.LOGIN7)
                self.assertNotIn(tds._encode_password(self.session_password), login)
                self.assertEqual(tds._field(login, 40).decode("utf-16-le"), self.target["user"])
                self.assertEqual(tds._field(login, 44), tds._encode_password(self.upstream_secret))
                self.assertEqual(tds._field(login, 68).decode("utf-16-le"), "reports")
                self.seen.append("login")
                await tds._send(writer, tds.REPLY, self.login_reply, packet_size=24)
                if self.login_reply == login_ack() + DONE:
                    # Only our transparent relay test sends a SQL batch.
                    query = await tds._receive(reader, 0x01)
                    self.seen.append(query)
                    await tds._send(writer, tds.REPLY, DONE)
            except asyncio.IncompleteReadError:
                pass
            except Exception as exc:
                self.failures.append(exc)
            finally:
                writer.close()

        async def gateway(reader, writer):
            upstream_writer = None
            try:
                upstream_reader, upstream_writer = await tds.authenticate(reader, writer, self.target, self.session_password)
                query = await tds._receive(reader, 0x01)
                await tds._send(upstream_writer, 0x01, query)
                reply = await tds._receive(upstream_reader, tds.REPLY)
                await tds._send(writer, tds.REPLY, reply)
            except (ValueError, PermissionError, OSError) as exc:
                self.proxy_errors.append(exc)
            finally:
                if upstream_writer:
                    upstream_writer.close()
                writer.close()

        self.target["port"] = await self._listen(upstream)
        self.local_port = await self._listen(gateway)

    async def _client(self, *, password=None, username="keyheron", database="reports"):
        context = ssl.create_default_context(cafile=self.ca_file)
        context.set_alpn_protocols([tds.ALPN])
        reader, writer = await asyncio.open_connection("127.0.0.1", self.local_port,
                                                      ssl=context, server_hostname="localhost")
        self.addCleanup(writer.close)
        await tds._send(writer, tds.PRELOGIN, tds._prelogin())
        await tds._receive(reader, tds.REPLY)
        login = tds._login(username, password or self.session_password, database, "localhost", 4096)
        await tds._send(writer, tds.LOGIN7, login, packet_size=19)
        return reader, writer

    async def test_native_sql_batch(self):
        reader, writer = await self._client()
        self.assertEqual(await tds._receive(reader, tds.REPLY), login_ack() + DONE)
        sql = "SELECT 1".encode("utf-16-le")
        await tds._send(writer, 0x01, sql)
        self.assertEqual(await tds._receive(reader, tds.REPLY), DONE)
        self.assertEqual(self.seen, ["login", sql])
        self.assertFalse(self.failures or self.proxy_errors)

    async def test_refuses_before_upstream_login(self):
        for options in [dict(password="invalid"), dict(username="sysadmin"), dict(database="master")]:
            reader, _ = await self._client(**options)
            self.assertEqual(await reader.read(), b"")
        self.assertFalse(self.seen)
        self.assertEqual(len(self.proxy_errors), 3)

    async def test_refuses_invalid_upstream_certificate(self):
        # The fixture's TLS server sees the client's expected handshake abort.
        loop = asyncio.get_running_loop()
        debug = loop.get_debug()
        loop.set_debug(False)
        self.addCleanup(loop.set_debug, debug)
        self.target["host"] = "127.0.0.1"  # The certificate is valid for DNS:localhost only.
        reader, _ = await self._client()
        self.assertEqual(await reader.read(), b"")
        self.assertFalse(self.seen)
        self.assertIsInstance(self.proxy_errors[0], ssl.SSLCertVerificationError)

    async def test_refuses_upstream_login_error_without_disclosing_message(self):
        self.login_reply = token(0xaa, self.upstream_secret.encode("utf-16-le")) + DONE
        reader, _ = await self._client()
        self.assertEqual(await reader.read(), b"")
        self.assertEqual(self.seen, ["login"])

    def test_rejects_sensitive_login_options(self):
        login = tds._login("keyheron", self.session_password, "reports", "localhost", 4096)
        for offset, bits in [(25, 128), (27, 1), (27, 4)]:
            altered = bytearray(login)
            altered[offset] |= bits
            with self.assertRaises(ValueError):
                tds._verify_login(altered, self.target, self.session_password)


if __name__ == "__main__":
    unittest.main()
