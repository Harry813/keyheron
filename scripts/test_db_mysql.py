"""Verify MySQL login, TLS peer verification and credential separation on loopback."""

import asyncio
import hashlib
from pathlib import Path
import socket
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dbproxy import mysql
from dbproxy.session import relay
from verify_external import make_ca


UPSTREAM_SECRET = b"synthetic-upstream-password"
SESSION_SECRET = "synthetic-session-password"
NONCE = b"0123456789ABCDEFGHIJ"
OK = bytes.fromhex("00 00 00 02 00 00 00")


def packet(seq, payload):
    return len(payload).to_bytes(3, "little") + bytes((seq,)) + payload


def proof(password, seed):
    first = hashlib.sha256(password).digest()
    mask = hashlib.sha256(hashlib.sha256(first).digest() + seed).digest()
    return bytes(a ^ b for a, b in zip(first, mask))


def read_packet(file, seq):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            chunk = file.read(size - len(data))
            if not chunk:
                raise AssertionError("Missing MySQL packet")
            data.extend(chunk)
        return bytes(data)

    header = exact(4)
    if header[3] != seq:
        raise AssertionError("Unexpected MySQL packet sequence")
    return exact(int.from_bytes(header[:3], "little"))


class Mysql(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.certs = Path(cls.temp.name) / "certs"
        make_ca(cls.certs)
        cls.password_path = Path(cls.temp.name) / "password"
        cls.password_path.write_bytes(UPSTREAM_SECRET + b"\n")
        cls.password_path.chmod(0o600)

    async def check_session(self, *, correct_host=True, native_switch=False):
        loop = asyncio.get_running_loop()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(6)
            target = dict(host="localhost" if correct_host else "127.0.0.1", port=listener.getsockname()[1],
                          user="reader", database="catalog", ca_file=str(self.certs / "root.pem"),
                          password_file=str(self.password_path))

            def fixture():
                with listener.accept()[0] as sock:
                    sock.settimeout(4)
                    flags = mysql.OFFERED | mysql.SSL | mysql.LOCAL_FILES
                    hello = (b"\x0a8.4.0\x00" + bytes(4) + NONCE[:8] + b"\0"
                             + struct.pack("<HBHHB", flags & 65535, 45, 2, flags >> 16, 21)
                             + bytes(10) + NONCE[8:] + b"\0caching_sha2_password\0")
                    sock.sendall(packet(0, hello))
                    with sock.makefile("rb", buffering=0) as plain:
                        ssl_request = read_packet(plain, 1)
                    cap = int.from_bytes(ssl_request[:4], "little")
                    self.assertTrue(cap & mysql.SSL)
                    self.assertFalse(cap & mysql.LOCAL_FILES)
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.certs / "server.pem", self.certs / "server.key")
                    if not correct_host:
                        with self.assertRaises(ssl.SSLError):
                            context.wrap_socket(sock, server_side=True)
                        return
                    with context.wrap_socket(sock, server_side=True) as tls, tls.makefile("rb") as stream:
                        self.assertEqual(read_packet(stream, 2), ssl_request + b"reader\0\x20"
                                         + proof(UPSTREAM_SECRET, NONCE) + b"catalog\0caching_sha2_password\0")
                        if native_switch:
                            seed = NONCE[::-1]
                            tls.sendall(packet(3, b"\xfemysql_native_password\0" + seed + b"\0"))
                            first = hashlib.sha1(UPSTREAM_SECRET).digest()
                            mask = hashlib.sha1(seed + hashlib.sha1(first).digest()).digest()
                            self.assertEqual(read_packet(stream, 4), bytes(a ^ b for a, b in zip(first, mask)))
                        else:
                            tls.sendall(packet(3, b"\x01\x04"))
                            self.assertEqual(read_packet(stream, 4), UPSTREAM_SECRET + b"\0")
                        tls.sendall(packet(5, OK))
                        self.assertEqual(read_packet(stream, 0), b"\x0e")  # COM_PING
                        tls.sendall(packet(1, OK))

            done = loop.create_future()

            async def gateway(reader, writer):
                try:
                    source, upstream = await mysql.authenticate(reader, writer, target, SESSION_SECRET)
                    try:
                        await relay((reader, writer), (source, upstream), asyncio.Event(),
                                    loop.time() + 5, mysql_commands=True)
                    finally:
                        upstream.close()
                    done.set_result(None)
                except Exception as exc:
                    done.set_result(exc)
                finally:
                    writer.close()

            async with await asyncio.start_server(gateway, "127.0.0.1", 0) as server:
                origin = loop.run_in_executor(None, fixture)
                reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
                try:
                    greeting = await mysql._packet(reader, 0)
                    scramble = greeting.index(b"\0", 1) + 5
                    seed = greeting[scramble:scramble+8] + greeting[scramble+27:scramble+39]
                    self.assertNotEqual(seed, NONCE)
                    caps = mysql.REQUIRED | mysql.CONNECT_WITH_DB | mysql.LOCAL_FILES
                    login = (struct.pack("<IIB23x", caps, 1048576, 45) + b"keyheron\0\x20"
                             + proof(SESSION_SECRET.encode(), seed) + b"catalog\0caching_sha2_password\0")
                    writer.write(packet(1, login))
                    if correct_host:
                        self.assertEqual(await mysql._packet(reader, 2), b"\x01\x03")
                        self.assertEqual(await mysql._packet(reader, 3), OK)
                        writer.write(packet(0, b"\x0e"))
                        self.assertEqual(await mysql._packet(reader, 1), OK)
                        self.assertIsNone(await done)
                    else:
                        self.assertEqual(await reader.read(), b"")
                        self.assertIsInstance(await done, ssl.SSLCertVerificationError)
                    await origin
                finally:
                    writer.close()
                    await writer.wait_closed()

    async def test_verified_tls_full_auth_and_native_frames(self):
        await asyncio.wait_for(self.check_session(correct_host=True), 12)

    async def test_wrong_hostname_refused(self):
        await asyncio.wait_for(self.check_session(correct_host=False), 12)

    async def test_native_auth_switch_on_upstream_only(self):
        await asyncio.wait_for(self.check_session(native_switch=True), 12)

    def test_reject_wrong_login_or_capabilities(self):
        caps = mysql.REQUIRED | mysql.CONNECT_WITH_DB
        pw = proof(SESSION_SECRET.encode(), NONCE)
        for flags, user, db, response in [
            (caps, b"reader", b"catalog", pw), (caps, b"keyheron", b"other", pw),
            (caps, b"keyheron", b"catalog", bytes(32)),
            (caps | mysql.COMPRESS, b"keyheron", b"catalog", pw),
        ]:
            login = (struct.pack("<IIB23x", flags, 100000, 45) + user + b"\0\x20" + response
                     + db + b"\0caching_sha2_password\0")
            with self.assertRaises(ValueError):
                mysql._login(login, NONCE, SESSION_SECRET, "catalog")


class CommandReader(unittest.IsolatedAsyncioTestCase):
    class Sink:
        def __init__(self):
            self.digest = hashlib.sha256()
            self.largest_write = 0

        def write(self, part):
            self.digest.update(part)
            self.largest_write = max(self.largest_write, len(part))

        async def drain(self):
            pass

    async def run_stream(self, parts, *, error=None):
        reader = asyncio.StreamReader()
        sink = self.Sink()
        worker = asyncio.create_task(mysql.relay_commands(
            reader, sink, asyncio.Event(), asyncio.get_running_loop().time() + 15))
        for part in parts:
            reader.feed_data(part)
            await asyncio.sleep(0)
        reader.feed_eof()
        if error is None:
            await worker
        else:
            with self.assertRaises(error):
                await worker
        return sink

    async def test_normal_commands_and_reauthentication_boundary(self):
        normal = packet(0, b"\x03SELECT 42") + packet(0, b"\x04orders\0%") + packet(0, b"\x0e")
        # Only the forbidden opcode is supplied: no alternate account or credentials are involved.
        chunks = [normal[:2], normal[2:], packet(0, bytes([mysql.COM_CHANGE_USER]))]
        sink = await self.run_stream(chunks, error=mysql.AccountChangeDenied)
        self.assertEqual(sink.digest.digest(), hashlib.sha256(normal).digest())

    async def test_large_command_continuations_are_data_and_memory_is_bounded(self):
        full = packet(0, b"\x18" + bytes(mysql.MAX_PACKET - 1))
        pieces = (full, packet(1, b"\x11binary data"), full, packet(1, b""), packet(0, b"\x0e"))
        expected = hashlib.sha256()
        for piece in pieces:
            expected.update(piece)
        sink = await self.run_stream(pieces)
        self.assertEqual(sink.digest.digest(), expected.digest())
        self.assertLessEqual(sink.largest_write, 65536)

    async def test_invalid_or_truncated_framing_closes_the_stream(self):
        for data in (b"\x01\x00", packet(1, b"\x0e"), packet(0, b""), packet(0, b"\x03SELECT 1")[:-2]):
            with self.subTest(data=data):
                await self.run_stream([data], error=ValueError)


if __name__ == "__main__":
    unittest.main()
