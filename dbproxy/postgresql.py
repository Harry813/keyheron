"""PostgreSQL v3 login for a loopback client and a separately authenticated TLS upstream."""

import asyncio
import hmac
import struct

from dbproxy import read_password, upstream_tls


U32 = struct.Struct("!I")
V3 = 3 << 16
SSL_REQUEST = 80877103
GSS_REQUEST = 80877104
SCRAM = b"SCRAM-SHA-256"


def _frame(kind, body):
    return kind + U32.pack(len(body) + 4) + body


async def _body(reader):
    size, = U32.unpack(await reader.readexactly(4))
    if not 4 <= size <= 64 * 1024:
        raise ValueError("Invalid PostgreSQL login packet")
    return await reader.readexactly(size - 4)


async def _message(reader):
    return await reader.readexactly(1), await _body(reader)


async def _login_client(reader, writer, database, session_password):
    seen = set()
    while True:
        startup = await _body(reader)
        version, = U32.unpack(startup[:4])
        if version not in (SSL_REQUEST, GSS_REQUEST):
            break
        if len(startup) != 4 or version in seen:
            raise ValueError("Invalid PostgreSQL negotiation")
        seen.add(version)
        writer.write(b"N")
        await writer.drain()
    if version >> 16 != 3 or not startup.endswith(b"\0\0"):
        raise ValueError("Expected PostgreSQL v3 startup")
    fields = startup[4:-2].split(b"\0")
    if len(fields) % 2:
        raise ValueError("Invalid PostgreSQL startup parameters")
    params = dict(zip(fields[::2], fields[1::2]))
    if len(params) * 2 != len(fields) or params.get(b"user") != b"keyheron":
        raise PermissionError("Unknown session user")
    if params.get(b"database", b"keyheron") not in (b"keyheron", database.encode()):
        raise PermissionError("Unknown session database")
    # Negotiate protocol 3.0 with newer libpq clients. Recognize no extensions.
    options = [key for key in params if key.startswith(b"_pq_.")]
    if version != V3 or options:
        data = U32.pack(V3) + U32.pack(len(options)) + b"".join(key + b"\0" for key in options)
        writer.write(_frame(b"v", data))
    writer.write(_frame(b"R", U32.pack(3)))
    await writer.drain()
    kind, password = await _message(reader)
    if kind != b"p" or not hmac.compare_digest(password, session_password.encode() + b"\0"):
        raise PermissionError("Invalid session password")


async def _expect_auth(reader, code):
    kind, body = await _message(reader)
    if kind != b"R" or body[:4] != U32.pack(code):
        raise PermissionError("PostgreSQL authentication failed")
    return body[4:]


async def _login_upstream(reader, writer, target):
    from scramp import ScramClient

    writer.write(_frame(b"", U32.pack(SSL_REQUEST)))
    await writer.drain()
    if await reader.readexactly(1) != b"S":
        raise PermissionError("PostgreSQL requires verified TLS")
    # The SSLResponse is exactly one byte. asyncio retains prefetched data
    # in StreamReader across start_tls; never interpret cleartext as TLS data.
    if reader._buffer:
        raise PermissionError("Unexpected bytes before PostgreSQL TLS")
    context = upstream_tls(target)
    await writer.start_tls(context, server_hostname=target["host"])
    user, database = target["user"], target["database"]
    startup = b"user\0" + user.encode() + b"\0database\0" + database.encode()
    writer.write(_frame(b"", U32.pack(V3) + startup + b"\0client_encoding\0UTF8\0\0"))
    await writer.drain()
    mechanisms = await _expect_auth(reader, 10)
    if SCRAM not in mechanisms.split(b"\0"):
        raise PermissionError("PostgreSQL upstream requires SCRAM-SHA-256")
    password = await asyncio.to_thread(read_password, target)
    auth = ScramClient([SCRAM.decode()], user, password)
    first = auth.get_client_first().encode()
    writer.write(_frame(b"p", SCRAM + b"\0" + U32.pack(len(first)) + first))
    await writer.drain()
    challenge = (await _expect_auth(reader, 11)).decode("ascii")
    auth.set_server_first(challenge)
    # Keep the event loop responsive while deriving the salted key.
    proof = await asyncio.to_thread(auth.get_client_final)
    writer.write(_frame(b"p", proof.encode()))
    await writer.drain()
    auth.set_server_final((await _expect_auth(reader, 12)).decode("ascii"))
    await _expect_auth(reader, 0)


async def authenticate(client_reader, client_writer, target, session_password):
    """Return a ready upstream connection; the owner closes both ends on revoke."""
    upstream = None
    try:
        await _login_client(client_reader, client_writer, target["database"], session_password)
        reader, upstream = await asyncio.open_connection(target["host"], target["port"])
        await _login_upstream(reader, upstream, target)
        ready = bytearray(_frame(b"R", U32.pack(0)))
        for _ in range(128):
            kind, body = await _message(reader)
            if kind == b"S" and len(ready) + len(body) <= 65536:
                ready.extend(_frame(kind, body))
            elif kind == b"Z" and body == b"I":
                client_writer.write(ready + _frame(kind, body))
                await client_writer.drain()
                return reader, upstream
            elif kind not in (b"K", b"N"):
                break
            # The cancellation key belongs to the upstream session, never to the client.
        raise ValueError("PostgreSQL upstream did not become ready")
    except BaseException as exc:
        if upstream is not None:
            upstream.close()
        if isinstance(exc, Exception):
            client_writer.write(_frame(b"E", b"SFATAL\0C28000\0MDatabase login failed\0\0"))
            await client_writer.drain()
            raise PermissionError("Database login failed") from None
        raise
