"""MySQL classic protocol, with separate credentials on the two connections."""

import asyncio
import hashlib
import hmac
import secrets
import struct

from dbproxy import read_password, upstream_tls


LONG_PASSWORD = 1
FOUND_ROWS = 1 << 1
LONG_FLAG = 1 << 2
CONNECT_WITH_DB = 1 << 3
COMPRESS = 1 << 5
LOCAL_FILES = 1 << 7
PROTOCOL_41 = 1 << 9
SSL = 1 << 11
TRANSACTIONS = 1 << 13
SECURE_CONNECTION = 1 << 15
MULTI_RESULTS = 1 << 17
PS_MULTI_RESULTS = 1 << 18
PLUGIN_AUTH = 1 << 19
CONNECT_ATTRS = 1 << 20
LENENC_AUTH = 1 << 21
DEPRECATE_EOF = 1 << 24
ZSTD = 1 << 26
REQUIRED = PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH
# These flags change command or result semantics. Both peers must agree.
COMMAND_FLAGS = FOUND_ROWS | LONG_FLAG | TRANSACTIONS | MULTI_RESULTS | PS_MULTI_RESULTS | DEPRECATE_EOF
OFFERED = REQUIRED | COMMAND_FLAGS | LONG_PASSWORD | CONNECT_WITH_DB | CONNECT_ATTRS | LENENC_AUTH
CACHING = b"caching_sha2_password"
NATIVE = b"mysql_native_password"
MAX_HANDSHAKE = 65536
MAX_PACKET = (1 << 24) - 1
COM_CHANGE_USER = 0x11


class AccountChangeDenied(PermissionError):
    pass


async def relay_commands(reader, writer, stop, deadline):
    """Forward Classic commands under the authenticated identity, retaining packet boundaries."""
    loop = asyncio.get_running_loop()
    continuation = None
    while not stop.is_set() and loop.time() < deadline:
        try:
            header = await reader.readexactly(4)
        except asyncio.IncompleteReadError as exc:
            if exc.partial or continuation is not None:
                raise ValueError("Incomplete MySQL command") from None
            return
        size = int.from_bytes(header[:3], "little")
        sequence = header[3]
        remaining = size
        if continuation is None:
            if sequence != 0 or size == 0:
                raise ValueError("Invalid MySQL command framing")
            first = await reader.readexactly(1)
            if first[0] == COM_CHANGE_USER:
                raise AccountChangeDenied("当前会话绑定配置的数据库账户，不能切换用户")
            prefix = header + first
            remaining -= 1
        elif sequence == continuation:
            prefix = header
        else:
            raise ValueError("Invalid MySQL command continuation")
        if stop.is_set() or loop.time() >= deadline:
            return
        writer.write(prefix)
        await writer.drain()
        while remaining:
            chunk = await reader.read(min(65536, remaining))
            if not chunk:
                raise ValueError("Incomplete MySQL command payload")
            if stop.is_set() or loop.time() >= deadline:
                return
            writer.write(chunk)
            await writer.drain()
            remaining -= len(chunk)
        # A full-size frame always continues, including an empty terminating frame.
        continuation = (sequence + 1) & 255 if size == MAX_PACKET else None


async def _packet(reader, seq):
    header = await reader.readexactly(4)
    size = int.from_bytes(header[:3], "little")
    if header[3] != seq or not 0 < size <= MAX_HANDSHAKE:
        raise ValueError("Invalid MySQL handshake packet")
    return await reader.readexactly(size)


async def _send(writer, seq, data):
    writer.write(len(data).to_bytes(3, "little") + bytes((seq,)) + data)
    await writer.drain()


def _nul(data, offset):
    end = data.index(b"\0", offset)
    return data[offset:end], end + 1


def _length(data, offset):
    length = data[offset]
    if length < 251:
        return length, offset + 1
    width = {0xfc: 2, 0xfd: 3, 0xfe: 8}.get(length)
    if width is None or offset + 1 + width > len(data):
        raise ValueError("Invalid length in MySQL handshake")
    return int.from_bytes(data[offset+1:offset+1+width], "little"), offset + 1 + width


def _proof(plugin, password, nonce):
    if len(nonce) != 20:
        raise ValueError("Invalid MySQL challenge")
    if plugin == CACHING:
        first = hashlib.sha256(password).digest()
        second = hashlib.sha256(first).digest()
        mask = hashlib.sha256(second + nonce).digest()
    elif plugin == NATIVE:
        first = hashlib.sha1(password).digest()
        second = hashlib.sha1(first).digest()
        mask = hashlib.sha1(nonce + second).digest()
    else:
        raise ValueError("Unsupported MySQL authentication plugin")
    return bytes(a ^ b for a, b in zip(first, mask))


def _greeting(nonce):
    return (b"\x0a8.0.0-KeyHeron\0" + secrets.token_bytes(4) + nonce[:8] + b"\0"
            + struct.pack("<HBHHB", OFFERED & 0xffff, 45, 2, OFFERED >> 16, 21)
            + bytes(10) + nonce[8:] + b"\0" + CACHING + b"\0")


def _login(data, nonce, session_password, database):
    if len(data) < 34:
        raise ValueError("Incomplete MySQL login")
    flags = int.from_bytes(data[:4], "little")
    # libmysqlclient can report LOCAL_FILES even with --local-infile=0.
    # Its value never enters either the greeting or the upstream login.
    if flags & REQUIRED != REQUIRED or flags & (SSL | COMPRESS | ZSTD):
        raise ValueError("Unsupported MySQL client capabilities")
    user, pos = _nul(data, 32)
    if flags & LENENC_AUTH:
        size, pos = _length(data, pos)
    else:
        size, pos = data[pos], pos + 1
    proof, pos = data[pos:pos+size], pos + size
    if flags & CONNECT_WITH_DB:
        db, pos = _nul(data, pos)
        if db and db != database.encode():
            raise ValueError("Database outside this session")
    plugin, pos = _nul(data, pos)
    if flags & CONNECT_ATTRS:
        length, pos = _length(data, pos)
        pos += length
    if pos != len(data) or user != b"keyheron" or plugin != CACHING:
        raise ValueError("Invalid MySQL login")
    if not hmac.compare_digest(proof, _proof(CACHING, session_password.encode(), nonce)):
        raise ValueError("Invalid MySQL login")
    return flags & COMMAND_FLAGS, data[4:9]


def _parse_greeting(data):
    if not data.startswith(b"\x0a"):
        raise ValueError("MySQL protocol 10 required")
    _, pos = _nul(data, 1)
    pos += 4  # connection ID
    seed = data[pos:pos+8]
    low, _, _, high, auth_size = struct.unpack_from("<HBHHB", data, pos+9)
    flags = low | high << 16
    # Both supported plugins have a 20-byte challenge and trailing NUL.
    mandatory = REQUIRED | SSL | CONNECT_WITH_DB
    if flags & mandatory != mandatory or auth_size != 21:
        raise ValueError("TLS and MySQL 4.1 plugin login are required")
    pos += 8 + 1 + 8 + 10
    nonce = seed + data[pos:pos+12]
    if data[pos+12:pos+13] != b"\0":
        raise ValueError("Invalid MySQL greeting")
    plugin = data[pos+13:].removesuffix(b"\0")
    return flags, plugin, nonce


async def _upstream(reader, writer, target, local_flags, size_and_charset):
    flags, plugin, nonce = _parse_greeting(await _packet(reader, 0))
    if local_flags & ~flags:
        raise ValueError("Incompatible MySQL result capabilities")
    client_flags = REQUIRED | SSL | CONNECT_WITH_DB | (flags & LONG_PASSWORD) | local_flags
    prefix = struct.pack("<I", client_flags) + size_and_charset + bytes(23)
    ctx = upstream_tls(target)
    writer.transport.pause_reading()
    # StreamReader can prefetch beyond the greeting. Only the TLS transport
    # may supply the data consumed by the authentication state machine.
    if reader._buffer:
        raise ValueError("Unexpected data before MySQL TLS handshake")
    await _send(writer, 1, prefix)
    await writer.start_tls(ctx, server_hostname=target["host"])

    password = (await asyncio.to_thread(read_password, target)).encode()
    if not password or len(password) >= MAX_HANDSHAKE or b"\0" in password:
        raise ValueError("Invalid MySQL credential file")
    proof = _proof(plugin, password, nonce)
    response = (prefix + target["user"].encode() + b"\0" + bytes((len(proof),)) + proof
                + target["database"].encode() + b"\0" + plugin + b"\0")
    await _send(writer, 2, response)
    seq = 3
    reply = await _packet(reader, seq)
    if reply.startswith(b"\xfe"):
        plugin, pos = _nul(reply, 1)
        challenge = reply[pos:]
        if len(challenge) == 21 and challenge[-1] == 0:
            challenge = challenge[:20]
        await _send(writer, seq + 1, _proof(plugin, password, challenge))
        seq += 2
        reply = await _packet(reader, seq)
    if plugin == CACHING and reply == b"\x01\x04":
        # The upstream socket has already verified its TLS peer and hostname.
        await _send(writer, seq + 1, password + b"\0")
        seq += 2
        reply = await _packet(reader, seq)
    elif plugin == CACHING and reply == b"\x01\x03":
        reply = await _packet(reader, seq + 1)
    if not reply.startswith(b"\x00\x00\x00") or len(reply) < 7:
        raise ValueError("MySQL upstream authentication failed")
    return reply[:7]  # status and warnings only


async def authenticate(client_reader, client_writer, target, session_password):
    # Some native clients treat the nonce as a C string.
    nonce = bytes(secrets.randbelow(255) + 1 for _ in range(20))
    await _send(client_writer, 0, _greeting(nonce))
    login = await _packet(client_reader, 1)
    try:
        flags, charset = _login(login, nonce, session_password, target["database"])
    except (ValueError, IndexError):
        await _send(client_writer, 2, b"\xff\x15\x04#28000Access denied")
        raise ValueError("MySQL session authentication failed") from None
    reader, writer = await asyncio.open_connection(target["host"], target["port"])
    try:
        ok = await _upstream(reader, writer, target, flags, charset)
        await _send(client_writer, 2, b"\x01\x03")  # local fast-auth success
        await _send(client_writer, 3, ok)
        return reader, writer
    except BaseException:
        writer.close()
        raise
