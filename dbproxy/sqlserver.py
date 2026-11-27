"""SQL Server 2022+ authenticated TDS 8.0 session over two independent TLS transports."""

import asyncio
import hmac
import struct

from dbproxy import read_password, upstream_tls


PRELOGIN = 0x12
LOGIN7 = 0x10
REPLY = 0x04
ALPN = "tds/8.0"
MAX_HANDSHAKE = 65535
LOGIN_HEADER = 94
PACKET_HEADER = struct.Struct("!BBHHBB")


async def _receive(reader, kind):
    data = bytearray()
    while True:
        header = await reader.readexactly(PACKET_HEADER.size)
        actual, status, length, _, _, _ = PACKET_HEADER.unpack(header)
        if actual != kind or status not in (0, 1) or length <= PACKET_HEADER.size:
            raise ValueError("Invalid TDS handshake packet")
        length -= PACKET_HEADER.size
        if len(data) + length > MAX_HANDSHAKE:
            raise ValueError("Oversized TDS handshake")
        data.extend(await reader.readexactly(length))
        if status == 1:
            return bytes(data)


async def _send(writer, kind, data, packet_size=4096):
    chunk = packet_size - PACKET_HEADER.size
    for i, start in enumerate(range(0, len(data), chunk), 1):
        part = data[start:start + chunk]
        last = start + len(part) == len(data)
        writer.write(PACKET_HEADER.pack(kind, last, len(part) + 8, 0, i & 255, 0) + part)
    await writer.drain()


def _prelogin():
    # VERSION, ENCRYPTION (ignored within TLS-first), MARS (disabled).
    fields = [(0, b"\x10\x00\x03\xe8\x00\x00"), (1, b"\x03"), (4, b"\x00")]
    offset = len(fields) * 5 + 1
    options = bytearray()
    for token, value in fields:
        options.extend(struct.pack("!BHH", token, offset, len(value)))
        offset += len(value)
    return bytes(options) + b"\xff" + b"".join(value for _, value in fields)


def _check_prelogin(data, *, upstream=False):
    if not data or data[0] != 0:
        raise ValueError("Missing TDS version")
    fields = {}
    pos = 0
    while pos < len(data) and data[pos] != 255:
        if pos + 5 > len(data):
            raise ValueError("Incomplete PRELOGIN")
        token, start, size = struct.unpack_from("!BHH", data, pos)
        if token in fields or start + size > len(data):
            raise ValueError("Invalid PRELOGIN option")
        fields[token] = (start, size)
        pos += 5
    if pos == len(data) or any(start <= pos for start, size in fields.values() if size):
        raise ValueError("Invalid PRELOGIN offsets")
    if fields[0][1] != 6:
        raise ValueError("Invalid PRELOGIN version")
    if upstream:
        for token in (4, 6):  # MARS and federated authentication are not requested
            if token in fields:
                start, size = fields[token]
                if data[start:start + size] != b"\0":
                    raise ValueError("Unsupported SQL Server prelogin response")


def _field(data, index, *, unit=2):
    offset, count = struct.unpack_from("<HH", data, index)
    if count == 0:
        return b""
    end = offset + unit * count
    if offset < LOGIN_HEADER or end > len(data):
        raise ValueError("Invalid LOGIN7 field")
    return data[offset:end]


def _encode_password(password):
    return bytes((((b << 4) & 255) | (b >> 4)) ^ 0xa5 for b in password.encode("utf-16-le"))


def _verify_login(data, target, session_password):
    if len(data) < LOGIN_HEADER or int.from_bytes(data[:4], "little") != len(data):
        raise ValueError("Invalid LOGIN7 length")
    if data[25] & 0x80 or data[27] & 0x05 or any(data[90:94]):
        raise ValueError("Only ordinary SQL authentication is supported")
    if any(_field(data, i, unit=u) for i, u in ((78, 1), (82, 2), (86, 2))):
        raise ValueError("SSPI, attaching files and changing passwords are disabled")
    if data[27] & 0x10:
        # Ordinary drivers advertise optional extensions too. Negotiate none. Never
        # forward feature data, and reject authentication and session restoration.
        pointer = _field(data, 56, unit=1)
        if len(pointer) != 4:
            raise ValueError("Invalid LOGIN7 extension pointer")
        pos = int.from_bytes(pointer, "little")
        if pos < LOGIN_HEADER:
            raise ValueError("Invalid LOGIN7 extension offset")
        while pos < len(data) and data[pos] != 0xff:
            if pos + 5 > len(data):
                raise ValueError("Invalid LOGIN7 extension")
            kind = data[pos]
            size = int.from_bytes(data[pos + 1:pos + 5], "little")
            if kind == 2 or (kind == 1 and size != 0):
                raise ValueError("Alternative authentication or session recovery is disabled")
            pos += 5 + size
        if pos >= len(data):
            raise ValueError("Incomplete LOGIN7 extensions")
    if _field(data, 40) != "keyheron".encode("utf-16-le"):
        raise PermissionError("Unknown local database user")
    if not hmac.compare_digest(_field(data, 44), _encode_password(session_password)):
        raise PermissionError("Invalid database session")
    name = _field(data, 68).decode("utf-16-le")
    if name and name != target["database"]:
        raise PermissionError("Unexpected database")
    size = int.from_bytes(data[8:12], "little")
    if not 512 <= size <= 32767:
        raise ValueError("Unsupported TDS packet size")
    return size


def _login(user, password, database, host, packet_size):
    # Construct a fresh standard login. No SSPI, extensions, attach filename,
    # alternate password, routing or client-controlled identity is passed through.
    data = bytearray(LOGIN_HEADER)
    struct.pack_into("<II", data, 4, 0x08000000, packet_size)
    data[24] = 0xe0  # USE_DB, fatal initial database failure, SET_LANG
    data[25] = 0x02  # ODBC semantics
    for index, text in ((36, "keyheron"), (40, user), (44, password), (48, "KeyHeron"),
                        (52, host), (60, "KeyHeron"), (68, database)):
        raw = _encode_password(text) if index == 44 else text.encode("utf-16-le")
        if len(raw) > 256 and index in (40, 44, 68):
            raise ValueError("SQL Server login field exceeds 128 UTF-16 code units")
        struct.pack_into("<HH", data, index, len(data), len(raw) // 2)
        data.extend(raw)
    struct.pack_into("<I", data, 0, len(data))
    return bytes(data)


def _login_reply(data):
    pos = 0
    saw_ack = False
    reply = bytearray()
    while pos < len(data):
        token = data[pos]
        if token == 0xfd:  # DONE
            status = int.from_bytes(data[pos + 1:pos + 3], "little")
            if len(data) - pos != 13 or not saw_ack or status & 0x127:
                raise ValueError("SQL Server did not finish login successfully")
            return bytes(reply) + data[pos:]
        if token not in (0xad, 0xe3, 0xab) or pos + 3 > len(data):
            raise ValueError("SQL Server login was refused or requires unsupported negotiation")
        size, = struct.unpack_from("<H", data, pos + 1)
        end = pos + 3 + size
        if not size or end > len(data):
            raise ValueError("Invalid SQL Server login response")
        if token == 0xad:
            if saw_ack or size < 10 or size != 10 + 2 * data[pos + 8]:
                raise ValueError("Invalid LOGINACK")
            saw_ack = True
        if token == 0xe3 and data[pos + 3] not in (1, 2, 3, 4, 5, 6, 7):
            raise ValueError("Unsupported login environment change")
        if token != 0xab:  # INFO messages from upstream can contain arbitrary text
            reply.extend(data[pos:end])
        pos = end
    raise ValueError("Missing SQL Server login acknowledgement")


async def authenticate(client_reader, client_writer, target, session_password):
    client_tls = client_writer.get_extra_info("ssl_object")
    if client_tls is None or client_tls.selected_alpn_protocol() not in (None, ALPN):
        raise PermissionError("SQL Server requires TDS 8.0 over verified TLS")
    _check_prelogin(await _receive(client_reader, PRELOGIN))
    await _send(client_writer, REPLY, _prelogin())
    size = _verify_login(await _receive(client_reader, LOGIN7), target, session_password)

    context = upstream_tls(target)
    context.set_alpn_protocols([ALPN])
    reader, writer = await asyncio.open_connection(
        target["host"], target["port"], ssl=context, server_hostname=target["host"]
    )
    try:
        if writer.get_extra_info("ssl_object").selected_alpn_protocol() not in (None, ALPN):
            raise ValueError("Unknown upstream protocol")
        await _send(writer, PRELOGIN, _prelogin())
        _check_prelogin(await _receive(reader, REPLY), upstream=True)
        password = await asyncio.to_thread(read_password, target)
        login = _login(target["user"], password, target["database"], target["host"], size)
        await _send(writer, LOGIN7, login)
        response = _login_reply(await _receive(reader, REPLY))
        await _send(client_writer, REPLY, response, packet_size=min(4096, size))
        return reader, writer
    except BaseException:
        writer.transport.abort()
        raise
