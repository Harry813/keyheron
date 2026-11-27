"""Sandbox-side connector client. This file can be copied into an Agent image on its own."""

import argparse
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile


async def relay(left, right):
    async def copy(reader, writer):
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()

    streams = [asyncio.create_task(copy(left[0], right[1])),
               asyncio.create_task(copy(right[0], left[1]))]
    try:
        done, _ = await asyncio.wait(streams, return_when=asyncio.FIRST_COMPLETED)
        for stream in done:
            stream.result()
    finally:
        for stream in streams:
            stream.cancel()
        await asyncio.gather(*streams, return_exceptions=True)


async def wait_for_peer(ready, closed):
    pending = asyncio.ensure_future(ready)
    ended = asyncio.create_task(closed)
    try:
        await asyncio.wait((pending, ended), return_when=asyncio.FIRST_COMPLETED)
        if ended.done():
            raise ConnectionError("数据库会话已关闭")
        return pending.result()
    finally:
        for future in (pending, ended):
            future.cancel()
        await asyncio.gather(pending, ended, return_exceptions=True)


async def serve_one_database(remote, descriptor, ready):
    """Publish a single sandbox-local endpoint and bridge it only to this authorized session."""
    accepted = asyncio.get_running_loop().create_future()

    def accept(reader, writer):
        if accepted.done():
            writer.close()
        else:
            accepted.set_result((reader, writer))

    expires = datetime.fromisoformat(descriptor["expires_at"])
    ttl = (expires - datetime.now(timezone.utc)).total_seconds()
    with tempfile.TemporaryDirectory(prefix="keyheron-client-") as tmp:
        for field, file_field in (("ca_pem", "ca_file"), ("server_certificate_pem", "server_certificate")):
            if field in descriptor:
                path = Path(tmp) / (file_field + ".pem")
                path.write_text(descriptor.pop(field), encoding="ascii")
                descriptor[file_field] = str(path)
        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        try:
            async with asyncio.timeout(ttl):
                descriptor.update(host="127.0.0.1", port=server.sockets[0].getsockname()[1])
                path = Path(tmp) / "connection.json"
                with path.open("x") as out:
                    os.fchmod(out.fileno(), 0o600)
                    json.dump(descriptor, out)
                ready(path)
                # The Warden sends native bytes only after the local client is ready.
                local = await wait_for_peer(accepted, remote[0].read(1))
                server.close()
                remote[1].write(b"\x01")
                await remote[1].drain()
                await relay(local, remote)
        finally:
            server.close()
            # Close an active SQL client before waiting for the listener to drain it.
            if accepted.done() and not accepted.cancelled():
                accepted.result()[1].transport.abort()
            else:
                accepted.cancel()
            await server.wait_closed()


def add_arguments(parser):
    parser.add_argument("--socket", type=Path,
                        default=os.environ.get("KEYHERON_WARDEN_SOCKET", "/run/keyheron/warden.sock"))
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("list", help="查看本次任务当前可用的连接器")
    describe = sub.add_parser("describe", help="查看已授权插件的接口与资源")
    describe.add_argument("connector")
    use = sub.add_parser("invoke", help="调用任务已获授权的连接器")
    use.add_argument("connector")
    use.add_argument("plugin_action", metavar="action")
    use.add_argument("resource")


async def run(args):
    if args.operation == "list":
        request = {"op": "list"}
    elif args.operation == "describe":
        request = {"api_version": 1, "op": "describe", "connector": args.connector}
    else:
        request = {"connector": args.connector, "action": args.plugin_action, "resource": args.resource}
    reader, writer = await asyncio.open_unix_connection(args.socket, limit=2 * 1024 * 1024)
    try:
        writer.write(json.dumps(request).encode() + b"\n")
        await writer.drain()
        async with asyncio.timeout(35):
            reply = json.loads(await reader.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"])
        transport = reply.get("transport")
        # Older Wardens only supported database/connect and omitted the transport field.
        if transport is None and (request.get("connector"), request.get("action")) == ("database", "connect"):
            transport = "database-stream"
        if transport == "database-stream":
            await serve_one_database((reader, writer), reply["result"], lambda path: print(path, flush=True))
        elif transport is None:
            print(json.dumps(reply["result"], ensure_ascii=False, indent=2))
        else:
            raise RuntimeError("连接器使用了当前客户端不支持的传输方式")
    finally:
        writer.close()
        with suppress(ConnectionError):
            await writer.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    try:
        asyncio.run(run(parser.parse_args()))
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")
