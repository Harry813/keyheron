"""Sandbox-side connector client. This file can be copied into an Agent image on its own."""

import argparse
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import tempfile


MAX_CONNECTIONS = 16


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
    if expires.utcoffset() is None:
        raise ValueError("数据库会话缺少有效的到期时间")
    ttl = (expires - datetime.now(timezone.utc)).total_seconds()
    if ttl <= 0:
        raise ConnectionError("数据库会话已到期")
    deadline = asyncio.get_running_loop().time() + ttl
    with tempfile.TemporaryDirectory(prefix="keyheron-client-") as tmp:
        for field, file_field in (("ca_pem", "ca_file"), ("server_certificate_pem", "server_certificate")):
            if field in descriptor:
                path = Path(tmp) / (file_field + ".pem")
                path.write_text(descriptor.pop(field), encoding="ascii")
                descriptor[file_field] = str(path)
        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        try:
            async with asyncio.timeout_at(deadline):
                if asyncio.get_running_loop().time() >= deadline:
                    raise ConnectionError("数据库会话已到期")
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


async def _stop_workers(workers):
    for worker in workers:
        if not worker.done() and not worker.cancelling():
            worker.cancel()
    if workers:
        # Cancelling a client request must not cancel the workers a second time during cleanup.
        cleanup = asyncio.gather(*workers, return_exceptions=True)
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await asyncio.shield(cleanup)
            raise


async def _close_stream(reader, writer, *, native):
    try:
        if native and not writer.is_closing() and not writer.transport.get_write_buffer_size():
            # A write-side EOF also releases a Warden still waiting for the first SQL client.
            # Give the peer time to finish its stream; discard any final native bytes locally.
            async with asyncio.timeout(2):
                writer.write_eof()
                while await reader.read(65536):
                    pass
    except (ConnectionError, TimeoutError):
        pass
    finally:
        if asyncio.current_task().cancelling():
            writer.transport.abort()
        else:
            writer.close()
        try:
            async with asyncio.timeout(2):
                await writer.wait_closed()
        except (ConnectionError, TimeoutError):
            writer.transport.abort()


class ConnectorSession:
    """Sandbox-local client for one Warden socket; the context owns its live native bridges."""

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self._open = False
        self._workers = set()
        self._connections = {}

    async def __aenter__(self):
        if self._open or self._workers:
            raise RuntimeError("连接器会话正在使用")
        self._open = True
        return self

    async def __aexit__(self, *_):
        self._open = False
        await _stop_workers(tuple(self._workers))

    async def list(self):
        result, _ = await self._request({"op": "list"})
        return result

    async def describe(self, connector):
        result, _ = await self._request({"api_version": 1, "op": "describe", "connector": connector})
        return result

    async def invoke(self, connector, action, resource):
        result, _ = await self._invoke(connector, action, resource)
        return result

    async def _invoke(self, connector, action, resource):
        return await self._request({"connector": connector, "action": action, "resource": resource})

    async def close_connection(self, handle):
        worker = self._connections.get(handle) if isinstance(handle, str) else None
        if worker is None:
            raise ValueError("未知或已关闭的数据库连接")
        await _stop_workers((worker,))

    def _finished(self, worker):
        self._workers.discard(worker)
        if not worker.cancelled():
            worker.exception()  # A bridge can expire or be revoked after invoke() has returned.

    async def _request(self, request):
        if not self._open:
            raise RuntimeError("请在连接器会话中执行操作")
        ready = asyncio.get_running_loop().create_future()
        worker = asyncio.create_task(self._exchange(request, ready))
        self._workers.add(worker)
        worker.add_done_callback(self._finished)
        try:
            await asyncio.wait((worker, ready), return_when=asyncio.FIRST_COMPLETED)
            if worker.done():
                result = worker.result()
                if ready.done():
                    raise ConnectionError("数据库会话已结束")
                return result, None
            return ready.result(), worker
        except BaseException:
            await _stop_workers((worker,))
            raise
        finally:
            if not ready.done():
                ready.cancel()

    async def _exchange(self, request, ready):
        writer = handle = None
        try:
            async with asyncio.timeout(35):
                body = json.dumps(request).encode("utf-8") + b"\n"
                if len(body) > 4096:
                    raise ValueError("连接器请求超出大小限制")
                reader, writer = await asyncio.open_unix_connection(self.socket_path, limit=2 * 1024 * 1024)
                writer.write(body)
                await writer.drain()
                try:
                    reply = json.loads(await reader.readuntil(b"\n"))
                except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, ValueError, RecursionError):
                    raise ConnectionError("Warden 响应无效或连接已关闭") from None
            if isinstance(reply, dict) and set(reply) == {"error"} and isinstance(reply["error"], str):
                raise RuntimeError(reply["error"])
            if not isinstance(reply, dict) or "result" not in reply or reply.keys() - {"result", "transport"}:
                raise ConnectionError("Warden 未返回有效结果")
            transport = reply.get("transport")
            # The first Warden release omitted transport for its database/connect connector.
            if transport is None and (request.get("connector"), request.get("action")) == ("database", "connect"):
                transport = "database-stream"
            if transport is None:
                return reply["result"]
            if transport != "database-stream" or "action" not in request:
                raise RuntimeError("Warden 返回了不支持的连接器传输方式")
            descriptor = reply["result"]
            if not isinstance(descriptor, dict) or not isinstance(descriptor.get("expires_at"), str):
                raise ConnectionError("Warden 未返回有效数据库会话")
            if len(self._connections) >= MAX_CONNECTIONS:
                raise RuntimeError("当前连接器会话的数据库连接数已达上限")
            handle = secrets.token_urlsafe(24)
            self._connections[handle] = asyncio.current_task()

            def publish(path):
                ready.set_result({"handle": handle, "descriptor_path": str(path), "expires_at": descriptor["expires_at"]})

            await serve_one_database((reader, writer), descriptor, publish)
        finally:
            try:
                if writer is not None:
                    await _close_stream(reader, writer, native=handle is not None)
            finally:
                if handle is not None:
                    self._connections.pop(handle, None)


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
    async with ConnectorSession(args.socket) as session:
        if args.operation == "list":
            result = await session.list()
        elif args.operation == "describe":
            result = await session.describe(args.connector)
        else:
            result, worker = await session._invoke(args.connector, args.plugin_action, args.resource)
            if worker is not None:
                print(result["descriptor_path"], flush=True)
                await worker
                return
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    try:
        asyncio.run(run(parser.parse_args()))
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")
