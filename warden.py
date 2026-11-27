"""One trusted Warden owns a private Unix socket for exactly one task."""

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
from functools import partial
import json
import os
import signal
import socket
import stat

from dbproxy.native_relay import relay
from warden_client import wait_for_peer
from plugin_runtime import PluginRuntime
from warden_control import ControlClient, _object, valid_id
from warden_plugins import PluginHost


async def respond(writer, body):
    writer.write(json.dumps(body, ensure_ascii=False).encode("utf-8") + b"\n")
    await writer.drain()


async def handle(reader, writer, host, client, task):
    descriptor = None
    upstream = None
    sent_result = False
    try:
        async with asyncio.timeout(5):
            request = json.loads(await reader.readuntil(b"\n"), object_pairs_hook=_object)
        versioned = isinstance(request, dict) and "api_version" in request
        if versioned:
            version = request.pop("api_version")
            if type(version) is not int or version != 1 or request.get("op") not in ("list", "describe", "invoke"):
                raise ValueError
        describe = versioned and request.get("op") == "describe"
        if request == {"op": "list"} or describe:
            if describe and (set(request) != {"op", "connector"} or not valid_id(request["connector"])):
                raise ValueError
            rules = await asyncio.to_thread(client.capabilities, task)
            available = [r for r in rules if host.available(r["connector"], r["action"], r["resource"])]
            if describe:
                connector = request["connector"]
                resources = [{"resource": r["resource"], "ttl": r["ttl"]}
                             for r in available if r["connector"] == connector]
                if not resources:
                    raise PermissionError
                await respond(writer, {"result": {**host.runtime.plugins[connector], "resources": resources}})
            else:
                await respond(writer, {"result": available})
            return
        if versioned and request.pop("op") != "invoke":
            raise ValueError
        scope = ("connector", "action", "resource")
        if (not isinstance(request, dict) or set(request) != set(scope)
                or not all(valid_id(request[key]) for key in scope)):
            raise ValueError
        result = await host.invoke(*(request[key] for key in scope))
        if not host.runtime.plugins[request["connector"]]["native_stream"]:
            await respond(writer, {"result": result})
            return

        # Addresses come exclusively from our own DB broker. The Agent supplies only a resource ID.
        descriptor = result
        public = {k: v for k, v in result.items() if k not in ("host", "port", "session_id")}
        await respond(writer, {"result": public, "transport": "database-stream"})
        sent_result = True
        ttl = (datetime.fromisoformat(result["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
        async with asyncio.timeout(ttl) as lifetime:
            start = await wait_for_peer(reader.readexactly(1), host.wait_database_closed(descriptor))
            if start != b"\x01":
                return
            upstream = await host.open_database_stream(descriptor)
            await wait_for_peer(relay(host.runtime.binary, (reader, writer), upstream, lifetime.when()),
                                host.wait_database_closed(descriptor))
    except (ValueError, RecursionError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
        if not sent_result:
            await respond(writer, {"error": "连接器请求无效"})
    except PermissionError:
        if not sent_result:
            await respond(writer, {"error": "任务未获此连接器操作的授权"})
    except (OSError, RuntimeError):
        if not sent_result:
            await respond(writer, {"error": "连接器或授权服务不可用"})
    finally:
        if upstream:
            upstream[1].close()
        writer.close()
        if descriptor:
            await host.close_database(descriptor)


async def serve(args):
    if not valid_id(args.task):
        raise ValueError("任务名称无效")
    state = args.state_dir.absolute()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Warden 状态目录必须由当前账户独占，权限 0700")
    client = ControlClient(args.server, args.ca, args.cert, args.key)
    # Verify identity, registration and policy before exposing the task endpoint.
    await asyncio.to_thread(client.capabilities, args.task)
    workers = {}
    stopped = asyncio.Event()
    path = state / "warden.sock"
    loop = asyncio.get_running_loop()

    def finished(worker):
        workers.pop(worker).close()
        if not worker.cancelled():
            worker.exception()

    runtime = PluginRuntime(args.plugin_manifest, args.core)
    async with PluginHost(args.plugins, state, args.task, client.plugin_grant, client.event, runtime,
                          session_grant=partial(client.plugin_grant, session_check=True)) as host:
        def accept(reader, writer):
            if len(workers) >= 32 or stopped.is_set():
                writer.close()
                return
            worker = asyncio.create_task(handle(reader, writer, host, client, args.task))
            workers[worker] = writer
            worker.add_done_callback(finished)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            # bind() refuses an existing endpoint, including another running Warden.
            sock.bind(str(path))
            bound = path.lstat()
            server = None
            try:
                path.chmod(0o600)
                sock.listen(32)
                sock.setblocking(False)
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                    loop.add_signal_handler(sig, stopped.set)
                server = await asyncio.start_unix_server(accept, sock=sock, limit=4096)
                print(f"Warden 已就绪 {path}", flush=True)
                await stopped.wait()
            finally:
                stopped.set()
                if server is not None:
                    server.close()
                for worker, writer in workers.copy().items():
                    writer.transport.abort()
                    worker.cancel()
                if workers:
                    await asyncio.gather(*workers, return_exceptions=True)
                if server is not None:
                    await server.wait_closed()
                with suppress(FileNotFoundError):
                    if os.path.samestat(bound, path.lstat()):
                        path.unlink()
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                    loop.remove_signal_handler(sig)
    return 0
