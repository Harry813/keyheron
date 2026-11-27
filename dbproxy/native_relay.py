"""Hand off the two plaintext Warden-side socket transports after authorization."""

import asyncio
from contextlib import ExitStack, suppress
import math
import socket


async def relay(binary, agent, broker, deadline):
    loop = asyncio.get_running_loop()
    peers = (agent, broker)
    with ExitStack() as descriptors:
        sockets = []
        for _, writer in peers:
            if writer.get_extra_info("ssl_object") is not None:
                raise ValueError("TLS 终端不可交给原生字节中继")
            source = writer.get_extra_info("socket")
            if source is None:
                raise ConnectionError("数据库中继连接已关闭")
            sockets.append(descriptors.enter_context(source.dup()))
        for _, writer in peers:
            writer.transport.pause_reading()
            writer.close()
        # Graceful close flushes queued writes and delivers EOF to StreamReader. The duplicates
        # retain the actual connections, and StreamReader.read() now returns just read-ahead.
        await asyncio.gather(*(writer.wait_closed() for _, writer in peers))
        prefixes = await asyncio.gather(*(reader.read() for reader, _ in peers))
        await asyncio.gather(*(loop.sock_sendall(dest, prefix)
                               for dest, prefix in zip(reversed(sockets), prefixes) if prefix))

        ttl_ms = min(900_000, math.floor((deadline - loop.time()) * 1000))
        if ttl_ms <= 0:
            raise TimeoutError("数据库会话已到期")
        parent, child = socket.socketpair()
        with parent, child:
            fds = [sock.fileno() for sock in sockets]
            process = await asyncio.create_subprocess_exec(
                binary, "db-relay", *map(str, fds), str(ttl_ms),
                stdin=child, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                pass_fds=fds, env={},
            )
            child.close()
            # The child now owns the data path. Closing this control socket on Warden exit
            # also terminates the relay after an uncatchable process kill.
            descriptors.close()
            try:
                if await process.wait() != 0:
                    raise ConnectionError("原生数据库中继未完成")
            finally:
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
