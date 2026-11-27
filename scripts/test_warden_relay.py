"""Exercise the actual native data path using only a local broker and an AF_UNIX Agent."""
import asyncio
from contextlib import suppress
import os
from pathlib import Path
import socket
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dbproxy.native_relay import relay
from plugin_runtime import PluginRuntime


async def read_bytes(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = await asyncio.get_running_loop().sock_recv(sock, size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class WardenRelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.binary = PluginRuntime(core=os.environ.get("KEYHERON_TEST_CORE")).binary
        self.loop = asyncio.get_running_loop()
        self.agent, self.agent_fd = socket.socketpair()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            self.broker_fd = socket.create_connection(listener.getsockname())
            self.broker, _ = listener.accept()
        for sock in (self.agent, self.broker, self.agent_fd, self.broker_fd):
            sock.setblocking(False)
            self.addCleanup(sock.close)

    async def test_prefetched_and_live_native_bytes_in_order_and_half_close(self):
        agent = await asyncio.open_unix_connection(sock=self.agent_fd, limit=4096)
        broker = await asyncio.open_connection(sock=self.broker_fd)
        # A protocol marker may already be followed by PostgreSQL startup or a MySQL greeting.
        await self.loop.sock_sendall(self.agent, b"\x01early-agent")
        await self.loop.sock_sendall(self.broker, b"\x01early-broker")
        self.assertEqual(await agent[0].readexactly(1), b"\x01")
        self.assertEqual(await broker[0].readexactly(1), b"\x01")
        agent[1].write(b"approved\n")
        async with asyncio.timeout(8):
            worker = asyncio.create_task(relay(self.binary, agent, broker, self.loop.time() + 7))
            try:
                self.assertEqual(await read_bytes(self.agent, 21), b"approved\nearly-broker")
                self.assertEqual(await read_bytes(self.broker, 11), b"early-agent")
                packet = bytes(range(256)) * 2048
                await asyncio.gather(self.loop.sock_sendall(self.agent, packet),
                                     self._assert_received(self.broker, packet))
                self.agent.shutdown(socket.SHUT_WR)
                self.assertEqual(await self.loop.sock_recv(self.broker, 1), b"")
                await self.loop.sock_sendall(self.broker, b"last-reply")
                self.broker.shutdown(socket.SHUT_WR)
                self.assertEqual(await read_bytes(self.agent, 10), b"last-reply")
                await worker
            finally:
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)

    async def _assert_received(self, sock, packet):
        self.assertEqual(await read_bytes(sock, len(packet)), packet)

    async def test_child_exits_on_control_eof_or_ttl_and_rejects_wrong_fd(self):
        for trigger in ("warden-exit", "ttl", "wrong-fd"):
            with self.subTest(trigger=trigger):
                parent, child = socket.socketpair()
                with parent, child:
                    agent_fd = self.agent_fd.fileno()
                    broker_fd = self.broker_fd.fileno() if trigger != "wrong-fd" else self.agent.fileno()
                    ttl = "60" if trigger == "ttl" else "900000"
                    proc = await asyncio.create_subprocess_exec(
                        self.binary, "db-relay", str(agent_fd), str(broker_fd), ttl,
                        pass_fds=(agent_fd, broker_fd), stdin=child, stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL, env={},
                    )
                    try:
                        child.close()
                        if trigger == "warden-exit":
                            await self.loop.sock_sendall(self.agent, b"R")
                            self.assertEqual(await asyncio.wait_for(read_bytes(self.broker, 1), 5), b"R")
                            parent.close()
                        code = await asyncio.wait_for(proc.wait(), 5)
                        self.assertEqual(code == 0, trigger != "wrong-fd")
                    finally:
                        if proc.returncode is None:
                            with suppress(ProcessLookupError):
                                proc.kill()
                            await proc.wait()


if __name__ == "__main__":
    unittest.main()
