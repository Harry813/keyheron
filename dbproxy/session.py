"""A foreground broker owns one target, one deadline, and every socket of its session."""

import asyncio
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from importlib import import_module
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import ssl
import tempfile
import uuid

from agent_access import _openssl, _private_write, unlock_policy_store
from dbproxy import read_password
from dbproxy.mysql import AccountChangeDenied, relay_commands
from web_demo import database_session


def local_tls(directory):
    # A separate local trust anchor keeps upstream identity validation independent.
    ca = directory / "client-ca.pem"
    ca_key, key = directory / "ca.key", directory / "server.key"
    cert, csr = directory / "server.pem", directory / "server.csr"
    config = directory / "openssl.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign\n[leaf]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    )
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-config", config, "-extensions",
             "ca", "-subj", "/CN=KeyHeron session CA", "-days", "1", "-keyout", ca_key, "-out", ca)
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-config", config, "-subj", "/CN=localhost",
             "-keyout", key, "-out", csr)
    _openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-set_serial",
             str(secrets.randbits(120) + 1), "-days", "1", "-extfile", config,
             "-extensions", "leaf", "-out", cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["tds/8.0"])
    context.load_cert_chain(cert, key)
    key.unlink()
    ca_key.unlink()
    return context, ca


async def relay(left, right, stop, deadline, *, mysql_commands=False):
    loop = asyncio.get_running_loop()

    async def copy(reader, writer):
        while data := await reader.read(65536):
            if stop.is_set() or loop.time() >= deadline:
                return
            writer.write(data)
            await writer.drain()

    outbound = (relay_commands(left[0], right[1], stop, deadline) if mysql_commands
                else copy(left[0], right[1]))
    flows = [asyncio.create_task(outbound),
             asyncio.create_task(copy(right[0], left[1]))]
    try:
        done, _ = await asyncio.wait(flows, return_when=asyncio.FIRST_COMPLETED)
        for flow in done:
            flow.result()
    finally:
        for flow in flows:
            flow.cancel()
        await asyncio.gather(*flows, return_exceptions=True)


async def run_session(target, ttl, directory, record, stop, *, on_ready=None):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + ttl
    engine = target["engine"]
    if engine == "postgresql":
        try:
            import_module("scramp")
        except ImportError:
            raise RuntimeError("PostgreSQL 连接需要安装 requirements-db-postgres.txt 中的依赖") from None
    adapter = import_module("dbproxy." + engine)
    password = secrets.token_urlsafe(32)
    tls_options = {}
    public = {"engine": engine, "host": "127.0.0.1", "database": target["database"],
              "user": "keyheron", "password": password}
    if engine == "sqlserver":
        context, ca = await asyncio.to_thread(local_tls, directory)
        tls_options = {"ssl": context, "ssl_handshake_timeout": 5}
        public.update(ca_file=str(ca), server_certificate=str(directory / "server.pem"),
                      encrypt="strict")

    tasks = set()

    async def connection(reader, writer):
        upstream = None
        try:
            async with asyncio.timeout_at(min(deadline, loop.time() + 15)):
                upstream = await adapter.authenticate(reader, writer, target, password)
            if stop.is_set() or loop.time() >= deadline:
                return
            record("connect", "allowed")
            async with asyncio.timeout_at(deadline):
                await relay((reader, writer), upstream, stop, deadline, mysql_commands=engine == "mysql")
        except asyncio.CancelledError:
            raise
        except AccountChangeDenied:
            record("change_user", "denied")
        except sqlite3.Error:
            # Losing the audit trail closes this session and every peer.
            stop.set()
            raise
        except Exception:
            # Driver errors can contain credentials, DSNs, server text or row data.
            record("disconnect" if upstream else "login", "closed" if upstream else "failed")
        finally:
            writer.transport.abort()
            if upstream is not None:
                upstream[1].transport.abort()

    def finished(task, writer):
        # Cancellation can preempt a freshly scheduled task before its first line.
        writer.transport.abort()
        tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            stop.set()

    def accept(reader, writer):
        if stop.is_set() or loop.time() >= deadline or len(tasks) >= 16:
            writer.transport.abort()
            return
        task = asyncio.create_task(connection(reader, writer))
        tasks.add(task)
        task.add_done_callback(lambda done: finished(done, writer))

    listener = await asyncio.start_server(accept, "127.0.0.1", 0, backlog=16, **tls_options)
    try:
        public["port"] = listener.sockets[0].getsockname()[1]
        public["expires_at"] = (datetime.now(timezone.utc) + timedelta(
            seconds=max(0, deadline - loop.time()))).isoformat()
        if stop.is_set() or loop.time() >= deadline:
            return
        record("open", "allowed")
        if on_ready is None:
            descriptor = directory / "connection.json"
            _private_write(descriptor, public)
            print(f"数据库客户端连接信息（仅本次会话） {descriptor}", flush=True)
        else:
            on_ready(public)
        try:
            async with asyncio.timeout_at(deadline):
                await stop.wait()
        except TimeoutError:
            pass
    finally:
        stop.set()
        listener.close()
        # Cancel peers before wait_closed, which can itself wait for active transports.
        active = list(tasks)
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        await listener.wait_closed()
        record("expire" if loop.time() >= deadline else "close", "closed")


@contextmanager
def database_audit(path, session_id, task, actor, environment, target_name, engine):
    with closing(sqlite3.connect(path, timeout=1)) as audit:
        audit.execute("""CREATE TABLE IF NOT EXISTS database_events (
            id INTEGER PRIMARY KEY, at TEXT DEFAULT CURRENT_TIMESTAMP, session TEXT NOT NULL,
            task TEXT NOT NULL, actor TEXT NOT NULL, environment TEXT NOT NULL,
            target TEXT NOT NULL, engine TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL
        )""")

        def record(action, result):
            with audit:
                audit.execute("""INSERT INTO database_events
                    (session, task, actor, environment, target, engine, action, result)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (session_id, task, actor, environment, target_name, engine, action, result))

        yield record


async def serve_database(policy, args):
    target = policy["environments"].get(args.env, {}).get(args.target)
    if target is None:
        raise ValueError("该环境未配置此数据库目标")
    ttl = target["max_ttl"] if args.ttl is None else args.ttl
    if not 1 <= ttl <= target["max_ttl"]:
        raise ValueError("会话时限超出该数据库目标的策略")
    if "password_ref" in target:
        target = {**target, "_read_secret": unlock_policy_store(policy).reader(args.env, target["password_ref"])}
    read_password(target)  # Fail before publishing an unusable endpoint.
    if target.get("ca_file") and not Path(target["ca_file"]).is_file():
        raise ValueError("数据库 CA 文件不可用")
    state = args.state_dir.resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.stat().st_uid != os.getuid() or state.stat().st_mode & 0o077:
        raise ValueError("请使用当前用户独占的 0700 状态目录")
    path = state / "db-events.sqlite3"
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    signals = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    with (database_session(path), database_audit(path, uuid.uuid4().hex, policy["task"],
          policy["identities"]["applicant"], args.env, args.target, target["engine"]) as record,
          tempfile.TemporaryDirectory(prefix="session-", dir=state) as tmp):
        for sig in signals:
            loop.add_signal_handler(sig, stop.set)
        try:
            await run_session(target, ttl, Path(tmp), record, stop)
        finally:
            for sig in signals:
                loop.remove_signal_handler(sig)
    return 0
