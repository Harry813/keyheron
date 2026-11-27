"""Warden-managed psql round trip and revocation against the running PostgreSQL fixture."""

from contextlib import closing, suppress
import json
import os
import secrets
import socket
from pathlib import Path
import sqlite3
import subprocess
import tempfile

from test_warden_control import IDENTITY, client_cert
from test_warden_e2e import first_line, process
from verify_external import make_ca
from warden_admin import change, snapshot


def verify_managed_postgres(config, psql):
    # A short path also fits Darwin's sun_path limit when TMPDIR has a long prefix.
    with tempfile.TemporaryDirectory(prefix="kh-pg-", dir="/tmp") as temporary, socket.socket() as mysql_probe:
        root = Path(temporary)
        ca = root / "control"
        make_ca(ca)
        cert, key = client_cert(ca, "db-warden", "URI:" + IDENTITY)
        policy, audit = root / "policy.json", root / "audit.db"
        task, scope = "query-orders", {"connector": "postgresql", "action": "connect", "resource": "orders"}
        grants = [{**scope, "ttl": 60}]
        rules = {"version": 1, "wardens": {IDENTITY: {"tasks": {task: grants}}}}
        policy.write_text(json.dumps(rules))
        plugins = root / "plugins.json"
        # Both engines have a valid local resource named orders. Only PostgreSQL is authorized.
        mysql_probe.bind(("127.0.0.1", 0))
        mysql_probe.listen()
        mysql_probe.setblocking(False)
        mysql_config = root / "mysql.json"
        password_file = root / "mysql.password"
        password_file.write_text(secrets.token_hex(16))
        password_file.chmod(0o600)
        mysql_config.write_text(json.dumps({
            "version": 1, "task": task, "identities": {"applicant": "reader", "approver": "owner"},
            "environments": {"DEV": {"databases": {"sample": {
                "engine": "mysql", "host": "127.0.0.1", "port": mysql_probe.getsockname()[1],
                "user": "fixture", "database": "fixture", "password_file": str(password_file),
            }}}},
        }))
        plugins.write_text(json.dumps({
            engine: {"orders": {"config": str(path.absolute()), "env": "DEV", "target": "sample"}}
            for engine, path in (("postgresql", config), ("mysql", mysql_config))
        }))
        state = root / "state"
        client_cli = ("connector", "--socket", state / "warden.sock")
        invoke = (*client_cli, "invoke", "postgresql", "connect", "orders")
        with process("warden-server", "--port", 0, "--policy", policy, "--audit", audit, "--ca", ca / "root.pem",
                     "--cert", ca / "server.pem", "--key", ca / "server.key") as server:
            port = int(first_line(server).strip().rsplit(":", 1)[1])
            with process("warden", "--server", f"https://localhost:{port}", "--ca", ca / "root.pem",
                         "--cert", cert, "--key", key, "--task", task, "--plugins", plugins,
                         "--state-dir", state) as warden:
                first_line(warden)
                with process(*client_cli, "list") as listing:
                    stdout, stderr = listing.communicate(timeout=5)
                    assert listing.returncode == 0 and json.loads(stdout) == grants, stderr
                with process(*client_cli, "invoke", "mysql", "connect", "orders") as other:
                    stdout, _ = other.communicate(timeout=5)
                    assert other.returncode != 0 and stdout == ""
                with process(*invoke) as bridge:
                    descriptor = Path(first_line(bridge).strip())
                    info = json.loads(descriptor.read_text())
                    assert info["engine"] == "postgresql" and info["host"] == "127.0.0.1" and info["user"] == "keyheron"
                    env = {"PATH": os.defpath, "PGSSLMODE": "disable", "PGCONNECT_TIMEOUT": "5",
                           "PGPASSWORD": info["password"], "HOME": str(root / "unused-client-home")}
                    client = [psql, "-X", "-w", "-v", "ON_ERROR_STOP=1", "-At", "-h", info["host"],
                              "-p", str(info["port"]), "-d", info["database"], "-U", info["user"]]
                    with subprocess.Popen(client, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True) as active:
                        try:
                            active.stdin.write("select current_user, current_database(), 6 * 7;\n")
                            active.stdin.flush()
                            assert first_line(active, timeout=5).strip() == "fixture_owner|postgres|42"
                            revoked = change(policy, "revoke", {
                                "revision": snapshot(policy)["revision"], "warden": IDENTITY, "task": task,
                            })
                            assert task not in revoked["policy"]["wardens"][IDENTITY]["tasks"]
                            bridge.wait(timeout=8)
                            assert not descriptor.exists()
                            with suppress(BrokenPipeError):
                                active.stdin.write("select 9;\n")
                                active.stdin.flush()
                            assert active.wait(timeout=5) != 0
                            assert "9" not in active.stdout.read().splitlines()
                        finally:
                            if active.poll() is None:
                                active.kill()
                with process(*invoke) as blocked:
                    assert blocked.wait(timeout=5) != 0 and blocked.stdout.read() == ""
                with closing(sqlite3.connect(state / "db-events.sqlite3")) as db:
                    rows = db.execute("SELECT engine, action FROM database_events ORDER BY id").fetchall()
                    assert {engine for engine, _ in rows} == {"postgresql"}, rows
                    actions = [action for _, action in rows]
                    assert actions.count("open") == actions.count("connect") == 1 and actions[-1] == "close", actions
            with closing(sqlite3.connect(audit)) as db:
                events = {row for row in db.execute(
                    """SELECT connector, kind, result FROM warden_events
                       WHERE warden=? AND task=? AND action='connect' AND resource='orders'""", (IDENTITY, task))}
                assert {("postgresql", "authorization", "allowed"), ("postgresql", "authorization", "denied"),
                        ("postgresql", "reported", "succeeded"), ("postgresql", "reported", "closed"),
                        ("mysql", "authorization", "denied")} == events, events
        try:
            unexpected, _ = mysql_probe.accept()
        except BlockingIOError:
            return
        unexpected.close()
        raise AssertionError("A denied MySQL request reached the probe")
