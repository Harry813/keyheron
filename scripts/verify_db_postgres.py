"""Use an encrypted credential and native psql against a temporary TLS/SCRAM server."""

from contextlib import closing, suppress
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from verify_external import make_ca
from credential_store import initialize, unlock
from verify_warden_postgres import verify_managed_postgres


def read_line(pipe, timeout=15):
    with selectors.DefaultSelector() as selector:
        selector.register(pipe, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise TimeoutError("Timed out waiting for the database fixture")
    return pipe.readline()


def verify(tmp):
    binaries = os.environ.get("PG_BIN") or subprocess.check_output(
        ["pg_config", "--bindir"], text=True).strip()
    initdb, pg_ctl = (str(Path(binaries) / name) for name in ("initdb", "pg_ctl"))
    psql = os.environ.get("PSQL") or shutil.which("psql") or str(Path(binaries) / "psql")
    data = tmp / "cluster"
    password = secrets.token_hex(32)
    phrase = secrets.token_urlsafe(32).encode()
    phrase_file = tmp / "unlock"
    phrase_file.write_bytes(phrase)
    phrase_file.chmod(0o600)
    vault = tmp / "vault" / "credentials.sqlite3"
    initialize(vault, phrase)
    unlock(vault, phrase).put("DEV", "reader", password.encode())
    tls = tmp / "tls"
    make_ca(tls)
    (tls / "server.key").chmod(0o600)
    # initdb needs the initial DB user's password. Remove its private bootstrap
    # file before starting either server, so the broker can only use the vault.
    with tempfile.NamedTemporaryFile(dir=tmp) as bootstrap:
        bootstrap.write(password.encode() + b"\n")
        bootstrap.flush()
        subprocess.run([initdb, "-D", data, "-U", "fixture_owner", "--encoding=UTF8",
                        "--no-locale", "--auth=scram-sha-256", "--pwfile", bootstrap.name],
                       check=True, stdout=subprocess.DEVNULL, timeout=60)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with (data / "postgresql.conf").open("a") as config:
        config.write(f"\nlisten_addresses='127.0.0.1'\nport={port}\nunix_socket_directories=''\n"
                     f"ssl=on\nssl_cert_file='{tls}/server.pem'\nssl_key_file='{tls}/server.key'\n")
    policy = tmp / "policy.json"
    policy.write_text(json.dumps({
        "version": 1, "task": "pg-integration",
        "identities": {"applicant": "client", "approver": "operator"},
        "credential_store": {"path": "vault/credentials.sqlite3", "passphrase_file": "unlock"},
        "environments": {"DEV": {"databases": {"sample": {
            "engine": "postgresql", "host": "localhost", "port": port, "user": "fixture_owner",
            "database": "postgres", "password_ref": "reader", "ca_file": "tls/root.pem"
        }}}}
    }))
    state = tmp / "state"
    startup = subprocess.run([pg_ctl, "-D", data, "-l", tmp / "postgres.log", "-w", "start"],
                             stdout=subprocess.DEVNULL, timeout=60)
    if startup.returncode:
        raise RuntimeError("PostgreSQL fixture startup failed: " + (tmp / "postgres.log").read_text())
    try:
        with subprocess.Popen([sys.executable, ROOT / "keyheron.py", "db", "--config", policy,
                               "--env", "DEV", "--target", "sample", "--state-dir", state],
                              stdout=subprocess.PIPE, text=True) as broker:
            try:
                line = read_line(broker.stdout)
                if not line:
                    raise RuntimeError("Database broker failed to publish its session")
                descriptor = Path(line.rstrip().split(" ", 1)[1])
                info = json.loads(descriptor.read_text())
                assert password not in descriptor.read_text()
                assert phrase not in descriptor.read_bytes()
                # The client process receives only local credentials and connectivity.
                client_env = {"PATH": os.defpath, "PGSSLMODE": "disable", "PGCONNECT_TIMEOUT": "5",
                              "PGPASSWORD": info["password"], "HOME": str(tmp / "unused-client-home")}
                client = [psql, "-X", "-w", "-v", "ON_ERROR_STOP=1", "-At", "-h", info["host"],
                          "-p", str(info["port"]), "-d", info["database"], "-U", info["user"]]
                result = subprocess.check_output(
                    [*client, "-c", "select current_user, current_database(), 6 * 7"],
                    env=client_env, text=True, timeout=15)
                assert result.strip() == "fixture_owner|postgres|42", result
                with subprocess.Popen(client, env=client_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True) as active:
                    try:
                        active.stdin.write("select 17;\n")
                        active.stdin.flush()
                        assert read_line(active.stdout).strip() == "17"
                        broker.terminate()
                        assert broker.wait(8) == 0
                        assert not descriptor.exists()
                        with suppress(BrokenPipeError):
                            active.stdin.write("select 9;\n")
                            active.stdin.flush()
                        assert active.wait(8) != 0
                    finally:
                        if active.poll() is None:
                            active.kill()
                with closing(sqlite3.connect(state / "db-events.sqlite3")) as audit:
                    actions = [row[0] for row in audit.execute("SELECT action FROM database_events ORDER BY id")]
                    assert actions.count("connect") == 2 and actions[-1] == "close", actions
            finally:
                if broker.poll() is None:
                    broker.terminate()
        verify_managed_postgres(policy, psql)
    finally:
        subprocess.run([pg_ctl, "-D", data, "-m", "immediate", "-w", "stop"],
                       check=True, stdout=subprocess.DEVNULL, timeout=30)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="keyheron-pg-") as directory:
        verify(Path(directory))
    print("PostgreSQL TLS/SCRAM, native psql query and revocation passed in standalone and Warden modes.")
