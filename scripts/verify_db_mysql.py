"""Run a native MySQL 8 client and server through keyheron.py db.

Set MYSQL_BIN to a directory containing mysql and mysqld (or a MySQL binary
distribution root). This test creates and removes its own database instance.
"""

from contextlib import closing, contextmanager
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
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from verify_external import make_ca


def binaries():
    configured = os.environ.get("MYSQL_BIN")
    if configured:
        directory = Path(configured).resolve()
        if directory.is_file():
            directory = directory.parent
        if (directory / "bin" / "mysql").is_file():
            directory /= "bin"
        mysql, server = directory / "mysql", directory / "mysqld"
    else:
        mysql, server = (shutil.which(name) for name in ("mysql", "mysqld"))
    if not all(path and os.access(path, os.X_OK) for path in (mysql, server)):
        raise RuntimeError("Set MYSQL_BIN to the MySQL bin directory containing mysql and mysqld")
    return Path(mysql).resolve(), Path(server).resolve()


@contextmanager
def process(command, *, env):
    proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        proc.stdout.close()


def wait_until(predicate, proc, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("Fixture process exited before it became ready")
        if predicate():
            return
        time.sleep(0.05)
    raise RuntimeError("Timed out waiting for fixture")


def verify(tmp, mysql, server):
    tls = tmp / "certs"
    make_ca(tls)
    data = tmp / "data"
    data.mkdir()
    # Keep user-specific MySQL settings and login paths out of the fixture.
    env = {"MYSQL_TEST_LOGIN_FILE": str(tmp / "unused.mylogin.cnf"), "TMPDIR": str(tmp),
           "PATH": os.environ.get("PATH", os.defpath), "LANG": "C"}
    startup = [str(server), "--no-defaults", "--basedir=" + str(mysql.parent.parent),
               "--datadir=" + str(data)]
    subprocess.run([*startup, "--initialize", "--log-error=" + str(tmp / "init.log")],
                   env=env, check=True, timeout=90, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    password = secrets.token_urlsafe(32)
    secret = tmp / "password"
    secret.write_text(password)
    secret.chmod(0o600)
    bootstrap = tmp / "bootstrap.sql"
    bootstrap.write_text(
        "CREATE DATABASE fixture;\nCREATE TABLE fixture.verification (value varchar(32));\n"
        "INSERT INTO fixture.verification VALUES ('native-ok');\n"
        f"CREATE USER 'khreader'@'127.0.0.1' IDENTIFIED BY '{password}';\n"
        "GRANT SELECT ON fixture.* TO 'khreader'@'127.0.0.1';\n")
    bootstrap.chmod(0o600)
    with socket.socket() as picker:
        picker.bind(("127.0.0.1", 0))
        port = picker.getsockname()[1]
    target = dict(engine="mysql", host="localhost", port=port, user="khreader", database="fixture",
                  password_file=str(secret), ca_file=str(tls / "root.pem"))
    policy = tmp / "policy.json"
    policy.write_text(json.dumps({"version": 1, "task": "mysql-verification",
        "identities": {"applicant": "developer", "approver": "owner"},
        "environments": {"DEV": {"databases": {"orders": target}}}}))
    log = tmp / "server.log"
    state = tmp / "state"
    with process([*startup, "--bind-address=127.0.0.1", f"--port={port}",
                  f"--socket={tmp / 'db.sock'}", f"--log-error={log}", f"--init-file={bootstrap}",
                  "--mysqlx=OFF", "--skip-name-resolve", f"--ssl-cert={tls / 'server.pem'}",
                  f"--ssl-key={tls / 'server.key'}", f"--ssl-ca={tls / 'root.pem'}"], env=env) as instance:
        wait_until(lambda: log.is_file() and "ready for connections" in log.read_text(), instance, 45)
        with process([sys.executable, str(ROOT / "keyheron.py"), "db", "--config", str(policy),
                      "--state-dir", str(state), "--env", "DEV", "--target", "orders",
                      "--ttl", "60"], env=env) as broker:
            with selectors.DefaultSelector() as selector:
                selector.register(broker.stdout, selectors.EVENT_READ)
                if not selector.select(8):
                    raise RuntimeError("KeyHeron database session startup timed out")
                broker.stdout.readline()
            descriptor, = state.glob("session-*/connection.json")
            conn = json.loads(descriptor.read_text())
            assert conn["password"] != password and password not in descriptor.read_text()
            options = tmp / "client.cnf"
            options.write_text("[client]\npassword=" + conn["password"] + "\n")
            options.chmod(0o600)
            client = [str(mysql), f"--defaults-file={options}", "--protocol=TCP", "--ssl-mode=DISABLED",
                      "--local-infile=0", "--connect-timeout=4", "-h", conn["host"], "-P", str(conn["port"]),
                      "-u", conn["user"], conn["database"], "-BN", "-e"]

            def sql(query):
                return subprocess.run([*client, query], capture_output=True, text=True,
                                      env=env, timeout=8)

            result = sql("SELECT value FROM fixture.verification")
            assert result.returncode == 0 and result.stdout.strip() == "native-ok", "Native SELECT failed"
            result = sql("INSERT INTO fixture.verification VALUES ('denied')")
            assert result.returncode and "1142" in result.stderr, "Missing database privilege denial"
            options.write_text("[client]\npassword=incorrect-session-password\n")
            result = sql("SELECT 1")
            assert result.returncode and "1045" in result.stderr, "Incorrect session credential accepted"
            options.write_text("[client]\npassword=" + conn["password"] + "\n")

            with closing(sqlite3.connect(state / "db-events.sqlite3")) as audit:
                def connections():
                    return audit.execute(
                        "SELECT count(*) FROM database_events WHERE action='connect' AND result='allowed'"
                    ).fetchone()[0]
                prior = connections()
                with process([*client, "SELECT SLEEP(10)"], env=env) as active:
                    wait_until(lambda: connections() > prior, active, 4)
                    broker.terminate()
                    assert broker.wait(timeout=5) == 0
                    assert active.wait(timeout=4) != 0, "Revoked client connection survived"
            assert not descriptor.exists(), "Ended session descriptor was retained"


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="kh-mysql-") as tmp:
        verify(Path(tmp), *binaries())
    print("MySQL native SELECT, database privileges, session credential and active-session revocation passed")
