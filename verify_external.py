"""Offline verification with two authenticated HTTPS services and an ordinary SDK client."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from agent_access import control, running_external, sdk_env

ROOT = Path(__file__).resolve().parent
READ = "/catalog/records/private"
DIAGNOSE = "/monitoring/private-diagnostics"
RETRY = "/workflow/jobs/safe-retry"
FIXED_BODY = {"operation": "verify", "priority": "normal"}


def check(condition, description):
    if not condition:
        raise AssertionError(description)


def make_ca(directory):
    """Generate a fixture CA and a localhost server certificate; never modify host trust."""
    directory.mkdir(mode=0o700)

    def openssl(*args):
        subprocess.run(
            ["openssl", *args],
            cwd=directory,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=20,
        )

    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "root.key",
        "-out",
        "root.pem",
        "-subj",
        "/CN=KeyHeron fixture root",
        "-days",
        "2",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "server.key",
        "-out",
        "server.csr",
        "-subj",
        "/CN=localhost",
    )
    (directory / "ext").write_text(
        "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\n"
        "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "root.pem",
        "-CAkey",
        "root.key",
        "-CAcreateserial",
        "-out",
        "server.pem",
        "-days",
        "1",
        "-extfile",
        "ext",
    )


class Fixture:
    def __init__(self, directory, environment):
        self.environment = environment
        self.directory = directory
        self.keys = {
            r: secrets.token_hex(32) for r in ("reader", "inspector", "worker")
        }
        self.authenticated = []
        self.arrivals = 0
        self.lock = threading.Lock()
        self.operations = set()
        self.next_response_gate = None
        self.port = 0

    @property
    def origin(self):
        return f"https://localhost:{self.port}"

    def config(self, cert_path):
        keys = {}
        for role, secret in self.keys.items():
            path = self.directory / (self.environment + "-" + role)
            path.write_text(secret)
            path.chmod(0o600)
            keys[role] = str(path)
        routes = {
            "read": {
                "method": "GET",
                "path": READ,
                "resource": "catalog-record",
                "credential": "reader",
                "max_ttl": 300,
            }
        }
        if self.environment == "PROD":
            routes["diagnose"] = {
                "method": "GET",
                "path": DIAGNOSE,
                "resource": "service-health",
                "credential": "inspector",
                "max_ttl": 60,
            }
            routes["retry"] = {
                "method": "POST",
                "path": RETRY,
                "resource": "fixture-workflow",
                "credential": "worker",
                "body": FIXED_BODY,
                "max_ttl": 60,
                "auth_header": "X-Test-API-Key",
                "auth_scheme": "",
                "idempotency_supported": True,
            }
        return {
            "origin": self.origin,
            "ca_file": str(cert_path),
            "credential_files": keys,
            "routes": routes,
        }

    def handler(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True

            def log_message(self, *_):
                pass

            def serve(self):
                role = {
                    ("GET", READ): "reader",
                    ("GET", DIAGNOSE): "inspector",
                    ("POST", RETRY): "worker",
                }.get((self.command, self.path))
                data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                with fixture.lock:
                    fixture.arrivals += 1
                    if role == "worker":
                        op = self.headers.get("Idempotency-Key")
                        ok = (
                            self.headers.get("X-Test-API-Key") == fixture.keys["worker"]
                            and op
                            and json.loads(data) == FIXED_BODY
                        )
                        if ok:
                            fixture.operations.add(op)
                    else:
                        ok = (
                            role
                            and self.headers.get("Authorization")
                            == "Bearer " + fixture.keys[role]
                        )
                    gate = fixture.next_response_gate if ok else None
                    if gate is not None:
                        fixture.next_response_gate = None
                    if ok:
                        fixture.authenticated.append(role)
                    # Custom response fields deliberately differ from the built-in synthetic service.
                    value = (
                        {
                            "account_seen": fixture.environment.lower() + "-" + role,
                            "payload": "private-fixture",
                        }
                        if ok
                        else {"error": "unauthorized"}
                    )
                if gate is not None:
                    admitted, finish = gate
                    admitted.set()
                    check(finish.wait(7), "test upstream response was not released")
                body = json.dumps(value).encode()
                self.send_response(200 if ok else 401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = serve

        return Handler

    @contextmanager
    def start(self, cert_dir):
        class Server(ThreadingHTTPServer):
            request_queue_size = 128

        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_dir / "server.pem", cert_dir / "server.key")
        with Server(("127.0.0.1", 0), self.handler()) as server:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            self.port = server.server_port
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            thread.start()
            try:
                yield self
            finally:
                server.shutdown()
                thread.join()


def curl(info, issued, env_name, url):
    env = sdk_env(info, issued, env_name)
    # Force the loopback fixture through the same proxy path as a real service.
    r = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "6",
            "--noproxy",
            "",
            "--write-out",
            "\n%{http_connect} %{http_code}",
            url,
        ],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )
    body, _, codes = r.stdout.rpartition("\n")
    return tuple(int(x) for x in codes.split()), body


def denied_by_control(info, action, payload, owner=False):
    try:
        control(info, action, payload, owner=owner)
    except (RuntimeError, PermissionError, ValueError, OSError):
        return True
    return False


@contextmanager
def warm_tunnel(info, session, fixture):
    conn = http.client.HTTPSConnection(
        "127.0.0.1", info["proxy_port"], timeout=6,
        context=ssl.create_default_context(cafile=str(info["ca_file"])),
    )
    encoded = base64.b64encode(("agent:" + session["token"]).encode()).decode()
    conn.set_tunnel("localhost", fixture.port, headers={"Proxy-Authorization": "Basic " + encoded})
    try:
        conn.request("GET", READ)
        response = conn.getresponse()
        check(response.status == 200 and json.loads(response.read())["account_seen"] == "dev-reader",
              "new tunnel failed its initial authenticated GET")
        check(conn.sock is not None, "expected an established keep-alive connection")
        yield conn
    finally:
        conn.close()


def wait_for_tunnel_close(conn, seconds=3):
    if conn.sock is None:
        return
    conn.sock.settimeout(seconds)
    try:
        data = conn.sock.recv(1)
    except (ConnectionResetError, ssl.SSLEOFError):
        return
    check(data == b"", "expected server-side closure of the inactive tunnel")


def bench_tls(info, session, fixture, origin_ca, samples):
    target = urlsplit(fixture.origin)
    client_ca = ssl.create_default_context(cafile=str(info["ca_file"]))
    upstream_ca = ssl.create_default_context(cafile=str(origin_ca))
    proxy_auth = (
        "Basic " + base64.b64encode(("agent:" + session["token"]).encode()).decode()
    )
    expected = fixture.environment.lower() + "-reader"

    def measure(kind, workers, cold):
        def connection():
            if kind == "direct":
                return http.client.HTTPSConnection(
                    target.hostname, target.port, context=upstream_ca, timeout=8
                )
            conn = http.client.HTTPSConnection(
                "127.0.0.1", info["proxy_port"], context=client_ca, timeout=8
            )
            conn.set_tunnel(
                target.hostname,
                target.port,
                headers={"Proxy-Authorization": proxy_auth},
            )
            return conn

        def lane(n):
            conn = connection()
            hdr = (
                {}
                if kind == "sdk"
                else {"Authorization": "Bearer " + fixture.keys["reader"]}
            )
            times = []
            try:
                for i in range(n + 2):
                    if cold:
                        conn.close()
                    now = time.perf_counter_ns()
                    conn.request("GET", READ, headers=hdr)
                    resp = conn.getresponse()
                    raw = resp.read()
                    elapsed = (time.perf_counter_ns() - now) / 1e6
                    check(
                        resp.status == 200
                        and json.loads(raw)["account_seen"] == expected,
                        "unexpected TLS benchmark response",
                    )
                    if i >= 2:
                        times.append(elapsed)
            finally:
                conn.close()
            return times

        with ThreadPoolExecutor(max_workers=workers) as pool:
            merged = sorted(
                v
                for group in pool.map(
                    lane,
                    [
                        samples // workers + int(i < samples % workers)
                        for i in range(workers)
                    ],
                )
                for v in group
            )
        return {
            f"p{p}_ms": round(merged[math.ceil(len(merged) * p / 100) - 1], 4)
            for p in (50, 95, 99)
        }

    modes = []
    before = fixture.arrivals
    for cold in (False, True):
        for workers in (1, 4):
            r = {k: measure(k, workers, cold) for k in ("direct", "sdk")}
            modes.append(
                {
                    "connections": "cold" if cold else "warm",
                    "concurrency": workers,
                    "samples_per_path": samples,
                    **r,
                }
            )
    check(
        fixture.arrivals - before == 8 * samples + 40,
        "TLS benchmark request reconciliation failed",
    )
    return {
        "scope": "local HTTPS + verified ephemeral CA on both legs, synthetic secrets, HTTP/1.1; "
        "cold=new TCP/TLS connection to proxy for each operation; broker retains its upstream pool",
        "observed_upstream_gets": fixture.arrivals - before,
        "errors": 0,
        "measurements": modes,
    }


def verify(core=None, samples=0):
    with (
        tempfile.TemporaryDirectory(prefix="keyheron-verified-") as tmp,
        ExitStack() as stack,
    ):
        root = Path(tmp)
        for name in ("ca-one", "ca-two"):
            make_ca(root / name)
        dev = stack.enter_context(Fixture(root, "DEV").start(root / "ca-one"))
        prod = stack.enter_context(Fixture(root, "PROD").start(root / "ca-two"))
        conf = {
            "version": 1,
            "task": "external-service-demo",
            "identities": {"applicant": "alice", "approver": "owner"},
            "environments": {
                "DEV": dev.config(root / "ca-one" / "root.pem"),
                "PROD": prod.config(root / "ca-two" / "root.pem"),
            },
        }
        conf["environments"]["STG"] = dict(
            conf["environments"]["DEV"], ca_file=str(root / "ca-two" / "root.pem")
        )
        config = root / "policy.json"
        config.write_text(json.dumps(conf))
        state = root / "state"
        info = stack.enter_context(running_external(config, state, core=core))

        def switch(env):
            return control(info, "switch", {"environment": env})

        def mint(env, ttl=60):
            return control(info, "sdk-session", {"environment": env, "ttl": ttl})

        switch("DEV")
        dev_session = mint("DEV", ttl=200)
        counters_before = dev.arrivals
        codes, body = curl(info, dev_session, "DEV", dev.origin + READ)
        check(
            codes == (200, 200) and json.loads(body)["account_seen"] == "dev-reader",
            "DEV auth and raw SDK payload",
        )
        codes, _ = curl(
            info, dev_session, "DEV", dev.origin.replace("https://", "http://") + READ
        )
        check(
            codes[-1] == 403 and dev.arrivals == counters_before + 1,
            "plaintext reached upstream",
        )
        codes, _ = curl(info, dev_session, "DEV", dev.origin + READ + "?revision=other")
        check(
            codes[-1] == 403 and dev.arrivals == counters_before + 1,
            "unapproved query reached upstream",
        )
        bench = (
            bench_tls(info, dev_session, dev, root / "ca-one" / "root.pem", samples)
            if samples
            else None
        )
        # A real child tool is launched with the documented command: no test-specific credentials passed.
        before_cli = len(dev.authenticated)
        cli = subprocess.run(
            [
                sys.executable,
                str(ROOT / "keyheron.py"),
                "run",
                "--state-dir",
                str(state),
                "--env",
                "DEV",
                "--",
                sys.executable,
                str(ROOT / "examples" / "read_resource.py"),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        check(
            cli.returncode == 0
            and len(dev.authenticated) == before_cli + 1
            and dev.authenticated[-1] == "reader",
            "published keyheron run → Python HTTPS client did not read expected private data",
        )
        summary = json.loads(cli.stdout)
        check(
            summary.get("status") == 200 and summary.get("bytes", 0) > 0,
            "SDK example did not confirm the read",
        )
        # run may select a new DEV base session. Mint a fresh ticket before testing standalone revocation.
        standalone = mint("DEV")
        # Two ordinary clients share a capability: one idle, one with an
        # already admitted GET. Revocation closes the first while the second
        # may finish its response, after which its socket must also close.
        with warm_tunnel(info, standalone, dev) as idle, warm_tunnel(info, standalone, dev) as busy:
            admitted, finish = threading.Event(), threading.Event()
            with dev.lock:
                dev.next_response_gate = (admitted, finish)
            try:
                busy.request("GET", READ)
                check(admitted.wait(3), "expected one admitted read before revocation")
                control(info, "sdk-revoke", {"id": standalone["id"]})
                wait_for_tunnel_close(idle)
            finally:
                finish.set()
            response = busy.getresponse()
            check(response.status == 200 and json.loads(response.read())["account_seen"] == "dev-reader",
                  "revocation interrupted an admitted read")
            wait_for_tunnel_close(busy)
        check(
            curl(info, standalone, "DEV", dev.origin + READ)[0][0] == 407,
            "SDK revoke not enforced",
        )
        expiring = mint("DEV", ttl=2)
        with warm_tunnel(info, expiring, dev) as idle:
            wait_for_tunnel_close(idle, seconds=4)
        check(
            curl(info, expiring, "DEV", dev.origin + READ)[0][0] == 407,
            "expired SDK session still accepted",
        )
        old = mint("DEV")
        switch("STG")
        stg = mint("STG")
        before = dev.arrivals
        check(
            curl(info, stg, "STG", dev.origin + READ)[0] == (200, 502)
            and dev.arrivals == before,
            "invalid origin certificate received a request",
        )
        switch("PROD")
        check(
            curl(info, old, "DEV", dev.origin + READ)[0][0] == 407,
            "environment switch did not end DEV session",
        )
        prod_session = mint("PROD")
        codes, body = curl(info, prod_session, "PROD", prod.origin + READ)
        check(
            codes == (200, 200) and json.loads(body)["account_seen"] == "prod-reader",
            "PROD account mismatch",
        )
        diag = control(info, "request", {"action": "diagnose", "ttl": 30})["id"]
        check(
            denied_by_control(info, "use", {"id": diag})
            and denied_by_control(info, "approve", {"id": diag}),
            "temporary action or approval admitted for wrong role",
        )
        control(info, "approve", {"id": diag}, owner=True)
        control(info, "use", {"id": diag})
        check(
            prod.authenticated[-1] == "inspector",
            "temporary privilege did not use configured credential",
        )
        control(info, "revoke", {"id": diag})
        check(
            denied_by_control(info, "use", {"id": diag}),
            "revoked temporary grant remained usable",
        )
        once = control(info, "request", {"action": "retry", "ttl": 30})["id"]
        control(info, "approve", {"id": once}, owner=True)
        control(info, "use", {"id": once})
        check(
            denied_by_control(info, "use", {"id": once})
            and prod.operations == {once}
            and prod.authenticated.count("worker") == 1,
            "fixed command or one-shot grant mismatch",
        )
        control(info, "end", {})
        check(
            curl(info, prod_session, "PROD", prod.origin + READ)[0][0] == 407,
            "task end retained SDK access",
        )
        db_files = []
        for file in state.rglob("*"):
            if file.is_file():
                with file.open("rb") as f:
                    if f.read(16) == b"SQLite format 3\x00":
                        db_files.append(file)
        check(len(db_files) == 1, "missing expected SDK audit database")
        with sqlite3.connect(db_files[0]) as audit:
            rows = audit.execute(
                "SELECT actor,environment,action,resource,result,detail FROM events"
            ).fetchall()
        audit_text = json.dumps(rows)
        tokens = [
            info["applicant"],
            info["approver"],
            *(
                s["token"]
                for s in (dev_session, standalone, expiring, old, stg, prod_session)
            ),
            *dev.keys.values(),
            *prod.keys.values(),
        ]
        check(
            not any(t in audit_text for t in tokens),
            "credential literal found in persisted audit",
        )
        for suffix in ("", "-wal", "-shm"):
            file = Path(str(db_files[0]) + suffix)
            if file.exists():
                raw = file.read_bytes()
                check(
                    not any(t.encode() in raw for t in tokens),
                    "credential literal found in SQLite files",
                )
        check(
            any(
                r[2] == "sdk_read" and r[1] == "DEV" and r[4] == "allowed" for r in rows
            )
            and any(r[2] == "sdk_read" and r[4] == "denied" for r in rows)
            and any(once in r[5] and r[2] == "use" for r in rows),
            "SDK/approval audit missing",
        )
        return {
            "result": "passed",
            "original_client": "curl and Python standard library via keyheron run",
            "verified_accounts": ["dev-reader", "prod-reader"],
            "plaintext_blocked_before_origin": True,
            "untrusted_upstream_tls_blocked_before_origin": True,
            "sdk_revocation_and_environment_switch": True,
            "expired_sdk_rejected": True,
            "revoked_existing_tls_tunnel_closed": True,
            "expired_idle_tls_tunnel_closed": True,
            "already_admitted_read_completed_before_tunnel_closed": True,
            "temporary_approval_and_fixed_operation": True,
            "origin_retries": len(prod.operations),
            "task_end_invalidated_sdk_proxy_token": True,
            "sdk_writes_audit": True,
            "audit_rows": len(rows),
            **({"https_benchmark": bench} if bench else {}),
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--core", type=Path, help="Path to the built KeyHeron Rust executable."
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Also measure private HTTPS cold/warm paths.",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=80,
        help="Requests per path per concurrency when benchmarking.",
    )
    args = parser.parse_args()
    if args.benchmark and not 4 <= args.samples <= 2000:
        parser.error("--samples must be 4–2000")
    print(
        json.dumps(
            verify(args.core, args.samples if args.benchmark else 0),
            ensure_ascii=False,
            indent=2,
        )
    )
