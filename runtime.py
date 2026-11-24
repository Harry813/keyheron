"""Local synthetic upstreams and real, ephemeral KeyFence v0.4.0 processes."""

import http.client
import hmac
import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack, closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from guard import launch


ROUTES = {
    "read": ("GET", "/service/status", "reader"),
    "diagnose": ("GET", "/service/diagnostics", "diagnostics"),
    "retry": ("POST", "/jobs/job-4821/retry", "worker"),
}


def _request(port, method, target, headers=None, body=None):
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as conn:
        conn.request(method, target, headers=headers or {}, body=body)
        response = conn.getresponse()
        raw = response.read()
        try:
            data = json.loads(raw) if raw else {}
        except (ValueError, UnicodeError):
            data = {}
        return response.status, data if isinstance(data, dict) else {}


def _listeners(stack):
    sockets = []
    for _ in range(3):
        sock = stack.enter_context(socket.socket())
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sockets.append(sock)
    return sockets


def _write_secret(path, value):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as f:
        f.write(value)


class LocalUpstreamServer(ThreadingHTTPServer):
    # The stdlib default backlog of five is smaller than the benchmark's eight workers.
    request_queue_size = 128
    max_connections = 64
    connection_lifetime = 120

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(self.max_connections)
        self._deadlines = {}
        self._deadlines_lock = threading.Lock()
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._deadlines_lock:
            self._deadlines[request] = time.monotonic() + self.connection_lifetime
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._deadlines_lock:
                self._deadlines.pop(request, None)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._deadlines_lock:
                self._deadlines.pop(request, None)
            self._slots.release()

    def service_actions(self):
        # Checked by the existing accept loop, including during keep-alive traffic.
        now = time.monotonic()
        with self._deadlines_lock:
            due = [peer for peer, until in self._deadlines.items() if until <= now]
            for peer in due:
                del self._deadlines[peer]
        for peer in due:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # The handler may have closed the same socket first.


class MockService:
    """An upstream that authenticates the actual bytes forwarded by KeyFence."""

    def __init__(self, environment, credentials):
        self.environment = environment
        self.accounts = {"Bearer " + secret: name for name, secret in credentials.items()}
        self.operations = {}
        self.job_runs = 0
        self.observations = []
        self.lock = threading.Lock()
        self.receipt_key = secrets.token_urlsafe(32)
        self.allowed = {(method, path): name for method, path, name in ROUTES.values()}

    def handle(self, method, path, authorization, operation_id):
        role = self.accounts.get(authorization)
        if not role:
            return 401, {"error": "unknown upstream credential"}
        if self.allowed.get((method, path)) != role:
            return 403, {"error": "upstream account lacks permission"}
        record = {"environment": self.environment, "account": f"{self.environment.lower()}-{role}"}
        with self.lock:
            if role == "worker":
                if not operation_id or len(operation_id) > 160:
                    return 400, {"error": "expected operation ID"}
                already_applied = operation_id in self.operations
                if not already_applied:
                    self.job_runs += 1
                    self.operations[operation_id] = self.job_runs
                record.update(operation_id=operation_id, executions=1, replay=already_applied,
                              run_number=self.operations[operation_id])
            self.observations.append({**record, "method": method, "path": path})
            return 200, record

    def handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            disable_nagle_algorithm = True
            timeout = 10

            def respond(self):
                if self.command == "GET" and self.path.startswith("/__demo/receipts/"):
                    supplied = self.headers.get("Authorization", "")
                    if not hmac.compare_digest(supplied.encode(), ("Bearer " + service.receipt_key).encode()):
                        status, record = 403, {"error": "receipt reader required"}
                    else:
                        op = self.path.removeprefix("/__demo/receipts/")
                        with service.lock:
                            number = service.operations.get(op)
                        status, record = 200, {"state": "applied" if number is not None else "unconfirmed",
                                               "run_number": number}
                else:
                    status, record = service.handle(
                        self.command, self.path, self.headers.get("Authorization"),
                        self.headers.get("Idempotency-Key"),
                    )
                body = json.dumps(record).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = respond

            def log_message(self, *_):
                pass

        return Handler


class Broker:
    def __init__(self, binary, environment, work, stack):
        self.environment = environment
        self._parents = {}
        self._management_value = secrets.token_hex(32)
        keys = work / "credentials"
        keys.mkdir(mode=0o700, parents=True)
        roles = ("reader", "diagnostics", "worker") if environment == "PROD" else ("reader",)
        credentials = {role: secrets.token_hex(32) for role in roles}
        for role, value in credentials.items():
            _write_secret(keys / role, value)
        _write_secret(work / "management-key", self._management_value)
        self._service = MockService(environment, credentials)
        server = stack.enter_context(LocalUpstreamServer(("127.0.0.1", 0), self._service.handler()))
        self._origin_port = server.server_port
        self._origin = f"localhost:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        thread.start()
        stack.callback(thread.join)
        stack.callback(server.shutdown)

        listeners = _listeners(stack)
        self._proxy_port, self._control_port, ssh_port = (s.getsockname()[1] for s in listeners)
        # The v0.4.0 plaintext proxy loses the mock upstream's non-default port
        # on a reused client connection. HTTPS production traffic is not modeled here.
        args = [str(binary), "--no-reuse-connections", "--proxy", f"127.0.0.1:{self._proxy_port}",
                "--api", f"127.0.0.1:{self._control_port}", "--ssh", f"127.0.0.1:{ssh_port}",
                "--data-dir", str(work / "state"), "--credentials-dir", str(keys),
                "--api-key-file", str(work / "management-key")]
        self._proc = launch(args, work, listeners)
        stack.callback(self._stop)
        for _ in range(100):
            if self._proc.poll() is not None:
                raise RuntimeError(f"{environment}: KeyFence exited during startup ({self._proc.returncode})")
            try:
                if _request(self._control_port, "GET", "/health")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(.05)
        raise RuntimeError(f"{environment}: KeyFence did not start its authenticated control API")

    def _stop(self):
        if self._proc.stdin:
            self._proc.stdin.close()
        try:
            self._proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        self._parents.clear()

    def _control(self, method, path, data=None, bearer=None):
        if self._proc.poll() is not None:
            raise RuntimeError("受管代理已经退出")
        headers = {"Authorization": "Bearer " + (bearer or self._management_value),
                   "Content-Type": "application/json"}
        return _request(self._control_port, method, path, headers, json.dumps(data) if data is not None else None)

    def issue(self, kind: str, ttl: int, *, task_id: str, actor: str) -> str:
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("ttl must be a positive number of seconds, up to 3600")
        if kind not in ROUTES or (self.environment != "PROD" and kind != "read"):
            raise ValueError(f"{self.environment}: unsupported grant")
        method, path, role = ROUTES[kind]
        status, result = self._control("POST", "/tokens", {
            "credential_ref": role, "destinations": ["localhost" + path], "ttl_seconds": ttl,
            "policy": "readonly" if method == "GET" else "standard", "task_id": task_id, "agent_id": actor,
        })
        if status != 200 or not result.get("token"):
            raise RuntimeError(f"{self.environment}: KeyFence issuance failed (HTTP {status})")
        parent = result["token"]
        try:
            status, child = self._control("POST", "/tokens/attenuate", {"allowed_methods": [method]}, parent)
            if status != 200 or not child.get("token"):
                raise RuntimeError(f"{self.environment}: method attenuation failed (HTTP {status})")
            token = child["token"]
            self._parents[token] = parent
            return token
        except BaseException:
            self._revoke_parent(parent)
            raise

    def _revoke_parent(self, parent):
        status, _ = self._control("DELETE", "/tokens/" + parent)
        if status not in (200, 204, 404):
            raise RuntimeError(f"{self.environment}: KeyFence revocation failed (HTTP {status})")

    def revoke(self, token: str) -> None:
        parent = self._parents.get(token)
        if parent is not None:
            self._revoke_parent(parent)
            self._parents.pop(token, None)

    def call(self, token: str, method: str, path: str, operation_id: str | None = None) -> tuple[int, dict]:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("expected a local service path")
        headers = {"Authorization": "Bearer " + token}
        if operation_id is not None:
            headers["Idempotency-Key"] = operation_id
        # All generated credentials and both network hops are strictly local test fixtures.
        return _request(self._proxy_port, method, "http://" + self._origin + path, headers)

    @property
    def observations(self):
        with self._service.lock:
            return [dict(event) for event in self._service.observations]

    def operation_result(self, operation_id):
        # Trusted test adapter for the upstream's idempotency ledger.
        with self._service.lock:
            number = self._service.operations.get(operation_id)
        return {"state": "applied" if number is not None else "unconfirmed", "run_number": number}

    @property
    def proxy_port(self):
        return self._proxy_port

    def trusted_config(self):
        """Sent only over the private launcher-to-core pipe."""
        return {"proxy_port": self._proxy_port, "control_port": self._control_port,
                "origin_port": self._origin_port, "management_key": self._management_value,
                "receipt_key": self._service.receipt_key}

    def benchmark_origin(self):
        # The local benchmark needs the same synthetic upstream account for its direct baseline.
        for header, role in self._service.accounts.items():
            if role == "reader":
                return self._origin_port, header.removeprefix("Bearer ")
        raise RuntimeError("missing synthetic reader")


class DemoRuntime:
    def __init__(self, binary: Path):
        self._binary = Path(binary).resolve()
        self._brokers = {}
        self._stack = ExitStack()

    def __enter__(self):
        try:
            work = Path(self._stack.enter_context(tempfile.TemporaryDirectory(prefix="keyfence-demo-")))
            for environment in ("DEV", "STG", "PROD"):
                self._brokers[environment] = Broker(self._binary, environment, work / environment, self._stack)
            return self
        except BaseException:
            self._stack.close()
            raise

    def __exit__(self, *exc):
        self._brokers.clear()
        return self._stack.__exit__(*exc)

    def __getitem__(self, environment):
        return self._brokers[environment]
