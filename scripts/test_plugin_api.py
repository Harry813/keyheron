"""Install a third-party V1 manifest, grant it in the admin API and call it through a real Warden."""

from contextlib import closing, contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_warden_control import IDENTITY, client_cert
from test_warden_e2e import first_line, process
from verify_external import make_ca
from warden_control import ControlClient


@contextmanager
def issue_service(ca, test_token):
    arrivals = []
    summary = {"count": 4, "status": "pending", "internal_note": "non-public fixture field"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            authorized = self.headers.get("Authorization") == f"Bearer {test_token}"
            arrivals.append((self.path, authorized))
            if self.path != "/issues/summary" or not authorized:
                self.send_error(403)
                return
            body = json.dumps(summary).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ca / "server.pem", ca / "server.key")
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as upstream:
        upstream.socket = tls.wrap_socket(upstream.socket, server_side=True)
        thread = threading.Thread(target=upstream.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        try:
            yield f"https://localhost:{upstream.server_port}", arrivals, summary
        finally:
            upstream.shutdown()
            thread.join(timeout=3)


def admin_api(ready_line):
    entry = Path(unquote(urlsplit(ready_line.split()[-1]).path))
    # Read the synthetic operator's private bootstrap link directly, without launching a browser.
    endpoint = re.search(r'href="(http://127\.0\.0\.1:\d+/#access=[^"]+)"', entry.read_text())
    if not endpoint:
        raise AssertionError("缺少管理员入口")
    address = urlsplit(endpoint.group(1))
    origin = "http://" + address.netloc
    headers = {"Origin": origin, "Authorization": "Bearer " + address.fragment.removeprefix("access="),
               "Content-Type": "application/json"}

    def request(path, data=None):
        with closing(http.client.HTTPConnection(address.hostname, address.port, timeout=4)) as client:
            client.request("GET" if data is None else "POST", "/api/" + path,
                           body=None if data is None else json.dumps(data), headers=headers)
            response = client.getresponse()
            if response.status != 200:
                raise AssertionError(f"管理请求 {path} 失败，HTTP {response.status}")
            return json.loads(response.read())

    return request


def wire(sock_path, data):
    body = data if isinstance(data, bytes) else json.dumps(data).encode()
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(5)
        conn.connect(str(sock_path))
        conn.sendall(body + b"\n")
        with conn.makefile("rb") as stream:
            return json.loads(stream.readline())


class ThirdPartyPluginAPI(unittest.TestCase):
    def test_install_grant_describe_and_invoke(self):
        manifest = {"api_version": 1, "id": "team-issues", "action": "read", "driver": "https-json"}
        grant = {"connector": manifest["id"], "action": "read", "resource": "release-blocker", "ttl": 30}
        with tempfile.TemporaryDirectory(prefix="kh-plugin-", dir="/tmp") as tmp:
            root = Path(tmp)
            control_ca, upstream_ca = root / "control-ca", root / "upstream-ca"
            make_ca(control_ca)
            make_ca(upstream_ca)
            cert, key = client_cert(control_ca, "test-warden", "URI:" + IDENTITY)
            test_token = secrets.token_urlsafe(30)
            secret = root / "issues.token"
            secret.write_text(test_token)
            secret.chmod(0o600)
            manifest_file = root / "issue-reader.json"
            manifest_file.write_text(json.dumps(manifest))
            other_file = root / "separate-plugin.json"
            other_file.write_text(json.dumps({**manifest, "id": "unassigned-issues"}))
            extension_args = ("--plugin-manifest", manifest_file, "--plugin-manifest", other_file)
            policy, audit = root / "policy.json", root / "audit.sqlite3"
            policy.write_text(json.dumps({"version": 1, "wardens": {IDENTITY: {"tasks": {}}}}))
            state, catalog = root / "state", root / "catalog.json"
            sock = state / "warden.sock"

            def cli(*command, ok=True):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "keyheron.py"), "connector", "--socket", str(sock), *command],
                    capture_output=True, text=True, timeout=8,
                )
                self.assertNotIn(test_token, result.stdout + result.stderr)
                if ok:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    return json.loads(result.stdout)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

            with (issue_service(upstream_ca, test_token) as (origin, arrivals, summary),
                  process("warden-server", "--port", 0, "--policy", policy, "--audit", audit,
                          "--ca", control_ca / "root.pem", "--cert", control_ca / "server.pem",
                          "--key", control_ca / "server.key") as server,
                  process("warden-admin", "--port", 0, "--policy", policy, "--audit", audit, *extension_args) as admin):
                port = int(first_line(server).strip().rsplit(":", 1)[1])
                manage = admin_api(first_line(admin))
                admin_state = manage("state")
                self.assertEqual(admin_state["actions"]["team-issues"], "read")
                self.assertEqual(admin_state["actions"]["unassigned-issues"], "read")
                admin_state = manage("template", {"revision": admin_state["revision"], "template": "team-view",
                                                 "rules": [grant]})
                binding = {"warden": IDENTITY, "task": "triage", "template": "team-view"}
                admin_state = manage("bind", {**binding, "revision": admin_state["revision"]})
                control = ControlClient(f"https://localhost:{port}", control_ca / "root.pem", cert, key)
                # An authenticated Warden may ask the control server for an operation outside its grant.
                with self.assertRaises(PermissionError):
                    control.plugin_grant("triage", "team-issues", "write", "release-blocker")
                target = {"origin": origin, "path": "/issues/summary", "fields": ["status", "count"],
                          "token_file": str(secret), "ca_file": str(upstream_ca / "root.pem")}
                catalog.write_text(json.dumps({
                    "team-issues": {"release-blocker": target, "other": {**target, "path": "/other"}},
                    "unassigned-issues": {"release-blocker": target},
                }))
                with process("warden", "--server", f"https://localhost:{port}", "--ca", control_ca / "root.pem",
                             "--cert", cert, "--key", key, "--task", "triage", "--state-dir", state,
                             "--plugins", catalog, *extension_args) as warden:
                    first_line(warden)
                    self.assertEqual(cli("list"), [grant])
                    description = {**manifest, "native_stream": False, "legacy": False,
                                   "resources": [{"resource": grant["resource"], "ttl": grant["ttl"]}]}
                    self.assertEqual(cli("describe", manifest["id"]), description)
                    self.assertEqual(wire(sock, {"api_version": 1, "op": "list"})["result"], [grant])
                    self.assertEqual(wire(sock, {"api_version": 1, "op": "describe", "connector": manifest["id"]})
                                     ["result"], description)
                    scope = {key: grant[key] for key in ("connector", "action", "resource")}
                    invoke = {"api_version": 1, "op": "invoke", **scope}
                    projected = {"status": "pending", "count": 4}
                    self.assertEqual(wire(sock, invoke)["result"], projected)
                    self.assertEqual(cli("invoke", manifest["id"], "read", grant["resource"]), projected)
                    cli("invoke", manifest["id"], "write", grant["resource"], ok=False)
                    cli("describe", "unassigned-issues", ok=False)
                    cli("invoke", manifest["id"], "read", "other", ok=False)
                    cli("invoke", "unassigned-issues", "read", grant["resource"], ok=False)
                    for extra in ({"target": target}, {"manifest": manifest}, {"fields": ["internal_note"]},
                                  {"grant": scope}, {"api_version": 2}, {"api_version": True}):
                        with self.subTest(field=next(iter(extra))):
                            response = wire(sock, {**invoke, **extra})
                            self.assertEqual(set(response), {"error"})
                            self.assertNotIn(test_token, str(response))
                    duplicate = json.dumps(invoke)[:-1] + ', "action":"read"}'
                    self.assertEqual(set(wire(sock, duplicate.encode())), {"error"})
                    self.assertEqual(arrivals, [("/issues/summary", True)] * 2)
                    summary["status"] = {"internal_note": "out-of-contract nested data"}
                    cli("invoke", manifest["id"], "read", grant["resource"], ok=False)
                    manage("revoke", {"revision": admin_state["revision"], "warden": IDENTITY, "task": "triage"})
                    cli("invoke", manifest["id"], "read", grant["resource"], ok=False)
                    self.assertEqual(arrivals, [("/issues/summary", True)] * 3)
                events = manage("events")["events"]
                self.assertTrue(any(row["connector"] == manifest["id"] and row["result"] == "succeeded" for row in events))
                self.assertTrue(any(row["connector"] == manifest["id"] and row["action"] == "write"
                                    and row["kind"] == "authorization" and row["result"] == "denied" for row in events))
                self.assertNotIn(test_token, json.dumps(events))


if __name__ == "__main__":
    unittest.main()
