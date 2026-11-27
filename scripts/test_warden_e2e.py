"""Exercise the three shipped CLI commands against an authenticated local GitLab fixture."""

from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import selectors
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_warden_control import GRANT, IDENTITY, client_cert
from verify_external import make_ca


@contextmanager
def process(*args):
    command = [sys.executable, str(ROOT / "keyheron.py"), *map(str, args)]
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as child:
        try:
            yield child
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)


def first_line(child, *, timeout=30):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=timeout):
            raise AssertionError(f"等待本地子进程输出超过 {timeout} 秒")
    line = child.stdout.readline()
    if not line:
        child.wait(timeout=3)
        raise AssertionError(f"启动失败 {child.stderr.read()}")
    return line


@contextmanager
def gitlab(root, token):
    arrivals = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            authenticated = self.headers.get("PRIVATE-TOKEN") == token
            arrivals.append((self.path, authenticated))
            if not authenticated or self.path != "/api/v4/projects/17/merge_requests/42":
                self.send_error(403)
                return
            body = json.dumps({"id": 99, "iid": 42, "project_id": 17, "title": "Synthetic MR",
                               "state": "opened", "web_url": "https://example.test/mr/42",
                               "private_fixture_field": "outside the plugin contract"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root / "server.pem", root / "server.key")
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as httpd:
        httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        try:
            yield f"https://localhost:{httpd.server_port}", arrivals
        finally:
            httpd.shutdown()
            thread.join(timeout=3)


class ConnectorE2ETest(unittest.TestCase):
    def test_gitlab_template_revoke_and_audit(self):
        # Keep the Unix socket path under Darwin's 104-byte sun_path limit.
        with tempfile.TemporaryDirectory(prefix="kh-e2e-", dir="/tmp") as tmp:
            root = Path(tmp)
            ca = root / "control-ca"
            upstream_ca = root / "upstream-ca"
            make_ca(ca)
            make_ca(upstream_ca)
            cert, key = client_cert(ca, "warden", "URI:" + IDENTITY)
            audit, policy, plugins = root / "audit.db", root / "policy.json", root / "plugins.json"
            state = root / "warden"
            sock = state / "warden.sock"
            token = secrets.token_urlsafe(24)
            token_path = root / "gitlab.token"
            token_path.write_text(token)
            token_path.chmod(0o600)
            document = {"version": 1, "templates": {"reviewer": [GRANT]},
                        "wardens": {IDENTITY: {"tasks": {"review": {"template": "reviewer"}}}}}
            policy.write_text(json.dumps(document))

            def connector(*args, ok=True):
                run = subprocess.run([sys.executable, str(ROOT / "keyheron.py"), "connector",
                                      "--socket", str(sock), *args], capture_output=True, text=True, timeout=10)
                self.assertNotIn(token, run.stdout + run.stderr)
                if ok:
                    self.assertEqual(run.returncode, 0, run.stderr)
                    return json.loads(run.stdout)
                self.assertNotEqual(run.returncode, 0)

            with gitlab(upstream_ca, token) as (origin, requests):
                resources = {
                    f"mr-{iid}": {"origin": origin, "project": 17, "iid": iid, "token_file": str(token_path),
                                  "ca_file": str(upstream_ca / "root.pem")}
                    for iid in (41, 42)
                }
                plugins.write_text(json.dumps({"gitlab": resources}))
                with process("warden-server", "--port", 0, "--policy", policy, "--audit", audit,
                             "--ca", ca / "root.pem", "--cert", ca / "server.pem", "--key", ca / "server.key") as server:
                    port = int(first_line(server).strip().rsplit(":", 1)[1])
                    with process("warden", "--server", f"https://localhost:{port}", "--ca", ca / "root.pem",
                                 "--cert", cert, "--key", key, "--task", "review",
                                 "--plugins", plugins, "--state-dir", state) as warden:
                        first_line(warden)
                        self.assertTrue(sock.is_socket())
                        self.assertEqual(connector("list"), [GRANT])
                        result = connector("invoke", "gitlab", "read", "mr-42")
                        self.assertEqual(result["title"], "Synthetic MR")
                        self.assertNotIn("private_fixture_field", result)
                        connector("invoke", "gitlab", "read", "mr-41", ok=False)
                        document["templates"]["reviewer"].clear()
                        pending = policy.with_suffix(".new")
                        pending.write_text(json.dumps(document))
                        pending.replace(policy)
                        self.assertEqual(connector("list"), [])
                        connector("invoke", "gitlab", "read", "mr-42", ok=False)
                    self.assertEqual(requests, [("/api/v4/projects/17/merge_requests/42", True)])
                with closing(sqlite3.connect(audit)) as db:
                    rows = db.execute("""SELECT warden, task, kind, result, resource FROM warden_events
                                         ORDER BY id""").fetchall()
                self.assertTrue(all(row[:2] == (IDENTITY, "review") for row in rows))
                outcomes = [row[2:] for row in rows]
                self.assertIn(("authorization", "allowed", "mr-42"), outcomes)
                self.assertIn(("reported", "succeeded", "mr-42"), outcomes)
                self.assertIn(("authorization", "denied", "mr-41"), outcomes)
                self.assertIn(("authorization", "denied", "mr-42"), outcomes)
                self.assertNotIn(token.encode(), audit.read_bytes())


if __name__ == "__main__":
    unittest.main()
