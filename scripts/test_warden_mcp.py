"""Exercise the stdio MCP server using the official client and a real mTLS Warden."""

import asyncio
from contextlib import asynccontextmanager, closing, contextmanager
from datetime import timedelta
import json
from pathlib import Path
import secrets
import socket
import sqlite3
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_warden_control import GRANT, IDENTITY, client_cert
from test_warden_e2e import first_line, gitlab, process
from verify_external import make_ca
from warden_admin import change, snapshot

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ModuleNotFoundError as exc:
    if exc.name != "mcp":
        raise
    ClientSession = None


DATABASE_RULE = {"connector": "mysql", "action": "connect", "resource": "orders", "ttl": 60}


@contextmanager
def task_warden(root, catalog, rules):
    ca = root / "control-ca"
    make_ca(ca)
    cert, key = client_cert(ca, "warden", "URI:" + IDENTITY)
    policy = root / "grants.json"
    policy.write_text(json.dumps({"version": 1, "wardens": {IDENTITY: {"tasks": {"review": rules}}}}))
    plugins = root / "plugins.json"
    plugins.write_text(json.dumps(catalog))
    state = root / "state"
    audit = root / "audit.sqlite3"
    with process("warden-server", "--port", 0, "--policy", policy, "--audit", audit, "--ca", ca / "root.pem",
                 "--cert", ca / "server.pem", "--key", ca / "server.key") as server:
        port = int(first_line(server).strip().rsplit(":", 1)[1])
        with process("warden", "--server", f"https://localhost:{port}", "--ca", ca / "root.pem",
                     "--cert", cert, "--key", key, "--task", "review", "--plugins", plugins,
                     "--state-dir", state) as warden:
            first_line(warden)
            yield state / "warden.sock", policy, audit


@asynccontextmanager
async def mcp_session(sock):
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "warden_mcp.py"), "--socket", str(sock)])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=35)) as session:
            setup = await session.initialize()
            assert setup.capabilities.tools is not None
            yield session


def result_data(reply):
    assert not reply.isError, reply.content
    # Each tool returns one JSON object. Read the text a model sees on stdio.
    assert len(reply.content) == 1 and reply.content[0].type == "text", reply.content
    return json.loads(reply.content[0].text)


async def descriptor_removed(path):
    async with asyncio.timeout(6):
        while path.exists():
            await asyncio.sleep(.03)


@unittest.skipUnless(ClientSession, "install requirements-mcp.txt for the official MCP client")
class MCPAcceptance(unittest.IsolatedAsyncioTestCase):
    async def test_tools_over_stdio(self):
        with tempfile.TemporaryDirectory(prefix="kh-mcp-", dir="/tmp") as temp, socket.socket() as probe:
            root = Path(temp)
            tls = root / "gitlab-ca"
            make_ca(tls)
            # A deliberately unused local upstream lets us test publishing and closing database
            # descriptors without installing a database server in every protocol test environment.
            probe.bind(("127.0.0.1", 0))
            probe.listen()
            upstream_password = secrets.token_hex(24)
            password_file = root / "db.secret"
            password_file.write_text(upstream_password)
            password_file.chmod(0o600)
            config = root / "database.json"
            config.write_text(json.dumps({
                "version": 1, "task": "review", "identities": {"applicant": "reader", "approver": "operator"},
                "environments": {"DEV": {"databases": {"fixture": {
                    "engine": "mysql", "host": "127.0.0.1", "port": probe.getsockname()[1],
                    "user": "reader", "database": "test", "password_file": str(password_file),
                }}}},
            }))
            git_token = secrets.token_hex(24)
            git_secret = root / "git.secret"
            git_secret.write_text(git_token)
            git_secret.chmod(0o600)
            with gitlab(tls, git_token) as (origin, upstream_requests):
                catalog = {
                    "gitlab": {f"mr-{iid}": {"origin": origin, "project": 17, "iid": iid,
                               "ca_file": str(tls / "root.pem"), "token_file": str(git_secret)} for iid in (41, 42)},
                    "mysql": {"orders": {"config": str(config), "env": "DEV", "target": "fixture"}},
                }
                with task_warden(root, catalog, [GRANT, DATABASE_RULE]) as (sock, policy, audit):
                    async with mcp_session(sock) as session:
                        tools = await session.list_tools()
                        self.assertEqual({tool.name for tool in tools.tools}, {
                            "list_connectors", "describe_connector", "invoke_connector", "close_connection"})
                        rules = result_data(await session.call_tool("list_connectors"))["connectors"]
                        self.assertCountEqual(rules, [GRANT, DATABASE_RULE])
                        description = result_data(await session.call_tool("describe_connector", {"connector": "gitlab"}))
                        self.assertEqual(description["resources"], [{"resource": "mr-42", "ttl": GRANT["ttl"]}])
                        db_scope = {k: DATABASE_RULE[k] for k in ("connector", "action", "resource")}
                        git_scope = {k: GRANT[k] for k in db_scope}
                        result = result_data(await session.call_tool("invoke_connector", git_scope))
                        self.assertEqual(result["title"], "Synthetic MR")
                        self.assertNotIn("private_fixture_field", result)
                        for rejected in ({**git_scope, "task": "other"}, {**git_scope, "resource": "mr-41"},
                                         {**git_scope, "origin": origin}, {**db_scope, "sql": "SELECT 1"}):
                            reply = await session.call_tool("invoke_connector", rejected)
                            self.assertTrue(reply.isError)
                        self.assertTrue((await session.call_tool("close_connection", {"handle": "unknown"})).isError)

                        async def open_database():
                            reply = await session.call_tool("invoke_connector", db_scope)
                            info = result_data(reply)
                            self.assertEqual(set(info), {"handle", "descriptor_path", "expires_at"})
                            path = Path(info["descriptor_path"])
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                            private = json.loads(path.read_text())
                            self.assertEqual(private["host"], "127.0.0.1")
                            self.assertEqual(private["user"], "keyheron")
                            self.assertTrue(private["password"])
                            for secret in (git_token, upstream_password, private["password"]):
                                self.assertNotIn(secret, reply.model_dump_json())
                            return path, info["handle"]

                        path, handle = await open_database()
                        async with mcp_session(sock) as other:
                            self.assertTrue((await other.call_tool("close_connection", {"handle": handle})).isError)
                            other_db = result_data(await other.call_tool("invoke_connector", db_scope))
                            other_path = Path(other_db["descriptor_path"])
                            self.assertTrue(other_path.is_file())
                        await descriptor_removed(other_path)
                        self.assertTrue(path.is_file())
                        closed = result_data(await session.call_tool("close_connection", {"handle": handle},
                                                                     read_timeout_seconds=timedelta(seconds=6)))
                        self.assertEqual(closed, {"closed": True})
                        await descriptor_removed(path)
                        active, _ = await open_database()
                        change(policy, "revoke", {"warden": IDENTITY, "task": "review",
                                                  "revision": snapshot(policy)["revision"]})
                        revoked = await session.call_tool("invoke_connector", db_scope,
                                                          read_timeout_seconds=timedelta(seconds=6))
                        self.assertTrue(revoked.isError)
                        await descriptor_removed(active)
                    with closing(sqlite3.connect(audit)) as db:
                        events = set(db.execute("SELECT connector, kind, result FROM warden_events"))
                    self.assertIn(("mysql", "authorization", "denied"), events)
                    self.assertIn(("mysql", "reported", "closed"), events)
                self.assertEqual(upstream_requests, [("/api/v4/projects/17/merge_requests/42", True)])


if __name__ == "__main__":
    unittest.main()
