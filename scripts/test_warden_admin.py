"""Operator policy updates and loopback HTTP authorization."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import http.client
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from plugin_runtime import PluginRuntime
from warden_admin import AdminServer, Conflict, change, recent_events, snapshot
from warden_control import read_policy


WARDEN = "spiffe://keyheron/warden/demo"
MR = {"connector": "gitlab", "action": "read", "resource": "mr-42", "ttl": 30}
DB = {"connector": "postgresql", "action": "connect", "resource": "orders", "ttl": 20}


class WardenAdminTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.policy = Path(temporary.name, "policy.json")
        self.audit = Path(temporary.name, "events.sqlite3")
        self.policy.write_text(json.dumps({"version": 1, "wardens": {WARDEN: {"tasks": {}}}}))

    def test_template_binding_changes_authorizer_policy(self):
        state = snapshot(self.policy)
        state = change(self.policy, "template", {"revision": state["revision"], "template": "review-v1",
                                                  "rules": [MR, DB]})
        binding = {"warden": WARDEN, "task": "review", "template": "review-v1"}
        with self.assertRaises(Conflict):
            change(self.policy, "template", {"revision": state["revision"], "template": "review-v1", "rules": [DB]})
        with self.assertRaises(ValueError):
            change(self.policy, "bind", {**binding, "revision": state["revision"], "warden": "unknown"})
        state = change(self.policy, "bind", {**binding, "revision": state["revision"]})
        self.assertEqual(read_policy(self.policy)[WARDEN, "review"], {
            ("gitlab", "read", "mr-42"): 30, ("postgresql", "connect", "orders"): 20,
        })
        change(self.policy, "revoke", {"revision": state["revision"], "warden": WARDEN, "task": "review"})
        self.assertNotIn((WARDEN, "review"), read_policy(self.policy))
        self.assertIn("review-v1", snapshot(self.policy)["policy"]["templates"])

    def test_database_engines_are_distinct_and_legacy_templates_remain_bindable(self):
        legacy = {**DB, "connector": "database"}
        policy = snapshot(self.policy)["policy"]
        policy["templates"] = {"legacy": [legacy]}
        self.policy.write_text(json.dumps(policy))
        state = snapshot(self.policy)
        with self.assertRaises(ValueError):
            change(self.policy, "template", {"revision": state["revision"], "template": "new", "rules": [legacy]})
        state = change(self.policy, "bind", {"revision": state["revision"], "warden": WARDEN,
                                             "task": "old-task", "template": "legacy"})
        engines = ("postgresql", "mysql", "sqlserver")
        state = change(self.policy, "template", {"revision": state["revision"], "template": "by-engine",
                                                 "rules": [{**DB, "connector": engine} for engine in engines]})
        change(self.policy, "bind", {"revision": state["revision"], "warden": WARDEN,
                                     "task": "new-task", "template": "by-engine"})
        grants = read_policy(self.policy)
        self.assertEqual(grants[WARDEN, "old-task"], {("database", "connect", "orders"): 20})
        self.assertEqual(grants[WARDEN, "new-task"], {(engine, "connect", "orders"): 20 for engine in engines})

    def test_admin_accepts_an_action_exposed_by_a_new_plugin(self):
        manifest = self.policy.with_name("issues.json")
        manifest.write_text(json.dumps({"api_version": 1, "id": "issues", "action": "list", "driver": "https-json"}))
        state = change(self.policy, "template", {
            "revision": snapshot(self.policy)["revision"], "template": "issue-list",
            "rules": [{**MR, "connector": "issues", "action": "list"}],
        }, actions=PluginRuntime([manifest]).actions)
        self.assertEqual(state["policy"]["templates"]["issue-list"][0]["action"], "list")

    def test_stale_concurrent_and_invalid_edits_preserve_policy(self):
        revision = snapshot(self.policy)["revision"]
        def create(name):
            try:
                change(self.policy, "template", {"revision": revision, "template": name, "rules": [MR]})
                return 200
            except Conflict:
                return 409
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(create, ["one", "two"])), [200, 409])
        state = snapshot(self.policy)
        for rules in ([{**MR, "action": "write"}], [{**DB, "ttl": 0}], [DB, DB], []):
            with self.assertRaises(ValueError):
                change(self.policy, "template", {"revision": state["revision"], "template": "invalid", "rules": rules})
        self.assertEqual(snapshot(self.policy), state)

    def test_loopback_auth_origin_and_management_requests(self):
        with AdminServer(0, self.policy, self.audit) as srv:
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                def request(method, path, headers=None, data=None):
                    with closing(http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=3)) as client:
                        client.request(method, path, body=json.dumps(data) if data else None, headers=headers or {})
                        response = client.getresponse()
                        payload = response.read()
                        self.assertEqual(response.getheader("Cache-Control"), "no-store")
                        return response.status, json.loads(payload)
                bearer = {"Authorization": "Bearer " + srv.token}
                self.assertEqual(request("GET", "/api/events")[0], 401)
                self.assertEqual(request("GET", "/api/state", {**bearer, "Host": "other.example"})[0], 403)
                self.assertEqual(request("GET", "/api/state", {**bearer, "Origin": "null"})[0], 403)
                _, state = request("GET", "/api/state", bearer)
                self.assertEqual(state["actions"]["gitlab"], "read")
                self.assertNotIn("database", state["actions"])
                for connector in ("postgresql", "mysql", "sqlserver"):
                    self.assertEqual(state["actions"][connector], "connect")
                data = {"revision": state["revision"], "template": "initial", "rules": [DB]}
                self.assertEqual(request("POST", "/api/template", bearer, data)[0], 403)
                headers = {**bearer, "Content-Type": "application/json", "Origin": "http://127.0.0.1:" + str(srv.server_port)}
                self.assertEqual(request("POST", "/api/template", headers, data)[0], 200)
                self.assertEqual(request("POST", "/api/template", headers, data)[0], 409)
            finally:
                srv.shutdown()
                thread.join(3)

    def test_reads_existing_audit_without_creating_or_modifying_it(self):
        self.assertEqual(recent_events(self.audit), {"ready": False, "events": []})
        self.assertFalse(self.audit.exists())
        self.audit.touch(mode=0o600)
        with closing(sqlite3.connect(self.audit)) as db, db:
            db.execute("CREATE TABLE warden_events(id INTEGER, at, warden, task, connector, action, resource, kind, result)")
            db.execute("INSERT INTO warden_events VALUES(1,'time',?,'review','gitlab','read','mr-42','authorization','allowed')", (WARDEN,))
        before = self.audit.read_bytes()
        self.assertEqual(recent_events(self.audit)["events"][0]["resource"], "mr-42")
        self.assertEqual(self.audit.read_bytes(), before)
        self.assertEqual(set(self.audit.parent.iterdir()), {self.policy, self.audit})

    def test_admin_rejects_untrusted_files_for_reads_and_edits(self):
        state = snapshot(self.policy)
        old = self.policy.read_bytes()
        change_request = {"revision": state["revision"], "template": "t", "rules": [MR]}
        self.policy.chmod(0o664)
        with self.assertRaises(PermissionError):
            snapshot(self.policy)
        with self.assertRaises(PermissionError):
            change(self.policy, "template", change_request)
        self.assertEqual(self.policy.read_bytes(), old)
        self.policy.chmod(0o644)
        pointer = self.policy.with_name("pointer")
        pointer.symlink_to(self.policy)
        with self.assertRaises(OSError):
            snapshot(pointer)
        with self.assertRaises(OSError):
            change(pointer, "template", change_request)
        self.assertTrue(pointer.is_symlink())

        orphan = self.audit.with_name(self.audit.name + "-wal")
        orphan.touch(mode=0o600)
        with self.assertRaises(PermissionError):
            recent_events(self.audit)
        self.assertFalse(self.audit.exists())
        orphan.unlink()
        self.audit.symlink_to(self.audit.with_suffix(".absent"))
        with self.assertRaises(PermissionError):
            recent_events(self.audit)
        self.audit.unlink()
        self.audit.touch(mode=0o600)
        self.audit.chmod(0o644)
        with self.assertRaises(PermissionError):
            recent_events(self.audit)

    def test_shared_directory_cannot_substitute_a_policy_or_audit_file(self):
        parent = self.policy.parent / "data"
        parent.mkdir(mode=0o755)
        self.policy = self.policy.rename(parent / "policy.json")
        audit = parent / "audit.db"
        self.assertTrue(snapshot(self.policy))
        parent.chmod(0o777)
        with self.assertRaises(PermissionError):
            snapshot(self.policy)
        with self.assertRaises(PermissionError):
            recent_events(audit)
        parent.chmod(0o1777)
        with self.assertRaises(PermissionError):
            recent_events(audit)
        nested = parent / "private"
        nested.mkdir(mode=0o700)
        self.policy = self.policy.rename(nested / "policy.json")
        self.assertTrue(snapshot(self.policy))
        # A trusted system symlink can lead to a directory, as /var and /tmp do on macOS.
        alias = self.policy.parents[2] / "alias"
        alias.symlink_to(nested, target_is_directory=True)
        self.assertTrue(snapshot(alias / self.policy.name))
        parent.chmod(0o777)
        with self.assertRaises(PermissionError):
            snapshot(alias / self.policy.name)


if __name__ == "__main__":
    unittest.main()
