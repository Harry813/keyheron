"""Real mTLS, live connector revocation and fail-closed audit regressions."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import os
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_external import make_ca
from warden_control import (ControlBusy, ControlClient, ControlServer, _Quota, _QUOTAS, _RequestBudget,
                            _read_policy_state, read_policy)


IDENTITY = "spiffe://keyheron/warden/demo"
GRANT = {"connector": "gitlab", "action": "read", "resource": "mr-42", "ttl": 30}
SCOPE = ("review", "gitlab", "read", "mr-42")


def client_cert(ca, name, uri):
    """Use the fixture CA to issue a TLS client certificate with explicit SAN."""
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=ca, check=True, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    (ca / "client.ext").write_text("basicConstraints=critical,CA:FALSE\n"
                                 "keyUsage=critical,digitalSignature\n"
                                 "extendedKeyUsage=clientAuth\nsubjectAltName=" + uri + "\n")
    key, csr, cert = (name + suffix for suffix in (".key", ".csr", ".pem"))
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    openssl("req", "-new", "-key", key, "-subj", "/CN=fixture", "-out", csr)
    openssl("x509", "-req", "-sha256", "-in", csr, "-CA", "root.pem", "-CAkey", "root.key",
            "-CAcreateserial", "-days", "1", "-extfile", "client.ext", "-out", cert)
    return ca / cert, ca / key


class ControlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.root = Path(temp.name)
        cls.ca = cls.root / "ca"
        make_ca(cls.ca)
        cls.trust = cls.ca / "root.pem"
        cls.warden = client_cert(cls.ca, "warden", "URI:" + IDENTITY)
        cls.unknown = client_cert(cls.ca, "other", "URI:spiffe://keyheron/warden/other")
        cls.ambiguous = client_cert(cls.ca, "two", "URI:" + IDENTITY + ",URI:spiffe://keyheron/warden/other")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(tmp.cleanup)
        self.policy = Path(tmp.name) / "policy"
        self.audit = Path(tmp.name) / "audit.db"
        self.set_grants([GRANT])
        server = ControlServer(("127.0.0.1", 0), self.policy, self.audit, self.trust,
                               self.ca / "server.pem", self.ca / "server.key")
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.port = server.server_port
        self.url = f"https://localhost:{self.port}"
        self.client = ControlClient(self.url, self.trust, *self.warden)

    def set_grants(self, grants):
        self.policy.write_text(json.dumps({"version": 1, "wardens": {IDENTITY: {"tasks": {"review": grants}}}}))

    def test_listener_starts_without_reverse_dns(self):
        with patch("socket.getfqdn", side_effect=AssertionError("unexpected reverse DNS")):
            with ControlServer(("127.0.0.1", 0), self.policy, self.audit, self.trust,
                               self.ca / "server.pem", self.ca / "server.key") as server:
                self.assertEqual(server.server_name, "127.0.0.1")
                self.assertEqual(server.server_port, server.socket.getsockname()[1])

    def test_scope_revocation_and_audit(self):
        self.assertEqual(self.client.authorize(*SCOPE), 30)
        for scope in (("other", *SCOPE[1:]), ("review", "database", "read", "mr-42"),
                      ("review", "gitlab", "write", "mr-42"), (*SCOPE[:3], "mr-41")):
            with self.assertRaises(PermissionError):
                self.client.authorize(*scope)
        self.set_grants([])
        with self.assertRaises(PermissionError):
            self.client.authorize(*SCOPE)
        self.client.event(*SCOPE, "closed")
        with self.assertRaises(PermissionError):
            self.client.event("other", *SCOPE[1:], "succeeded")
        with closing(sqlite3.connect(self.audit)) as db:
            rows = db.execute("SELECT warden, task, kind, result FROM warden_events ORDER BY id").fetchall()
        self.assertEqual(rows[0], (IDENTITY, "review", "authorization", "allowed"))
        self.assertEqual(rows[-2:], [(IDENTITY, "review", "reported", "closed"),
                                     (IDENTITY, "other", "reported", "denied")])

    def test_removed_task_can_report_terminal_outcomes_for_its_own_authorizations(self):
        with self.assertRaises(PermissionError):
            self.client.event(*SCOPE, "closed")
        self.client.authorize(*SCOPE)
        self.policy.write_text(json.dumps({"version": 1, "wardens": {IDENTITY: {"tasks": {}}}}))
        self.client.event(*SCOPE, "closed")
        self.client.event(*SCOPE, "failed")
        with self.assertRaises(PermissionError):
            self.client.event(*SCOPE, "succeeded")
        for scope in (("other", *SCOPE[1:]), (*SCOPE[:3], "mr-41")):
            with self.assertRaises(PermissionError):
                self.client.event(*scope, "closed")
        with self.assertRaises(PermissionError):
            ControlClient(self.url, self.trust, *self.unknown).event(*SCOPE, "closed")
        with self.assertRaises(PermissionError):
            self.client.authorize(*SCOPE)
        with self.assertRaises(PermissionError):
            self.client.capabilities(SCOPE[0])

    def test_removed_identity_or_old_authorization_cannot_report_an_outcome(self):
        self.client.authorize(*SCOPE)
        self.policy.write_text(json.dumps({"version": 1, "wardens": {}}))
        for result in ("closed", "failed", "succeeded"):
            with self.subTest(result=result), self.assertRaises(PermissionError):
                self.client.event(*SCOPE, result)
        self.set_grants([GRANT])
        self.client.authorize(*SCOPE)
        self.set_grants([])
        with closing(sqlite3.connect(self.audit)) as db, db:
            db.execute("UPDATE warden_events SET at=datetime('now','-2 hours') WHERE kind='authorization'")
        with self.assertRaises(PermissionError):
            self.client.event(*SCOPE, "closed")

    def test_template_discovery_and_revocation(self):
        entry = {"tasks": {"review": {"template": "readonly"}}}
        policy = {"version": 1, "templates": {"readonly": [GRANT]}, "wardens": {IDENTITY: entry}}
        self.policy.write_text(json.dumps(policy))
        self.assertEqual(self.client.capabilities("review"), [GRANT])
        self.assertEqual(self.client.authorize(*SCOPE), 30)
        with self.assertRaises(PermissionError):
            self.client.capabilities("other")
        policy["templates"]["readonly"] = []
        self.policy.write_text(json.dumps(policy))
        self.assertEqual(self.client.capabilities("review"), [])
        with self.assertRaises(PermissionError):
            self.client.authorize(*SCOPE)
        del policy["templates"]["readonly"]
        self.policy.write_text(json.dumps(policy))
        with self.assertRaisesRegex(OSError, "HTTP 503"):
            self.client.capabilities("review")

    def test_cert_identity_and_server_name(self):
        for cert in (self.unknown, self.ambiguous):
            with self.assertRaises(PermissionError):
                ControlClient(self.url, self.trust, *cert).authorize(*SCOPE)
        with self.assertRaises(ssl.SSLCertVerificationError):
            ControlClient(f"https://127.0.0.1:{self.port}", self.trust, *self.warden).authorize(*SCOPE)
        tls = ssl.create_default_context(cafile=self.trust)
        with closing(http.client.HTTPSConnection("localhost", self.port, timeout=3, context=tls)) as conn:
            with self.assertRaises((OSError, http.client.HTTPException)):
                conn.request("POST", "/authorize", b"{}")
                conn.getresponse()
        tls.load_cert_chain(*self.warden)
        tls.maximum_version = ssl.TLSVersion.TLSv1_2
        with closing(http.client.HTTPSConnection("localhost", self.port, timeout=3, context=tls)) as conn:
            with self.assertRaises(ssl.SSLError):
                conn.connect()

    def test_no_identity_override_or_duplicates(self):
        payload = dict(zip(("task", "connector", "action", "resource"), SCOPE))
        with self.assertRaisesRegex(OSError, "HTTP 400"):
            self.client._post("/authorize", {**payload, "warden": IDENTITY})
        self.set_grants([GRANT, GRANT])
        with self.assertRaises(ValueError):
            read_policy(self.policy)
        with self.assertRaisesRegex(OSError, "HTTP 503"):
            self.client.authorize(*SCOPE)
        self.policy.write_text('{"version":1,"version":1,"wardens":{}}')
        with self.assertRaises(ValueError):
            read_policy(self.policy)

    def test_audit_outage_denies_authorization(self):
        with closing(sqlite3.connect(self.audit)) as db, db:
            db.execute("CREATE TRIGGER fail BEFORE INSERT ON warden_events BEGIN SELECT RAISE(FAIL, 'stop'); END")
        with self.assertRaisesRegex(OSError, "HTTP 503"):
            self.client.authorize(*SCOPE)

    def test_task_budgets_precede_tls_policy_and_audit_and_leave_other_tasks_available(self):
        self.policy.write_text(json.dumps({"version": 1, "wardens": {
            IDENTITY: {"tasks": {"review": [GRANT], "second": [GRANT]}}}}))
        with (patch.dict(_QUOTAS, ordinary=_QUOTAS["ordinary"]._replace(task_rate=2)),
              patch("warden_control.time") as clock,
              patch("warden_control._read_policy_state", wraps=_read_policy_state) as read):
            clock.monotonic.return_value = 10
            self.client.capabilities("review")
            with self.assertRaises(PermissionError):
                self.client.authorize(*SCOPE[:-1], "ungranted")
            with patch.object(self.client, "_send") as send, self.assertRaises(ControlBusy):
                self.client.capabilities("review")
            send.assert_not_called()
            second = ControlClient(self.url, self.trust, *self.warden)
            with self.assertRaisesRegex(ControlBusy, "HTTP 429"):
                second.capabilities("review")
            self.assertEqual(second.capabilities("second"), [GRANT])
            self.assertEqual(read.call_count, 3)
            with closing(sqlite3.connect(self.audit)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM warden_events").fetchone(), (3,))
            clock.monotonic.return_value = 11
            self.assertEqual(self.client.authorize(*SCOPE), 30)

    def test_task_concurrency_is_released_after_errors(self):
        budget = _RequestBudget()
        with patch.dict(_QUOTAS, ordinary=_QUOTAS["ordinary"]._replace(task_concurrent=1)):
            with self.assertRaises(ValueError), budget.request("first"):
                with self.assertRaises(ControlBusy), budget.request("first"):
                    self.fail("exceeded task concurrency")
                with budget.request("second"):
                    raise ValueError
            with budget.request("first"):
                self.assertEqual(budget.active, {("ordinary", "first"): 1})

    def test_lifecycle_budgets_survive_task_and_server_limits_and_honor_revocation(self):
        other = ControlClient(self.url, self.trust, *self.warden)
        with (patch.dict(_QUOTAS, ordinary=_Quota(2, 2, 1, 1), session=_Quota(2, 2, 1, 1),
                         outcome=_Quota(1, 1, 1, 1), closed=_Quota(1, 1, 1, 1)),
              patch("warden_control.time") as clock):
            clock.monotonic.return_value = 10
            with self.assertRaises(PermissionError):
                self.client.plugin_grant(*SCOPE, session_check=True)  # No previous authorization.
            self.client.authorize(*SCOPE)
            self.client.capabilities("review")
            with self.assertRaises(ControlBusy):
                self.client.capabilities("review")
            with self.assertRaisesRegex(OSError, "HTTP 429"):
                other.capabilities("different")
            self.assertEqual(self.client.plugin_grant(*SCOPE, session_check=True)["ttl"], 30)
            with self.assertRaises(ControlBusy):
                self.client.plugin_grant(*SCOPE, session_check=True)
            self.client.event(*SCOPE, "succeeded")
            with self.assertRaises(ControlBusy):
                self.client.event(*SCOPE, "failed")
            self.set_grants([])
            self.client.event(*SCOPE, "closed")  # Independent of every other budget.
            clock.monotonic.return_value = 11
            with self.assertRaises(PermissionError):
                self.client.plugin_grant(*SCOPE, session_check=True)
            with closing(sqlite3.connect(self.audit)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM warden_events WHERE result='closed'").fetchone(),
                                 (1,))

    def test_parallel_session_closures_use_bounded_client_connections_and_reach_audit(self):
        self.client.authorize(*SCOPE)
        with ThreadPoolExecutor(max_workers=16) as pool:
            reports = [pool.submit(self.client.event, *SCOPE, "closed") for _ in range(16)]
            for report in reports:
                report.result()
        with closing(sqlite3.connect(self.audit)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM warden_events WHERE result='closed'").fetchone(),
                             (16,))

    def test_close_retries_only_a_confirmed_admission_refusal(self):
        with (patch.object(self.client, "_post", side_effect=[ControlBusy(), {"recorded": True}]) as send,
              patch("warden_control.time.sleep") as sleep):
            self.client.event(*SCOPE, "closed")
            self.assertEqual(send.call_count, 2)
            sleep.assert_called_once_with(1)
        with patch.object(self.client, "_post", side_effect=OSError) as send, self.assertRaises(OSError):
            self.client.event(*SCOPE, "closed")
        send.assert_called_once()

    def test_audit_rotation_preserves_legacy_rows_and_unexpired_authorizations(self):
        self.client.capabilities("review")
        with closing(sqlite3.connect(self.audit)) as db, db:
            db.execute("DROP TABLE warden_audit_retention")  # Reopen a database from before retention.
        with ControlServer(("127.0.0.1", 0), self.policy, self.audit, self.trust,
                           self.ca / "server.pem", self.ca / "server.key"):
            pass
        with patch("warden_control.AUDIT_PRUNE_INTERVAL", 1), patch("warden_control.AUDIT_HISTORY_ROWS", 2):
            self.client.authorize(*SCOPE)
            for _ in range(4):
                self.client.capabilities("review")
            self.set_grants([])
            self.client.event(*SCOPE, "closed")
            with closing(sqlite3.connect(self.audit)) as db, db:
                self.assertEqual(db.execute("SELECT id FROM warden_events ORDER BY id").fetchall(),
                                 [(1,), (2,), (6,), (7,)])
                db.execute("UPDATE warden_events SET at=datetime('now','-2 hours') WHERE id=2")
            with self.assertRaises(PermissionError):
                self.client.event(*SCOPE, "closed")
            with closing(sqlite3.connect(self.audit)) as db:
                self.assertEqual(db.execute("SELECT id FROM warden_events ORDER BY id").fetchall(),
                                 [(1,), (7,), (8,)])

    def test_each_authorization_rechecks_policy_and_database_files(self):
        self.assertEqual(self.audit.stat().st_mode & 0o777, 0o600)
        self.policy.chmod(0o666)
        with self.assertRaisesRegex(OSError, "HTTP 503"):
            self.client.authorize(*SCOPE)
        self.policy.chmod(0o644)
        self.audit.chmod(0o644)
        with self.assertRaisesRegex(OSError, "HTTP 503"):
            self.client.authorize(*SCOPE)
        self.audit.chmod(0o600)
        for suffix in ("-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                sidecar = self.audit.with_name(self.audit.name + suffix)
                sidecar.touch(mode=0o600)
                sidecar.chmod(0o666)
                with self.assertRaisesRegex(OSError, "HTTP 503"):
                    self.client.authorize(*SCOPE)
                sidecar.unlink()
                sidecar.symlink_to(self.policy)
                with self.assertRaisesRegex(OSError, "HTTP 503"):
                    self.client.authorize(*SCOPE)
                sidecar.unlink()
        self.assertEqual(self.client.authorize(*SCOPE), 30)

    def test_startup_rejects_nonregular_policy_and_preexisting_unsafe_audit(self):
        args = (("127.0.0.1", 0), self.policy, self.audit, self.trust,
                self.ca / "server.pem", self.ca / "server.key")
        self.audit.chmod(0o660)
        with self.assertRaises(PermissionError):
            ControlServer(*args)
        self.audit.unlink()
        self.audit.symlink_to(self.policy)
        with self.assertRaises(PermissionError):
            ControlServer(*args)
        self.assertTrue(self.audit.is_symlink())
        self.audit.unlink()
        self.policy.unlink()
        os.mkfifo(self.policy, 0o600)
        with self.assertRaises(PermissionError):
            ControlServer(*args)
        self.assertFalse(self.audit.exists())


if __name__ == "__main__":
    unittest.main()
