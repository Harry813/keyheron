"""Offline checks for private role entry points, SDK cancellation and credential rotation."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_access import load_config, run_child
from web_demo import role_links


INFO = {
    "proxy_port": 1, "ca_file": "/fixture/ca.pem",
    "environments": {"DEV": {"origin": "https://example.invalid", "read_path": "/fixture"}},
}


def fixture_control(_info, action, payload=None):
    if action == "state":
        return {"environment": "DEV"}
    if action == "sdk-session":
        return {"id": "fixture-id", "token": "fixture-token"}
    if action == "sdk-revoke" and payload == {"id": "fixture-id"}:
        print("revoked", flush=True)
        return {}
    raise ValueError("unexpected fixture operation")


class SecurityLauncher(unittest.TestCase):
    def test_private_role_pages(self):
        output = io.StringIO()
        tokens = ("fixture-applicant-value", "fixture-approver-value")
        with redirect_stdout(output), patch("web_demo.webbrowser.open_new_tab") as opener:
            with role_links(1234, *tokens, open_browser=True):
                uris = [call.args[0] for call in opener.call_args_list]
                self.assertEqual(len(uris), 2)
                self.assertFalse(any(token in output.getvalue() for token in tokens))
                paths = []
                for i, uri in enumerate(uris):
                    self.assertIn(uri, output.getvalue())
                    self.assertFalse(any(t in uri for t in tokens))
                    self.assertEqual(urlsplit(uri).scheme, "file")
                    path = Path(unquote(urlsplit(uri).path))
                    paths.append(path)
                    self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    page = path.read_text()
                    self.assertIn(f"http://127.0.0.1:1234/#access={tokens[i]}", page)
                    self.assertNotIn(tokens[1-i], page)
            self.assertTrue(all(not p.parent.exists() for p in paths))

    def test_key_manager_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "second"):
                (root / name).write_text(name)
            logical = root / "active"
            logical.symlink_to("first")
            policy = json.loads((ROOT / "examples/github-readonly.json").read_text())
            policy["environments"] = {"DEV": policy["environments"]["DEV"]}
            policy["environments"]["DEV"]["credential_files"]["github-reader"] = "active"
            config = root / "policy.json"
            config.write_text(json.dumps(policy))
            path = Path(load_config(config)["environments"]["DEV"]["credential_files"]["github-reader"])
            self.assertEqual(path.read_text(), "first")
            (root / "pending").symlink_to("second")
            (root / "pending").replace(logical)
            self.assertEqual(path.read_text(), "second")

    def test_rotation_with_linked_policy_file_or_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = json.loads((ROOT / "examples/github-readonly.json").read_text())
            env = policy["environments"]["DEV"]
            env["credential_files"]["github-reader"] = "reader"
            env["ca_file"] = "ca.pem"
            policy["environments"] = {"DEV": env}
            for version in ("first", "second"):
                folder = root / version
                folder.mkdir()
                (folder / "policy.json").write_text(json.dumps(policy))
                (folder / "reader").write_text(version)
                (folder / "ca.pem").write_text(version)
            (root / "current").symlink_to("first")
            (root / "policy.json").symlink_to("first/policy.json")
            (root / "reader").symlink_to("current/reader")

            credentials = []
            for config in (root / "current" / "policy.json", root / "policy.json"):
                loaded = load_config(config)["environments"]["DEV"]
                self.assertEqual(Path(loaded["ca_file"]), (root / "first/ca.pem").resolve())
                credential = Path(loaded["credential_files"]["github-reader"])
                self.assertEqual(credential.read_text(), "first")
                credentials.append(credential)

            for name, target in (("current", "second"), ("policy.json", "second/policy.json")):
                pending = root / "pending"
                pending.symlink_to(target)
                pending.replace(root / name)
            self.assertEqual([p.read_text() for p in credentials], ["second", "second"])
            (root / "first").rename(root / "retired")
            self.assertEqual([p.read_text() for p in credentials], ["second", "second"])

    def test_normal_child_exit(self):
        output = io.StringIO()
        with patch("agent_access.control", fixture_control), redirect_stdout(output):
            status = run_child(INFO, "DEV", [sys.executable, "-c", "raise SystemExit(7)"])
        self.assertEqual(status, 7)
        self.assertEqual(output.getvalue().splitlines(), ["revoked"])

    def test_parent_cancellation(self):
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(sig=sig), subprocess.Popen(
                [sys.executable, __file__, "--cancel-fixture"], stdout=subprocess.PIPE, text=True
            ) as launcher:
                with selectors.DefaultSelector() as selector:
                    selector.register(launcher.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "client did not start")
                    self.assertEqual(launcher.stdout.readline().strip(), "ready")
                launcher.send_signal(sig)
                # The child and its descendant also hold stdout until their group is stopped.
                stdout, _ = launcher.communicate(timeout=5)
                self.assertEqual(launcher.returncode, 128 + sig)
                self.assertEqual(stdout.splitlines(), ["revoked"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--cancel-fixture"]:
        pause = (
            "import signal,subprocess,sys,time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(9)'])\n"
            "print('ready', flush=True)\n"
            "time.sleep(9)\n"
        )
        with patch("agent_access.control", fixture_control):
            raise SystemExit(run_child(INFO, "DEV", [sys.executable, "-c", pause]))
    unittest.main()
