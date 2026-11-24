"""Offline regression checks for release licensing, scope and source identity."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from zipfile import ZipFile

from package_release import NATIVE, ROOT, build


class ReleasePackage(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="keyheron-release-test-")
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.repo = self.work / "project"
        self.repo.mkdir()
        for name in (
            "README.md", "CONTRIBUTING.md", "SECURITY.md", "web/app.js", "web/index.html", "web/styles.css",
            "rust-core/src/main.rs", "rust-core/Cargo.lock", "agent_access.py", "keyheron.py", "verify_external.py",
            "examples/github-readonly.json", "examples/read_resource.py", "docs/QUICKSTART.md", "scripts/verify_github.py",
            "third_party/RUST-NOTICES.txt",
        ):
            self.put(name, "fixture\n")
        self.put("rust-core/Cargo.toml", '[package]\nversion = "0.1.0"\n')
        self.git("init", "-q")

    def put(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), "-c", "user.name=Packaging Test",
             "-c", "user.email=packaging@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args]
        ).decode().strip()

    def tag(self, tag):
        self.git("add", ".")
        self.git("commit", "-qm", "Fixture for release packaging")
        self.git("tag", tag)

    def test_pending_license_is_explicit_and_blocks_tag(self):
        self.tag("v0.1.0")
        out = self.work / "preview"
        self.assertEqual(build(self.repo, out)["original_license"], "pending")
        for name in ("web", "source"):
            with ZipFile(out / f"keyheron-{name}-working-preview.zip") as archive:
                self.assertIn(f"keyheron-{name}/LICENSE-STATUS.txt", archive.namelist())
        with self.assertRaisesRegex(ValueError, "LICENSE"):
            build(self.repo, self.work / "formal", "v0.1.0")

    def test_tag_determinism_and_bundle_scope(self):
        # A known license fixture exercises the release gate without publishing any test data.
        self.put("LICENSE", (ROOT / "third_party/KEYFENCE-LICENSE.txt").read_text())
        self.put("bin/keyfence-linux-amd64", "must remain outside release")
        self.put("examples/operator-local.json", "exclude local data")
        self.put("data/events.sqlite3", "exclude local data")
        self.tag("v0.1.0")
        commit = self.git("rev-parse", "HEAD")
        self.put("README.md", "an uncommitted edit")
        native = self.work / "native"
        native.mkdir()
        for asset in NATIVE:
            (native / asset).write_bytes(b"test fixture")
        first, second = self.work / "first", self.work / "second"
        build(self.repo, first, "v0.1.0", native)
        build(self.repo, second, "v0.1.0")
        meta = json.loads((first / "RELEASE-METADATA.json").read_text())
        self.assertEqual(meta["commit"], commit)
        self.assertEqual((first / "LICENSE").read_bytes(), (self.repo / "LICENSE").read_bytes())
        self.assertEqual((first / "RUST-NOTICES.txt").read_bytes(), b"fixture\n")
        for key, filename in (line.split("  ") for line in (first / "SHA256SUMS").read_text().splitlines()):
            self.assertEqual(key, hashlib.sha256((first / filename).read_bytes()).hexdigest())
        for kind in ("source", "web"):
            name = f"keyheron-{kind}-v0.1.0.zip"
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            with ZipFile(first / name) as z:
                self.assertIn(f"keyheron-{kind}/LICENSE", z.namelist())
                if kind == "source":
                    self.assertEqual(z.read("keyheron-source/README.md"), b"fixture\n")
                    self.assertTrue(all("/bin/" not in n and "/data/" not in n and "operator-local" not in n
                                        for n in z.namelist()))
        with self.assertRaisesRegex(ValueError, "empty destination"):
            build(self.repo, first, "v0.1.0")

    def test_apache_notice_is_present_in_standalone_web(self):
        license_file = ROOT / "LICENSE"
        if not license_file.is_file() or "Apache License" not in license_file.read_text():
            self.skipTest("suite running before project license selection")
        self.put("LICENSE", license_file.read_text())
        self.put("NOTICE", "KeyHeron\nCopyright 2026 Fixture Maintainer\n")
        self.put("web/NOTICE", "KeyHeron Web\nCopyright 2026 Fixture Maintainer\n")
        self.tag("v0.1.0-preview.1")
        out = self.work / "release"
        build(self.repo, out, "v0.1.0-preview.1")
        with ZipFile(out / "keyheron-web-v0.1.0-preview.1.zip") as web:
            self.assertEqual(web.read("keyheron-web/LICENSE"), license_file.read_bytes())
            self.assertIn(b"KeyHeron Web", web.read("keyheron-web/NOTICE"))


if __name__ == "__main__":
    unittest.main()
