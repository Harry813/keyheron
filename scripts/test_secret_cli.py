"""Operator credential import and input handling regressions."""

import getpass
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import secret_cli


class SecretInput(unittest.TestCase):
    def test_same_private_file_opened_and_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unlock"
            path.write_bytes("  测试口令有空格  \r\n".encode())
            path.chmod(0o400)
            self.assertEqual(secret_cli.load_passphrase(path, confirm=True), "  测试口令有空格  ".encode())
            path.chmod(0o640)
            with self.assertRaises(ValueError):
                secret_cli.load_passphrase(path)
            fifo = Path(tmp) / "fifo"
            os.mkfifo(fifo, mode=0o600)
            with self.assertRaises(ValueError):
                secret_cli.load_passphrase(fifo)

    def test_non_echoing_terminal_or_failure(self):
        with patch("getpass.getpass", side_effect=["many secret bytes", "does not match"]):
            with self.assertRaisesRegex(ValueError, "不同"):
                secret_cli.load_passphrase(confirm=True)

        def fallback(_prompt):
            warnings.warn("echo unavailable", getpass.GetPassWarning)
            self.fail("input should stop before the fallback reads from stdin")

        with patch("getpass.getpass", side_effect=fallback):
            with self.assertRaisesRegex(ValueError, "无回显"):
                secret_cli.load_passphrase()

    def test_text_boundaries_and_encoding(self):
        read = lambda data: secret_cli._read_text(io.BytesIO(data), 8)
        self.assertEqual(read(b"12345678\r\n"), b"12345678")
        self.assertEqual(read(b"  test \n"), b"  test ")
        self.assertEqual(read(b"test\n\n"), b"test\n")
        for invalid in (b"", b"\n", b"abc\0", b"\xff", b"a" * 9, b"a" * 9 + b"\r\n"):
            with self.subTest(data=invalid), self.assertRaises(ValueError):
                read(invalid)

    def test_cli_creates_and_rotates_without_disclosing_inputs(self):
        from credential_store import unlock

        with tempfile.TemporaryDirectory() as tmp:
            phrase = b"fixture master passphrase"
            file = Path(tmp) / "unlock"
            file.write_bytes(phrase)
            file.chmod(0o600)
            store = Path(tmp) / "credentials.sqlite3"
            base = [sys.executable, str(ROOT / "keyheron.py"), "secrets"]
            common = ["--store", str(store), "--passphrase-file", str(file)]

            def invoke(args, value=b""):
                return subprocess.run([*base, *args], input=value, capture_output=True,
                                      start_new_session=True, timeout=20)

            # Detached from any terminal: a pipe alone cannot become an unlock prompt.
            failed = invoke(["init", "--store", str(store)], phrase)
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(phrase, failed.stderr + failed.stdout)
            self.assertFalse(store.exists())
            created = invoke(["init", *common])
            self.assertEqual(created.returncode, 0, created.stderr)
            put = ["put", *common, "--env", "DEV", "--name", "fixture", "--stdin"]
            for value in (b"synthetic fixture one", " synthetic 凭据 two ".encode()):
                result = invoke(put, value + b"\r\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                output = result.stderr + result.stdout
                self.assertNotIn(value, output)
                self.assertNotIn(phrase, output)
                self.assertEqual(unlock(store, phrase).get("DEV", "fixture"), value)
                self.assertNotIn(value, store.read_bytes())


if __name__ == "__main__":
    unittest.main()
