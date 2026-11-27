"""Behavior and format checks for the encrypted SQLite credential store."""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import gc
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import weakref
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from credential_store import initialize, unlock


class CredentialStoreTests(unittest.TestCase):
    password = b"synthetic passphrase for local tests"
    value = b"synthetic-credential-MUST-NOT-APPEAR-IN-SQLITE-PAGES"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "private fixture?#" / "vault.db"
        initialize(self.path, self.password)
        self.store = unlock(self.path, self.password)

    def update(self, sql, parameters=()):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(sql, parameters)

    def test_rotation_and_binding_use_authenticated_ciphertext(self):
        self.store.put("DEV", "orders", self.value)
        bind = self.store.binding("DEV", "orders")
        self.assertEqual(set(bind), {"ref", "key", "salt", "db"})
        self.assertEqual(bind["db"], str(self.path))
        self.assertNotIn(bind["key"], repr(bind))
        self.assertNotIn(bind["key"], str(bind))
        key = base64.b64decode(json.loads(json.dumps(bind))["key"], validate=True)
        salt = base64.b64decode(bind["salt"], validate=True)
        self.assertEqual((len(key), len(salt)), (32, 16))
        with closing(sqlite3.connect(self.path)) as db:
            def entry():
                return db.execute("SELECT nonce, ciphertext FROM vault_credentials WHERE ref=?", (bind["ref"],)).fetchone()
            nonce1, cipher1 = entry()
            self.store.put("DEV", "orders", self.value)
            nonce2, cipher2 = entry()
            self.assertNotEqual(nonce1, nonce2)
            self.assertNotEqual(cipher1, cipher2)
            aad = b"KeyHeron/v1/credential\0" + salt + b"\0DEV/orders"
            self.assertEqual(AESGCM(key).decrypt(nonce2, cipher2, aad), self.value)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        for path in self.path.parent.iterdir():
            contents = path.read_bytes()
            for marker in (self.value, self.password, key, bind["key"].encode()):
                self.assertNotIn(marker, contents)
        self.store.put("DEV", "orders", b"rotated")
        self.assertEqual(self.store.get("DEV", "orders"), b"rotated")
        self.assertEqual(self.store.binding("DEV", "orders"), bind)

    def test_tamper_environment_substitution_and_row_size(self):
        self.store.put("DEV", "api", self.value)
        self.update("UPDATE vault_credentials SET ref='PROD/api'")
        with self.assertRaises(ValueError):
            self.store.get("PROD", "api")
        self.update("UPDATE vault_credentials SET ref='DEV/api', nonce=zeroblob(12)")
        with self.assertRaises(ValueError):
            self.store.get("DEV", "api")
        self.update("UPDATE vault_credentials SET ciphertext=zeroblob(16401)")
        with self.assertRaises(ValueError):
            self.store.binding("DEV", "api")

    def test_wrong_password_library_replacement_and_open_missing(self):
        with self.assertRaises(ValueError):
            unlock(self.path, b"a different synthetic passphrase")
        with self.assertRaises(FileExistsError):
            initialize(self.path, self.password)
        self.store.put("DEV", "api", self.value)
        second = self.path.with_name("second.db")
        initialize(second, self.password)
        second.replace(self.path)
        with self.assertRaises(ValueError):
            self.store.put("DEV", "api", self.value)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.store.get("DEV", "api")
        self.assertFalse(self.path.exists())

    def test_meta_tampering(self):
        self.update("UPDATE vault_meta SET verifier=zeroblob(16)")
        with self.assertRaises(ValueError):
            unlock(self.path, self.password)
        with self.assertRaises(ValueError):
            self.store.put("DEV", "api", self.value)

    def test_single_entry_reader_does_not_retain_master(self):
        self.store.put("DEV", "orders", self.value)
        read = self.store.reader("DEV", "orders")
        original = weakref.ref(self.store)
        del self.store
        gc.collect()
        self.assertIsNone(original())
        self.assertEqual(read(), self.value)
        unlock(self.path, self.password).put("DEV", "orders", b"rotated")
        self.assertEqual(read(), b"rotated")

    def test_concurrent_updates_return_complete_secrets(self):
        values = [self.value + bytes([i]) for i in range(12)]
        def update(value):
            self.store.put("DEV", "api", value)
            return self.store.get("DEV", "api")
        with ThreadPoolExecutor(max_workers=4) as pool:
            for result in pool.map(update, values):
                self.assertIn(result, values)
        self.assertIn(self.store.get("DEV", "api"), values)

    def test_permissions_validation_and_atomic_failure(self):
        with self.assertRaises(ValueError):
            initialize(self.root / "weak.db", b"short")
        with self.assertRaises(ValueError):
            self.store.put("DEV", "../x", b"private")
        with self.assertRaises(ValueError):
            self.store.put("DEV", "api", bytes(16385))
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            unlock(self.path, self.password)
        new = self.path.with_name("new.db")
        with patch("credential_store.os.link", side_effect=OSError("synthetic failure")), self.assertRaises(OSError):
            initialize(new, self.password)
        self.assertFalse(new.exists())
        self.assertEqual(list(new.parent.glob(".keyheron-init-*")), [])


if __name__ == "__main__":
    unittest.main()
