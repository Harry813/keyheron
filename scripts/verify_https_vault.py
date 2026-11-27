"""Use encrypted credentials through the Rust HTTPS broker, including live rotation."""

from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent_access import control, running_external
from credential_store import initialize, unlock
from verify_external import Fixture, READ, curl, make_ca


def verify(root, core=None):
    tls = root / "tls"
    make_ca(tls)
    passphrase = secrets.token_urlsafe(32).encode()
    unlock_file = root / "unlock"
    unlock_file.write_bytes(passphrase)
    unlock_file.chmod(0o600)
    vault = root / "vault.sqlite3"
    initialize(vault, passphrase)
    store = unlock(vault, passphrase)
    with Fixture(root, "DEV").start(tls) as origin:
        first = origin.keys["reader"].encode()
        store.put("DEV", "api-secret", first)
        store.put("STG", "api-secret", secrets.token_urlsafe(32).encode())
        conf = {
            "version": 1, "task": "encrypted-https-test",
            "identities": {"applicant": "client", "approver": "owner"},
            "credential_store": {"path": vault.name, "passphrase_file": unlock_file.name},
            "environments": {"DEV": {
                "origin": origin.origin, "ca_file": str(tls / "root.pem"),
                "credential_refs": {"reader": "api-secret"},
                "routes": {"read": {"method": "GET", "path": READ, "resource": "item", "credential": "reader"}}
            }}
        }
        policy = root / "policy.json"
        policy.write_text(json.dumps(conf))
        state = root / "state"
        derived_key = store.binding("DEV", "api-secret")["key"].encode()
        with running_external(policy, state, core=core) as info:
            control(info, "switch", {"environment": "DEV"})
            session = control(info, "sdk-session", {"environment": "DEV"})

            def fetch():
                return curl(info, session, "DEV", origin.origin + READ)

            assert fetch()[0] == (200, 200)
            rotated = secrets.token_urlsafe(32).encode()
            store.put("DEV", "api-secret", rotated)
            origin.keys["reader"] = rotated.decode()
            assert fetch()[0] == (200, 200), "rotated credential not recognized"
            assert origin.authenticated == ["reader", "reader"]
            with closing(sqlite3.connect(vault)) as db, db:
                db.execute("UPDATE vault_credentials SET ciphertext=zeroblob(length(ciphertext)) WHERE ref=?",
                           ("DEV/api-secret",))
            count = origin.arrivals
            status, error = fetch()
            assert status[-1] >= 400 and origin.arrivals == count, "tampered record reached upstream"
            for secret in (first, rotated, derived_key, passphrase):
                assert secret not in error.encode()
                assert secret not in json.dumps(info).encode()
                for file in [vault, *state.rglob("*")]:
                    if file.is_file():
                        assert secret not in file.read_bytes(), "sensitive bytes persisted in broker output"


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="keyheron-vault-https-") as tmp:
        verify(Path(tmp), os.environ.get("KEYHERON_TEST_CORE"))
    print("Encrypted HTTPS lookup, rotation, tamper rejection and client isolation passed.")
