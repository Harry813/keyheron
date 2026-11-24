"""Exercise control-plane resource limits and cleanup with an isolated TLS fixture."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_access import control, running_external
from verify_external import Fixture, READ, check, curl, make_ca


class PausedFixture(Fixture):
    def __init__(self, directory):
        super().__init__(directory, "PROD")
        self.readers = threading.Condition()
        self.pending = 0
        self.release = threading.Event()
        self.large_read = False

    def handler(self):
        fixture = self

        class Handler(super().handler()):
            def do_GET(self):
                if not fixture.release.is_set():
                    with fixture.readers:
                        fixture.pending += 1
                        fixture.readers.notify_all()
                    if not fixture.release.wait(12):
                        self.send_error(503)
                        return
                if fixture.large_read and self.path == READ:
                    if (
                        self.headers.get("Authorization")
                        != "Bearer " + fixture.keys["reader"]
                    ):
                        self.send_error(401)
                        return
                    chunk = b"public fixture record\n" * 1024
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(chunk) * 128))
                    self.end_headers()
                    for _ in range(128):
                        self.wfile.write(chunk)
                else:
                    super().do_GET()

        return Handler


def expect_error(status, fn, *args):
    try:
        fn(*args)
    except RuntimeError as error:
        check(f"HTTP {status}" in str(error), f"expected HTTP {status}, got {error}")
    else:
        raise AssertionError(f"expected HTTP {status}")


def verify(core):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ca = root / "ca"
        make_ca(ca)
        producer = PausedFixture(root)
        with producer.start(ca):
            state = root / "state"
            policy = root / "policy.json"
            task = "state-regression"
            policy.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "task": task,
                        "identities": {"applicant": "reader", "approver": "reviewer"},
                        "environments": {"PROD": producer.config(ca / "root.pem")},
                    }
                )
            )
            with running_external(policy, state, core=core) as info:
                control(info, "switch", {"environment": "PROD"})
                grant = control(info, "request", {"action": "diagnose", "ttl": 60})
                diagnostic = control(info, "request", {"action": "diagnose", "ttl": 60})
                ref = {"id": diagnostic["id"]}
                control(info, "approve", ref, owner=True)
                with ThreadPoolExecutor(max_workers=16) as pool:
                    reads = [pool.submit(control, info, "read", {}) for _ in range(15)]
                    slow_diagnostic = pool.submit(control, info, "use", ref)
                    try:
                        with producer.readers:
                            check(
                                producer.readers.wait_for(
                                    lambda: producer.pending == 16, 8
                                ),
                                "managed reads did not reach the fixture",
                            )
                        expect_error(429, control, info, "read", {})
                        expect_error(429, control, info, "use", ref)
                        control(info, "approve", {"id": grant["id"]}, owner=True)
                        control(info, "revoke", ref, owner=True)
                        expect_error(403, control, info, "use", ref)
                    finally:
                        producer.release.set()
                    check(
                        all(f.result()["upstream_status"] == 200 for f in reads),
                        "admitted reads did not finish normally",
                    )
                    check(
                        slow_diagnostic.result()["upstream_status"] == 200,
                        "already admitted diagnostic did not finish normally",
                    )

                producer.large_read = True
                metadata = control(info, "read", {})
                check(
                    metadata["upstream_status"] == 200
                    and len(json.dumps(metadata)) < 1000,
                    "large managed read did not return only metadata",
                )
                producer.large_read = False
                sessions = [
                    control(info, "sdk-session", {"environment": "PROD", "ttl": 60})
                    for _ in range(2)
                ]
                check(
                    curl(info, sessions[0], "PROD", producer.origin + READ)[0]
                    == (200, 200),
                    "active SDK read failed",
                )
                with sqlite3.connect(state / "events.sqlite3") as db:
                    # Keep an unrelated expiry pending while the reviewer revokes a live grant.
                    db.execute("""CREATE TRIGGER item_audit_failure BEFORE INSERT ON events
                                  WHEN NEW.action IN ('expire', 'revoke')
                                  BEGIN SELECT RAISE(FAIL, 'fixture audit outage'); END""")
                    control(info, "request", {"action": "diagnose", "ttl": 1})
                    time.sleep(1.1)
                    expect_error(
                        503,
                        lambda: control(
                            info, "revoke", {"id": grant["id"]}, owner=True
                        ),
                    )
                    before = producer.arrivals
                    expect_error(403, control, info, "use", {"id": grant["id"]})
                    check(
                        producer.arrivals == before, "disabled grant reached upstream"
                    )
                    db.execute("DROP TRIGGER item_audit_failure")
                    deadline = time.monotonic() + 8
                    while not db.execute(
                        "SELECT 1 FROM events WHERE actor='reviewer' AND action='revoke' "
                        "AND result='allowed' AND instr(detail, ?) > 0",
                        (grant["id"],),
                    ).fetchone():
                        check(
                            time.monotonic() < deadline,
                            "reviewer's revocation audit was not recovered",
                        )
                        time.sleep(0.1)
                    db.execute("""CREATE TRIGGER temporary_audit_failure BEFORE INSERT ON events
                                  WHEN NEW.action='revoke' AND NEW.actor='system'
                                  BEGIN SELECT RAISE(FAIL, 'fixture audit outage'); END""")
                    expect_error(503, control, info, "end", {})
                    check(
                        control(info, "state")["environment"] is None,
                        "base session still active during cleanup",
                    )
                    expect_error(
                        403, control, info, "sdk-session", {"environment": "PROD"}
                    )
                    before = producer.arrivals
                    for session in sessions:
                        check(
                            curl(info, session, "PROD", producer.origin + READ)[0][0]
                            == 407,
                            "SDK session remained active during audit outage",
                        )
                    check(
                        producer.arrivals == before,
                        "revoked SDK traffic reached upstream",
                    )
                    db.execute("DROP TRIGGER temporary_audit_failure")
                    deadline = time.monotonic() + 8
                    while True:
                        closed = [
                            row[0]
                            for row in db.execute(
                                "SELECT detail FROM events WHERE action='sdk-close'"
                            )
                        ]
                        if all(
                            any(
                                session["id"] in detail and "任务结束" in detail
                                for detail in closed
                            )
                            for session in sessions
                        ):
                            break
                        check(
                            time.monotonic() < deadline,
                            "pending SDK closure audit was not retried",
                        )
                        time.sleep(0.1)
                    control(info, "switch", {"environment": "PROD"})
                    check(
                        control(info, "read", {})["upstream_status"] == 200,
                        "legitimate reads failed after recovery",
                    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path)
    verify(parser.parse_args().core)
    print(
        "Managed read admission, approval availability and audited SDK recovery passed."
    )
