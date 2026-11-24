"""Lifecycle and failure checks for the demo (no production services)."""
import concurrent.futures
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from access import Access, Denied
from runtime import DemoRuntime
from tools import keyfence_binary


def check(exists, message):
    if not exists:
        raise AssertionError(message)


def crash_fixture():
    # No finally/context teardown: the guards must notice the controller has gone.
    with DemoRuntime(keyfence_binary()) as rt:
        control = Access(rt)
        control.start_task("alice", "crash-test")
        token = control.switch("alice", "crash-test", "PROD")
        check(rt["PROD"].call(token, "GET", "/service/status")[0] == 200, "unusable initial token")
        print(json.dumps([rt[env].proxy_port for env in ("DEV", "STG", "PROD")]), flush=True)
        # Crash only after the parent has verified the readiness notification.
        check(sys.stdin.buffer.read(1) == b"!", "missing crash instruction")
        os._exit(0)


def can_connect(port):
    with socket.socket() as s:
        s.settimeout(.1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def crash_cleanup():
    with tempfile.TemporaryDirectory() as tmp:
        with subprocess.Popen([sys.executable, "-B", __file__, "--crash-fixture"],
                              env={"PATH": os.defpath, "TMPDIR": tmp},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE) as controller:
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(controller.stdout, selectors.EVENT_READ)
                    check(ready.select(120), "cold fixture did not become ready within 120 seconds")
                ports = json.loads(controller.stdout.readline())
                check(len(set(ports)) == 3 and all(can_connect(p) for p in ports), "missing live fixture listeners")
                controller.stdin.write(b"!")
                controller.stdin.flush()
                check(controller.wait(timeout=5) == 0, "fixture controller did not exit abruptly")
            finally:
                if controller.poll() is None:
                    controller.kill()
                    controller.wait()
        for _ in range(80):
            if not any(can_connect(port) for port in ports) and not list(Path(tmp).iterdir()):
                return
            time.sleep(.1)
        raise AssertionError("controller exited but a broker listener or temporary directory survived")


def validate():
    binary = keyfence_binary()
    with DemoRuntime(binary) as rt:
        ctl = Access(rt)
        ctl.start_task("alice", "switch-check")
        old = ctl.switch("alice", "switch-check", "STG")
        check(rt["STG"].call(old, "GET", "/service/status")[1].get("account") == "stg-reader",
              "the inherited proxy and API listeners did not serve the broker")
        with patch.object(rt["STG"], "revoke", side_effect=OSError("simulated acknowledgement outage")), \
             patch.object(rt["PROD"], "issue", wraps=rt["PROD"].issue) as prod_issue:
            try:
                ctl.switch("alice", "switch-check", "PROD")
            except RuntimeError:
                pass
            else:
                raise AssertionError("reported a successful switch with unconfirmed revocation")
            prod_issue.assert_not_called()
            check(ctl.status("alice", "switch-check")["base"] == [], "controller still considered task active")
        ctl.switch("alice", "switch-check", "PROD")
        check(rt["STG"].call(old, "GET", "/service/status")[0] == 403, "unrevoked old credential")
        # Concurrent transitions to two authorized environments must leave exactly one live token.
        def select(env):
            return env, ctl.switch("alice", "switch-check", env)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            tokens = list(pool.map(select, ("DEV", "STG")))
        alive = [env for env, token in tokens if rt[env].call(token, "GET", "/service/status")[0] == 200]
        check(alive == [ctl.status("alice", "switch-check")["environment"]], "two environments remained active")
        before = ctl.switch("alice", "switch-check", "PROD")
        req = ctl.request("alice", "switch-check", "retry", "job-4821")
        ctl.approve("owner", req)
        broker = rt["PROD"]
        real_call = broker.call
        def lost_reply(*args, **kwargs):
            real_call(*args, **kwargs)
            raise TimeoutError("simulated response loss after upstream side effect")
        with patch.object(broker, "call", side_effect=lost_reply):
            try:
                ctl.use("alice", req)
            except TimeoutError:
                pass
            else:
                raise AssertionError("unacknowledged response was labeled successful")
        try:
            ctl.use("alice", req)
        except Denied:
            pass
        else:
            raise AssertionError("replayed a one-shot operation with unknown outcome")
        check(len([e for e in broker.observations if e.get("operation_id") == req]) == 1,
              "more than one execution after lost response")
        check(ctl.outcome("alice", req) == {"state": "applied", "run_number": 1},
              "could not reconcile the unacknowledged request against the upstream ledger")
        try:
            ctl.outcome("bob", req)
        except Denied:
            pass
        else:
            raise AssertionError("unrelated principal read another task's receipt")
    with DemoRuntime(binary) as restarted:
        check(restarted["PROD"].call(before, "GET", "/service/status")[0] == 403,
              "new broker accepted a previous runtime token")
    crash_cleanup()
    return {"revocation_outage_blocked_switch": True, "concurrent_switch_has_one_live_environment": True,
            "broker_served_authenticated_read_over_prebound_listeners": True,
            "lost_reply_reconciled_without_repeating_operation": True, "old_token_rejected_after_restart": True,
            "controller_abrupt_exit_closed_all_brokers_and_removed_temporary_material": True}


if __name__ == "__main__":
    if sys.argv[1:] == ["--crash-fixture"]:
        crash_fixture()
    else:
        print(json.dumps(validate(), indent=2))
