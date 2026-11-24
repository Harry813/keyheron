"""Exercise the Rust API, persistent audit trail and mock upstream without a browser."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout
import http.client
import io
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

from tools import keyfence_binary
from web_demo import running


def api(port, token, path, body=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=10)) as conn:
        conn.request("GET" if body is None else "POST", "/api/" + path,
                     body=None if body is None else json.dumps(body), headers=headers)
        r = conn.getresponse()
        result = json.loads(r.read())
    if expected is not None and r.status != expected:
        raise AssertionError(f"{path}: HTTP {r.status}, expected {expected}")
    return r.status, result


def verify():
    binary = keyfence_binary()
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "test.sqlite3"
        with running(binary, db) as (rt, port, roles):
            a, o = roles["alice"], roles["owner"]
            def post(role, action, data=None, status=200):
                return api(port,role,action,data or {},status)[1]
            api(port,None,"state",expected=401)
            post(o,"switch",{"environment":"PROD"},403)
            for env in ("DEV", "STG", "PROD"):
                post(a,"switch",{"environment":env})
                if post(a,"read")["account"] != env.lower() + "-reader":
                    raise AssertionError("wrong upstream identity")
            def request(kind, ttl):
                return post(a,"request",{"action":kind,"ttl":ttl})["id"]
            gid = request("diagnose",40)
            ref = {"id":gid}
            post(a,"approve",ref,403)
            post(a,"use",ref,403)
            post(o,"approve",ref)
            if post(a,"use",ref)["account"] != "prod-diagnostics":
                raise AssertionError("diagnostic account mismatch")
            post(a,"revoke",ref)
            post(a,"use",ref,403)
            post(a,"read")
            run_id = request("retry",40)
            run_ref = {"id":run_id}
            post(o,"approve",run_ref)
            def once(_):
                return api(port,a,"use",run_ref,expected=None)[0]
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(once,range(8)))
            if results.count(200) != 1 or results.count(403) != 7:
                raise AssertionError("duplicate authorization accepted")
            effects = [r for r in rt["PROD"].observations if r.get("operation_id") == run_id]
            if len(effects) != 1 or effects[0]["account"] != "prod-worker":
                raise AssertionError("unexpected upstream side effects")
            if post(o,"outcome",run_ref) != {"state":"applied","run_number":1}:
                raise AssertionError("independent upstream receipt lookup failed")
            if len([r for r in rt["PROD"].observations if r.get("operation_id") == run_id]) != 1:
                raise AssertionError("receipt lookup repeated the job")
            expiring = request("diagnose",2)
            post(o,"approve",{"id":expiring})
            time.sleep(2.15)
            post(a,"use",{"id":expiring},403)
            pending = request("retry",30)
            post(a,"switch",{"environment":"DEV"})
            post(o,"approve",{"id":pending},403)
            post(a,"end")
            post(a,"read",status=403)
            # Submit through the same API the browser uses, then handle it from the terminal client.
            from console import interactive_client
            post(a,"switch",{"environment":"PROD"})
            via_web = request("diagnose",60)
            console_input = io.StringIO("status\nreview 1\napprove 1\nuse 1\nrevoke 1\nexit\n")
            console_output = io.StringIO()
            with patch("sys.stdin",console_input), redirect_stdout(console_output):
                interactive_client(port,roles)
            if "prod-diagnostics" not in console_output.getvalue():
                raise AssertionError("terminal did not execute browser-originated grant")
            events = api(port,o,"events?limit=100")[1]["events"]
            raw = json.dumps(events,ensure_ascii=False)
            if "kf_" in raw or a in raw or o in raw:
                raise AssertionError("unexpected bearer value in audit output")
            if not any(e["action"] == "expire" and expiring in e["detail"] for e in events):
                raise AssertionError("missing expiry audit")
            if not any(e["action"] == "revoke" and pending in e["detail"] for e in events):
                raise AssertionError("missing auto-revocation audit")
            if not any(e["action"]=="approve" and e["actor"]=="owner" and via_web in e["detail"] for e in events):
                raise AssertionError("terminal approval not visible in browser history endpoint")
            for verb in ("admit","use","outcome"):
                if not any(e["action"]==verb and e["result"]=="allowed" and run_id in e["detail"] for e in events):
                    raise AssertionError(f"missing correlated {verb} event")
            first = api(port,o,"events?environment=PROD&limit=3")[1]["events"]
            second = api(port,o,f"events?environment=PROD&limit=3&before={first[-1]['id']}")[1]["events"]
            if len({e["id"] for e in first+second}) != 6 or any(e["environment"]!="PROD" for e in first+second):
                raise AssertionError("audit cursor or environment filter failed")
            ids = {e["id"] for e in events}
        with running(binary,db) as (_,port,roles):
            after = api(port,roles["owner"],"events?limit=100")[1]["events"]
            if not ids.issubset(e["id"] for e in after):
                raise AssertionError("audit history lost over restart")
            if api(port,roles["alice"],"state")[1]["environment"] is not None:
                raise AssertionError("active access survived restart")
            api(port,o,"state",expected=401)
        return {"outcome":"passed","read_accounts":["dev-reader","stg-reader","prod-reader"],
                "concurrent_retries":{"accepted":1,"refused":7,"upstream_executions":1},
                "audit_events_retained_across_restart":len(ids),"role_separation":True,
                "web_session_end_and_upstream_receipt_checked":True,"terminal_and_web_share_one_history":True,
                "expiry_and_environment_revocation_audited":True,"environment_filter_and_pagination":True,
                "role_tokens_rotated_on_restart":True}


if __name__ == "__main__":
    print(json.dumps(verify(),indent=2))
