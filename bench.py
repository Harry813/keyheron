"""Compare the same authenticated DEV read via three local paths. No real credentials."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
import hashlib
import http.client
import json
import math
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
from time import perf_counter_ns

from tools import keyfence_binary
from web_demo import core_binary, running


@dataclass(repr=False)
class Endpoint:
    name: str
    port: int
    method: str
    path: str
    token: str


def exchange(conn, endpoint):
    headers = {"Authorization": "Bearer " + endpoint.token}
    if endpoint.name == "keyfence":
        headers["Connection"] = "close"
    body = None
    if endpoint.method == "POST":
        headers["Content-Type"] = "application/json"
        body = "{}"
    conn.request(endpoint.method, endpoint.path, body=body, headers=headers)
    response = conn.getresponse()
    status, raw = response.status, response.read()
    if endpoint.name == "keyfence":
        conn.close()
    return status, raw


def lane(conn, endpoint, count):
    times, failures = [], Counter()
    for _ in range(count):
        started = perf_counter_ns()
        try:
            status, raw = exchange(conn, endpoint)
            elapsed = perf_counter_ns() - started
            if status != 200:
                failures[f"HTTP {status}"] += 1
                continue
            payload = json.loads(raw)
            if payload.get("environment") != "DEV" or payload.get("account") != "dev-reader":
                failures["unexpected upstream account"] += 1
                continue
            times.append(elapsed)
        except (OSError, http.client.HTTPException, ValueError, AttributeError) as err:
            conn.close()
            failures[type(err).__name__] += 1
    return times, failures


def percentile(sorted_samples, percent):
    if not sorted_samples:
        return None
    index = math.ceil(len(sorted_samples) * percent / 100) - 1
    return round(sorted_samples[index] / 1_000_000, 4)


def measure(endpoints, workers, samples, warmup):
    connections = {
        e.name: [http.client.HTTPConnection("127.0.0.1", e.port, timeout=8) for _ in range(workers)]
        for e in endpoints
    }
    timings = {e.name: [] for e in endpoints}
    failures = {e.name: Counter() for e in endpoints}
    wall = {e.name: 0 for e in endpoints}
    rounds = min(12, samples // workers)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for e in endpoints:
                for _, errors in pool.map(lambda c: lane(c, e, warmup), connections[e.name]):
                    if errors:
                        raise RuntimeError(f"{e.name} warm-up failed: {dict(errors)}")
            for i in range(rounds):
                per_round = samples // rounds + int(i < samples % rounds)
                shift = i % len(endpoints)
                for e in endpoints[shift:] + endpoints[:shift]:
                    start = perf_counter_ns()
                    futures = [
                        pool.submit(lane, c, e, per_round // workers + int(j < per_round % workers))
                        for j, c in enumerate(connections[e.name])
                    ]
                    for future in futures:
                        ns, errors = future.result()
                        timings[e.name].extend(ns)
                        failures[e.name].update(errors)
                    wall[e.name] += perf_counter_ns() - start
    finally:
        for group in connections.values():
            for conn in group:
                conn.close()

    summary = {}
    for e in endpoints:
        ns = sorted(timings[e.name])
        summary[e.name] = {
            "samples": samples, "success": len(ns), "errors": sum(failures[e.name].values()),
            "failures": dict(failures[e.name]),
            "p50_ms": percentile(ns, 50), "p95_ms": percentile(ns, 95), "p99_ms": percentile(ns, 99),
            "successful_rps": round(len(ns) * 1_000_000_000 / wall[e.name], 1),
        }

    def delta(baseline):
        complete, base = summary["rust_keyfence_audit"], summary[baseline]
        return {key: round(complete[key] - base[key], 4) for key in ("p50_ms", "p95_ms", "p99_ms")
                if complete[key] is not None and base[key] is not None}

    return {"concurrency": workers, "rounds": rounds, "paths": summary,
            "complete_minus_direct": delta("direct"), "complete_minus_keyfence": delta("keyfence")}


def binary_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def benchmark(binary, samples, concurrencies, warmup):
    core = core_binary()
    hashes = {"core_sha256": binary_digest(core), "keyfence_sha256": binary_digest(binary)}
    with tempfile.TemporaryDirectory(prefix="agent-access-benchmark-") as tmp:
        db = Path(tmp) / "audit.sqlite"
        with running(binary, db, port=0, core=core) as (rt, port, tokens):
            with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=8)) as control:
                control.request("POST", "/api/switch", body='{"environment":"DEV"}', headers={
                    "Content-Type": "application/json", "Authorization": "Bearer " + tokens["alice"],
                })
                response = control.getresponse()
                response.read()
                if response.status != 200:
                    raise RuntimeError(f"DEV activation failed (HTTP {response.status})")
            broker = rt["DEV"]
            origin, upstream_token = broker.benchmark_origin()
            proxy_token = broker.issue("read", 900, task_id="performance", actor="alice")
            path = "/service/status"
            endpoints = [
                Endpoint("direct", origin, "GET", path, upstream_token),
                Endpoint("keyfence", broker.proxy_port, "GET", f"http://localhost:{origin}{path}", proxy_token),
                Endpoint("rust_keyfence_audit", port, "POST", "/api/read", tokens["alice"]),
            ]
            try:
                modes = [measure(endpoints, c, samples, warmup) for c in concurrencies]
            finally:
                broker.revoke(proxy_token)
            expected_per_path = sum(samples + warmup * c for c in concurrencies)
            origin_reads = len(broker.observations)
            with closing(sqlite3.connect(db)) as reader:
                audited = reader.execute(
                    "SELECT count(*) FROM events WHERE action='read' AND result='allowed' AND environment='DEV'"
                ).fetchone()[0]
                journal = reader.execute("PRAGMA journal_mode").fetchone()[0]
                integrity = reader.execute("PRAGMA quick_check").fetchone()[0]

    ok = (all(not p["errors"] for m in modes for p in m["paths"].values())
          and origin_reads == 3 * expected_per_path and audited == expected_per_path
          and integrity == "ok" and journal == "wal")
    if hashes != {"core_sha256": binary_digest(core), "keyfence_sha256": binary_digest(binary)}:
        raise RuntimeError("基准运行期间二进制文件发生变化，请重新测量")
    return {"passed": ok, "binaries": hashes, "host": {"os": platform.system(), "release": platform.release(),
                                    "arch": platform.machine(), "python": platform.python_version()},
            "method": {"target": "same synthetic DEV reader and local upstream GET /service/status",
                       "wire": "loopback HTTP; no TLS, WAN, browser rendering or external provider",
                       "latency": "client request start through receipt of full HTTP response; excludes response validation",
                       "quantiles": "nearest-rank over successful requests; differences between path quantiles, not paired latencies",
                       "schedule": "closed-loop load; rotated path order per chunk; one reusable HTTP client connection per path per worker",
                       "proxy_hop": "KeyFence HTTP fixture uses a fresh agent-side proxy connection per request",
                       "warmup_per_worker_and_path": warmup, "samples_per_path_per_concurrency": samples},
            "measurements": modes, "checks": {"expected_upstream_reads": 3 * expected_per_path,
                "observed_upstream_reads": origin_reads, "expected_full_stack_audit_rows": expected_per_path,
                "observed_full_stack_audit_rows": audited, "sqlite_journal": journal, "sqlite_quick_check": integrity}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=1200, help="每个并发档、每条链路的测量请求数")
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8], help="并发档位，例如 1 8")
    parser.add_argument("--warmup", type=int, default=12, help="每个客户端、每条路径的预热请求数")
    parser.add_argument("--max-added-p95-ms", type=float, metavar="N",
                        help="逐并发档检查完整链路相对 KeyFence 的 p95 增量上限（毫秒）")
    parser.add_argument("--json", action="store_true", help="输出完整 JSON")
    args = parser.parse_args()
    if (not 1 <= args.samples <= 100_000 or not 1 <= args.warmup <= 500
            or any(not 1 <= c <= min(64, args.samples) for c in args.concurrency)):
        parser.error("样本范围为 1–100000，预热为 1–500，并发为 1–64 且不能多于样本。")
    limit = args.max_added_p95_ms
    if limit is not None and (not math.isfinite(limit) or limit < 0):
        parser.error("--max-added-p95-ms 必须是非负有限数。")
    result = benchmark(keyfence_binary(), args.samples, args.concurrency, args.warmup)
    if limit is not None:
        failed = []
        for mode in result["measurements"]:
            delta = mode["complete_minus_keyfence"].get("p95_ms")
            if delta is None or delta > limit:
                failed.append({"concurrency": mode["concurrency"], "added_p95_ms": delta})
        result["p95_budget"] = {"max_added_p95_ms": limit, "baseline": "keyfence", "failed_modes": failed}
        result["passed"] = result["passed"] and not failed
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("并发  路径                     p50(ms)   p95(ms)   p99(ms)    成功req/s  错误")
        for mode in result["measurements"]:
            for name, p in mode["paths"].items():
                print(f'{mode["concurrency"]:>4}  {name:<21} {str(p["p50_ms"]):>8} {str(p["p95_ms"]):>9}'
                      f' {str(p["p99_ms"]):>9} {p["successful_rps"]:>12.1f}  {p["errors"]}')
        print("请求及审计对账", result["checks"])
        if limit is not None:
            print("相对 KeyFence 的 p95 增量门槛", result["p95_budget"])
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
