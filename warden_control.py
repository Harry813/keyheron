"""Online connector authorization over mutually authenticated TLS 1.3."""

from contextlib import closing, contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sqlite3
import ssl
from socketserver import TCPServer
import threading
import time
from typing import NamedTuple
from urllib.parse import urlsplit

from warden_storage import open_audit, read_policy_bytes


ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
WARDEN = re.compile(r"spiffe://keyheron/warden/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
FIELDS = ("task", "connector", "action", "resource")
RESULTS = ("succeeded", "failed", "closed")
MAX_TTL = 900
AUDIT_HISTORY_ROWS = 65_536
AUDIT_PRUNE_INTERVAL = 256


class ControlBusy(OSError):
    pass


class _Quota(NamedTuple):
    task_rate: int
    server_rate: int
    task_concurrent: int
    server_concurrent: int


# The four classes together admit at most 256 requests/s and 32 active operations.
# A single Warden can have at most 16 outgoing connections across all classes.
_QUOTAS = {
    "ordinary": _Quota(48, 96, 8, 12),
    "session": _Quota(48, 64, 4, 8),
    "outcome": _Quota(48, 64, 2, 6),
    "closed": _Quota(16, 32, 2, 6),
}


def _traffic_class(path, request):
    if path == "/v1/session-check":
        return "session"
    if path == "/events":
        return "closed" if request.get("result") == "closed" else "outcome"
    return "ordinary"


class _RequestBudget:
    """Bound authenticated work. Counters for arbitrary task names last at most one window."""

    def __init__(self):
        self.changed = threading.Condition()
        self.window = -1
        self.totals = {}
        self.counts = {}
        self.active = {}
        self.active_totals = {}

    @contextmanager
    def request(self, actor, traffic="ordinary", *, wait=False):
        quota = _QUOTAS[traffic]
        key = (traffic, actor)
        with self.changed:
            def slot_available():
                return (self.active.get(key, 0) < quota.task_concurrent
                        and self.active_totals.get(traffic, 0) < quota.server_concurrent)

            # Only a Warden with a bounded set of live sessions queues lifecycle work.
            # Control server workers and ordinary Agent operations reject excess load immediately.
            if not self.changed.wait_for(slot_available, timeout=0.75 if wait else 0):
                raise ControlBusy("任务或控制服务请求已达上限")
            window = int(time.monotonic())
            if window != self.window:
                self.window = window
                self.totals.clear()
                self.counts.clear()
            count = self.counts.get(key, 0)
            total = self.totals.get(traffic, 0)
            if count >= quota.task_rate or total >= quota.server_rate:
                raise ControlBusy("任务或控制服务请求已达上限")
            self.totals[traffic] = total + 1
            self.counts[key] = count + 1
            self.active[key] = self.active.get(key, 0) + 1
            self.active_totals[traffic] = self.active_totals.get(traffic, 0) + 1
        try:
            yield
        finally:
            with self.changed:
                self.active[key] -= 1
                self.active_totals[traffic] -= 1
                if not self.active[key]:
                    del self.active[key]
                self.changed.notify_all()


def _object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("重复的 JSON 字段")
    return result


def _fields(obj, names):
    return isinstance(obj, dict) and set(obj) == set(names)


def valid_id(value):
    return isinstance(value, str) and bool(ID.fullmatch(value))


def _ttl(value):
    return type(value) is int and 1 <= value <= MAX_TTL


def _rules(rules):
    if not isinstance(rules, list) or len(rules) > 256:
        raise ValueError("每个任务或模板最多包含 256 条连接器授权")
    scopes = {}
    for rule in rules:
        if (not _fields(rule, (*FIELDS[1:], "ttl")) or not _ttl(rule["ttl"])
                or not all(valid_id(rule[k]) for k in FIELDS[1:])):
            raise ValueError("无效的连接器授权")
        scope = tuple(rule[k] for k in FIELDS[1:])
        if scope in scopes:
            raise ValueError("同一任务存在重复授权")
        scopes[scope] = rule["ttl"]
    return scopes


def validate_policy(policy):
    """Validate every template and task, then expand exact task grants."""
    if (not isinstance(policy, dict) or set(policy) - {"version", "wardens", "templates"}
            or type(policy.get("version")) is not int or policy["version"] != 1
            or not isinstance(policy.get("wardens"), dict)
            or not isinstance(policy.get("templates", {}), dict)):
        raise ValueError("无效的 Warden 控制策略")
    templates = {}
    for name, rules in policy.get("templates", {}).items():
        if not valid_id(name):
            raise ValueError("无效的 Warden 模板名称")
        templates[name] = _rules(rules)
    grants = {}
    for identity, entry in policy["wardens"].items():
        if (not isinstance(identity, str) or not WARDEN.fullmatch(identity)
                or not _fields(entry, ("tasks",)) or not isinstance(entry["tasks"], dict)):
            raise ValueError("无效的 Warden 身份或任务列表")
        for task, rules in entry["tasks"].items():
            if not valid_id(task):
                raise ValueError("无效的任务名称")
            if _fields(rules, ("template",)):
                name = rules["template"]
                if not valid_id(name) or name not in templates:
                    raise ValueError("任务引用了未知的 Warden 模板")
                grants[identity, task] = templates[name]
            else:
                grants[identity, task] = _rules(rules)
    return grants


def _read_policy_state(path):
    raw, _ = read_policy_bytes(path)
    policy = json.loads(raw, object_pairs_hook=_object)
    grants = validate_policy(policy)
    return policy["wardens"].keys(), grants


def read_policy(path):
    return _read_policy_state(path)[1]


def _context(protocol, ca, cert, key):
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca)
    context.verify_mode = ssl.CERT_REQUIRED
    if protocol == ssl.PROTOCOL_TLS_CLIENT:
        context.hostname_checks_common_name = False
    else:
        context.num_tickets = 0
    context.load_cert_chain(cert, key)
    return context


class ControlClient:
    """Only the trusted Warden holds these credentials. No redirects or system proxy."""

    def __init__(self, server_url, ca, cert, key):
        server = urlsplit(server_url)
        if (server.scheme != "https" or not server.hostname or server.username is not None
                or server.password is not None or server.path not in ("", "/")
                or server.query or server.fragment or server.port == 0):
            raise ValueError("控制服务必须是 HTTPS 源地址")
        self.host = server.hostname
        self.port = server.port
        self.credentials = ca, cert, key
        self.budget = _RequestBudget()

    def _post(self, path, body):
        # A Warden belongs to one task. Bound outgoing TLS handshakes as well as server work.
        traffic = _traffic_class(path, body)
        with self.budget.request(None, traffic, wait=traffic != "ordinary"):
            return self._send(path, body)

    def _send(self, path, body):
        try:
            tls = _context(ssl.PROTOCOL_TLS_CLIENT, *self.credentials)
            with closing(http.client.HTTPSConnection(self.host, self.port, context=tls, timeout=3)) as conn:
                conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
                response = conn.getresponse()
                if response.status == 403:
                    raise PermissionError("控制服务拒绝了本次请求")
                if response.status == 429:
                    raise ControlBusy("控制服务返回 HTTP 429")
                if response.status != 200:
                    raise OSError(f"控制服务返回 HTTP {response.status}")
                limit = 256 * 1024 if path == "/capabilities" else 4096
                payload = response.read(limit + 1)
                if len(payload) > limit:
                    raise OSError("控制服务响应过大")
                return json.loads(payload, object_pairs_hook=_object)
        except OSError:
            raise
        except (ValueError, RecursionError, http.client.HTTPException) as error:
            raise OSError("控制服务响应无效") from error

    def capabilities(self, task):
        reply = self._post("/capabilities", {"task": task})
        if not _fields(reply, ("capabilities",)):
            raise OSError("控制服务缺少能力列表")
        try:
            _rules(reply["capabilities"])
        except ValueError as error:
            raise OSError("控制服务的能力列表无效") from error
        return reply["capabilities"]

    def authorize(self, task, connector, action, resource):
        request = dict(zip(FIELDS, (task, connector, action, resource)))
        reply = self._post("/authorize", request)
        if not _fields(reply, ("allowed", "ttl")) or reply["allowed"] is not True or not _ttl(reply["ttl"]):
            raise OSError("缺少有效的控制服务授权")
        return reply["ttl"]

    def plugin_grant(self, task, connector, action, resource, *, session_check=False):
        request = dict(zip(FIELDS, (task, connector, action, resource)))
        reply = self._post("/v1/session-check" if session_check else "/v1/authorize", request)
        if not _fields(reply, ("scope", "ttl")) or not _ttl(reply["ttl"]) or reply["scope"] != request:
            raise PermissionError("控制服务未确认完整插件授权范围")
        return reply

    def event(self, task, connector, action, resource, result):
        request = {**dict(zip(FIELDS, (task, connector, action, resource))), "result": result}
        try:
            reply = self._post("/events", request)
        except ControlBusy:
            if result != "closed":
                raise
            # An explicit admission refusal cannot have written a row. Retry a close once.
            time.sleep(1)
            reply = self._post("/events", request)
        if not _fields(reply, ("recorded",)) or reply["recorded"] is not True:
            raise OSError("控制服务未确认事件")


class _Handler(BaseHTTPRequestHandler):
    # No request line, URL, arbitrary body or raw HTTP header goes to a log.
    def log_message(self, *_):
        pass

    def send_error(self, code, message=None, explain=None):
        self._reply(code, {})

    def _reply(self, status, payload):
        data = json.dumps(payload).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path not in ("/authorize", "/v1/authorize", "/v1/session-check", "/events", "/capabilities"):
            self._reply(404, {})
            return
        uris = [name for kind, name in self.connection.getpeercert().get("subjectAltName", ()) if kind == "URI"]
        if len(uris) != 1 or not WARDEN.fullmatch(uris[0]):
            self._reply(403, {})
            return
        discovery = self.path == "/capabilities"
        event = self.path == "/events"
        fields = ("task",) if discovery else FIELDS
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not re.fullmatch("[0-9]{1,4}", lengths[0])
                    or not 0 < int(lengths[0]) <= 4096 or "Transfer-Encoding" in self.headers
                    or self.headers.get_content_type() != "application/json"):
                raise ValueError
            size = int(lengths[0])
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError
            request = json.loads(body, object_pairs_hook=_object)
            if (not _fields(request, fields + (("result",) if event else ()))
                    or not all(valid_id(request[k]) for k in fields)
                    or (event and request["result"] not in RESULTS)):
                raise ValueError
        except (ValueError, RecursionError):
            self._reply(400, {})
            return
        try:
            with self.server.budget.request((uris[0], request["task"]), _traffic_class(self.path, request)):
                self._decide(uris[0], request, discovery, event)
        except ControlBusy:
            self._reply(429, {})

    def _decide(self, identity, request, discovery, event):
        try:
            identities, grants = _read_policy_state(self.server.policy)
            scopes = grants.get((identity, request["task"]))
            scope = tuple(request.get(k, "") for k in FIELDS[1:])
            ttl = (scopes or {}).get(scope)
            actor_scope = (identity, request["task"], *scope)
            with closing(open_audit(self.server.audit)) as db, db:
                if event or self.path == "/v1/session-check":
                    # A registered instance can finish a recently granted operation after task revocation.
                    terminal = event and request["result"] in ("failed", "closed")
                    allowed = identity in identities and (ttl is not None or terminal) and db.execute(
                        """SELECT at BETWEEN datetime('now', ?) AND CURRENT_TIMESTAMP FROM warden_events
                           WHERE warden=? AND task=? AND connector=? AND action=? AND resource=?
                           AND kind='authorization' AND result='allowed' ORDER BY id DESC LIMIT 1""",
                        (f"-{MAX_TTL} seconds", *actor_scope)).fetchone() == (1,)
                    # A successful recheck refreshes the evidence used to accept a late close.
                    kind = "reported" if event else "authorization"
                elif discovery:
                    kind = "discovery"
                    allowed = scopes is not None
                else:
                    kind = "authorization"
                    allowed = ttl is not None
                outcome = request.get("result", "allowed") if allowed else "denied"
                row = db.execute("""INSERT INTO warden_events
                              (warden, task, connector, action, resource, kind, result)
                              VALUES (?, ?, ?, ?, ?, ?, ?)""", (*actor_scope, kind, outcome))
                if row.lastrowid % AUDIT_PRUNE_INTERVAL == 0:
                    # Keep valid authorization receipts for terminal events even after a busy window.
                    db.execute("""DELETE FROM warden_events WHERE id > (SELECT legacy_end FROM warden_audit_retention)
                                  AND id <= ? AND (kind != 'authorization' OR result != 'allowed'
                                  OR at NOT BETWEEN datetime('now', ?) AND CURRENT_TIMESTAMP)""",
                               (row.lastrowid - AUDIT_HISTORY_ROWS, f"-{MAX_TTL} seconds"))
        except (OSError, ValueError, RecursionError, sqlite3.Error):
            self._reply(503, {})
            return
        if not allowed:
            self._reply(403, {})
        elif discovery:
            rules = [{**dict(zip(FIELDS[1:], key)), "ttl": ttl} for key, ttl in scopes.items()]
            self._reply(200, {"capabilities": rules})
        elif event:
            self._reply(200, {"recorded": True})
        elif self.path in ("/v1/authorize", "/v1/session-check"):
            self._reply(200, {"scope": dict(zip(FIELDS, (request["task"], *scope))), "ttl": ttl})
        else:
            self._reply(200, {"allowed": True, "ttl": ttl})


class WardenHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer normally reverse-resolves the bound IP. Warden endpoints use the
        # listener address for display and TLS SANs for identity; neither needs a PTR lookup.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class ControlServer(WardenHTTPServer):
    """Run each timed TLS handshake in its worker, outside the accept loop."""

    def __init__(self, address, policy, audit, ca, cert, key):
        read_policy(policy)
        self.policy = policy
        self.audit = audit
        self.tls = _context(ssl.PROTOCOL_TLS_SERVER, ca, cert, key)
        self.slots = threading.BoundedSemaphore(32)
        self.budget = _RequestBudget()
        with closing(open_audit(audit, create=True)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS warden_events (
                id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                warden TEXT NOT NULL, task TEXT NOT NULL, connector TEXT NOT NULL,
                action TEXT NOT NULL, resource TEXT NOT NULL, kind TEXT NOT NULL, result TEXT NOT NULL
            )""")
            db.execute("""CREATE INDEX IF NOT EXISTS warden_authorized_scopes
                          ON warden_events(warden, task, connector, action, resource)
                          WHERE kind='authorization' AND result='allowed'""")
            db.execute("""CREATE TABLE IF NOT EXISTS warden_audit_retention (
                          id INTEGER PRIMARY KEY CHECK(id=1), legacy_end INTEGER NOT NULL)""")
            db.execute("""INSERT OR IGNORE INTO warden_audit_retention
                          SELECT 1, COALESCE(MAX(id),0) FROM warden_events""")
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def finish_request(self, request, client_address):
        try:
            request.settimeout(3)
            with self.tls.wrap_socket(request, server_side=True) as conn:
                self.RequestHandlerClass(conn, client_address, self)
        except OSError:
            pass
        finally:
            self.slots.release()


def add_server_arguments(parser):
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    for flag in ("policy", "audit", "ca", "cert", "key"):
        parser.add_argument("--" + flag, type=Path, required=True)


def serve(args):
    with ControlServer((args.listen, args.port), args.policy, args.audit, args.ca, args.cert, args.key) as server:
        print(f"Warden 控制服务已监听 {server.server_address[0]}:{server.server_port}", flush=True)
        server.serve_forever()
    return 0
