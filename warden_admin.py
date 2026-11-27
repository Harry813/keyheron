"""Local operator console for task-scoped connector policies."""
from contextlib import closing
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile
import webbrowser

from plugin_runtime import PluginRuntime, add_runtime_arguments
from warden_control import _object, valid_id, validate_policy
from warden_storage import MAX_POLICY, open_audit, open_policy_lock, read_policy_bytes, trusted_path


WEB = Path(__file__).resolve().parent / "web"
ASSETS = {
    "/": ("warden-admin.html", "text/html; charset=utf-8"),
    "/warden-admin.js": ("warden-admin.js", "text/javascript; charset=utf-8"),
    "/warden-admin.css": ("warden-admin.css", "text/css; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


class Conflict(ValueError):
    pass


def _snapshot(path):
    raw, attrs = read_policy_bytes(path)
    policy = json.loads(raw, object_pairs_hook=_object)
    validate_policy(policy)
    return {"revision": hashlib.sha256(raw).hexdigest(), "policy": policy}, attrs


def snapshot(path):
    return _snapshot(path)[0]


def apply_change(policy, operation, data, actions):
    fields = {
        "template": {"revision", "template", "rules"},
        "bind": {"revision", "warden", "task", "template"},
        "revoke": {"revision", "warden", "task"},
    }
    if operation not in fields or not isinstance(data, dict) or set(data) != fields[operation]:
        raise ValueError("操作字段不完整或无法识别")
    for field in ("template", "task"):
        if field in data and not valid_id(data[field]):
            raise ValueError("模板和任务名称需使用 1–128 个字母、数字或标识符字符")
    templates = policy.setdefault("templates", {})
    if operation == "template":
        name, rules = data["template"], data["rules"]
        if name in templates:
            raise Conflict("模板名称已存在。请为新版本使用新名称")
        if not isinstance(rules, list) or not rules:
            raise ValueError("模板至少需要一条连接器规则")
        if actions is None:
            actions = PluginRuntime().actions
        for rule in rules:
            if (not isinstance(rule, dict) or not isinstance(rule.get("connector"), str)
                    or rule["connector"] not in actions
                    or actions[rule["connector"]] != rule.get("action")):
                raise ValueError("模板包含未注册的连接器操作")
        templates[name] = rules
    else:
        warden, task = data["warden"], data["task"]
        if not isinstance(warden, str) or warden not in policy["wardens"]:
            raise ValueError("请选择已登记的 Warden")
        tasks = policy["wardens"][warden]["tasks"]
        if operation == "bind":
            if data["template"] not in templates:
                raise ValueError("模板不存在")
            tasks[task] = {"template": data["template"]}
        else:
            if task not in tasks:
                raise Conflict("此任务已没有授权")
            del tasks[task]
    validate_policy(policy)


def change(path, operation, data, *, actions=None):
    if not isinstance(data, dict) or not isinstance(data.get("revision"), str):
        raise ValueError("缺少策略版本")
    path = trusted_path(path)
    with open_policy_lock(path) as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        state, attrs = _snapshot(path)
        if data["revision"] != state["revision"]:
            raise Conflict("策略已变化，请刷新后确认最新授权")
        apply_change(state["policy"], operation, data, actions)
        contents = (json.dumps(state["policy"], ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if len(contents) > MAX_POLICY:
            raise ValueError("控制策略超过 1 MiB")
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as target:
            pending = Path(target.name)
            try:
                target.write(contents)
                target.flush()
                target_attrs = os.fstat(target.fileno())
                if (target_attrs.st_uid, target_attrs.st_gid) != (attrs.st_uid, attrs.st_gid):
                    os.fchown(target.fileno(), attrs.st_uid, attrs.st_gid)
                os.fchmod(target.fileno(), stat.S_IMODE(attrs.st_mode) & 0o777)
                os.fsync(target.fileno())
                os.replace(pending, path)
            finally:
                pending.unlink(missing_ok=True)
    return {"revision": hashlib.sha256(contents).hexdigest(), "policy": state["policy"]}


def recent_events(path):
    try:
        connection = open_audit(path, readonly=True)
    except FileNotFoundError:
        return {"ready": False, "events": []}
    with closing(connection) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("""SELECT id, at, warden, task, connector, action, resource, kind, result
                             FROM warden_events ORDER BY id DESC LIMIT 100""")
        return {"ready": True, "events": [dict(row) for row in rows]}


class Handler(BaseHTTPRequestHandler):
    timeout = 5

    def log_message(self, *_):
        pass

    def reply(self, status, body, content_type="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        for key, value in (
            ("Content-Type", content_type), ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
            ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
             "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
        ):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def check(self, *, api, write=False):
        host = f"127.0.0.1:{self.server.server_port}"
        origins = self.headers.get_all("Origin", [])
        if (self.headers.get_all("Host", []) != [host]
                or ((write or origins) and origins != ["http://" + host])):
            self.reply(403, {"error": "管理请求来源无效"})
            return False
        if api:
            tokens = self.headers.get_all("Authorization", [])
            if len(tokens) != 1 or not hmac.compare_digest(
                tokens[0].encode(), ("Bearer " + self.server.token).encode()
            ):
                self.reply(401, {"error": "请通过管理员的私有本地入口打开"})
                return False
        return True

    def do_GET(self):
        asset = ASSETS.get(self.path)
        if not self.check(api=not asset):
            return
        try:
            if asset:
                name, mime = asset
                self.reply(200, (WEB / name).read_bytes(), mime)
            elif self.path == "/api/state":
                self.reply(200, {**snapshot(self.server.policy), "actions": self.server.actions})
            elif self.path == "/api/events":
                self.reply(200, recent_events(self.server.audit))
            else:
                self.reply(404, {"error": "未知入口"})
        except (OSError, ValueError, RecursionError, sqlite3.Error):
            self.reply(503, {"error": "无法读取文件，请核对策略或审计库"})

    def do_POST(self):
        if not self.check(api=True, write=True):
            return
        if self.path not in ("/api/template", "/api/bind", "/api/revoke"):
            self.reply(404, {"error": "未知操作"})
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or len(lengths[0]) > 6 or not 0 < int(lengths[0]) <= 65536
                    or "Transfer-Encoding" in self.headers
                    or self.headers.get_content_type() != "application/json"):
                raise ValueError("请提交有效的 JSON 请求")
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError("请求内容不完整")
            data = json.loads(raw, object_pairs_hook=_object)
            state = change(self.server.policy, self.path.split("/")[-1], data, actions=self.server.actions)
            self.reply(200, {**state, "actions": self.server.actions})
        except Conflict as exc:
            self.reply(409, {"error": str(exc)})
        except (ValueError, RecursionError) as exc:
            self.reply(400, {"error": str(exc)})
        except OSError:
            self.reply(503, {"error": "策略文件不可写，请核对目录和文件权限"})


class AdminServer(ThreadingHTTPServer):
    def __init__(self, port, policy, audit, *, runtime=None):
        self.actions = (runtime or PluginRuntime()).actions
        self.policy = Path(policy).absolute()
        self.audit = Path(audit)
        self.token = secrets.token_urlsafe(32)
        snapshot(self.policy)
        super().__init__(("127.0.0.1", port), Handler)


def add_arguments(parser):
    add_runtime_arguments(parser)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--open", action="store_true", help="使用默认浏览器打开管理员面板")


def serve(args):
    if not 0 <= args.port <= 65535:
        raise ValueError("端口须在 0–65535 之间")
    runtime = PluginRuntime(args.plugin_manifest, args.core)
    with (AdminServer(args.port, args.policy, args.audit, runtime=runtime) as server,
          tempfile.TemporaryDirectory(prefix="keyheron-warden-admin-") as tmp):
        entry = Path(tmp) / "admin.html"
        url = f"http://127.0.0.1:{server.server_port}/#access={server.token}"
        with os.fdopen(os.open(entry, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
            out.write('<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">'
                      f'<meta http-equiv="refresh" content="0;url={url}"><a href="{url}">打开管理面板</a>')
        print(f"本地管理员入口  {entry.as_uri()}", flush=True)
        if args.open:
            webbrowser.open_new_tab(entry.as_uri())
        server.serve_forever()
    return 0
