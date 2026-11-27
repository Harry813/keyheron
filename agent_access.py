"""KeyHeron developer preview: trusted launcher for HTTPS and database sessions."""

import argparse
from contextlib import contextmanager, suppress
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlsplit

from web_demo import ROOT, core_binary, database_session, role_links


def _checked_fields(data, allowed, required):
    if (
        not isinstance(data, dict)
        or not required.issubset(data)
        or not set(data).issubset(allowed)
    ):
        raise ValueError("配置字段缺失或存在无法识别的字段，请对照 v1 配置示例。")


def _file(base, value, *, rotating=False):
    if not isinstance(value, str) or not value:
        raise ValueError("需要非空文件路径")
    path = base / value
    if not path.is_file():
        raise ValueError(f"不是文件：{path.name}")
    # The secret manager owns the logical path and can atomically replace its link.
    return str(path if rotating else path.resolve(strict=True))


def load_config(path, *, database=False, read_json=None):
    """Only the trusted operator provides the configuration and its secret-file references."""
    logical_path = Path(path).absolute()
    path = logical_path.resolve(strict=True)
    data = read_json(logical_path) if read_json else json.loads(path.read_text())
    fields = {"version", "task", "identities", "environments"}
    _checked_fields(data, fields | {"credential_store"}, fields)
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("仅支持配置 version=1")
    if "credential_store" in data:
        store = data["credential_store"]
        _checked_fields(store, {"path", "passphrase_file"}, {"path"})
        for field, value in store.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError("凭据库配置需要非空文件路径")
            store[field] = str(logical_path.parent / value)

    def label(value):
        return (
            isinstance(value, str)
            and 0 < len(value.strip()) <= 100
            and value.isprintable()
        )

    roles = data["identities"]
    _checked_fields(roles, {"applicant", "approver"}, {"applicant", "approver"})
    if (
        not all(label(v) for v in (*roles.values(), data["task"]))
        or roles["applicant"] == roles["approver"]
        or "system" in roles.values()
    ):
        raise ValueError("任务及两个不同的身份需有明确名称，system 为保留身份")
    envs = data["environments"]
    if not isinstance(envs, dict) or not envs or set(envs) - {"DEV", "STG", "PROD"}:
        raise ValueError("需要至少一个 DEV、STG 或 PROD 环境")
    selected = {}
    for name, raw in envs.items():
        mandatory = {"origin", "routes"}
        https_fields = mandatory | {"ca_file", "credential_files", "credential_refs"}
        _checked_fields(raw, https_fields | {"databases"}, set())
        env = {k: v for k, v in raw.items() if k != "databases"}
        if not env and "databases" not in raw:
            raise ValueError(f"{name} 缺少 HTTPS 服务或数据库")
        if env:
            _checked_fields(env, https_fields, mandatory)
        if database:
            if "databases" in raw:
                from dbproxy import targets
                selected[name] = targets(raw["databases"], logical_path.parent)
            continue
        if not env:
            continue
        origin = urlsplit(env["origin"])
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username is not None
            or origin.password is not None
            or origin.path not in ("", "/")
            or origin.query
            or origin.fragment
            or origin.port == 0
        ):
            raise ValueError(
                f"{name} 的 origin 必须是仅包含主机和可选端口的 HTTPS 地址"
            )
        if not isinstance(env["routes"], dict) or "read" not in env["routes"]:
            raise ValueError(f"{name} 缺少只读路由")
        files = env.get("credential_files", {})
        refs = env.get("credential_refs", {})
        if not isinstance(files, dict) or not isinstance(refs, dict) or not (files or refs):
            raise ValueError(f"{name} 缺少凭据引用")
        if files.keys() & refs.keys():
            raise ValueError(f"{name} 的同一凭据只能使用一个来源")
        if refs and "credential_store" not in data:
            raise ValueError(f"{name} 的加密凭据需要配置 credential_store")
        env["credential_files"] = {
            k: _file(logical_path.parent, v, rotating=True) for k, v in files.items()
        }
        if env.get("ca_file"):
            env["ca_file"] = _file(path.parent, env["ca_file"])
        selected[name] = env
    if not selected:
        raise ValueError("策略中没有数据库连接" if database else "策略中没有 HTTPS 服务；数据库连接请使用 db 命令")
    data["environments"] = selected
    return data


def unlock_policy_store(policy):
    settings = policy.get("credential_store")
    if settings is None:
        raise ValueError("加密凭据需要配置 credential_store")
    from credential_store import unlock
    from secret_cli import load_passphrase
    return unlock(settings["path"], load_passphrase(settings.get("passphrase_file")))


def bind_https_credentials(policy):
    store = None
    for name, env in policy["environments"].items():
        refs = env.pop("credential_refs", {})
        if refs:
            if store is None:
                store = unlock_policy_store(policy)
            env["credential_bindings"] = {alias: store.binding(name, ref) for alias, ref in refs.items()}


def _openssl(*args):
    result = subprocess.run(
        ["openssl", *map(str, args)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"OpenSSL 的 {args[0]} 操作失败，请确认可用的 OpenSSL/LibreSSL 和临时目录。"
        )


def proxy_certs(directory, environments):
    """Issue a short-lived local CA and one leaf per exact configured host. Never touch system trust."""
    ca_key = directory / "issuer.key"
    ca = directory / "client-ca.pem"
    cfg = directory / "issuer.cnf"
    cfg.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
        "[dn]\nCN=KeyHeron local session\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
    )
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
    _openssl(
        "req",
        "-x509",
        "-new",
        "-sha256",
        "-key",
        ca_key,
        "-days",
        "2",
        "-config",
        cfg,
        "-out",
        ca,
    )
    for name, env in environments.items():
        host = urlsplit(env["origin"]).hostname
        try:
            san = "IP:" + str(ipaddress.ip_address(host))
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
                raise ValueError("主机名应使用 ASCII DNS 或 IP 地址")
            san = "DNS:" + host
        key = directory / (name + ".key")
        csr = directory / (name + ".csr")
        cert = directory / (name + ".pem")
        ext = directory / (name + ".ext")
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n"
        )
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        _openssl("req", "-new", "-key", key, "-subj", "/CN=KeyHeron proxy", "-out", csr)
        _openssl(
            "x509",
            "-req",
            "-sha256",
            "-in",
            csr,
            "-CA",
            ca,
            "-CAkey",
            ca_key,
            "-set_serial",
            str(secrets.randbits(120) + 1),
            "-days",
            "1",
            "-extfile",
            ext,
            "-out",
            cert,
        )
        env.update(proxy_cert_file=str(cert), proxy_key_file=str(key))
    # All approved hosts have been issued. No signing authority is needed at runtime.
    ca_key.unlink()
    return ca


def _private_write(path, data):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as out:
        json.dump(data, out)


@contextmanager
def running_external(
    config_path: Path, state_dir: Path, *, core=None, port=0, web_dir=None
):
    data = load_config(config_path)
    directory = Path(state_dir).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise ValueError("状态目录须由当前用户独占，请指定一个权限为 0700 的目录")
    db = directory / "events.sqlite3"
    with (
        database_session(db),
        tempfile.TemporaryDirectory(prefix="session-", dir=directory) as tmp,
    ):
        working = Path(tmp)
        envs = data["environments"]
        bind_https_credentials(data)
        ca = proxy_certs(working, envs)
        alice, owner = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        cfg = {
            "listen": f"127.0.0.1:{port}",
            "proxy_listen": "127.0.0.1:0",
            "db": str(db),
            "web": str(Path(web_dir or ROOT / "web").resolve()),
            "alice": alice,
            "owner": owner,
            "applicant_name": data["identities"]["applicant"],
            "approver_name": data["identities"]["approver"],
            "external": {"task": data["task"], "environments": envs},
        }
        process = subprocess.Popen(
            [core_binary(core)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env={"PATH": os.defpath},
            text=True,
            umask=0o077,
        )
        descriptor = directory / "client.json"
        try:
            process.stdin.write(json.dumps(cfg) + "\n")
            process.stdin.flush()
            for env in envs.values():
                env.pop("credential_bindings", None)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(15):
                    raise RuntimeError("HTTPS 服务启动超时")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("HTTPS 服务未启动，请检查配置和服务错误输出")
            ready = json.loads(line)
            common = {
                "port": ready["port"],
                "proxy_port": ready["proxy_port"],
                "applicant": alice,
                "ca_file": str(ca),
                "environments": {
                    e: {
                        "origin": v["origin"].rstrip("/"),
                        "read_path": v["routes"]["read"]["path"],
                    }
                    for e, v in envs.items()
                },
            }
            pending = working / "client.json"
            _private_write(pending, common)
            os.replace(pending, descriptor)
            yield {**common, "approver": owner}
        finally:
            descriptor.unlink(missing_ok=True)
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()


def control(info, action, payload=None, *, owner=False):
    token = info["approver" if owner else "applicant"]
    conn = http.client.HTTPConnection("127.0.0.1", info["port"], timeout=18)
    try:
        conn.request(
            "GET" if payload is None else "POST",
            "/api/" + action,
            None if payload is None else json.dumps(payload),
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        body = json.loads(resp.read())
        if resp.status != 200:
            raise RuntimeError(
                f"{action}: HTTP {resp.status} – {body.get('error', '请求未被接受')}"
            )
        return body
    finally:
        conn.close()


def sdk_env(info, session, env):
    proxy = f"http://agent:{quote(session['token'], safe='')}@127.0.0.1:{info['proxy_port']}"
    child = {
        k: os.environ[k]
        for k in ("PATH", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR")
        if k in os.environ
    }
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        child[k] = proxy
    for k in (
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    ):
        child[k] = info["ca_file"]
    entry = info["environments"][env]
    return {
        **child,
        "NO_PROXY": "",
        "no_proxy": "",
        "KEYHERON_ENV": env,
        "KEYHERON_URL": entry["origin"] + entry["read_path"],
        "KEYHERON_PLACEHOLDER": "keyheron-placeholder",
    }


@contextmanager
def _client_signals():
    stopped = 0

    def cancel(signum, _frame):
        nonlocal stopped
        stopped = signum

    previous = {s: signal.signal(s, cancel) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    try:
        yield lambda: stopped
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run_child(info, env, command):
    if not command or env not in info["environments"]:
        raise ValueError("需要已配置的环境以及 -- 后的客户端命令")
    with _client_signals() as cancelled:
        if control(info, "state")["environment"] != env and not cancelled():
            control(info, "switch", {"environment": env})
        if cancelled():
            return 128 + cancelled()
        session = control(info, "sdk-session", {"environment": env})
        child = None
        try:
            if not cancelled():
                child = subprocess.Popen(command, env=sdk_env(info, session, env), start_new_session=True)
                while not cancelled():
                    try:
                        return child.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
            return 128 + cancelled()
        finally:
            running = child is not None and child.returncode is None
            if running:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGTERM)
            try:
                control(info, "sdk-revoke", {"id": session["id"]})
            finally:
                if running:
                    # Reap only after signaling the whole group, keeping its ID reserved.
                    with suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait()


def main():
    import secret_cli
    import warden_client
    import warden_control
    parser = argparse.ArgumentParser(prog="keyheron", description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    secret_cli.register(sub)
    warden_control.add_server_arguments(sub.add_parser("warden-server", help="启动 mTLS 连接器授权服务"))
    admin = sub.add_parser("warden-admin", help="打开本地连接器模板和审计工作台")
    from warden_admin import add_arguments as add_admin_arguments
    add_admin_arguments(admin)
    worker = sub.add_parser("warden", help="为一个任务启动受信连接器进程")
    worker.add_argument("--task", required=True)
    worker.add_argument("--server", required=True)
    from plugin_runtime import add_runtime_arguments
    add_runtime_arguments(worker)
    for flag in ("ca", "cert", "key", "plugins", "state-dir"):
        worker.add_argument("--" + flag, required=True, type=Path)
    warden_client.add_arguments(sub.add_parser("connector", help="通过本任务的 Warden 使用已授权连接器"))
    serve = sub.add_parser("serve", help="启动已配置的 HTTPS 工作台和凭据代理")
    serve.add_argument("--config", type=Path, required=True)
    serve.add_argument("--core", type=Path)
    serve.add_argument("--port", type=int, default=0)
    serve.add_argument("--open", action="store_true")
    run = sub.add_parser("run", help="运行一次具有指定环境只读权限的客户端")
    run.add_argument("--env", choices=["DEV", "STG", "PROD"], required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    db = sub.add_parser("db", help="为原生 SQL 客户端开启一个限时本地连接")
    db.add_argument("--config", type=Path, required=True)
    db.add_argument("--env", choices=["DEV", "STG", "PROD"], required=True)
    db.add_argument("--target", required=True, help="管理员在该环境配置的数据库别名")
    db.add_argument("--ttl", type=int, help="会话秒数，默认使用目标策略上限")
    db.add_argument("--state-dir", type=Path, default=Path(".keyheron-db"))
    for p in (serve, run):
        p.add_argument("--state-dir", type=Path, default=Path(".keyheron"))
    args = parser.parse_args()
    if args.action == "warden-server":
        return warden_control.serve(args)
    if args.action == "warden-admin":
        from warden_admin import serve as serve_admin
        return serve_admin(args)
    if args.action in ("warden", "connector"):
        if sys.version_info < (3, 11):
            raise RuntimeError("Warden 和沙箱连接器客户端需要 Python 3.11 或更新版本")
        import asyncio
        if args.action == "warden":
            import warden
            return asyncio.run(warden.serve(args))
        return asyncio.run(warden_client.run(args))
    if args.action == "secrets":
        return secret_cli.run(args)
    if args.action == "db":
        if sys.version_info < (3, 11):
            raise RuntimeError("原生数据库连接需要 Python 3.11 或更新版本")
        from dbproxy.session import serve_database
        import asyncio
        return asyncio.run(serve_database(load_config(args.config, database=True), args))
    if args.action == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        descriptor = args.state_dir / "client.json"
        if not descriptor.is_file():
            raise RuntimeError("请先在同一状态目录启动 keyheron serve")
        return run_child(json.loads(descriptor.read_text()), args.env, command)
    if not 0 <= args.port <= 65535:
        raise ValueError("端口范围为 0–65535")
    stop = False

    def shutdown(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    with (
        running_external(args.config, args.state_dir, core=args.core, port=args.port) as info,
        role_links(info["port"], info["applicant"], info["approver"], open_browser=args.open),
    ):
        print("服务就绪。Ctrl+C 退出并回收本次会话。", flush=True)
        while not stop:
            time.sleep(0.25)
    return 0


def entry():
    try:
        return main()
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
