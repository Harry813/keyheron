"""Start the isolated local Agent Access console. Credentials and mock upstreams are disposable."""
import argparse
from contextlib import contextmanager
import fcntl
from html import escape
import json
import os
from pathlib import Path
import platform
import secrets
import selectors
import signal
import subprocess
import tempfile
import time
from urllib.parse import quote
import webbrowser

from runtime import DemoRuntime
from tools import keyfence_binary

ROOT = Path(__file__).resolve().parent


@contextmanager
def role_links(port, applicant, approver, *, open_browser=False):
    """Only private local files contain the bearer URLs, including when opening a browser."""
    with tempfile.TemporaryDirectory(prefix="keyheron-roles-") as directory:
        for name, label, token in (("applicant", "申请人", applicant), ("approver", "审批人", approver)):
            path = Path(directory) / f"{name}.html"
            target = escape(f"http://127.0.0.1:{port}/#access={quote(token, safe='')}", quote=True)
            with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8") as page:
                page.write(
                    '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                    '<meta name="referrer" content="no-referrer">'
                    f'<title>{label}工作台</title><meta http-equiv="refresh" content="0;url={target}">'
                    f'<a href="{target}" rel="noreferrer">打开{label}工作台</a></html>'
                )
            uri = path.resolve().as_uri()
            print(f"{label}本地入口  {uri}", flush=True)
            if open_browser:
                webbrowser.open_new_tab(uri)
        yield


def core_binary(override=None):
    machine = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
    if override:
        paths = [Path(override)]
    else:
        paths = [ROOT / "bin" / f"agent-access-core-{platform.system().lower()}-{machine}",
                 ROOT / "rust-core" / "target" / "release" / "agent-access-core"]
    for path in paths:
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    raise SystemExit("请先构建 Rust 核心：cargo build --release --locked --manifest-path rust-core/Cargo.toml")


@contextmanager
def database_session(db):
    # A database has one active controller. Session state lives in that controller.
    with os.fdopen(os.open(str(db) + ".lock", os.O_CREAT | os.O_RDWR, 0o600), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("此记录库已有运行中的控制台，请使用该实例的链接，或为独立实例指定 --db。") from None
        yield


@contextmanager
def running(binary_path: Path, db: Path, port: int = 0, *, core=None, web_dir=None):
    core = core_binary(core)
    db = Path(db).resolve()
    db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tokens = {role: secrets.token_urlsafe(32) for role in ("alice", "owner")}
    with database_session(db), DemoRuntime(binary_path) as rt:
        config = {"listen": f"127.0.0.1:{port}", "db": str(db), "web": str(Path(web_dir or ROOT / "web").resolve()),
                  **tokens, "environments": {env: rt[env].trusted_config() for env in ("DEV", "STG", "PROD")}}
        process = subprocess.Popen([core], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                   env={"PATH": os.defpath}, umask=0o077)
        try:
            process.stdin.write(json.dumps(config) + "\n")
            process.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(12):
                    raise RuntimeError("Rust 核心未在 12 秒内就绪")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("Rust 核心启动失败，请检查目录的写权限及端口")
            service_port = json.loads(line)["port"]
            yield rt, service_port, tokens
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0, help="本地端口，默认自动分配")
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "events.sqlite3")
    parser.add_argument("--core", type=Path, help="本机已编译的 Rust 核心")
    parser.add_argument("--web-dir", type=Path, help="从单独的前端检出目录加载三个静态文件")
    parser.add_argument("--binary", help="官方 KeyFence v0.4.0 可执行文件")
    parser.add_argument("--open", action="store_true", help="在默认浏览器打开申请人及审批人标签页")
    parser.add_argument("--terminal", action="store_true", help="同时在当前终端操作同一个控制服务")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("端口需在 0 到 65535 之间")
    stopped = False

    def stop(*_):
        nonlocal stopped
        if args.terminal:
            raise KeyboardInterrupt
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with (running(keyfence_binary(args.binary), args.db, args.port, core=args.core,
                  web_dir=args.web_dir) as (_, port, tokens),
          role_links(port, tokens["alice"], tokens["owner"], open_browser=args.open)):
        print(f"请在两个标签页分别打开。Ctrl+C 关闭。操作记录保存在 {args.db.resolve()}。", flush=True)
        if args.terminal:
            from console import interactive_client
            interactive_client(port, tokens)
        else:
            while not stopped:
                time.sleep(.3)


if __name__ == "__main__":
    main()
