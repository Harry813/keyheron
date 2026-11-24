"""Locate or explicitly install a pinned, verified KeyFence v0.4.0 binary."""
import argparse
import hashlib
import os
import platform
import shutil
import tempfile
import urllib.request
from pathlib import Path


VERSION = "v0.4.0"
RELEASE_URL = f"https://github.com/atgreen/keyfence/releases/download/{VERSION}"
BIN_DIR = Path(__file__).resolve().parent / "bin"
# Source: https://github.com/atgreen/keyfence/releases/tag/v0.4.0 (checksums.txt)
SHA256 = {
    "keyfence-darwin-amd64": "62797ee252c5fafbfa27723011f82e190098585aa9cd7fba4d92e64024595a50",
    "keyfence-darwin-arm64": "81c792a091d45ce0d67905ce7b00c22e28b30125fa49742800bfc1e81d33cf16",
    "keyfence-linux-amd64": "167ffe15b1ea6c0b2d2beed6d3acc7085a5e3665ed0dcdaa9552656c71d62732",
    "keyfence-linux-arm64": "b939f035ce9e88389ca881fd27c3164f175f41df68ba5dcd3975c1cc7763ebd2",
}


def _asset() -> str:
    machine = platform.machine().lower()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(machine, machine)
    name = f"keyfence-{platform.system().lower()}-{arch}"
    if name not in SHA256:
        raise RuntimeError(f"这个演示支持 macOS/Linux 的 arm64 和 amd64，当前平台为 {name}。")
    return name


def _check_digest(path: Path, name: str) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != SHA256[name]:
        raise RuntimeError(f"{path} 与官方 {VERSION} 的 SHA-256 不符。请检查文件或重新安装。")


def keyfence_binary(override: str | None = None) -> Path:
    """Return the verified executable for this system without using the network."""
    name = _asset()
    path = Path(override).expanduser().resolve() if override is not None else BIN_DIR / name
    if not path.is_file():
        raise RuntimeError(f"找不到 {path}。在演示目录运行 python3 tools.py --install。")
    _check_digest(path, name)
    if not os.access(path, os.X_OK):
        raise RuntimeError(f"请为已校验的文件 {path} 添加执行权限。")
    return path


def _install() -> Path:
    name = _asset()
    destination = BIN_DIR / name
    if destination.is_file():
        try:
            _check_digest(destination, name)
        except RuntimeError:
            pass
        else:
            if not os.access(destination, os.X_OK):
                destination.chmod(0o755)
            return destination
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=BIN_DIR) as temp_dir:
        temp_binary = Path(temp_dir) / name
        with urllib.request.urlopen(f"{RELEASE_URL}/{name}", timeout=90) as download:
            with temp_binary.open("wb") as stream:
                shutil.copyfileobj(download, stream)
        _check_digest(temp_binary, name)
        temp_binary.chmod(0o755)
        temp_binary.replace(destination)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="安装当前平台的官方版本到演示目录")
    args = parser.parse_args()
    try:
        print(_install() if args.install else keyfence_binary())
    except (OSError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")
