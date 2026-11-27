"""在原生 Linux Docker Engine 中运行 Agent，只挂载本任务的 Warden socket。"""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


CONTAINER_SOCKET = "/run/keyheron/warden.sock"


def task_socket(path):
    socket_path = path.parent.resolve(strict=True) / path.name
    directory = socket_path.parent.stat()
    node = socket_path.lstat()
    if (
        os.getuid() == 0
        or directory.st_uid != os.getuid()
        or directory.st_mode & 0o077
        or node.st_uid != os.getuid()
        or not stat.S_ISSOCK(node.st_mode)
        or stat.S_IMODE(node.st_mode) != 0o600
    ):
        raise ValueError("请以 Warden 的非 root 账户运行，使用私有目录内该账户独占的 0600 任务 socket")
    if any(c in str(socket_path) for c in (",", '"', "\n", "\r")):
        raise ValueError("Docker 挂载路径不能包含逗号、引号或换行")
    return socket_path


def image_id(inspect_output):
    config, digest = inspect_output.strip().splitlines()
    if json.loads(config).get("Volumes"):
        raise ValueError("Agent 镜像含 VOLUME 声明，会在只读文件系统之外创建可写卷")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Docker 未返回有效的本地镜像 ID")
    return digest


def sandbox_args(socket_path, digest, command):
    if not command or not command[0]:
        raise ValueError("请在 -- 后指定镜像内的 Agent 命令")
    return [
        "run", "--rm", "--interactive", "--pull=never",
        "--network=none", "--read-only", "--cap-drop=ALL",
        "--memory=512m", "--memory-swap=512m", "--cpus=1",
        "--security-opt=no-new-privileges=true", "--pids-limit=128", "--ipc=private",
        "--log-driver=none", "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        f"--mount=type=bind,src={socket_path},dst={CONTAINER_SOCKET},readonly",
        f"--user={os.getuid()}:{os.getgid()}", "--workdir=/tmp",
        f"--env=KEYHERON_WARDEN_SOCKET={CONTAINER_SOCKET}", "--env=HOME=/tmp",
        f"--entrypoint={command[0]}", digest, *command[1:],
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True, help="Warden 所属的单任务 Unix socket")
    parser.add_argument("--image", required=True, help="本机已有、经管理员选择且无内置凭据的 Linux 镜像")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- 后指定容器内命令及参数")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.exit(1, "沙箱需要 Warden 与 Docker Engine 运行在同一台原生 Linux 主机上。\n")
    if not args.image or args.image.startswith("-"):
        parser.error("镜像名称无效")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        path = task_socket(args.socket)
        # A fresh client config also prevents automatic injection of operator proxy credentials.
        with tempfile.TemporaryDirectory(prefix="keyheron-docker-") as config:
            cli = ["docker", "--host=unix:///var/run/docker.sock", f"--config={config}"]
            env = {"PATH": "/usr/local/bin:" + os.defpath, "HOME": config}
            # Some engines only warn when the kernel cannot enforce a requested limit.
            capabilities = subprocess.run(
                [*cli, "info", "--format",
                 '{{and .CgroupDriver (ne .CgroupDriver "none") .MemoryLimit .SwapLimit .CPUCfsPeriod .CPUCfsQuota}}'],
                env=env, stdout=subprocess.PIPE, text=True, check=True,
            )
            if capabilities.stdout.strip() != "true":
                raise ValueError("Docker Engine 需要支持 cgroup 内存、交换空间和 CPU 配额")
            result = subprocess.run(
                [*cli, "image", "inspect", "--format", "{{json .Config}}\n{{.Id}}", args.image],
                env=env, stdout=subprocess.PIPE, text=True, check=True,
            )
            run = sandbox_args(path, image_id(result.stdout), command)
            return subprocess.run([*cli, *run], env=env).returncode
    except subprocess.CalledProcessError as exc:
        return exc.returncode
    except (OSError, ValueError) as exc:
        parser.exit(1, f"无法启动 Agent 沙箱：{exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
