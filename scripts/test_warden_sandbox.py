"""Offline launcher checks and optional real Linux Docker test with a local Python image."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from run_warden_sandbox import CONTAINER_SOCKET, image_id, main, sandbox_args, task_socket


DIGEST = "sha256:" + "a" * 64


class SandboxLauncherTests(unittest.TestCase):
    def test_single_socket_mount_and_fixed_isolation(self):
        argv = sandbox_args("/private/task.sock", DIGEST, ["python3", "--network=host"])
        self.assertEqual(argv[-3:], ["--entrypoint=python3", DIGEST, "--network=host"])
        self.assertEqual([flag for flag in argv if flag.startswith("--mount=")], [
            f"--mount=type=bind,src=/private/task.sock,dst={CONTAINER_SOCKET},readonly",
        ])
        for flag in ("--network=none", "--cap-drop=ALL", "--read-only", "--pull=never",
                     "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=128",
                     "--security-opt=no-new-privileges=true"):
            self.assertIn(flag, argv[:argv.index(DIGEST)])
        with self.assertRaises(ValueError):
            sandbox_args("/private/task.sock", DIGEST, [])

    def test_missing_resource_controller_stops_before_launch(self):
        argv = ["sandbox", "--socket", "/unused", "--image", "agent", "--", "python3"]
        with (patch.object(sys, "argv", argv), patch.object(sys, "platform", "linux"),
              patch("run_warden_sandbox.task_socket"), patch("subprocess.run") as docker,
              patch("sys.stderr"), self.assertRaises(SystemExit) as exited):
            docker.return_value.stdout = "false\n"
            main()
        self.assertEqual(exited.exception.code, 1)
        docker.assert_called_once()
        self.assertIn("info", docker.call_args.args[0])

    def test_runs_exact_inspected_image_without_implicit_writable_volumes(self):
        self.assertEqual(image_id(f"{{}}\n{DIGEST}\n"), DIGEST)
        with self.assertRaises(ValueError):
            image_id('{"Volumes": {"/data": {}}}\n' + DIGEST)
        with self.assertRaises(ValueError):
            image_id("{}\n--privileged")

    def test_requires_operator_owned_private_socket(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp, socket.socket(socket.AF_UNIX) as server:
            directory = Path(tmp)
            path = directory / "task.sock"
            server.bind(str(path))
            path.chmod(0o600)
            if os.getuid() != 0:
                self.assertEqual(task_socket(path), path.resolve())
                link = directory / "link"
                link.symlink_to(path)
                with self.assertRaises(ValueError):
                    task_socket(link)
                path.chmod(0o666)
                with self.assertRaises(ValueError):
                    task_socket(path)
            with patch("os.getuid", return_value=0), self.assertRaises(ValueError):
                task_socket(path)

    @unittest.skipUnless(sys.platform == "linux" and os.environ.get("KEYHERON_SANDBOX_TEST_IMAGE"),
                         "指定原生 Linux Engine 上已有的 Python 镜像以运行容器实测")
    def test_real_agent_can_only_reach_task_socket(self):
        image = os.environ["KEYHERON_SANDBOX_TEST_IMAGE"]
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp, socket.socket(socket.AF_UNIX) as server:
            directory = Path(tmp)
            secret = directory / "operator-secret"
            secret.write_text("not in the sandbox")
            path = directory / "task.sock"
            server.bind(str(path))
            path.chmod(0o600)
            server.listen(1)
            server.settimeout(30)
            probe = """
import json, os, socket, sys
from pathlib import Path
assert os.getuid() != 0
assert set(os.listdir('/sys/class/net')) == {'lo'}
assert not Path(sys.argv[1]).exists()
assert not Path('/var/run/docker.sock').exists()
assert not os.getenv('KEYHERON_OPERATOR_TEST_TOKEN')
assert os.statvfs('/').f_flag & os.ST_RDONLY
root = Path('/sys/fs/cgroup')
groups = {}
for entry in Path('/proc/self/cgroup').read_text().splitlines():
    _, controllers, path = entry.split(':', 2)
    for controller in controllers.split(','):
        groups[controller] = path.lstrip('/')
def own_group(controller):
    mount = root / controller
    group = mount / groups[controller]
    # Docker can mount either the hierarchy or just this container's subtree.
    return group if group.is_dir() else mount
if (root / 'cgroup.controllers').exists():
    group = own_group('')
    assert int((group / 'memory.max').read_text()) == 512 * 1024**2
    assert int((group / 'memory.swap.max').read_text()) == 0
    quota, period = map(int, (group / 'cpu.max').read_text().split())
else:
    memory = own_group('memory')
    cpu = own_group('cpu')
    assert int((memory / 'memory.limit_in_bytes').read_text()) == 512 * 1024**2
    assert int((memory / 'memory.memsw.limit_in_bytes').read_text()) == 512 * 1024**2
    quota = int((cpu / 'cpu.cfs_quota_us').read_text())
    period = int((cpu / 'cpu.cfs_period_us').read_text())
assert quota == period and period > 0
with socket.socket(socket.AF_UNIX) as client:
    client.connect(os.environ['KEYHERON_WARDEN_SOCKET'])
    client.sendall(b'task')
    print(json.dumps(client.recv(4).decode()))
"""
            launcher = Path(__file__).with_name("run_warden_sandbox.py")
            proc = subprocess.Popen(
                [sys.executable, str(launcher), "--socket", str(path), "--image", image,
                 "--", "python3", "-c", probe, str(secret)],
                env={**os.environ, "KEYHERON_OPERATOR_TEST_TOKEN": "fixture"},
                stdout=subprocess.PIPE, text=True,
            )
            try:
                client, _ = server.accept()
                with client:
                    client.settimeout(5)
                    self.assertEqual(client.recv(4), b"task")
                    client.sendall(b"done")
                stdout, _ = proc.communicate(timeout=15)
                self.assertEqual(proc.returncode, 0)
                self.assertEqual(json.loads(stdout), "done")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    unittest.main()
