"""Keep the lifetime of one broker tied to its controller's pipe (POSIX)."""
import os
import fcntl
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


def launch(args, work, listeners):
    descriptors = tuple(sock.fileno() for sock in listeners)
    return subprocess.Popen(
        [sys.executable, "-I", __file__, str(work), ",".join(map(str, descriptors)), *args],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "TMPDIR": tempfile.gettempdir()}, pass_fds=descriptors,
    )


def exec_activated(numbers, args):
    """Enter KeyFence with the sd_listen_fds ABI, preserving the port owner."""
    incoming = tuple(map(int, numbers.split(",")))
    if len(incoming) != 3 or len(set(incoming)) != 3 or min(incoming) < 3:
        raise ValueError("expected three inherited listeners")
    # Move above the reserved range first: incoming descriptors can overlap 3..5.
    copies = [fcntl.fcntl(fd, fcntl.F_DUPFD, 6) for fd in incoming]
    for dest, fd in enumerate(copies, start=3):
        os.dup2(fd, dest, inheritable=True)
    for fd in set(copies + list(incoming)).difference({3, 4, 5}):
        os.close(fd)
    env = dict(os.environ, LISTEN_PID=str(os.getpid()), LISTEN_FDS="3",
               LISTEN_FDNAMES="proxy:api:ssh")
    os.execve(args[0], args, env)


def supervise(work, numbers, args):
    # Only this demo's environment directory may be reaped on parent disconnect.
    base = Path(tempfile.gettempdir()).resolve()
    work = Path(work).resolve()
    if (work.parent.parent != base or not work.parent.name.startswith("keyfence-demo-")
            or work.name not in {"DEV", "STG", "PROD"}):
        raise ValueError("unexpected demo directory")
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        with subprocess.Popen([sys.executable, "-I", __file__, "--activated", numbers, *args],
                              stdin=subprocess.DEVNULL,
                              pass_fds=tuple(map(int, numbers.split(",")))) as broker:
            try:
                with selectors.DefaultSelector() as watch:
                    watch.register(0, selectors.EVENT_READ)
                    while not stopping and broker.poll() is None:
                        if watch.select(.25) and os.read(0, 1) == b"":
                            break
            finally:
                if broker.poll() is None:
                    broker.terminate()
                    try:
                        broker.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        broker.kill()
                        broker.wait()
    finally:
        shutil.rmtree(work, ignore_errors=True)
        # On controller death its TemporaryDirectory context cannot run.
        try:
            work.parent.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    if sys.argv[1] == "--activated":
        exec_activated(sys.argv[2], sys.argv[3:])
    else:
        supervise(sys.argv[1], sys.argv[2], sys.argv[3:])
