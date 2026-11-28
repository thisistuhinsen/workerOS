"""Runnable proof: compiled C workers write, read twice and observe an owned report."""
import os
from pathlib import Path
from subprocess import TimeoutExpired
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from workeros import WorkerRoster, observe


def run(executable):
    argv = [str(Path(executable).resolve()), "local-report"]
    roster = WorkerRoster()
    def complete(name, role, fd):
        due = monotonic_ns() + 5_000_000_000  # This example's declared deadline.
        w = roster.start_executable(name, role, argv,
                                    fds={"REPORT": fd}, due_ns=due, env={})
        status = roster.join(name, due_ns=due)
        if status is None:
            # Explicit reconciliation for this owned disposable child only.
            if w.process.poll() is None:
                w.process.terminate()
            try:
                w.process.wait(timeout=1)
            except TimeoutExpired:
                w.process.kill()  # fixed libc fixture has no descendants
                w.process.wait(timeout=1)
            raise TimeoutError(name)
        if status != 0:
            raise RuntimeError(f"{name} exited {status}; do not retry")
        return w

    with TemporaryDirectory() as folder:
        report = Path(folder) / "report.txt"
        fd = os.open(report, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        try:
            identity = observe(fd).identity
            complete("writer", "write", fd)
            assert observe(fd).size == 6
        finally:
            os.close(fd)
        ro = os.open(report, os.O_RDONLY | os.O_CLOEXEC)
        try:
            assert observe(ro).identity == identity
            os.lseek(ro, 2, os.SEEK_SET)
            for name, role in (("read-one","read"), ("read-two","read"),
                               ("observe-one","observe"), ("observe-two","observe")):
                complete(name, role, ro)
            assert os.lseek(ro, 0, os.SEEK_CUR) == 2
        finally:
            os.close(ro)
        try:
            observe(ro)
        except OSError:
            pass
        else:
            raise AssertionError("parent's owned descriptor did not close")
        assert report.read_bytes() == b"ready\n"
    print("five C workers exited 0; same original, byte content and local cleanup checked")
    return tuple(w.role for w in roster)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("pass one path to the compiled report_worker executable")
    run(sys.argv[1])
