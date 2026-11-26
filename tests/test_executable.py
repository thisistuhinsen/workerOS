import os
from pathlib import Path
import subprocess
import sys
import tempfile
from time import monotonic_ns
import unittest

from worker_handoff import WorkerRoster, observe

ROOT = Path(__file__).resolve().parents[1]


def until():
    return monotonic_ns() + 5_000_000_000


class ExecutableBoundary(unittest.TestCase):
    def test_real_libc_worker_report(self):
        with tempfile.TemporaryDirectory() as d:
            exe = Path(d) / "report_worker"
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(ROOT/"examples"/"report_worker.c"), "-o", str(exe)], check=True)
            p = subprocess.run([sys.executable, str(ROOT/"examples"/"run_local_report.py"), str(exe)],
                               check=True, capture_output=True, text=True, timeout=20)
            self.assertEqual(p.stdout.splitlines(), [
                "writer write LOCAL_OK", "read-one read LOCAL_OK", "read-two read LOCAL_OK",
                "observe-one observe LOCAL_OK", "observe-two observe LOCAL_OK",
                "five C workers exited 0; same original, byte content and local cleanup checked",
            ])
            self.assertFalse(p.stderr)

    def test_no_shell_passthrough_only_named_handles_and_exact_status(self):
        with tempfile.TemporaryFile() as original, tempfile.TemporaryFile() as unlisted:
            owned, other = original.fileno(), unlisted.fileno()
            from_fd = observe(owned).identity
            args = [sys.executable,"-c", '''
import os, sys
assert sys.argv[1] == "two; literals"
assert os.environ["WORKER_HANDOFF_ABI"]=="1"
assert os.environ["WORKER_HANDOFF_NAME"]=="one reader"
assert os.environ["WORKER_HANDOFF_ROLE"]=="custom"
assert os.environ["WORKER_HANDOFF_ACCESS_NOTE"]=="read-write"
fd=int(os.environ["WORKER_HANDOFF_FD_NOTE"])
s=os.fstat(fd)
assert s.st_dev==int(os.environ["WORKER_HANDOFF_DEV_NOTE"])
assert s.st_ino==int(os.environ["WORKER_HANDOFF_INO_NOTE"])
try: os.fstat(int(sys.argv[2]))
except OSError: pass
else: raise AssertionError("unlisted fd inherited")
raise SystemExit(7)
''', "two; literals",str(other)]
            roster=WorkerRoster()
            w = roster.start_executable("one reader","custom",args,due_ns=until(),fds={"NOTE":owned},env={},uid=os.getuid())
            self.assertEqual(w.uid,os.getuid())
            self.assertEqual(roster.join(w.name,due_ns=until()),7)
            self.assertEqual(observe(owned).identity,from_fd)
            self.assertFalse(os.get_inheritable(owned))
            self.assertEqual(tuple(roster),(w,))

    def test_join_timeout_is_not_retirement_or_an_implicit_stop(self):
        r=WorkerRoster()
        w=r.start_executable("pending","app-handler",
                             [sys.executable,"-c","import time; time.sleep(10)"],
                             due_ns=until(),env={})
        try:
            self.assertIsNone(r.join(w.name,due_ns=1))
            self.assertIsNone(w.process.poll())
        finally:
            if w.process.poll() is None:
                w.process.terminate()
            w.process.wait(timeout=2)

    def test_deadline_unsafe_scope_and_duplicate_refuse_before_start(self):
        r=WorkerRoster()
        cmd=["this-does-not-exist-in-a-valid-fixture"]
        p_read,p_write=os.pipe()
        try:
            with self.assertRaises(TimeoutError):
                r.start_executable("late","read",cmd,due_ns=1)
            with self.assertRaises(ValueError):
                r.start_executable("pipe","read",cmd,due_ns=until(),fds={"RAW":p_read})
            with self.assertRaises(ValueError):
                r.start_executable("wrong alias","observe",cmd,due_ns=until(),fds={"a=b":p_read})
            with self.assertRaises(ValueError):
                r.start_executable("reserved","read",cmd,due_ns=until(),env={"WORKER_HANDOFF_ABI":"99"})
            self.assertEqual(tuple(r),())
            r.external("named","other",pid=os.getpid(),uid=os.getuid())
            with self.assertRaises(ValueError):
                r.start_executable("named","read",cmd,due_ns=until())
        finally:
            os.close(p_read)
            os.close(p_write)
