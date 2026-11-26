import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic_ns, sleep
import unittest

from worker_handoff.supervisor import CleanupStatus, DirectChildSupervisor, LifecycleStatus


def due():
    return monotonic_ns() + 5_000_000_000


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.supervisor = DirectChildSupervisor()
        try:
            self.supervisor.check_available("worker", "read")
        except (OSError, RuntimeError) as exc:
            self.skipTest(f"Linux pidfd supervision unavailable ({exc})")

    def start(self, name, code, *args, fds=None):
        worker = self.supervisor.start_executable(
            name, "read", [sys.executable, "-c", code, *args],
            due_ns=due(), fds=fds, env={},
        )
        self.addCleanup(lambda: self.supervisor.cleanup(name, due_ns=due()))
        return worker

    def start_external(self, code):
        process = subprocess.Popen([sys.executable, "-c", code])

        def finish():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)

        self.addCleanup(finish)
        return process

    def test_start_keeps_existing_fd_abi_and_reports_exact_exit(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"W")
            fd = os.open(path, os.O_RDONLY)
            try:
                os.lseek(fd, 1, os.SEEK_SET)
                worker = self.start("reader", '''
import os
assert os.environ["WORKER_HANDOFF_ABI"] == "1"
assert os.environ["WORKER_HANDOFF_ROLE"] == "read"
assert os.environ["WORKER_HANDOFF_ACCESS_INPUT"] == "read"
fd = int(os.environ["WORKER_HANDOFF_FD_INPUT"])
assert os.pread(fd, 1, 0) == b"W"
os.close(fd)
raise SystemExit(7)
''', fds={"INPUT": fd})
                result = self.supervisor.wait(worker.name, due_ns=due())
                self.assertEqual((result.lifecycle, result.returncode), (LifecycleStatus.EXITED, 7))
                self.assertEqual(result.cleanup.status, CleanupStatus.NOT_REQUESTED)
                self.assertIsNone(worker.process)
                self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 1)
                self.assertEqual(self.supervisor.cleanup(worker.name, due_ns=due()).returncode, 7)
            finally:
                os.close(fd)

    def test_timeout_and_expired_cleanup_leave_owned_child_running(self):
        worker = self.start("slow", "import time; time.sleep(60)")
        timed_out = self.supervisor.wait(worker.name, due_ns=1)
        self.assertEqual(timed_out.lifecycle, LifecycleStatus.TIMED_OUT)
        self.assertEqual(timed_out.cleanup.status, CleanupStatus.NOT_REQUESTED)
        self.assertIsNone(timed_out.returncode)
        expired = self.supervisor.cleanup(worker.name, due_ns=1)
        self.assertEqual(expired.status, CleanupStatus.PENDING)
        self.assertFalse(expired.terminate_sent)
        self.assertFalse(expired.kill_sent)
        cleanup = self.supervisor.cleanup(worker.name, due_ns=due())
        self.assertEqual((cleanup.status, cleanup.returncode), (CleanupStatus.REAPED, -signal.SIGTERM))
        self.assertTrue(cleanup.terminate_sent)
        self.assertFalse(cleanup.kill_sent)
        with self.assertRaises(ChildProcessError):
            os.waitpid(worker.pid, os.WNOHANG)

    def test_cancel_keeps_lifecycle_separate_from_escalated_cleanup(self):
        with TemporaryDirectory() as directory:
            marker = Path(directory) / "ready"
            worker = self.start("ignores-term", '''
from pathlib import Path
import signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).touch()
time.sleep(60)
''', str(marker))
            ready_due = due()
            while not marker.exists() and monotonic_ns() < ready_due:
                sleep(0.01)
            self.assertTrue(marker.exists())
            cancel = Event()

            def request_cancel():
                sleep(0.02)
                cancel.set()

            thread = Thread(target=request_cancel)
            thread.start()
            try:
                result = self.supervisor.wait(worker.name, due_ns=due(), cancel=cancel, cleanup_due_ns=due())
            finally:
                thread.join()
            self.assertEqual(result.lifecycle, LifecycleStatus.CANCELLED)
            self.assertIsNone(result.returncode)
            self.assertEqual((result.cleanup.status, result.cleanup.returncode),
                             (CleanupStatus.REAPED, -signal.SIGKILL))
            self.assertTrue(result.cleanup.terminate_sent)
            self.assertTrue(result.cleanup.kill_sent)

    def test_timeout_with_requested_cleanup_reports_original_outcome(self):
        worker = self.start("slow", "import time; time.sleep(60)")
        result = self.supervisor.wait(worker.name, due_ns=1, cleanup_due_ns=due())
        self.assertEqual(result.lifecycle, LifecycleStatus.TIMED_OUT)
        self.assertIsNone(result.returncode)
        self.assertEqual(result.cleanup.status, CleanupStatus.REAPED)
        self.assertEqual(result.cleanup.returncode, -signal.SIGTERM)

    def test_observed_external_child_keeps_its_own_wait_and_signal_owner(self):
        process = self.start_external("import time; time.sleep(60)")
        worker = self.supervisor.external("endpoint", "read", pid=process.pid, uid=os.getuid())
        observed = self.supervisor.wait(worker.name, due_ns=1, cleanup_due_ns=due())
        self.assertEqual(observed.lifecycle, LifecycleStatus.OBSERVED)
        self.assertEqual(observed.cleanup.status, CleanupStatus.OUTSIDE_SCOPE)
        self.assertEqual(self.supervisor.cleanup(worker.name, due_ns=due()).status,
                         CleanupStatus.OUTSIDE_SCOPE)
        self.assertIsNone(process.poll())
        process.terminate()
        event = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
        self.assertEqual(event.si_status, signal.SIGTERM)
        self.assertEqual(self.supervisor.cleanup(worker.name, due_ns=due()).status,
                         CleanupStatus.OUTSIDE_SCOPE)
        self.assertEqual(process.wait(timeout=5), -signal.SIGTERM)

    def test_explicit_adoption_checks_identity_and_grants_cleanup(self):
        process = self.start_external("import time; time.sleep(60)")
        worker = self.supervisor.external("endpoint", "read", pid=process.pid, uid=os.getuid())
        with self.assertRaises(ValueError):
            self.supervisor.adopt(worker.name, "different role", process, uid=os.getuid())
        self.assertIsNone(process.poll())
        self.assertEqual(self.supervisor.adopt(worker.name, worker.role, process, uid=worker.uid), worker)
        with self.assertRaises(ValueError):
            self.supervisor.adopt("alias", worker.role, process)
        cleanup = self.supervisor.cleanup(worker.name, due_ns=due())
        self.assertEqual((cleanup.status, cleanup.returncode), (CleanupStatus.REAPED, -signal.SIGTERM))
        self.assertEqual(process.returncode, -signal.SIGTERM)

    def test_competing_waiter_does_not_turn_lost_wait_status_into_success(self):
        process = self.start_external("raise SystemExit(19)")
        worker = self.supervisor.adopt("endpoint", "read", process)
        _, observed = os.waitpid(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(observed)
        result = self.supervisor.wait(worker.name, due_ns=due(), cleanup_due_ns=due())
        self.assertEqual(result.lifecycle, LifecycleStatus.UNKNOWN)
        self.assertIsNone(result.returncode)
        self.assertIsInstance(result.error, ChildProcessError)
        cleanup = self.supervisor.cleanup(worker.name, due_ns=due())
        self.assertEqual(cleanup.status, CleanupStatus.UNKNOWN)
        self.assertFalse(cleanup.terminate_sent)
        self.assertFalse(cleanup.kill_sent)

    def test_due_and_name_validation_precede_launch(self):
        with self.assertRaises(TimeoutError):
            self.supervisor.start_executable("late", "read", [sys.executable, "-c", "pass"], due_ns=1)
        self.supervisor.check_available("late", "read")
        with self.assertRaises(ValueError):
            self.supervisor.check_available("invalid\0name", "read")
        self.supervisor.external("already-observed", "read", pid=os.getpid())
        with self.assertRaises(ValueError):
            self.supervisor.check_available("already-observed", "read")
        with self.assertRaises(TypeError):
            self.supervisor.wait("already-observed", due_ns=due(), cancel=lambda: False)
        with self.assertRaises(ValueError):
            self.supervisor.wait("already-observed", due_ns=due(), cleanup_due_ns=False)
