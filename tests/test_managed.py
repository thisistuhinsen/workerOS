import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from threading import Event
from time import monotonic_ns
import unittest
from unittest.mock import patch

from worker_handoff import Writer, observe
from worker_handoff.managed import (
    DeliveryStatus, EffectStatus, PositionalWrite, ReleasePlan, release_executable,
)
from worker_handoff.supervisor import CleanupStatus, DirectChildSupervisor, LifecycleStatus


READ_INPUT = """
import fcntl
import os
from pathlib import Path
import sys

assert os.environ["WORKER_HANDOFF_ABI"] == "1"
fd = int(os.environ["WORKER_HANDOFF_FD_INPUT"])
assert fd >= 3
assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
Path(sys.argv[1]).write_bytes(os.pread(fd, 8, 0))
os.close(fd)
raise SystemExit(int(sys.argv[2]))
"""


class ManagedReleaseTest(unittest.TestCase):
    def setUp(self):
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = work / "original"
        self.marker = work / "child-read"
        self.path.write_bytes(b"abcdef")
        self.input_fd = self.open_fd(self.path, os.O_RDONLY)
        self.writer_fd = self.open_fd(self.path, os.O_WRONLY)
        self.identity = observe(self.input_fd).identity
        os.lseek(self.input_fd, 3, os.SEEK_SET)
        os.lseek(self.writer_fd, 5, os.SEEK_SET)

    def open_fd(self, path, flags):
        fd = os.open(path, flags | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        return fd

    def plan(self, *, exclusive_writer=False, exit_status=0):
        return ReleasePlan(
            "test-reader",
            "read",
            (sys.executable, "-I", "-c", READ_INPUT, str(self.marker), str(exit_status)),
            self.identity,
            monotonic_ns() + 5_000_000_000,
            write=PositionalWrite(2, b"YZ"),
            exclusive_writer=exclusive_writer,
        )

    def release(self, *, plan=None, **options):
        arguments = dict(input_fd=self.input_fd, authorize=lambda _: True, writer_fd=self.writer_fd)
        arguments.update(options)
        return release_executable(self.plan() if plan is None else plan, **arguments)

    def assert_refused(self, result):
        self.assertIs(result.delivery, DeliveryStatus.NOT_ATTEMPTED)
        self.assertIs(result.effect, EffectStatus.NOT_ATTEMPTED)
        self.assertIsNone(result.worker)
        self.assertIsNone(result.lifecycle)
        self.assertIsNone(result.custody)
        self.assertTrue(result.error)
        self.assertEqual(self.path.read_bytes(), b"abcdef")
        self.assertFalse(self.marker.exists())
        self.assertEqual(observe(self.input_fd).identity, self.identity)
        self.assertEqual(observe(self.writer_fd).identity, self.identity)

    def test_four_supervision_and_custody_combinations(self):
        for supervised in (False, True):
            for strict in (False, True):
                with self.subTest(supervised=supervised, strict_custody=strict):
                    supervisor = DirectChildSupervisor() if supervised else None
                    if strict:
                        with (patch("subprocess.Popen") as launch,
                              patch("worker_handoff.managed.os.pwrite") as write):
                            result = self.release(supervisor=supervisor, strict_custody=True)
                        launch.assert_not_called()
                        write.assert_not_called()
                        self.assert_refused(result)
                        continue
                    result = self.release(supervisor=supervisor)
                    self.assertIs(result.delivery, DeliveryStatus.DISPATCHED)
                    self.assertIs(result.effect, EffectStatus.COMPLETE)
                    self.assertEqual(result.bytes_written, 2)
                    self.assertIsNone(result.custody)
                    if supervised:
                        self.assertEqual(result.lifecycle.returncode, 0)
                    else:
                        self.assertIsNone(result.lifecycle)
                        self.assertEqual(result.worker.process.wait(timeout=5), 0)
                    self.assertEqual(self.marker.read_bytes(), b"abYZef")
                    self.assertEqual(os.lseek(self.input_fd, 0, os.SEEK_CUR), 3)
                    self.assertEqual(os.lseek(self.writer_fd, 0, os.SEEK_CUR), 5)
                    self.marker.unlink()
                    self.path.write_bytes(b"abcdef")

    def test_truthy_authorization_and_mock_custody_do_not_grant(self):
        plan = self.plan()
        seen = []

        def authorize(candidate):
            seen.append(candidate)
            return "yes"

        with patch("subprocess.Popen") as launch:
            self.assert_refused(self.release(plan=plan, authorize=authorize))
            self.assert_refused(self.release(strict_custody=True, custody=lambda **_: True))
        self.assertEqual(seen, [plan])
        launch.assert_not_called()

    def test_append_mode_denies_positional_write_and_legacy_append_still_works(self):
        flags = os.O_WRONLY | os.O_APPEND
        with patch("subprocess.Popen") as launch:
            self.assert_refused(self.release(writer_fd=self.open_fd(self.path, flags)))
        launch.assert_not_called()
        fd = os.open(self.path, flags | os.O_CLOEXEC)
        with Writer(fd, self.identity) as writer:
            os.lseek(writer.fileno(), 0, os.SEEK_SET)
            self.assertEqual(writer.write(b"!"), 1)
        self.assertEqual(self.path.read_bytes(), b"abcdef!")

    def test_exclusion_contends_on_original_and_ignores_unrelated_file(self):
        other = self.path.with_name("unrelated")
        other.write_bytes(b"unrelated")
        other_fd = self.open_fd(other, os.O_WRONLY)
        original_lock = self.open_fd(self.path, os.O_WRONLY)
        fcntl.flock(original_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with patch("subprocess.Popen") as launch:
            self.assert_refused(self.release(plan=self.plan(exclusive_writer=True)))
        launch.assert_not_called()
        fcntl.flock(original_lock, fcntl.LOCK_UN)

        fcntl.flock(self.writer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with patch("subprocess.Popen") as launch:
            self.assert_refused(self.release(plan=self.plan(exclusive_writer=True)))
        launch.assert_not_called()
        with self.assertRaises(BlockingIOError):
            fcntl.flock(original_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(self.writer_fd, fcntl.LOCK_UN)

        fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        result = self.release(plan=self.plan(exclusive_writer=True))
        self.assertIs(result.delivery, DeliveryStatus.DISPATCHED)
        self.assertEqual(result.worker.process.wait(timeout=5), 0)
        self.assertEqual(self.marker.read_bytes(), b"abYZef")
        self.assertEqual(other.read_bytes(), b"unrelated")
        fcntl.flock(original_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_writer_descriptor_for_different_file_refuses_before_grant(self):
        other = self.path.with_name("unrelated")
        other.write_bytes(b"unrelated")
        other_fd = self.open_fd(other, os.O_WRONLY)
        with patch("subprocess.Popen") as launch:
            self.assert_refused(self.release(plan=self.plan(exclusive_writer=True), writer_fd=other_fd))
        launch.assert_not_called()
        self.assertEqual(other.read_bytes(), b"unrelated")

    def test_partial_and_unknown_writes_are_not_retried_or_delivered(self):
        real_pwrite = os.pwrite
        for effect, count in ((EffectStatus.PARTIAL, 1), (EffectStatus.UNKNOWN, None)):
            with self.subTest(effect=effect):
                def write_once(fd, data, offset):
                    written = real_pwrite(fd, data[:1], offset)
                    if effect is EffectStatus.UNKNOWN:
                        raise OSError("simulated ambiguous write result")
                    return written

                with patch("worker_handoff.managed.os.pwrite", side_effect=write_once) as write:
                    with patch("subprocess.Popen") as launch:
                        result = self.release()
                self.assertEqual(write.call_count, 1)
                launch.assert_not_called()
                self.assertIs(result.delivery, DeliveryStatus.NOT_ATTEMPTED)
                self.assertIs(result.effect, effect)
                self.assertEqual(result.bytes_written, count)
                self.assertIsNone(result.worker)
                self.assertTrue(result.error)
                self.assertEqual(self.path.read_bytes(), b"abYdef")
                self.assertFalse(self.marker.exists())
                self.path.write_bytes(b"abcdef")

    def test_child_failure_is_separate_from_delivery_and_write(self):
        supervisor = DirectChildSupervisor()
        result = self.release(plan=self.plan(exit_status=7), supervisor=supervisor)
        self.assertIs(result.delivery, DeliveryStatus.DISPATCHED)
        self.assertIs(result.effect, EffectStatus.COMPLETE)
        self.assertEqual(result.lifecycle.returncode, 7)
        self.assertEqual(self.marker.read_bytes(), b"abYZef")

    def test_presignaled_cancellation_prevents_the_write_and_launch(self):
        cancel = Event()
        cancel.set()
        with (patch("subprocess.Popen") as launch,
              patch("worker_handoff.managed.os.pwrite") as write):
            result = self.release(supervisor=DirectChildSupervisor(), cancel=cancel)
        self.assert_refused(result)
        self.assertIn("cancel", result.error)
        launch.assert_not_called()
        write.assert_not_called()

    def test_timeout_keeps_successful_dispatch_and_records_separate_cleanup(self):
        supervisor = DirectChildSupervisor()
        deadline = monotonic_ns() + 2_000_000_000
        plan = ReleasePlan(
            "slow-reader", "read", (sys.executable, "-I", "-c", "import time; time.sleep(10)"),
            self.identity, deadline,
        )
        result = self.release(plan=plan, writer_fd=None, supervisor=supervisor,
                              cleanup_due_ns=deadline + 5_000_000_000)
        if result.worker is not None:
            self.addCleanup(
                lambda: supervisor.cleanup(plan.name, due_ns=monotonic_ns() + 5_000_000_000),
            )
        self.assertIs(result.delivery, DeliveryStatus.DISPATCHED)
        self.assertIs(result.effect, EffectStatus.NOT_ATTEMPTED)
        self.assertIs(result.lifecycle.lifecycle, LifecycleStatus.TIMED_OUT)
        self.assertIsNone(result.lifecycle.returncode)
        self.assertIs(result.lifecycle.cleanup.status, CleanupStatus.REAPED)
        self.assertIn(result.lifecycle.cleanup.returncode, (-signal.SIGTERM, -signal.SIGKILL))

    def test_exec_with_failed_pidfd_pin_retains_dispatch_and_process_for_reconciliation(self):
        def refuse_pin(process):
            self.addCleanup(process.wait, timeout=5)
            raise OSError("simulated pidfd pin failure after exec")

        with (patch("worker_handoff.supervisor._pin_child", side_effect=refuse_pin) as pin,
              patch("subprocess.Popen", wraps=subprocess.Popen) as launch):
            result = self.release(supervisor=DirectChildSupervisor())
        launch.assert_called_once()
        pin.assert_called_once()
        self.assertIs(result.delivery, DeliveryStatus.DISPATCHED)
        self.assertIs(result.effect, EffectStatus.COMPLETE)
        self.assertEqual(result.bytes_written, 2)
        self.assertIs(result.lifecycle.lifecycle, LifecycleStatus.UNKNOWN)
        self.assertIs(result.lifecycle.cleanup.status, CleanupStatus.UNKNOWN)
        self.assertIs(result.worker.process, pin.call_args.args[0])
        self.assertEqual(result.worker.process.wait(timeout=5), 0)
        self.assertEqual(self.marker.read_bytes(), b"abYZef")
