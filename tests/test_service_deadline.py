"""Use real Linux timers and owned process handles without a service launch."""
import os
import subprocess
import sys
from time import monotonic_ns
from unittest import TestCase

from workeros.managed_launch import ServiceWindow
from workeros.service_deadline import ArmedServiceWindow


class ArmedServiceWindowTest(TestCase):
    def test_absolute_cutoffs_do_not_reset(self):
        start = monotonic_ns()
        window = ServiceWindow(start + 100_000_000, start + 200_000_000)
        with ArmedServiceWindow(window) as armed:
            self.assertFalse(armed.wait_for_child())
            self.assertGreaterEqual(monotonic_ns(), window.active_until_ns)
            self.assertFalse(armed.wait_for_child())
            self.assertFalse(armed.wait_for_child(cleanup=True))
            self.assertGreaterEqual(monotonic_ns(), window.cleanup_until_ns)
        with self.assertRaisesRegex(ValueError, 'service_window_closed'):
            armed.wait_for_child()

    def test_child_readiness_is_observed_without_consuming_the_reap(self):
        with subprocess.Popen([sys.executable, '-I', '-B', '-c', 'pass']) as process:
            pidfd = os.pidfd_open(process.pid)
            try:
                start = monotonic_ns()
                with ArmedServiceWindow(ServiceWindow(start+2_000_000_000, start+3_000_000_000)) as armed:
                    self.assertTrue(armed.wait_for_child(pidfd))
                result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                self.assertEqual(result.si_pid, process.pid)
            finally:
                os.close(pidfd)
