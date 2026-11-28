"""Deterministic checks for results first observed around a wait deadline."""

import os
from subprocess import TimeoutExpired
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from workeros import policy_cli, supervisor


_DUE = 50_000_000
_STEP = 5_000_000


class WaitObservationTest(unittest.TestCase):
    def test_basic_wait_reports_exit_even_when_its_budget_is_already_zero(self):
        for now, timeout in ((_DUE - _STEP, 0.005), (_DUE, 0.0), (_DUE + _STEP, 0.0)):
            with self.subTest(observed_at=now):
                process = Mock()
                process.wait.return_value = 7
                with patch.object(policy_cli, "monotonic_ns", return_value=now):
                    result = policy_cli._wait_basic(process, _DUE, _DUE + _STEP)
                self.assertEqual(result, {
                    "lifecycle": "exited", "returncode": 7, "error": False,
                    "cleanup": {"status": "reaped", "returncode": 7, "terminate_sent": False,
                                "kill_sent": False, "error": False},
                })
                process.wait.assert_called_once_with(timeout=timeout)
                process.poll.assert_not_called()
                process.kill.assert_not_called()

    def test_basic_no_result_reports_timeout_with_only_the_remaining_cleanup_budget(self):
        now = _DUE + _STEP
        for cleanup_due, seconds, kill_count in ((now, 0.0, 0), (now + _STEP, 0.005, 1)):
            with self.subTest(cleanup_due=cleanup_due):
                process = Mock()
                process.poll.return_value = None
                process.wait.side_effect = (TimeoutExpired("child", 0), TimeoutExpired("child", seconds))
                with patch.object(policy_cli, "monotonic_ns", return_value=now):
                    result = policy_cli._wait_basic(process, _DUE, cleanup_due)
                self.assertEqual((result["lifecycle"], result["returncode"]), ("timed_out", None))
                self.assertEqual(result["cleanup"], {
                    "status": "pending", "returncode": None, "terminate_sent": False,
                    "kill_sent": bool(kill_count), "error": False,
                })
                self.assertEqual(process.wait.call_args_list, [call(timeout=0.0), call(timeout=seconds)])
                self.assertEqual(process.kill.call_count, kill_count)

    def test_basic_cleanup_can_observe_exit_without_rewriting_wait_timeout(self):
        process = Mock()
        process.wait.side_effect = (TimeoutExpired("child", 0), 7)
        process.poll.return_value = 7
        with patch.object(policy_cli, "monotonic_ns", return_value=_DUE + _STEP):
            result = policy_cli._wait_basic(process, _DUE, _DUE + _STEP)
        self.assertEqual((result["lifecycle"], result["returncode"]), ("timed_out", 7))
        self.assertEqual((result["cleanup"]["status"], result["cleanup"]["returncode"]), ("reaped", 7))
        self.assertEqual(process.wait.call_args_list, [call(timeout=0.0), call(timeout=0.0)])
        process.kill.assert_not_called()

    def test_direct_wait_reaps_a_ready_result_before_reporting_deadline_expiry(self):
        ready = SimpleNamespace(si_code=os.CLD_EXITED, si_status=7)
        for observed_at in (_DUE - _STEP, _DUE, _DUE + _STEP):
            with self.subTest(observed_at=observed_at):
                start = _DUE - _STEP
                pin = Mock()
                process = SimpleNamespace(returncode=None)
                child = supervisor._Child(process, pin)
                with patch.object(supervisor, "monotonic_ns", return_value=start) as clock:
                    def observe(*_):
                        return ready if clock.return_value >= observed_at else None

                    def sleep(_):
                        clock.return_value = observed_at

                    with (patch.object(supervisor.os, "waitid", side_effect=observe),
                          patch.object(supervisor, "sleep", side_effect=sleep) as advance):
                        result = supervisor._wait(child, _DUE)

                self.assertIs(result, supervisor.LifecycleStatus.EXITED)
                self.assertEqual((child.returncode, process.returncode), (7, 7))
                self.assertIsNone(child.pin)
                pin.close.assert_called_once_with()
                if observed_at == start:
                    advance.assert_not_called()
                else:
                    advance.assert_called_once()

    def test_direct_wait_without_a_result_times_out_and_retains_the_owned_pin(self):
        pin = Mock()
        process = SimpleNamespace(returncode=None)
        child = supervisor._Child(process, pin)
        with (patch.object(supervisor, "monotonic_ns", side_effect=(_DUE - _STEP, _DUE)),
              patch.object(supervisor.os, "waitid", return_value=None) as observe,
              patch.object(supervisor, "sleep") as delay):
            result = supervisor._wait(child, _DUE)
        self.assertIs(result, supervisor.LifecycleStatus.TIMED_OUT)
        self.assertEqual(observe.call_count, 2)
        delay.assert_called_once()
        self.assertIs(child.pin, pin)
        self.assertIsNone(child.returncode)
        self.assertIsNone(process.returncode)
        pin.close.assert_not_called()
