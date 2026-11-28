"""Native handle checks and a detached manager loop; no delegated host scope."""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import Mock, patch

from workeros.delegated_service_leaf import DelegatedServiceLeaf
from workeros.managed_launch import LaunchInvocation, LaunchPlan, ServiceLimits, ServiceMeterReading, ServiceWindow
from workeros.managed_service import ServiceScope
from workeros.managed_service_parent import PlacementRefusal, ServiceParent
from workeros.scope_meter import CgroupIdentity, _mount_id
from workeros.service_bootstrap import _hold_release
from workeros.service_deadline import ArmedServiceWindow


class DelegatedServiceLeafTest(TestCase):
    def setUp(self):
        self.key = 'a'*64
        self.unit = f'workeros-{self.key}.service'
        self.identity = CgroupIdentity(1, 6, 7)
        self.parent = ServiceParent('reports.slice', '/reports.slice', 1, 2, 7)
        self.limits = ServiceLimits(2000, 1000, True)
        self.clock = 'fixture-clock'

    def test_plain_directory_cannot_arm_a_service(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        child = root / self.unit
        child.mkdir()
        control = child / 'cgroup.kill'
        control.write_bytes(b'unchanged')
        stat = child.stat()
        fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        mount = _mount_id(fd)
        parent_info = root.stat()
        parent = ServiceParent('reports.slice', '/reports.slice', parent_info.st_dev, parent_info.st_ino, mount)

        @contextmanager
        def directory(_parent):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                yield fd
            finally:
                os.close(fd)

        start = monotonic_ns()
        window = ServiceWindow(start + 2_000_000_000, start + 3_000_000_000)
        plan = LaunchPlan('approved', '1'*64, 'gen', 'worker-role', 'worker', '2'*64, '3'*64,
                          'launcher', 'authority', '4'*64, self.key, 1001)
        invocation = LaunchInvocation('5'*64, self.clock, plan, window)
        with patch('workeros.managed_bootstrap.setup_clock_id', return_value=self.clock), patch.object(
                ServiceParent, 'directory', directory):
            with self.assertRaisesRegex(PlacementRefusal, 'service_cgroup_mount_unverified'):
                DelegatedServiceLeaf(invocation, parent, CgroupIdentity(stat.st_dev, stat.st_ino, mount), self.limits)
        self.assertEqual(control.read_bytes(), b'unchanged')

    def child(self, command):
        return self.enterContext(subprocess.Popen(
            [sys.executable, '-I', '-B', '-c', command], stdin=subprocess.PIPE))

    def detached(self, *, active_ms, cleanup_ms):
        # Only the cgroup placement and population are modelled. The timer,
        # child fd and waitid/reap in finish use the actual Linux kernel.
        start = monotonic_ns()
        guard = object.__new__(DelegatedServiceLeaf)
        guard._window = ServiceWindow(start + active_ms * 1_000_000,
                                      start + (active_ms + cleanup_ms) * 1_000_000)
        guard._timers = self.enterContext(ArmedServiceWindow(guard._window))
        guard._leaf, guard._key, guard._clock = self.identity, self.key, self.clock
        guard._unit, guard._parent = self.unit, self.parent
        guard._check_leaf = Mock()
        guard._populated = Mock(return_value=False)
        guard._stop = Mock()
        guard._final = None
        guard._finished = guard._retirement_attempted = False
        guard._bootstrap_attempted = False
        guard._unreleased = None
        guard.stop_sent_ns = None
        guard._metered = True
        guard._begin = ServiceMeterReading(start, self.identity, 10, 0, 4096, False)
        guard._sample_empty = lambda: ServiceMeterReading(monotonic_ns(), self.identity, 12, 0, 8192, False)
        return guard

    def test_real_direct_child_reap_precedes_final_sample_and_retirement(self):
        guard = self.detached(active_ms=2000, cleanup_ms=1000)
        with self.assertRaisesRegex(PlacementRefusal, 'delegated_service_retirement_not_ready'):
            guard.retire()
        child = self.child('pass')
        guard._child = os.pidfd_open(child.pid)
        self.addCleanup(os.close, guard._child)
        guard._adopted = monotonic_ns()
        report = guard.finish()
        self.assertEqual((report.invocation_key, report.cgroup, report.disposition, report.exit_status),
                         (self.key, self.identity, 'exited', 0))
        self.assertLessEqual(report.reaped_ns, report.empty_ns)
        self.assertLessEqual(report.empty_ns, report.meter_end.observed_ns)
        self.assertEqual(report.active_cutoff_observation, 'empty_observed_before_cutoff')
        self.assertIsNone(report.retired_ns)
        guard._stop.assert_not_called()
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PIDFD, guard._child, os.WEXITED | os.WNOHANG)
        child.returncode = report.exit_status

    def test_cancel_removes_only_the_same_unstarted_empty_leaf_once(self):
        guard = self.detached(active_ms=2000, cleanup_ms=1000)
        guard._child = None
        root = Path(self.enterContext(TemporaryDirectory()))
        leaf = root / guard._unit
        sibling = root / 'keep'
        leaf.mkdir()
        sibling.mkdir()
        info = leaf.stat()
        guard._leaf = CgroupIdentity(info.st_dev, info.st_ino, 7)

        @contextmanager
        def directory(_parent):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                yield fd
            finally:
                os.close(fd)

        # This unit test exercises exact removal of a scratch leaf. It does
        # not mutate a real cgroup or certify installed production ownership.
        guard._check_clock = Mock()
        with patch.object(ServiceParent, 'directory', directory):
            guard._bootstrap_attempted = True
            with self.assertRaisesRegex(PlacementRefusal, 'cancellation_unverified'):
                guard.cancel_unstarted()
            self.assertTrue(leaf.is_dir())
            guard._bootstrap_attempted = False
            self.assertLess(guard.cancel_unstarted(), guard._window.cleanup_until_ns)
            self.assertFalse(leaf.exists())
            self.assertTrue(sibling.is_dir())
            with self.assertRaisesRegex(PlacementRefusal, 'cancellation_unverified'):
                guard.cancel_unstarted()

    def test_crossed_scope_cannot_select_release_inputs(self):
        guard = self.detached(active_ms=2000, cleanup_ms=1000)
        guard._limits = self.limits
        writable = ServiceScope('/approved/root', 1, 2, '/worker', 1001, 'read-write', 3, 4, 5,
                                limits=guard._limits, parent=guard._parent)
        with ExitStack() as held, patch('workeros.delegated_service_leaf.os.open') as open_resource:
            guard._scope_sha256 = 'f'*64
            with self.assertRaisesRegex(PlacementRefusal, 'release_scope_unsupported'):
                guard._release_inputs(replace(writable, mode='read'), guard._window.active_until_ns, held)
        open_resource.assert_not_called()

    def test_actual_gate_reap_can_classify_unreleased_but_never_attempted_send(self):
        for attempted in (False, True):
            with self.subTest(attempted=attempted):
                guard = self.detached(active_ms=2000, cleanup_ms=1000)
                guard._child = None
                root = Path(self.enterContext(TemporaryDirectory()))
                (root / 'cgroup.procs').write_bytes(b'')
                guard._directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                self.addCleanup(os.close, guard._directory)
                # The gate, socket close and direct-child reap are real.
                # The placement controls here are a scratch-file fixture.
                guard._member = Mock(return_value=b'0::/reports.slice/manager')
                guard._verify_gated_child = Mock(side_effect=lambda *_: monotonic_ns())
                guard._metric = Mock(side_effect=lambda *_: int((root / 'cgroup.procs').read_bytes()))
                guard._remove_empty = Mock(side_effect=monotonic_ns)

                def hold():
                    return _hold_release(guard._timers, guard._window, os.getuid(), os.getgid(),
                                         guard._window.active_until_ns)

                def mount(fd):
                    return guard._leaf.mount_id

                with patch('workeros.delegated_service_leaf._mount_id', side_effect=mount):
                    with self.assertRaisesRegex(PlacementRefusal, 'fixture abort'):
                        with guard._place_bootstrap(hold) as child:
                            # Mark an ambiguous send boundary without making a send.
                            child.attempted = attempted
                            raise PlacementRefusal('fixture abort')
                self.assertIsNotNone(child.reaped_ns)
                if attempted:
                    with self.assertRaisesRegex(PlacementRefusal, 'unreleased_unverified'):
                        guard.retire_unreleased()
                    guard._remove_empty.assert_not_called()
                else:
                    retired = guard.retire_unreleased()
                    self.assertLessEqual(retired.placed_ns, retired.reaped_ns)
                    self.assertLessEqual(retired.reaped_ns, retired.empty_ns)
                    self.assertLessEqual(retired.empty_ns, retired.retired_ns)
                    guard._remove_empty.assert_called_once()

    def test_late_reap_and_empty_observation_do_not_certify_active_cutoff(self):
        guard = self.detached(active_ms=90, cleanup_ms=1200)
        child = self.child('pass')
        guard._child = os.pidfd_open(child.pid)
        self.addCleanup(os.close, guard._child)
        guard._adopted = monotonic_ns()
        self.assertFalse(guard._timers.wait_for_child())
        report = guard.finish()
        child.returncode = report.exit_status
        self.assertGreaterEqual(report.reaped_ns, guard._window.active_until_ns)
        self.assertEqual(report.active_cutoff_observation, 'unconfirmed')

    def test_cleanup_cutoff_returns_unconfirmed_when_child_does_not_exit(self):
        guard = self.detached(active_ms=90, cleanup_ms=120)
        child = self.child('import sys; sys.stdin.buffer.read(1)')
        guard._child = os.pidfd_open(child.pid)
        self.addCleanup(os.close, guard._child)
        guard._adopted = monotonic_ns()
        try:
            with self.assertRaisesRegex(TimeoutError, 'delegated_service_reap_unconfirmed'):
                guard.finish()
            self.assertGreaterEqual(monotonic_ns(), guard._window.cleanup_until_ns)
            guard._stop.assert_called_once()
            self.assertIsNone(guard._final)
            self.assertIsNone(child.poll())
        finally:
            child.stdin.close()
            child.wait(timeout=3)

    def test_replaced_leaf_never_receives_stop_writes(self):
        guard = self.detached(active_ms=2000, cleanup_ms=1000)
        guard._check_leaf.side_effect = PlacementRefusal('delegated_service_leaf_changed')
        with patch('workeros.delegated_service_leaf.os.write') as write:
            with self.assertRaisesRegex(PlacementRefusal, 'delegated_service_leaf_changed'):
                DelegatedServiceLeaf._stop(guard)
            write.assert_not_called()

    def test_live_waitable_pidfd_outside_the_exact_leaf_is_refused(self):
        guard = self.detached(active_ms=2000, cleanup_ms=1000)
        guard._child = None
        child = self.child('import sys; sys.stdin.buffer.read(1)')
        fd = os.pidfd_open(child.pid)
        self.addCleanup(os.close, fd)
        try:
            with self.assertRaisesRegex(PlacementRefusal, 'delegated_service_child_outside_leaf'):
                guard.adopt_gated_child(pid=child.pid, pidfd=fd)
            self.assertIsNone(guard._child)
            self.assertIsNone(child.poll())
        finally:
            child.stdin.close()
            child.wait(timeout=3)
