"""Real no-workload bootstrap and fail-closed local ownership checks."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import Mock, patch

from workeros.delegated_service_leaf import DelegatedServiceLeaf
from workeros.managed_launch import ServiceWindow
from workeros.managed_service_parent import PlacementRefusal, ServiceParent
from workeros.scope_meter import CgroupIdentity
from workeros.service_bootstrap import _hold_bootstrap, _hold_release
from workeros.service_deadline import ArmedServiceWindow


class TrustedBootstrapTest(TestCase):
    def window(self):
        now = monotonic_ns()
        window = ServiceWindow(now + 2_000_000_000, now + 3_000_000_000)
        return window, self.enterContext(ArmedServiceWindow(window))

    def assert_reaped(self, pid):
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_real_bootstrap_has_only_control_socket_and_is_reaped(self):
        window, timers = self.window()
        path = Path(self.enterContext(TemporaryDirectory())) / 'preheld-original'
        with path.open('w+b') as original:
            os.set_inheritable(original.fileno(), True)
            with _hold_bootstrap(timers, window) as child:
                fd_directory = Path(f'/proc/{child.pid}/fd')
                links = [os.readlink(fd) for fd in fd_directory.iterdir()]
                self.assertEqual(len(links), 5)
                self.assertEqual(links.count('/dev/null'), 3)
                self.assertEqual(sum(link.startswith('socket:') for link in links), 1)
                self.assertEqual(links.count('anon_inode:[timerfd]'), 1)
                self.assertNotIn(str(path), links)
                self.assertIsNone(os.waitid(os.P_PIDFD, child.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT))
                self.assertIs(child.attempted, False)
                self.assertIsNone(child.reaped_ns)
            with self.assertRaises(OSError):
                os.fstat(child.pidfd)
            self.assert_reaped(child.pid)
            self.assertLess(child.reaped_ns, window.cleanup_until_ns)

    def test_bootstrap_exits_when_existing_absolute_timer_expires_without_gate_close(self):
        now = monotonic_ns()
        window = ServiceWindow(now + 300_000_000, now + 1_500_000_000)
        with ArmedServiceWindow(window) as timers, _hold_bootstrap(timers, window) as child:
            self.assertTrue(timers.wait_for_child(child.pidfd, cleanup=True))
            self.assertGreaterEqual(monotonic_ns(), window.active_until_ns)
            event = os.waitid(os.P_PIDFD, child.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertEqual(event.si_status, 0)
        self.assert_reaped(child.pid)

    def test_missing_pidfd_closes_gate_and_reaps_the_exact_direct_child(self):
        window, timers = self.window()
        processes = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with patch('workeros.service_bootstrap.subprocess.Popen', side_effect=start), patch(
                'workeros.service_bootstrap.os.pidfd_open', side_effect=OSError('fixture pidfd unavailable')):
            with self.assertRaisesRegex(OSError, 'fixture pidfd unavailable'):
                with _hold_bootstrap(timers, window):
                    self.fail('bootstrap exposed without pidfd')
        self.assertEqual(len(processes), 1)
        self.assert_reaped(processes[0].pid)

    def test_release_gate_inherits_only_control_until_one_actual_exec_and_reap(self):
        window, timers = self.window()
        path = Path(self.enterContext(TemporaryDirectory())) / 'preheld-original'
        path.write_bytes(b'exact read-only input')
        launcher = os.open('/bin/true', os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, launcher)
        launch = subprocess.Popen
        with path.open('rb') as original, path.open('rb') as inert_image, patch(
                'workeros.service_bootstrap.subprocess.Popen', wraps=launch) as spawn:
            handles = launcher, inert_image.fileno(), original.fileno(), None, None
            with _hold_release(timers, window, os.getuid(), os.getgid(), window.active_until_ns) as child:
                pid = child.pid
                passed = spawn.call_args.kwargs['pass_fds']
                self.assertEqual(len(passed), 2)
                self.assertEqual(set(passed).intersection(handles), set())
                self.assertIsNone(os.waitid(os.P_PIDFD, child.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT))
                # True is a harmless inert stand-in for the sandbox binary.
                # This exercises actual descriptor delivery and kernel exec;
                # it claims no cgroup placement or worker confinement.
                child.release(handles, window.active_until_ns)
                with self.assertRaisesRegex(ValueError, 'release_already_attempted'):
                    child.release(handles, window.active_until_ns)
                self.assertTrue(timers.wait_for_child(child.pidfd))
                event = os.waitid(os.P_PIDFD, child.pidfd, os.WEXITED | os.WNOHANG)
                self.assertEqual((event.si_pid, event.si_code, event.si_status), (pid, os.CLD_EXITED, 0))
                child.observe_reap(event)
                self.assertLess(child.reaped_ns, window.cleanup_until_ns)
            self.assert_reaped(pid)
        self.assertEqual(path.read_bytes(), b'exact read-only input')

    def test_release_gate_cannot_execute_without_exact_rights_packet(self):
        window, timers = self.window()
        with _hold_release(timers, window, os.getuid(), os.getgid(), window.active_until_ns) as child:
            pid = child.pid
            child.channel.sendall(b'R')
            self.assertTrue(timers.wait_for_child(child.pidfd))
            event = os.waitid(os.P_PIDFD, child.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertEqual((event.si_pid, event.si_code, event.si_status), (pid, os.CLD_EXITED, 125))
        self.assert_reaped(pid)

    def test_release_gate_routes_the_selected_stdout_slot(self):
        window, timers = self.window()
        root = Path(self.enterContext(TemporaryDirectory()))
        image = root / 'inert-image'
        image.write_bytes(b'not a worker image')
        output = root / 'selected-output'
        launcher = os.open('/bin/echo', os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, launcher)
        # The inert echo process observes the exact stdout mapping. This
        # validates the physical gate only; there is no claimed cgroup run.
        with image.open('rb') as executable, output.open('wb') as stream:
            descriptors = launcher, executable.fileno(), None, stream.fileno(), None
            with _hold_release(timers, window, os.getuid(), os.getgid(), window.active_until_ns) as child:
                self.assertEqual(output.stat().st_size, 0)
                self.assertIsNone(child.reaped_ns)
                child.release(descriptors, window.active_until_ns)
                self.assertTrue(timers.wait_for_child(child.pidfd))
            self.assert_reaped(child.pid)
        self.assertLess(child.reaped_ns, window.cleanup_until_ns)
        self.assertIn(b'--remount-ro / -- /worker', output.read_bytes())

    def test_release_cutoff_sets_attempted_before_trying_to_send(self):
        window, timers = self.window()
        with _hold_release(timers, window, os.getuid(), os.getgid(), window.active_until_ns) as child:
            with self.assertRaises(TimeoutError):
                child.release((3, 4, 5, None, None), monotonic_ns() - 1)
            self.assertIs(child.attempted, True)
            with self.assertRaisesRegex(ValueError, 'release_already_attempted'):
                child.release((3, 4, 5, None, None), window.active_until_ns)
        self.assertLess(child.reaped_ns, window.cleanup_until_ns)
        self.assert_reaped(child.pid)

    def test_unavailable_credential_authority_refuses_before_staging(self):
        window, timers = self.window()
        target = os.getuid() + 1
        with patch('workeros.service_bootstrap._fields', return_value={b'CapEff': b'0'}), patch(
                'workeros.service_bootstrap.subprocess.Popen') as spawn:
            with self.assertRaisesRegex(PermissionError, 'credential_authority_unavailable'):
                with _hold_release(timers, window, target, os.getgid(), window.active_until_ns):
                    self.fail('cross-UID gate without existing credential authority')
        spawn.assert_not_called()

    def placement_fixture(self):
        # A scratch directory models only the configured placement control.
        # No real cgroup mutation, live managed service, or delegated role runs.
        root = Path(self.enterContext(TemporaryDirectory()))
        control = root / 'cgroup.procs'
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        guard = object.__new__(DelegatedServiceLeaf)
        guard._leaf = CgroupIdentity(1, 6, 7)
        guard._parent = ServiceParent('reports.slice', '/reports.slice', 1, 2, 7)
        guard._unit = f"workeros-{'a'*64}.service"
        guard._window, guard._timers = self.window()
        guard._directory = fd
        guard._bootstrap_attempted = guard._finished = False
        guard._child = None
        guard._check_leaf = Mock()
        guard._populated = Mock(return_value=False)
        guard._member = Mock(return_value=b'0::/reports.slice/anchor')
        return guard, control

    def test_control_unavailable_refuses_before_creating_child(self):
        guard, _ = self.placement_fixture()
        with patch('workeros.delegated_service_leaf._hold_bootstrap') as spawn:
            with self.assertRaises(FileNotFoundError):
                with guard.stage_trusted_bootstrap():
                    self.fail('bootstrap held without an approved control')
        spawn.assert_not_called()

    def test_denied_placement_reaps_real_bootstrap_and_does_not_replay(self):
        guard, control = self.placement_fixture()
        control.write_bytes(b'unchanged')
        observed = []
        guard._verify_gated_child = lambda pid, _fd, _membership: observed.append(pid)
        with patch('workeros.delegated_service_leaf._mount_id', return_value=guard._leaf.mount_id), patch(
                'workeros.delegated_service_leaf.os.write', side_effect=PermissionError('fixture outside delegation')) as move:
            with self.assertRaisesRegex(PermissionError, 'fixture outside delegation'):
                with guard.stage_trusted_bootstrap():
                    self.fail('child should not pass denied placement')
            with self.assertRaisesRegex(PlacementRefusal, 'delegated_service_bootstrap_already_requested'):
                with guard.stage_trusted_bootstrap():
                    self.fail('replayed placement')
        self.assertEqual(len(observed), 1)
        move.assert_called_once()
        self.assert_reaped(observed[0])
        self.assertEqual(control.read_bytes(), b'unchanged')

    def test_staged_waitable_bootstrap_cannot_transfer_workload_reaping(self):
        guard, control = self.placement_fixture()
        control.write_bytes(b'unchanged')
        staged = []

        def membership(pid):
            if staged and pid == staged[0]:
                return guard._leaf_membership()
            return b'0::/reports.slice/anchor'

        def model_move(_fd, data):
            staged.append(int(data))
            return len(data)

        guard._member = membership
        guard._metric = lambda _metric: staged[0]
        # Model cgroup placement only. The bootstrap, timer, pidfd,
        # waitability checks and final reap all use the real kernel.
        with patch('workeros.delegated_service_leaf._mount_id', return_value=guard._leaf.mount_id), patch(
                'workeros.delegated_service_leaf.os.write', side_effect=model_move) as move:
            with guard.stage_trusted_bootstrap() as child:
                with self.assertRaisesRegex(PlacementRefusal, 'delegated_service_bootstrap_release_unavailable'):
                    guard.adopt_gated_child(pid=child.pid, pidfd=child.pidfd)
                with self.assertRaisesRegex(PlacementRefusal, 'delegated_service_child_not_waitable'):
                    guard.finish()
                self.assertIsNone(os.waitid(os.P_PIDFD, child.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT))
        move.assert_called_once()
        self.assertEqual(staged, [child.pid])
        self.assertIsNone(guard._child)
        with self.assertRaises(OSError):
            os.fstat(child.pidfd)
        self.assert_reaped(child.pid)
        self.assertEqual(control.read_bytes(), b'unchanged')
