"""Exercise the guarded manager protocol with a real socket and journal."""

from array import array
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, nullcontext, redirect_stdout
from dataclasses import asdict, replace
import fcntl
from io import StringIO
import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic, monotonic_ns
from unittest import TestCase
from unittest.mock import Mock, patch
from uuid import uuid4

from workeros import cli, managed_guard_server as server
from workeros.delegated_service_leaf import LeafObservation, UnreleasedBootstrap
from workeros.managed_executor import _Authority, _FRAME
from workeros.managed_launch import (GUARDED_SERVICE, LaunchInvocation, LaunchPlan, LaunchReadback, LaunchRegistration,
                                     LaunchRolePolicy, ScopedLaunch, ServiceProcessIdentity, ServiceWindow)
from workeros.managed_service import ServiceScope, verify_native_readback
from workeros.managed_service_client import _frame_read, _frame_write, _response
from workeros.managed_service_guard import GuardedServiceAuthority
from workeros.managed_service_parent import PlacementRefusal, ServiceParent
from workeros.recording import LocalStore
from workeros.roles_cli import _canonical
from workeros.scope_meter import CgroupIdentity


class GuardManagerTest(TestCase):
    def setUp(self):
        directory = Path(self.enterContext(TemporaryDirectory()))
        file = directory / 'input'
        file.write_bytes(b'fixture')
        original = self.enterContext(file.open('rb'))
        info = os.fstat(original.fileno())
        self.parent = ServiceParent('owner-guard.service', '/owner.slice/owner-guard.service', 7, 8, 9)
        self.scope = ServiceScope('/approved/root', 11, 12, '/worker', 100, 'read',
                                  info.st_dev, info.st_ino, original.fileno(),
                                  {'active_ms': 2000, 'cleanup_ms': 2000, 'metered': False}, self.parent)
        policy = LaunchRolePolicy('review', 'a'*64, 'r1', 'auditor', 'worker', 'b'*64,
                                  'c'*64, 'launcher', 'authority', 'd'*64, 100)
        now = monotonic_ns()
        self.key = 'f'*64
        self.unit = f'workeros-{self.key}.service'
        self.invocation = LaunchInvocation('e'*64, 'clock', LaunchPlan(**asdict(policy), invocation_key=self.key),
                                          ServiceWindow(now + 2_000_000_000, now + 4_000_000_000))
        self.service = {'enforcement': 'guarded-service-v1', 'scope_sha256': self.scope.digest,
                        'parent': asdict(self.parent), 'unit': self.unit,
                        'leaf': self.parent.control_group + '/' + self.unit}
        self.enrollment = server.GuardEnrollment(policy, self.scope, 'e'*64, 'clock', os.getuid())
        self.store = LocalStore(directory)
        self.current = Mock(return_value=True)
        self.lock_directory = directory / 'role-store'
        self.lock_directory.mkdir(mode=0o700)
        self.lock_fd = os.open(self.lock_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.lock_fd)
        info = os.fstat(self.lock_fd)
        self.lock_pin = (info.st_dev, info.st_ino)
        self.manager = self.new_manager()
        self.addCleanup(self.manager.close)
        identity = CgroupIdentity(7, 18, 9)
        self.physical = Mock(armed_ns=now)
        self.physical.retire.return_value = LeafObservation(
            self.key, 'clock', identity, now + 1, now + 2, 'exited', 0, now + 3,
            None, None, 'empty_observed_before_cutoff', now + 4,
            reaped_process=ServiceProcessIdentity(42, 10, 11),
        )
        self._placement_implementation = server._require_guard_placement
        self.manager_placement = self.enterContext(patch.object(server, '_require_guard_placement'))
        self.placement = self.enterContext(patch.object(server, '_open_leaf', return_value=(identity, self.physical)))

    def request(self, operation, **fields):
        return {'version': 1, 'operation': operation, 'nonce': uuid4().hex,
                'invocation': asdict(self.invocation), 'service': self.service, **fields}

    def new_manager(self, enrollment=None):
        return server.GuardedManager(enrollment or self.enrollment, self.store, self.current,
                                     role_store_lock=self.lock_pin)

    def send(self, client, request, deadline, lock):
        if request['operation'] == 'submit_service' and lock is not None:
            body = _canonical(request)
            frame = _FRAME.pack(len(body)) + body
            self.assertEqual(client.sendmsg([frame[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                         array('i', [lock]))]), 1)
            client.sendall(frame[1:])
        else:
            _frame_write(client, request, deadline)

    def exchange(self, request, *, drop=False, manager=None, with_lock=True):
        current = self.manager if manager is None else manager
        client, connected = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with client, connected:
            deadline = monotonic() + 1
            self.send(client, request, deadline, self.lock_fd if with_lock else None)
            if drop:
                client.close()
                with self.assertRaises(OSError):
                    current.serve_connection(connected, deadline=deadline)
                return None
            current.serve_connection(connected, deadline=deadline)
            reply = _frame_read(client, deadline)
            self.assertEqual((reply['operation'], reply['nonce']), (request['operation'], request['nonce']))
            return reply['result']

    def test_arm_submit_same_key_terminal_and_lost_reply_do_not_replay(self):
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'not_started')
        armed = self.exchange(self.request('arm_service'))
        request = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])

        def assert_claimed(scope, *, deadline_ns, approval):
            claim = server._read(self.store, server.GuardedManager._key(self.invocation, 'submitted'))
            self.assertEqual(claim['ticket'], armed['approval']['ticket_sha256'])
            self.assertEqual(scope, self.scope)
            self.assertEqual(deadline_ns, self.invocation.service_window.active_until_ns)
            with approval():
                pass

        self.physical.release_approved_child.side_effect = assert_claimed
        self.exchange(request, drop=True)
        self.assertIsNone(self.exchange(request))
        self.physical.release_approved_child.assert_called_once()
        self.physical.close.assert_called_once()
        restarted = self.new_manager()
        observed = self.exchange(self.request('read_service'), manager=restarted)['observation']
        self.assertEqual(observed['status'], 'terminal')
        self.assertIsNone(observed['service']['invocation_id'])
        self.assertIsNotNone(observed['service']['manager_run_id'])
        self.assertEqual(observed['service']['reaped_process'],
                         {'pid': 42, 'start_ticks': 10, 'pid_namespace_inode': 11})
        result = {'status': 'terminal', 'effect': 'dispatched', 'code': 'launch_readback_verified',
                  'service': observed['service'], 'request_id': '1'*64, 'invocation_key': self.key,
                  'receipt_sha256': observed['receipt_sha256'], 'cleanup': 'verified'}
        with patch('workeros.managed_bootstrap.setup_clock_id', return_value='clock'), patch(
                'workeros.managed_service._retired_leaf_absent', return_value=True):
            labeled = verify_native_readback(self.parent, result, monotonic_ns() + 1_000_000_000, guarded=True)
        self.assertEqual((labeled['effect'], labeled['code']), ('unknown', 'service_terminal_reported'))
        self.assertEqual(_response(labeled, {'request_id': '1'*64}), labeled)

    def test_phase_needs_current_release_and_a_point_sample_of_the_exact_leaf(self):
        directory = self.lock_directory.parent
        leaf = directory / self.unit
        leaf.mkdir()
        (leaf / 'cgroup.events').write_bytes(b'populated 1\n')
        stat = leaf.stat()
        self.parent = replace(self.parent, device=stat.st_dev)
        self.scope = replace(self.scope, parent=self.parent)
        self.service.update(parent=asdict(self.parent), scope_sha256=self.scope.digest)
        self.manager = self.new_manager(replace(self.enrollment, scope=self.scope))
        self.addCleanup(self.manager.close)
        identity = CgroupIdentity(stat.st_dev, stat.st_ino, self.parent.mount_id)
        parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, parent_fd)
        self.placement.return_value = (identity, self.physical)
        self.physical.retire.return_value = replace(self.physical.retire.return_value, cgroup=identity)
        allow_finish = Event()

        def release(_scope, *, deadline_ns, approval, on_released):
            with approval():
                on_released(monotonic_ns())
            self.assertTrue(allow_finish.wait(3))

        self.physical.release_approved_child.side_effect = release
        with ThreadPoolExecutor(1) as worker, patch.object(
                ServiceParent, 'directory', return_value=nullcontext(parent_fd)), patch.object(
                server, '_identity', return_value=identity), patch('workeros.scope_meter._mount_id',
                return_value=identity.mount_id), patch('workeros.managed_bootstrap.setup_clock_id',
                return_value='clock'):
            self.manager._worker = worker
            try:
                armed = self.exchange(self.request('arm_service'))
                self.assertNotIn('phase_observation', self.exchange(self.request('read_service')))
                self.exchange(self.request('submit_service', arm=armed['arm'],
                                           ticket_sha256=armed['approval']['ticket_sha256']))
                sampled = self.exchange(self.request('read_service'))
                self.assertEqual(sampled['observation']['status'], 'unknown')
                phase = sampled['phase_observation']
                self.assertTrue(phase['populated'])
                self.assertEqual(phase['invocation_key'], self.key)
                self.assertEqual(phase['scope_sha256'], self.scope.digest)
                self.assertEqual(phase['cgroup'], asdict(identity))
                self.assertLessEqual(phase['released_ns'], phase['observed_ns'])
                transport = Mock()
                transport._decode.side_effect = _Authority._decode
                transport._exchange.return_value = sampled
                reader = GuardedServiceAuthority(transport, self.scope, check_resources=lambda: None)
                observed = reader.readback(self.invocation, deadline_ns=monotonic_ns() + 1_000_000_000)
                self.assertEqual(observed.status, 'unknown')
                self.assertEqual(reader.phase_observation, phase)
                transport._exchange.return_value = {
                    **sampled, 'phase_observation': {**phase, 'scope_sha256': '0'*64}}
                with self.assertRaisesRegex(ValueError, 'phase observation mismatch'):
                    reader.readback(self.invocation, deadline_ns=monotonic_ns() + 1_000_000_000)
                self.assertIsNone(reader.phase_observation)
                (leaf / 'cgroup.events').write_bytes(b'populated 0\n')
                empty = self.exchange(self.request('read_service'))
                self.assertFalse(empty['phase_observation']['populated'])
            finally:
                allow_finish.set()
                if self.manager._retirement is not None:
                    self.manager._retirement.result(timeout=3)
        self.assertNotIn('phase_observation', self.exchange(self.request('read_service')))

    def test_reaped_failed_guard_child_retains_lifecycle_without_inferred_effect(self):
        self.physical.retire.return_value = replace(
            self.physical.retire.return_value, disposition='signaled', exit_status=9)
        armed = self.exchange(self.request('arm_service'))
        self.exchange(self.request('submit_service', arm=armed['arm'],
                                   ticket_sha256=armed['approval']['ticket_sha256']))
        observed = self.exchange(self.request('read_service'), manager=self.new_manager())['observation']
        self.assertEqual(observed['status'], 'terminal')
        self.assertTrue(observed['service']['handles_closed'])
        candidate = {'status': 'terminal', 'effect': 'dispatched', 'code': 'launch_readback_verified',
                     'service': observed['service'], 'request_id': '1'*64, 'invocation_key': self.key,
                     'receipt_sha256': observed['receipt_sha256'], 'cleanup': 'verified',
                     'observer_result': {'expires_ns': monotonic_ns() + 1_000_000_000}}
        with patch('workeros.managed_bootstrap.setup_clock_id', return_value='clock'), patch(
                'workeros.managed_service._retired_leaf_absent', return_value=True):
            outcome = verify_native_readback(self.parent, candidate, monotonic_ns() + 1_000_000_000, guarded=True)
        self.assertEqual((outcome['status'], outcome['effect'], outcome['code']),
                         ('unknown', 'unknown', 'service_terminal_reported'))
        life = outcome['provider_report']['service']['lifecycle']
        self.assertEqual((life['terminal_disposition'], life['terminal_status']), ('signaled', 9))
        self.assertTrue(outcome['provider_report']['service']['group_empty'])
        self.assertNotIn('observer_result', outcome)
        self.assertEqual(_response(outcome, {'request_id': '1'*64}), outcome)

    def test_witness_capture_leaves_time_for_native_retirement(self):
        from workeros import managed_witness_activation

        end = self.invocation.service_window.cleanup_until_ns
        handoff = managed_witness_activation.WitnessHandoff({}, self.invocation, {}, 'fixture', None)
        with patch.object(managed_witness_activation, 'monotonic_ns', return_value=end-1200), patch.object(
                handoff, '_confirm') as confirm:
            handoff.captured()
        confirm.assert_called_once_with('captured', end-600)

    def test_commissioned_witness_is_ready_before_release_and_captures_before_retirement(self):
        from workeros import managed_witness_activation

        config = {'source': 'witness'}
        self.manager._witness = config
        phases = []

        def release(scope, *, deadline_ns, approval, witness):
            with approval():
                witness(None, None, [], deadline_ns)
                phases.append('released')

        physical_retire = self.physical.retire.return_value
        self.physical.release_approved_child.side_effect = release
        self.physical.retire.side_effect = lambda: phases.append('retired') or physical_retire
        with patch.object(managed_witness_activation, 'WitnessHandoff') as constructor:
            exchange = constructor.return_value
            exchange.activate.side_effect = lambda *_: phases.append('ready')
            exchange.captured.side_effect = lambda: phases.append('captured')
            exchange.closed.side_effect = lambda: phases.append('closed')
            armed = self.exchange(self.request('arm_service'))
            self.exchange(self.request('submit_service', arm=armed['arm'],
                                       ticket_sha256=armed['approval']['ticket_sha256']))
            self.assertEqual(constructor.call_args.args[:3], (config, self.invocation, self.service))
        self.assertEqual(phases, ['ready', 'released', 'captured', 'retired', 'closed'])
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'terminal')

    def test_revoked_or_cancelled_arm_never_releases(self):
        armed = self.exchange(self.request('arm_service'))
        self.current.return_value = False
        request = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])
        self.assertIsNone(self.exchange(request))
        self.manager.close()
        self.physical.cancel_unstarted.assert_called_once()
        self.physical.release_approved_child.assert_not_called()
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'unknown')
        self.current.return_value = True
        self.assertIsNone(self.exchange(self.request('arm_service')))
        self.placement.assert_called_once()

    def test_installation_guard_waits_for_the_batch_after_discovering_its_own_parent(self):
        directory = Path(self.enterContext(TemporaryDirectory()))
        staged = directory / 'staged'
        staged.mkdir()
        for name in server._REGISTRATIONS:
            (staged / (name + '.json')).write_bytes(name.encode())
        output = StringIO()
        with ExitStack() as held, redirect_stdout(output), patch.object(
                server.managed_cli, '_safe_directory'), patch.object(
                server.managed_system_bus, 'discover_guard_parent', return_value=(self.parent, 'a' * 32)) as discover, patch.object(
                server, 'sleep', side_effect=lambda _: staged.rename(directory / 'registration')):
            opened, parent, incarnation = server._await_registration(
                str(directory), self.parent.unit, monotonic_ns() + 1_000_000_000, held)
            self.assertEqual((parent, incarnation), (self.parent, 'a' * 32))
            self.assertEqual([os.read(fd, 100).decode() for fd in opened], list(server._REGISTRATIONS))
            self.assertEqual(discover.call_args.kwargs, {'guard_uid': os.geteuid(), 'guard_pid': os.getpid()})
            with self.assertRaisesRegex(ValueError, 'guard_commissioning_registration_already_present'):
                server._await_registration(str(directory), self.parent.unit, monotonic_ns() + 1_000_000_000, held)
        self.assertEqual(json.loads(output.getvalue()), {
            'phase': 'guard_parent_pinned', 'parent': asdict(self.parent), 'invocation_id': 'a' * 32,
            'main_pid': os.getpid(), 'guard_uid': os.geteuid(), 'workload_started': False})
        self.placement.assert_not_called()

    def test_commissioning_refuses_a_different_manager_incarnation(self):
        with patch.object(server.managed_system_bus, 'verify_parent', return_value='b' * 32):
            with self.assertRaisesRegex(PlacementRefusal, 'guard_commissioning_incarnation_changed'):
                self._placement_implementation(self.scope, monotonic_ns() + 1_000_000_000, invocation_id='a' * 32)

    def test_matching_pending_submit_without_live_lock_retires_without_release(self):
        armed = self.exchange(self.request('arm_service'))
        submit = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])
        self.assertIsNone(self.exchange(submit, with_lock=False))
        self.assertIsNone(self.exchange(submit))
        self.physical.cancel_unstarted.assert_called_once()
        self.physical.release_approved_child.assert_not_called()
        self.assertIsNone(server._read(self.store, server.GuardedManager._key(self.invocation, 'submitted')))
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'unknown')

    def test_stale_protected_approval_at_final_gate_never_releases(self):
        armed = self.exchange(self.request('arm_service'))
        submit = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])
        # Stage completed conceptually, but the protected approval vanished before release.
        self.current.side_effect = (True, True, False)
        released = Mock()

        def staged(scope, *, deadline_ns, approval):
            with approval():
                released()

        self.physical.release_approved_child.side_effect = staged
        begin = self.physical.armed_ns
        self.physical.retire_unreleased.return_value = UnreleasedBootstrap(
            CgroupIdentity(**armed['arm']['leaf']), begin + 1, begin + 2, begin + 3, begin + 4)
        self.assertIsNone(self.exchange(submit))
        released.assert_not_called()
        self.physical.retire_unreleased.assert_called_once()
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'unreleased')

    def test_transferred_kernel_lock_survives_sender_loss_until_release(self):
        armed = self.exchange(self.request('arm_service'))
        submit = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])

        def busy():
            with self.assertRaises(BlockingIOError):
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def staged(scope, *, deadline_ns, approval):
            with approval():
                busy()
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        self.physical.release_approved_child.side_effect = staged
        client, connected = socket.socketpair()
        with client, connected:
            deadline = monotonic() + 1
            authority = os.open(self.lock_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                fcntl.flock(authority, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.send(client, submit, deadline, authority)
            finally:
                os.close(authority)
            busy()
            client.close()
            with self.assertRaises(OSError):
                self.manager.serve_connection(connected, deadline=deadline)
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'terminal')

    def test_crossed_binding_and_untrusted_peer_fail_before_arm(self):
        crossed = self.request('arm_service', service={**self.service, 'scope_sha256': '0'*64})
        with self.assertRaisesRegex(PermissionError, 'guard_enrollment_mismatch'):
            self.exchange(crossed)
        enrolled = server.GuardEnrollment(self.enrollment.policy, self.scope, 'e'*64, 'clock', os.getuid() + 1)
        untrusted = self.new_manager(enrolled)
        with self.assertRaisesRegex(PermissionError, 'guard_caller_untrusted'):
            self.exchange(self.request('arm_service'), manager=untrusted)
        self.placement.assert_not_called()

    def test_failed_sandbox_preserves_only_guard_child_terminal(self):
        self.physical.retire.return_value = replace(self.physical.retire.return_value, exit_status=125)
        armed = self.exchange(self.request('arm_service'))
        request = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])
        self.assertIsNone(self.exchange(request))
        self.assertIsNone(self.exchange(request))
        self.physical.release_approved_child.assert_called_once()
        self.physical.retire.assert_called_once()
        guarded_child = self.exchange(self.request('read_service'))['observation']
        self.assertEqual(guarded_child['status'], 'terminal')
        self.assertEqual(guarded_child['service']['lifecycle']['terminal_status'], 125)

    def test_proven_unreleased_bootstrap_settles_same_key_without_reopening_submit(self):
        armed = self.exchange(self.request('arm_service'))
        submit = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])
        begin = self.physical.armed_ns
        identity = CgroupIdentity(**armed['arm']['leaf'])
        self.physical.release_approved_child.side_effect = OSError('Fixture: gate stopped before release')
        self.physical.retire_unreleased.return_value = UnreleasedBootstrap(
            identity, begin + 1, begin + 2, begin + 3, begin + 4,
        )
        self.exchange(submit, drop=True)
        restarted = self.new_manager()
        self.assertIsNone(self.exchange(submit, manager=restarted))
        self.assertIsNone(self.exchange(self.request('arm_service'), manager=restarted))
        observed = self.exchange(self.request('read_service'), manager=restarted)['observation']
        self.assertEqual(observed['status'], 'unreleased')
        self.assertIsNone(observed['service'])
        self.physical.release_approved_child.assert_called_once()
        self.physical.retire_unreleased.assert_called_once()
        self.physical.retire.assert_not_called()
        result = {'status': 'not_started', 'effect': 'not_attempted', 'code': 'service_bootstrap_unreleased',
                  'unreleased': observed['unreleased'], 'request_id': '1'*64, 'invocation_key': self.key}
        with patch('workeros.managed_bootstrap.setup_clock_id', return_value='clock'), patch(
                'workeros.managed_service._retired_leaf_absent', return_value=True):
            labeled = verify_native_readback(self.parent, result, monotonic_ns() + 1_000_000_000, guarded=True)
        self.assertEqual(labeled, result)
        self.assertEqual(_response(labeled, {'request_id': '1'*64}), labeled)
        authorize, dispatch = Mock(), Mock()

        def readback(invocation, *, deadline_ns):
            self.assertEqual(invocation, self.invocation)
            wire = self.exchange(self.request('read_service'), manager=restarted)['observation']
            return _Authority._decode(wire, LaunchReadback)

        registration = LaunchRegistration(
            self.invocation.plan, authorize, dispatch, readback, bounded=True,
            service_scope_sha256=self.scope.digest, service_limits=self.scope.limits,
            service_enforcement=GUARDED_SERVICE, require_ticket_claim=True,
        )
        launch = ScopedLaunch(registration, self.invocation.profile_identity, self.invocation.clock_id,
                              already_reserved=True, service_window=self.invocation.service_window)
        result = launch.start(valid_until_ns=self.invocation.service_window.active_until_ns,
                              deadline_ns=monotonic_ns() + 1_000_000_000)
        self.assertEqual((result['effect'], result['code']), ('not_attempted', 'service_bootstrap_unreleased'))
        authorize.assert_not_called()
        dispatch.assert_not_called()

    def test_unreleased_cannot_be_inferred_if_proof_or_retirement_is_uncertain(self):
        armed = self.exchange(self.request('arm_service'))
        submit = self.request('submit_service', arm=armed['arm'], ticket_sha256=armed['approval']['ticket_sha256'])
        self.physical.release_approved_child.side_effect = OSError('Fixture: release uncertain')
        self.physical.retire_unreleased.side_effect = ValueError('Fixture: no proof')
        self.physical.cancel_unstarted.side_effect = ValueError('Fixture: gate already placed')
        with self.assertRaises(ValueError):
            self.exchange(submit)
        self.assertIsNone(self.exchange(submit))
        self.assertEqual(self.exchange(self.request('read_service'))['observation']['status'], 'unknown')
        self.physical.release_approved_child.assert_called_once()

    def test_installed_command_refuses_invalid_registration_before_effect(self):
        output = StringIO()
        with redirect_stdout(output):
            code = cli.main(['managed', 'serve-guard', '--config-fd', '0', '--setup-fd', '1',
                             '--executor-fd', '2', '--listen-fd', '3'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()),
                         {'status': 'refused', 'effect': 'not_attempted', 'code': 'guard_registration_unavailable'})
        self.placement.assert_not_called()
