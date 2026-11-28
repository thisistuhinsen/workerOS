"""Exercise live descriptor handoff and finite installed overlap without host privileges."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Barrier, Event, Lock
from time import monotonic, monotonic_ns
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from workeros import managed_cli, managed_guard_server, managed_holder, managed_service_client, roles_cli
from workeros.appointment_registry import launch_policy_sha256
from workeros.delegated_service_leaf import LeafObservation
from workeros.managed_executor import _Authority, authority_pin
from workeros.managed_host import ManagedHostAdapter
from workeros.managed_launch import GUARDED_SERVICE, LaunchRolePolicy
from workeros.managed_service_scope import ServiceBundle
from workeros.recording import LocalStore
from workeros.scope_meter import CgroupIdentity


@contextmanager
def listener(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as opened:
        opened.bind(str(path))
        try:
            opened.listen()
            yield opened
        finally:
            Path(path).unlink()


class HolderOverlapTest(TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.uid = os.getuid()
        self.profile, self.revision = 'inventory', 'review'
        self.output = self.enterContext(ExitStack())

    def scope(self, name):
        path = self.root / name
        path.write_bytes(name.encode())
        fd = self.output.enter_context(path.open('rb')).fileno()
        info = os.fstat(fd)
        return ServiceBundle('/approved/root', 1, 2, '/fixture', 1, [
            {'slot': 'stdin', 'scope': name, 'owner_uid': self.uid, 'mode': 'read',
             'device': info.st_dev, 'inode': info.st_ino, 'fd': fd},
        ], 2500, 1000, False, parent={'unit': 'inventory-guard.service',
                                     'control_group': '/inventory.slice/inventory-guard.service',
                                    'device': 7, 'inode': 17, 'mount_id': 25})

    def test_holder_refuses_crossed_scope_and_receiver_closes_exact_copy(self):
        scope, crossed = self.scope('genuine'), self.scope('crossed')
        endpoint = self.root / 'holder.sock'
        pin = managed_holder._pin(self.profile, self.revision, 'genuine', scope)
        config = {'uid': self.uid, 'socket': str(endpoint)}
        with listener(endpoint) as receiver, ThreadPoolExecutor(1) as worker:
            task = worker.submit(managed_holder.serve_originals, receiver, scope, pin, {self.uid},
                                 deadline=monotonic() + 2)
            with ExitStack() as resources:
                with self.assertRaisesRegex(ValueError, 'service_holder_reply_invalid'):
                    managed_holder.receive_originals(config, self.profile, self.revision, 'genuine', crossed,
                                                     resources, monotonic() + 1)
                bound = managed_holder.receive_originals(config, self.profile, self.revision, 'genuine', scope,
                                                         resources, monotonic() + 1)
                copy = bound.streams['stdin']
                self.assertEqual((os.pread(copy, 99, 0), bound.digest), (b'genuine', scope.digest))
                self.assertFalse(os.get_inheritable(copy))
            with self.assertRaises(OSError):
                os.fstat(copy)
            task.result(timeout=2)
        self.assertEqual(os.pread(scope.streams['stdin'], 99, 0), b'genuine')

    def test_two_commissioned_requests_overlap_inside_one_profile(self):
        names = ('first', 'second')
        ids = {name: sha256(name.encode()).hexdigest() for name in names}
        account_uids = list(uid for uid in range(40, 50) if uid != self.uid)
        wheel = self.root / 'fixture.whl'
        executor = {'version': 2, 'profile': self.profile, 'revision': self.revision,
                    'wheel_path': str(wheel), 'wheel_sha256': 'a'*64, 'workflows': {}}
        route = {'version': 1, 'profile': self.profile, 'revision': self.revision,
                 'socket': str(self.root / 'launcher.sock'), 'peer_uid': self.uid, 'workflows': {}}
        setup = {key: executor[key] for key in ('profile', 'revision', 'version', 'wheel_path')}
        setup['scopes'] = [{'definition': {'name': name, 'package_sha256': 'a'*64}} for name in names]
        callbacks = self.enterContext(ExitStack())
        callbacks.enter_context(patch.multiple(managed_cli, _TRUSTED_UID=self.uid, _TIMEOUT=3.0))
        callbacks.enter_context(patch.multiple(roles_cli, _PARENT=str(self.root), _UID=self.uid))
        with roles_cli._store(create=True):
            state = (self.root / 'workeros').stat()
        lock_pin = state.st_dev, state.st_ino

        scheduler = self.enterContext(ThreadPoolExecutor(10))
        peer_transport = _Authority._exchange
        originals_transport = managed_holder.receive_originals

        # This disposable venue supplies real frames and FDs under one UID.
        # Substitute only the expected receiver credentials at transport edges.
        def fixture_authority(authority, *args, **kwargs):
            return peer_transport(SimpleNamespace(endpoint=authority.endpoint, uid=self.uid), *args, **kwargs)

        def fixture_holder(holder, *args):
            return originals_transport({**holder, 'uid': self.uid}, *args)

        callbacks.enter_context(patch.object(_Authority, '_exchange', new=fixture_authority))
        callbacks.enter_context(patch.object(managed_holder, 'receive_originals', side_effect=fixture_holder))
        callbacks.enter_context(patch('workeros.managed_registration.require_pinned_pair', return_value=setup))
        callbacks.enter_context(patch.object(managed_service_client, '_read_registration', return_value=executor))
        callbacks.enter_context(patch.object(managed_service_client, '_client_registration', return_value=route))
        callbacks.enter_context(patch.object(managed_service_client, 'verify_install'))
        service = managed_service_client.managed_service
        callbacks.enter_context(patch.object(service, '_system_manager'))
        callbacks.enter_context(patch.object(service.managed_system_bus, 'verify_parent'))
        callbacks.enter_context(patch.object(service, '_retired_leaf_absent', return_value=True))
        callbacks.enter_context(patch('workeros.managed_service_guard._require_empty_leaf'))
        callbacks.enter_context(patch.object(managed_service_client.managed_bootstrap, 'setup_clock_id', return_value='fixture-clock'))

        def open_launch(_setup, registration, **_):
            adapter = object.__new__(ManagedHostAdapter)
            adapter._launch_registration = registration
            adapter.profile, adapter.revision = self.profile, self.revision
            adapter.clock_id, adapter.identity = 'fixture-clock', 'b'*64
            adapter._checked_launch_limit = lambda *_: monotonic_ns() + 2_500_000_000

            def launch(*, request_id):
                with roles_cli._store(create=False) as store:
                    return adapter._launch_reusable(request_id, store, {}, monotonic_ns() + 2_500_000_000)

            return nullcontext(SimpleNamespace(launch_approved=launch))

        callbacks.enter_context(patch.object(managed_service_client.managed_bootstrap, '_open_approved_launch',
                                             side_effect=open_launch))
        ready, both_active, close_reapers, terminal = Event(), Event(), Event(), Event()
        released, reaped, samples = {}, {}, {}
        completed = set()
        mutex = Lock()
        holder_tasks, guards, managers = [], [], []

        def require_guard_event(event):
            if not event.wait(2):
                for manager in managers:
                    retirement = manager._retirement
                    if retirement is not None and retirement.done():
                        retirement.result()
                self.fail('guard fixtures did not reach the expected release or terminal event')

        commit = managed_guard_server._commit

        def record(store, key, data):
            committed = commit(store, key, data)
            if committed and key.record_id == 'guard-terminal':
                with mutex:
                    completed.add(key.run_id)
                    if len(completed) == 2:
                        terminal.set()
            return committed

        callbacks.enter_context(patch.object(managed_guard_server, '_commit', side_effect=record))

        def create_guard(index, name):
            holder_path, guard_path = self.root / (name + '-h.sock'), self.root / (name + '-g.sock')
            held, policy_uid, guard_uid, holder_uid = self.scope(name), *account_uids[index*3:index*3+3]
            policy = LaunchRolePolicy(name, '1'*64, 'generation', 'inventory-role', 'worker', '2'*64, '3'*64,
                                      'launcher', 'guard', authority_pin('guard', str(guard_path), guard_uid), policy_uid)
            holder = {'uid': holder_uid, 'socket': str(holder_path)}
            executor['workflows'][name] = {'policy': asdict(policy), 'service': json.loads(roles_cli._canonical(asdict(held))),
                'authority': {'uid': guard_uid, 'socket': str(guard_path), 'enforcement': GUARDED_SERVICE},
                'holder': holder, 'run_uids': [self.uid], 'result_uids': [self.uid]}
            route['workflows'][name] = launch_policy_sha256(policy)
            socket_path = self.output.enter_context(listener(holder_path))
            expected = managed_holder._pin(self.profile, self.revision, name, held)

            def holder_fixture():
                for _ in range(2):
                    managed_holder.serve_originals(socket_path, held, expected, {self.uid}, deadline=monotonic() + 3)

            holder_tasks.append(scheduler.submit(holder_fixture))
            bound = fixture_holder(holder, self.profile, self.revision, name, held, self.output, monotonic() + 2)
            journal = self.root / (name + '-journal')
            journal.mkdir(mode=0o700)
            enrollment = managed_guard_server.GuardEnrollment(policy, bound, 'b'*64, 'fixture-clock', self.uid)
            guard = managed_guard_server.GuardedManager(enrollment, LocalStore(journal), lambda: True,
                                                         role_store_lock=lock_pin)
            managers.append(guard)
            guards.append(scheduler.submit(guard.serve, self.output.enter_context(listener(guard_path)),
                                          detach_retirement=True))

        for index, name in enumerate(names):
            create_guard(index, name)

        def scope_leaf(invocation, scope, unit):
            name = invocation.plan.workflow
            inode = 100 + names.index(name)
            identity = CgroupIdentity(7, inode, 25)

            class ScopedFixture:
                armed_ns = monotonic_ns()

                def release_approved_child(self, scope, *, deadline_ns, approval, on_released):
                    with approval():
                        scope.check_original()
                        original = os.pread(scope.streams['stdin'], 99, 0)
                        sent_ns = monotonic_ns()
                        on_released(sent_ns)
                        with mutex:
                            released[name] = sent_ns
                            samples[name] = original
                            if len(released) == 2:
                                both_active.set()
                    if not close_reapers.wait(2):
                        raise TimeoutError('fixture did not release cleanup')

                def retire(self):
                    reaped[name] = monotonic_ns()
                    finished = reaped[name]
                    return LeafObservation(invocation.plan.invocation_key, invocation.clock_id, identity,
                                           released[name], finished-3, 'exited', 0, finished-2, None, None,
                                           'empty_observed_before_cutoff', finished-1)

                def close(self):
                    pass

            return identity, ScopedFixture()

        callbacks.enter_context(patch.object(managed_guard_server, '_open_leaf', side_effect=scope_leaf))
        callbacks.enter_context(patch.object(managed_guard_server, '_require_guard_placement'))

        @contextmanager
        def local_launcher(path, _uid, *, public):
            with listener(path) as endpoint:
                ready.set()
                yield endpoint

        callbacks.enter_context(patch.object(managed_service_client, 'registered_listener', side_effect=local_launcher))
        flags = [word for name in names for word in ('--commissioned', name)]
        launcher = scheduler.submit(managed_cli.main, ['serve-launch', *flags])
        barrier = Barrier(3)

        def run(name):
            barrier.wait(timeout=2)
            return managed_service_client.request_service(name, ids[name])

        try:
            self.assertTrue(ready.wait(2))
            jobs = [scheduler.submit(run, name) for name in names]
            barrier.wait(timeout=2)
            require_guard_event(both_active)
            self.assertFalse(reaped)
            rows = [job.result(timeout=2) for job in jobs]
            self.assertEqual([row['effect'] for row in rows], ['unknown', 'unknown'])
            self.assertEqual(len({row['invocation_key'] for row in rows}), 2)
            self.assertEqual(samples, {'first': b'first', 'second': b'second'})
            self.assertEqual(launcher.result(timeout=2), 0)
        finally:
            close_reapers.set()
        require_guard_event(terminal)
        for manager in managers:
            manager._retirement.result(timeout=2)
        self.assertEqual(completed, {row['invocation_key'] for row in rows})
        ready.clear()
        readbacks = scheduler.submit(managed_cli.main, ['serve-launch', *flags])
        self.assertTrue(ready.wait(2))
        for name, prior in zip(names, rows, strict=True):
            result = managed_service_client.request_service(name, ids[name], readback=True)
            self.assertEqual((result['effect'], result['code'], result['invocation_key']),
                             ('unknown', 'service_terminal_reported', prior['invocation_key']))
            lifecycle = result['provider_report']['service']['lifecycle']
            self.assertEqual(lifecycle['cgroup']['inode'], 100 + names.index(name))
            self.assertLess(lifecycle['empty_ns'], lifecycle['retired_ns'])
        self.assertEqual(readbacks.result(timeout=managed_cli._TIMEOUT + 2), 0)
        for task in holder_tasks + guards:
            task.result(timeout=4)
        self.assertEqual(set(reaped), set(names))
        self.assertLess(max(released.values()), min(reaped.values()))
