"""Integrated managed service approval and real retained-descriptor checks."""
from contextlib import ExitStack, nullcontext
from dataclasses import asdict, replace
from hashlib import sha256
import os
from pathlib import Path
import pwd
import tempfile
from time import monotonic_ns, time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from workeros import managed_bootstrap, managed_cli, managed_guard_server, managed_service, managed_service_client
from workeros import managed_service_parent, managed_system_bus
from workeros import roles_cli
from workeros.appointment_registry import definition_sha256, launch_policy_sha256, launch_scope_sha256, register
from workeros.managed_host import _read_historical_launch
from workeros.managed_launch import LaunchAuthorization, LaunchReadback, LaunchRegistration, LaunchRolePolicy
from workeros.managed_service_parent import ManagerObservation, PlacementRefusal, ServiceParent
from workeros.managed_service_scope import ServiceBundle, ServiceDescriptor
from workeros.scope_meter import CgroupIdentity
from workeros.profile_setup import ProfileDefinition, ProviderBinding


class DelegatedServiceParentTest(TestCase):
    def setUp(self):
        self.parent = ServiceParent('qualified-guard.service', '/qualification.slice/qualified-guard.service',
                                    7, 101, 25)

    def test_five_field_pin_is_scoped_and_guard_never_creates_below_slice(self):
        self.assertEqual(ServiceParent(**asdict(self.parent)), self.parent)
        for unit, group in (('qualification.scope', '/qualification.scope'),
                            (self.parent.unit, '/qualification.slice/../qualified-guard.service'),
                            (self.parent.unit, '/qualification.slice/crossed.service')):
            with self.subTest(unit=unit, group=group), self.assertRaises(PlacementRefusal):
                replace(self.parent, unit=unit, control_group=group)
        legacy = ServiceParent('qualification.slice', '/qualification.slice', 7, 101, 25)
        with patch.object(managed_guard_server.os, 'mkdir') as mkdir:
            with self.assertRaisesRegex(ValueError, '^service_guard_delegated_parent_required$'):
                managed_guard_server._open_leaf(None, SimpleNamespace(parent=legacy), 'unused')
            mkdir.assert_not_called()
        with self.assertRaisesRegex(PlacementRefusal, '^service_slice_observation_required$'):
            managed_system_bus._Bus(None, None).check_parent(b':1', self.parent, monotonic_ns())

    def test_pinned_root_requires_owner_delegation_empty_domain_and_selected_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for name, data in (('cgroup.type', 'domain\n'), ('cgroup.procs', ''),
                               ('cgroup.subtree_control', 'memory\n')):
                (path / name).write_text(data)
            parent_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, parent_fd)
            guard_uid = os.getuid() or 1
            fstat = os.fstat

            def owned(fd):
                info = fstat(fd)
                return SimpleNamespace(st_uid=guard_uid, st_mode=info.st_mode)

            with patch.object(managed_service_parent, '_identity', return_value=self.parent.identity), patch.object(
                    managed_service_parent, '_mount_id', return_value=self.parent.mount_id), patch.object(
                    managed_service_parent.os, 'fstat', side_effect=owned), patch.object(
                    managed_service_parent.os, 'getxattr', return_value=b'1') as marker:
                self.parent.check_delegated_root(parent_fd, guard_uid, metered=True)
                with self.assertRaisesRegex(PlacementRefusal, '^service_parent_delegation_unverified$'):
                    self.parent.check_delegated_root(parent_fd, guard_uid + 1, metered=False)
                marker.return_value = b'0'
                with self.assertRaisesRegex(PlacementRefusal, '^service_parent_delegation_unverified$'):
                    self.parent.check_delegated_root(parent_fd, guard_uid, metered=False)
                marker.return_value = b'1'
                (path / 'cgroup.procs').write_text('1\n')
                with self.assertRaisesRegex(PlacementRefusal, '^service_parent_delegation_unverified$'):
                    self.parent.check_delegated_root(parent_fd, guard_uid, metered=False)
                (path / 'cgroup.procs').write_text('')
                (path / 'cgroup.subtree_control').write_text('')
                self.parent.check_delegated_root(parent_fd, guard_uid, metered=False)
                with self.assertRaisesRegex(PlacementRefusal, '^service_parent_memory_controller_unavailable$'):
                    self.parent.check_delegated_root(parent_fd, guard_uid, metered=True)

    def test_manager_pins_running_delegate_and_live_guard_before_allowing_scope(self):
        bus = managed_system_bus._Bus(None, None)
        pid = os.getpid()
        uid = os.getuid()
        process = managed_system_bus._guard_process
        self.assertTrue(process(pid, uid).startswith(b'/'))
        with self.assertRaisesRegex(PlacementRefusal, '^guard_manager_process_unverified$'):
            process(pid, uid + 1)
        membership = self.parent.control_group.encode() + b'/guard'

        def member(process_id, actual_uid):
            process(process_id, actual_uid)
            return membership

        self.enterContext(patch.object(managed_system_bus, '_guard_process', side_effect=member))
        properties = {b'Id': self.parent.unit.encode(), b'ActiveState': b'active', b'SubState': b'running',
                      b'ControlGroup': self.parent.control_group.encode(), b'Delegate': 1, b'MainPID': pid,
                      b'DelegateSubgroup': b'guard', b'InvocationID': '1' * 32}
        now = monotonic_ns() + 1_000_000_000
        with patch.object(bus, 'unit', return_value=b'/unit'), patch.object(
                bus, 'property', side_effect=lambda _owner, _path, _interface, name, _kind, _deadline:
                properties[name]), patch.object(ServiceParent, 'directory', return_value=nullcontext(99)), patch.object(
                ServiceParent, 'check_delegated_root') as root, patch.object(
                ServiceParent, 'check_guard_subgroup') as subgroup:
            bus.check_delegation(b':1', self.parent, now, guard_uid=uid, metered=True, guard_pid=pid)
            root.assert_called_once_with(99, uid, metered=True)
            subgroup.assert_called_once_with(99, membership, pid, uid)
            for field, value in ((b'Delegate', 0), (b'SubState', b'exited'), (b'MainPID', pid + 1),
                                 (b'ControlGroup', b'/crossed.service'), (b'InvocationID', '0' * 32)):
                with self.subTest(field=field):
                    previous = properties[field]
                    properties[field] = value
                    with self.assertRaisesRegex(PlacementRefusal, '^service_parent_manager_mismatch$'):
                        bus.check_delegation(b':1', self.parent, now, guard_uid=uid, metered=True, guard_pid=pid)
                    properties[field] = previous
            with self.assertRaisesRegex(PlacementRefusal, '^guard_manager_process_unverified$'):
                bus.check_delegation(b':1', self.parent, now, guard_uid=uid + 1, metered=True, guard_pid=pid)
            properties[b'DelegateSubgroup'] = b'other'
            with self.assertRaisesRegex(PlacementRefusal, '^guard_manager_outside_approved_parent$'):
                bus.check_delegation(b':1', self.parent, now, guard_uid=uid, metered=True, guard_pid=pid)

    def test_historical_readback_checks_pinned_mount_when_the_live_guard_is_gone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / self.parent.control_group[1:]
            group.mkdir(parents=True)
            identity = group.stat()
            parent = replace(self.parent, device=identity.st_dev, inode=identity.st_ino)
            unit = 'workeros-' + 'a' * 64 + '.service'
            deadline = monotonic_ns() + 1_000_000_000

            def pin(fd):
                info = os.fstat(fd)
                return CgroupIdentity(info.st_dev, info.st_ino, parent.mount_id)

            with patch.object(managed_service_parent, '_CGROUP_ROOT', directory), patch.object(
                    managed_service_parent, '_identity', side_effect=pin), patch.object(
                    managed_service, '_system_manager'), patch.object(
                    managed_system_bus, 'verify_parent') as live_verification:
                (group / unit).mkdir()
                self.assertFalse(managed_service._retired_leaf_absent(parent, unit, deadline))
                (group / unit).rmdir()
                self.assertTrue(managed_service._retired_leaf_absent(parent, unit, deadline))
                group.rename(group.with_name('retired'))
                self.assertTrue(managed_service._retired_leaf_absent(parent, unit, deadline))
                group.mkdir()
                self.assertFalse(managed_service._retired_leaf_absent(parent, unit, deadline))
                group.rmdir()
                self.assertFalse(managed_service._retired_leaf_absent(
                    replace(parent, mount_id=parent.mount_id + 1), unit, deadline))
                live_verification.assert_not_called()


class DescriptorServiceTest(TestCase):
    def test_preheld_write_is_to_the_exact_renamed_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'input'
            with path.open('w+b') as held:
                held.write(b'original')
                held.flush()
                info = os.fstat(held.fileno())
                scope = managed_service.ServiceScope('/approved/root', 1, 2, '/reader', 3, 'read-write',
                                                     info.st_dev, info.st_ino, held.fileno())
                path.chmod(0o400)
                path.rename(root / 'retained')
                path.write_bytes(b'replacement')
                scope.check_original()
                self.assertEqual(os.pwrite(held.fileno(), b'F', 0), 1)
                self.assertEqual((root / 'retained').read_bytes(), b'Friginal')
                self.assertEqual(path.read_bytes(), b'replacement')
                with path.open('rb') as crossed:
                    wrong = {**asdict(scope), 'original_fd': crossed.fileno()}
                    with self.assertRaisesRegex(managed_service.ServiceRefusal, '^service_original_mismatch$'):
                        managed_service.ServiceScope(**wrong).check_original()
                wrong_mode = {**asdict(scope), 'mode': 'read'}
                with self.assertRaisesRegex(managed_service.ServiceRefusal, '^service_original_mismatch$'):
                    managed_service.ServiceScope(**wrong_mode).check_original()

    def test_absent_system_manager_cannot_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = str(Path(temporary) / 'missing')
            with patch.object(managed_service, '_MANAGER_SOCKET', missing):
                with self.assertRaisesRegex(managed_service.ServiceRefusal, '^system_service_manager_unavailable$'):
                    managed_service._system_manager()

    def test_manager_submission_retains_terminal_and_separates_phase_budgets(self):
        scope = managed_service.ServiceScope('/approved/root', 1, 2, '/reader', 30, 'read', 3, 4, 5)
        parent = ServiceParent('reports.slice', '/reports.slice', 7, 100, 25)
        with self.assertRaisesRegex(managed_service.ServiceRefusal, 'service_parent_registration_required'):
            managed_service._properties(scope, SimpleNamespace(principal_uid=70), {},
                                        remaining_us=1200, cleanup_us=450)
        pinned = replace(scope, parent=parent)
        self.assertNotEqual(scope.digest, pinned.digest)
        self.assertNotEqual(pinned.digest, replace(pinned, parent=replace(parent, inode=101)).digest)
        properties = {name:(kind, value) for name, kind, value in managed_service._properties(
            pinned, SimpleNamespace(principal_uid=70), {'stdin': 5, 'stdout': 6}, remaining_us=1200, cleanup_us=450)}
        self.assertEqual(properties['Slice'], (b's', 'reports.slice'))
        self.assertEqual(properties['RuntimeMaxUSec'], (b't', 1200))
        self.assertEqual(properties['TimeoutStartUSec'], (b't', 1200))
        self.assertEqual(properties['TimeoutStopUSec'], (b't', 450))
        self.assertEqual(properties['RemainAfterExit'], (b'b', True))
        self.assertEqual(properties['CollectMode'], (b's', 'inactive'))
        self.assertEqual(properties['StandardInputFileDescriptor'], (b'h', 5))
        self.assertEqual(properties['StandardOutputFileDescriptor'], (b'h', 6))
        self.assertEqual(properties['StandardError'], (b's', 'null'))


    def test_native_history_requires_same_incarnation_and_holds_retirement(self):
        parent = ServiceParent('reports.slice', '/reports.slice', 7, 100, 25)
        child = CgroupIdentity(7, 101, 25)
        key = 'a' * 64
        unit = f'workeros-{key}.service'
        native = ManagerObservation(unit, 'b'*32, '/reports.slice/' + unit, child, 1, 0, 25_000,
                                    b'active', b'exited', 0)
        receipt = {
            'status': 'terminal', 'effect': 'dispatched', 'code': 'launch_readback_verified',
            'request_id': 'c'*64, 'invocation_key': key, 'receipt_sha256': 'd'*64,
            'service': {'unit': unit, 'invocation_id': native.invocation_id, 'scope_sha256': 'e'*64,
                        'group_empty': True, 'handles_closed': True,
                        'lifecycle': {'clock_id': 'fixture-clock', 'start_ns': 20_000,
                                      'cgroup': asdict(child), 'terminal_ns': 30_000,
                                      'terminal_disposition': 'exited', 'terminal_status': 0,
                                      'empty_ns': 31_000, 'retired_ns': 32_000, 'handles_closed_ns': 33_000}},
            'cleanup': 'verified',
        }
        deadline = monotonic_ns() + 4_000_000_000
        with patch.object(managed_service, '_system_manager'), patch.object(
                managed_bootstrap, 'setup_clock_id', return_value='fixture-clock'), patch.object(
                managed_service.managed_system_bus, 'observe', return_value=native) as observe:
            matched = managed_service.verify_native_readback(parent, receipt, deadline)
            self.assertEqual((matched['status'], matched['effect'], matched['cleanup']),
                             ('terminal', 'dispatched', 'unconfirmed'))
            observe.assert_called_once_with(parent, unit, deadline)
            for wrong in (replace(native, invocation_id='f'*32),
                          replace(native, cgroup=replace(child, inode=102)),
                          replace(native, exit_status=42)):
                observe.return_value = wrong
                result = managed_service.verify_native_readback(parent, receipt, deadline)
                self.assertEqual((result['status'], result['effect']), ('unknown', 'unknown'))
                self.assertNotIn('receipt_sha256', result)
            observe.side_effect = FileNotFoundError()
            self.assertEqual(managed_service.verify_native_readback(parent, receipt, deadline)['code'],
                             'service_native_readback_unconfirmed')
            with patch.object(managed_service, '_retired_leaf_absent', return_value=True) as absence:
                retired = managed_service.verify_native_readback(parent, receipt, deadline, guarded=True)
            absence.assert_called_once_with(parent, unit, deadline)
            self.assertEqual((retired['status'], retired['effect'], retired['code']),
                             ('unknown', 'unknown', 'service_terminal_reported'))
            self.assertEqual(retired['provider_report']['service']['lifecycle'], receipt['service']['lifecycle'])
            self.assertEqual(managed_service_client._response(retired, {'request_id': receipt['request_id']}), retired)
        self.assertEqual(managed_service.verify_native_readback(None, receipt, deadline), receipt)


    def test_native_history_never_reports_started_for_an_exited_service(self):
        parent = ServiceParent('reports.slice', '/reports.slice', 7, 100, 25)
        child = CgroupIdentity(7, 101, 25)
        key = 'a' * 64
        unit = f'workeros-{key}.service'
        native = ManagerObservation(unit, 'b'*32, '/reports.slice/' + unit, child, 0, 0, 0,
                                    b'active', b'running', 812)
        prior = {
            'status': 'started', 'effect': 'dispatched', 'code': 'launch_readback_verified',
            'request_id': 'c'*64, 'invocation_key': key, 'receipt_sha256': 'd'*64, 'cleanup': 'not_observed',
            'service': {'unit': unit, 'invocation_id': native.invocation_id, 'scope_sha256': 'e'*64,
                        'lifecycle': {'clock_id': 'fixture-clock', 'start_ns': 20_000, 'cgroup': asdict(child)}},
        }
        deadline = monotonic_ns() + 4_000_000_000
        with patch.object(managed_service, '_system_manager'), patch.object(
                managed_bootstrap, 'setup_clock_id', return_value='fixture-clock'), patch.object(
                managed_service.managed_system_bus, 'observe', return_value=native) as observe:
            self.assertEqual(managed_service.verify_native_readback(parent, prior, deadline), prior)
            for changed in (replace(native, exit_code=1, exit_ns=25_000),
                            replace(native, active_state=b'inactive'),
                            replace(native, sub_state=b'exited'), replace(native, main_pid=0)):
                observe.return_value = changed
                result = managed_service.verify_native_readback(parent, prior, deadline)
                self.assertEqual((result['status'], result['effect'], result['code']),
                                 ('unknown', 'unknown', 'service_native_readback_unconfirmed'))
                self.assertNotIn('receipt_sha256', result)


    def test_native_observation_rejects_exit_during_the_same_manager_read(self):
        parent = ServiceParent('reports.slice', '/reports.slice', 7, 100, 25)
        child = CgroupIdentity(7, 101, 25)
        unit = f"workeros-{'a' * 64}.service"
        deadline = monotonic_ns() + 4_000_000_000
        manager = Mock()
        manager.manager.return_value = b':1.1'
        manager.unit.return_value = b'/org/freedesktop/systemd1/unit/workeros'
        properties = {
            b'InvocationID': 'b'*32, b'Id': unit.encode(), b'Slice': parent.unit.encode(),
            b'ControlGroup': f'{parent.control_group}/{unit}'.encode(), b'ActiveState': b'active',
            b'SubState': b'running', b'MainPID': 812, b'ExecMainCode': 0, b'ExecMainStatus': 0,
        }
        exit_timestamps = iter((0, 25))

        def get_property(owner, path, interface, name, kind, call_deadline):
            self.assertEqual(call_deadline, deadline)
            if name == b'ExecMainExitTimestampMonotonic':
                return next(exit_timestamps)
            return properties[name]

        manager.property.side_effect = get_property
        with patch.object(managed_system_bus, '_system_bus', return_value=nullcontext(manager)), patch.object(
                ServiceParent, 'child_identity', return_value=child):
            with self.assertRaisesRegex(PlacementRefusal, '^service_child_changed_during_readback$'):
                managed_system_bus.observe(parent, unit, deadline)
        manager.check_parent.assert_called_once_with(b':1.1', parent, deadline)


class ServiceApprovalTest(TestCase):
    def setUp(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel required')
        self.wheel = Path(wheel)
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(self.root), _UID=os.getuid()))
        self.enterContext(patch.object(managed_bootstrap, 'setup_clock_id', return_value='fixture-clock'))
        self.enterContext(patch.object(managed_cli, '_TRUSTED_UID', os.getuid()))
        self.original = self.enterContext((self.root/'input').open('w+b'))
        file = os.fstat(self.original.fileno())
        self.scope = managed_service.ServiceScope('/approved/root', 1, 2, '/reader', 1, 'read-write',
                                                  file.st_dev, file.st_ino, self.original.fileno())
        self.account = pwd.getpwuid(os.getuid())
        self.deadline = monotonic_ns() + 45_000_000_000
        self.dispatch = Mock(side_effect=self._dispatch)
        self.authorize = Mock(side_effect=self._authorize)
        self.readback = Mock(side_effect=self._readback)
        self.result = None

    def document(self, *, writable):
        workflow, scope, role = 'write-report', 'report-scope', 'approved-editor'
        name, uid = self.account.pw_name, self.account.pw_uid
        bundle = type(self.scope) is ServiceBundle
        role_resources = ({item.scope:{'device':item.original[0], 'inode':item.original[1]}
                           for item in self.scope.descriptors} if bundle else
                          {scope:{'device': self.scope.original[0], 'inode': self.scope.original[1]}})
        roles_scopes = sorted({scope, *role_resources})
        role_spec = {'name': role, 'principal': name, 'scopes': roles_scopes, 'expires_at': int(time())+120,
                     'operations': ['launch', 'read', 'write'] if writable else ['launch', 'read'],
                     'resources': role_resources}
        streams = ({slot:f'original.{slot}' for slot in self.scope.streams} if bundle else {'stdin':'original'})
        compiled = {'version':1, 'roles':{role:{'operations':['launch']}}, 'workflows':{
            workflow:{'role':role, 'operations':['launch'], 'bindings':{
                'executable':'program', 'supervisor':'system-launcher', 'streams':streams}}}}
        encode = roles_cli._canonical
        scope_pin = launch_scope_sha256(role_spec, scope, ['launch'])
        bindings = (
            ProviderBinding('program', '2'*64, scope, 'executable', 'launcher', 'executable'),
            ProviderBinding('system-launcher', scope_pin, scope, 'scoped-launch', 'launcher', 'supervisor'),
            ProviderBinding('original', self.scope.digest, scope, 'systemd-fd', 'launcher', 'streams'),
        )
        definition = ProfileDefinition(workflow, 'r1', '0.8.0', sha256(self.wheel.read_bytes()).hexdigest(),
                                       sha256(encode(compiled)).hexdigest(), 'manager', scope, 'fixture-clock',
                                       self.deadline, bindings)
        self.policy = LaunchRolePolicy(workflow, definition_sha256(definition), 'generation', role, name,
                                       '2'*64, scope_pin, 'launcher', 'authority', '5'*64, uid)
        declaration = roles_cli.apply(encode({'version':1, 'profile':'reports', 'revision':'r1',
                                               'roles':[role_spec]}))
        local = {'declaration_sha256':declaration['digest'], 'intent_sha256':'6'*64}
        roles_cli.commission('reports','r1',**local)
        entry = {'workflow':workflow, 'workflow_revision':'r1', 'definition_sha256':definition_sha256(definition),
                 'role':role, 'principal':name, 'scope':scope, 'generation':'generation',
                 'operations':['launch'], 'launch':{'scope_sha256':scope_pin,
                                                      'policy_sha256':launch_policy_sha256(self.policy)}}
        register(encode({'version':1, 'profile':'reports','revision':'r1', **local, 'appointments':[entry]}))
        return {'version':2,'profile':'reports','revision':'r1','operation_key':'7'*64,'authorized_uids':[uid],
                'wheel_path':str(self.wheel),'local_approval':local,'scopes':[{'definition':asdict(definition),
                'policy':compiled,'role':role,'binding_generation':'generation'}]}

    def _authorize(self, invocation, *, deadline_ns):
        if invocation.service_window is not None:
            return LaunchAuthorization(invocation, 'authority', '5'*64, '8'*64,
                                       invocation.service_window.active_until_ns, guard_sha256='f'*64)
        return LaunchAuthorization(invocation, 'authority', '5'*64, '8'*64, self.deadline-1_000_000)

    def _readback(self, invocation, *, deadline_ns):
        return self.result or LaunchReadback(invocation, 'authority', '5'*64, 'not_started')

    def _dispatch(self, invocation, ticket, *, deadline_ns):
        plan = invocation.plan
        self.result = LaunchReadback(invocation, 'authority', '5'*64, 'terminal',
                                    plan.principal, plan.executable_sha256, plan.scope_sha256, 'a'*64,
                                    plan.principal_uid, {'unit': f'workeros-{plan.invocation_key}.service',
                                    'invocation_id':'b'*32,'scope_sha256': self.scope.digest,
                                    'group_empty':True,'handles_closed':True})

    def approved(self, *, writable):
        config = self.document(writable=writable)
        self.registration = LaunchRegistration(self.policy,self.authorize,self.dispatch,self.readback,bounded=True,
                            service_scope_sha256=self.scope.digest, service_limits=managed_service.limits(self.scope))
        return managed_bootstrap._open_approved_launch(config, self.registration,
                    executable_argv=(self.scope.executable,), require_launch_resource=True, launch_service=self.scope)

    def test_exact_named_writable_approval_without_optional_observer(self):
        with self.approved(writable=True) as adapter:
            result = adapter.launch_approved(request_id='e'*64)
            self.assertEqual((result['status'], result['cleanup']), ('terminal','verified'))
            self.assertEqual(result['service']['scope_sha256'], self.scope.digest)
            self.assertEqual(adapter.launch_approved(request_id='e'*64), result)
            self.assertEqual(adapter.read_launch(request_id='e'*64),result)
        self.dispatch.assert_called_once()
        self.authorize.assert_called_once()

    def test_read_only_role_cannot_select_writable_descriptor(self):
        with self.assertRaisesRegex(PermissionError, '^role_appointment_mismatch$'):
            with self.approved(writable=False):
                self.fail('read-only approval unexpectedly admitted a writer')
        self.dispatch.assert_not_called()
        self.authorize.assert_not_called()

    def composite_fixture(self):
        (self.root/'other').write_bytes(b'input')
        reader = self.enterContext((self.root/'other').open('rb'))
        r, w = os.fstat(reader.fileno()), os.fstat(self.original.fileno())
        uid = os.getuid()
        separate = 1 if uid != 1 else 2
        self.scope = ServiceBundle('/approved/root', 1, 2, '/reader', 1, (
            ServiceDescriptor('stdin','approved-input',separate,'read',r.st_dev,r.st_ino,reader.fileno()),
            ServiceDescriptor('stdout','approved-output',uid,'read-write',w.st_dev,w.st_ino,self.original.fileno()),
        ), active_ms=1000, cleanup_ms=350, metered=False)
        # Separate ownership and manager observations are simulated only in
        # this installed policy-path test, not in the descriptor kernel tests.
        self.enterContext(patch.object(ServiceDescriptor, 'check_original'))

    def test_bundle_reserves_same_guard_window_and_reconciles_after_revoke(self):
        self.composite_fixture()
        historical_result = None

        def dispatch(invocation, ticket, *, deadline_ns):
            nonlocal historical_result
            window = invocation.service_window
            self.assertEqual(deadline_ns, window.active_until_ns)
            self.assertEqual(ticket.guard_sha256, 'f'*64)
            self.assertEqual(window.cleanup_until_ns - window.active_until_ns, 350_000_000)
            tick = monotonic_ns()
            plan = invocation.plan
            historical_result = LaunchReadback(invocation, 'authority', '5'*64, 'terminal',
                plan.principal, plan.executable_sha256, plan.scope_sha256, 'a'*64, plan.principal_uid,
                {'unit': f'workeros-{plan.invocation_key}.service', 'invocation_id':'b'*32,
                 'scope_sha256': self.scope.digest, 'group_empty':True, 'handles_closed':True,
                 'lifecycle':{'clock_id':'fixture-clock', 'start_ns':tick, 'terminal_ns':tick+1,
                              'terminal_disposition':'exited', 'terminal_status':0, 'empty_ns':tick+2,
                              'retired_ns':tick+3, 'handles_closed_ns':tick+4,
                              'cgroup':{'device':3,'inode':4,'mount_id':5}}})
            raise OSError('fixture lost the submit reply')

        self.dispatch.side_effect = dispatch
        request_id = 'b'*64
        with self.approved(writable=True) as adapter:
            lost = adapter.launch_approved(request_id=request_id)
            self.assertEqual(lost['effect'], 'unknown')
            self.assertIsNotNone(historical_result)
        roles_cli.revoke('reports','r1')
        self.result = historical_result
        readback = _read_historical_launch(self.registration, 'reports', 'r1', request_id,
                                           monotonic_ns()+1_000_000_000)
        self.assertEqual((readback['status'],readback['cleanup']), ('terminal','verified'))
        self.assertEqual(readback['invocation_key'], lost['invocation_key'])
        self.authorize.assert_called_once()
        self.dispatch.assert_called_once()

    def test_bundle_absent_armed_guard_refuses_before_dispatch(self):
        self.composite_fixture()
        self.authorize.side_effect = lambda request, **_: LaunchAuthorization(
            request,'authority','5'*64,'8'*64,request.service_window.active_until_ns)
        with self.approved(writable=True) as adapter:
            result = adapter.launch_approved(request_id='c'*64)
            self.assertEqual((result['code'],result['effect']), ('launch_authority_unverified','not_attempted'))
        self.dispatch.assert_not_called()
