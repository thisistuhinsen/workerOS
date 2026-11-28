"""Guarded service product contract with a transport peer that starts no workers."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import asdict, replace
from functools import partial
from hashlib import sha256
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from time import monotonic, monotonic_ns
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from workeros import managed_service, managed_service_client, roles_cli
from workeros.managed_executor import _Authority
from workeros.managed_host import _claim_launch_ticket, _launch_record, _recorded_launch
from workeros.managed_launch import (
    GUARDED_SERVICE, LaunchRegistration, LaunchPlan, LaunchRolePolicy, ScopedLaunch, ServiceLimits, ServiceWindow,
)
from workeros.managed_service_guard import GuardedServiceAuthority
from workeros.managed_service_parent import PlacementRefusal, ServiceParent
from workeros.recording import LocalStore, Persistence
from workeros.roles_cli import _canonical, _key, _read


class GuardedProtocolTest(TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(root), _UID=os.getuid()))
        self.listener = self.enterContext(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        self.listener.bind(str(root / 'authority.sock'))
        self.listener.listen()
        self.listener.settimeout(0.8)
        # Detached same-UID peer. The production constructor's distinct UID
        # registration is covered separately. Real SO_PEERCRED framing stays on.
        self.transport = object.__new__(_Authority)
        self.transport.endpoint = self.listener.getsockname()
        self.transport.uid = os.getuid()
        self.plan = LaunchPlan('approved', 'd'*64, 'generation', 'worker-role', 'worker',
                               'a'*64, 'b'*64, 'launcher', 'authority', 'c'*64, 'e'*64, 1001)
        self.scope = SimpleNamespace(parent=ServiceParent('report-guard.service', '/reports.slice/report-guard.service',
                                                         5, 17, 23),
                                     digest='f'*64)
        self.authority = GuardedServiceAuthority(self.transport, self.scope, check_resources=lambda: None)
        self.registration = LaunchRegistration(
            self.plan, self.authority.authorize, self.authority.submit, self.authority.readback, bounded=True,
            service_scope_sha256=self.scope.digest, service_limits=ServiceLimits(2000, 1000, True),
            service_enforcement=GUARDED_SERVICE)
        self.deadline = monotonic_ns() + 2_000_000_000
        self.window = ServiceWindow(self.deadline, self.deadline + 1_000_000_000)
        self.launch = ScopedLaunch(self.registration, '1'*64, 'detached-clock', service_window=self.window)
        self.leaf = {'device': 5, 'inode': 28, 'mount_id': 23}
        self.order = []

    def reserve(self):
        self.order.append('reserved')
        return True

    def provider(self, operations, *, corrupt=None, drop=None):
        arm = None
        submitted = False
        for expected in operations:
            connection, _ = self.listener.accept()
            with connection:
                deadline = monotonic() + 0.8
                request = managed_service_client._frame_read(connection, deadline)
                operation = request['operation']
                self.assertEqual(operation, expected)
                self.order.append(operation)
                invocation = request['invocation']
                service = request['service']
                unit = f'workeros-{self.plan.invocation_key}.service'
                self.assertEqual(invocation, asdict(self.launch.invocation))
                self.assertEqual(service, {'parent': asdict(self.scope.parent), 'unit': unit,
                                           'leaf': f'{self.scope.parent.control_group}/{unit}',
                                           'scope_sha256': self.scope.digest,
                                           'enforcement': GUARDED_SERVICE})
                fields = {'invocation': invocation, 'source': self.plan.authority,
                          'source_sha256': self.plan.authority_sha256}
                if operation == 'arm_service':
                    anchor = {'invocation': invocation, 'service': service}
                    arm = {'binding_sha256': sha256(_canonical(anchor)).hexdigest(), 'guard_sha256': '2'*64,
                           'armed_ns': monotonic_ns(), 'leaf': self.leaf}
                    valid = {**fields, 'guard_sha256': arm['guard_sha256'], 'ticket_sha256': '3'*64,
                             'expires_ns': self.window.active_until_ns}
                    result = {'approval': valid, 'arm': arm}
                    if corrupt:
                        corrupt(result)
                elif operation == 'submit_service':
                    self.assertEqual(request['arm'], arm)
                    self.assertEqual(request['ticket_sha256'], '3'*64)
                    submitted = True
                    result = None
                else:
                    report = {**fields, 'status': 'pending' if arm is not None else 'not_started'}
                    if submitted:
                        start = arm['armed_ns'] + 1
                        report.update(status='terminal', effective_principal=self.plan.principal,
                                      effective_executable_sha256=self.plan.executable_sha256,
                                      effective_scope_sha256=self.plan.scope_sha256,
                                      effective_principal_uid=self.plan.principal_uid, receipt_sha256='4'*64,
                                      service={'unit': unit, 'invocation_id': 'a'*32, 'scope_sha256': self.scope.digest,
                                               'group_empty': True, 'handles_closed': True,
                                               'lifecycle': {'clock_id': invocation['clock_id'], 'start_ns': start,
                                                             'terminal_ns': start+1, 'terminal_disposition': 'exited',
                                                             'terminal_status': 0, 'empty_ns': start+2,
                                                             'meter_begin': {'observed_ns': start, 'cgroup': self.leaf,
                                                                             'usage_usec': 0, 'memory_current_bytes': 0,
                                                                             'memory_peak_bytes': 0, 'populated': False},
                                                             'meter_end': {'observed_ns': start+3, 'cgroup': self.leaf,
                                                                           'usage_usec': 8, 'memory_current_bytes': 0,
                                                                           'memory_peak_bytes': 4096, 'populated': False},
                                                             'retired_ns': start+4, 'handles_closed_ns': start+5,
                                                             'cgroup': self.leaf}})
                    result = {'observation': report, 'arm': arm}
                if operation != drop:
                    managed_service_client._frame_write(connection, {
                        'version': 1, 'operation': operation, 'nonce': request['nonce'], 'result': result,
                    }, deadline)

    def launch_under(self, operations, *, claim_ticket=None, **settings):
        with ThreadPoolExecutor(1) as server:
            future = server.submit(self.provider, operations, **settings)
            with roles_cli._store(create=True):
                result = self.launch.start(valid_until_ns=self.deadline, deadline_ns=self.deadline,
                                           reserve=self.reserve, claim_ticket=claim_ticket)
            future.result(timeout=2)
        return result

    def test_reserved_and_armed_before_submit_lost_reply_uses_readback_only(self):
        with patch('workeros.managed_service_guard._require_empty_leaf') as empty:
            result = self.launch_under(('read_service', 'arm_service', 'submit_service', 'read_service'),
                                       drop='submit_service')
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service', 'submit_service', 'read_service'])
        self.assertEqual(empty.call_count, 2)
        self.assertEqual(result['status'], 'terminal')
        life = result['service']['lifecycle']
        self.assertLess(life['terminal_ns'], life['meter_end']['observed_ns'])
        self.assertLess(life['meter_end']['observed_ns'], life['retired_ns'])
        self.assertEqual(life['meter_end']['cgroup'], self.leaf)

    def test_crossed_guard_refuses_submit_with_reserved_outcome_unknown(self):
        for index, (label, change) in enumerate((
            ('parent or cutoff binding', lambda reply: reply['arm'].update(binding_sha256='9'*64)),
            ('mount', lambda reply: reply['arm'].update(leaf={**self.leaf, 'mount_id': 99})),
            ('expiry', lambda reply: reply['approval'].update(expires_ns=self.window.cleanup_until_ns)),
        )):
            with self.subTest(label=label):
                self.plan = replace(self.plan, invocation_key=f'{index+1:064x}')
                self.authority = GuardedServiceAuthority(self.transport, self.scope, check_resources=lambda: None)
                self.registration = replace(self.registration, plan=self.plan, authorize=self.authority.authorize,
                                            dispatch_once=self.authority.submit, readback=self.authority.readback)
                self.launch = ScopedLaunch(self.registration, '1'*64, 'detached-clock', service_window=self.window)
                self.order.clear()
                with patch('workeros.managed_service_guard._require_empty_leaf') as empty:
                    result = self.launch_under(('read_service', 'arm_service'), corrupt=change)
                self.assertEqual(result['code'], 'service_arming_unconfirmed')
                self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service'])
                empty.assert_not_called()

    def test_lost_arm_never_submits(self):
        result = self.launch_under(('read_service', 'arm_service'), drop='arm_service')
        self.assertEqual((result['status'], result['effect']), ('unknown', 'unknown'))
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service'])

    def test_authenticated_arm_still_requires_an_exact_empty_leaf(self):
        with patch('workeros.managed_service_guard._require_empty_leaf',
                   side_effect=PlacementRefusal('armed_service_leaf_occupied')) as empty:
            result = self.launch_under(('read_service', 'arm_service'))
        empty.assert_called_once()
        self.assertEqual(result['code'], 'service_arming_unconfirmed')
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service'])

    def test_occupied_leaf_after_arm_cannot_submit_or_replay(self):
        occupied = PlacementRefusal('armed_service_leaf_occupied')
        with patch('workeros.managed_service_guard._require_empty_leaf', side_effect=(None, occupied)) as empty:
            result = self.launch_under(('read_service', 'arm_service', 'read_service'))
        self.assertEqual((result['status'], result['effect']), ('unknown', 'unknown'))
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service', 'read_service'])
        self.assertEqual(empty.call_count, 2)
        with self.assertRaisesRegex(ValueError, 'guarded service submission refused'):
            self.authority.submit(self.launch.invocation, self.authority._armed[0], deadline_ns=self.deadline)

    def test_durable_reservation_cannot_switch_enforcement_on_replay(self):
        fields = asdict(self.plan)
        del fields['invocation_key']
        guarded = replace(self.registration, plan=LaunchRolePolicy(**fields))
        _, raw = _launch_record(guarded, '1'*64, 'detached-clock', '7'*64, window=self.window)
        saved = _recorded_launch(guarded, raw, '7'*64)
        self.assertEqual(saved.invocation.service_window, self.window)
        with self.assertRaisesRegex(ValueError, 'different launch registration'):
            _recorded_launch(replace(guarded, service_enforcement=None), raw, '7'*64)

    def stock_registration(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        path = root / 'original'
        path.write_bytes(b'exact')
        original = self.enterContext(path.open('rb'))
        identity = os.fstat(original.fileno())
        self.scope = managed_service.ServiceScope(
            '/approved/root', 1, 2, '/worker', 1001, 'read', identity.st_dev, identity.st_ino,
            original.fileno(), limits=self.registration.service_limits, parent=self.scope.parent,
        )
        self.authority = GuardedServiceAuthority(self.transport, self.scope, check_resources=self.scope.check_original)
        with ExitStack() as resources, patch.object(managed_service, '_system_manager'), patch.object(
                managed_service.managed_system_bus, 'verify_parent'):
            self.registration = managed_service.prepare(
                self.scope, self.plan, self.authority, resources, deadline_ns=self.deadline,
            )
        self.assertTrue(self.registration.require_ticket_claim)
        self.launch = ScopedLaunch(self.registration, '1'*64, 'detached-clock', service_window=self.window)
        return LocalStore(root)

    def test_stock_guard_consumes_ticket_and_refuses_cross_invocation_reuse(self):
        store = self.stock_registration()
        key = _key('launch-tickets', self.plan.authority_sha256, '3'*64)

        def claim(approval):
            self.order.append('claimed')
            return _claim_launch_ticket(store, approval)

        with patch('workeros.managed_service_guard._require_empty_leaf'):
            result = self.launch_under(('read_service', 'arm_service', 'submit_service', 'read_service'),
                                       claim_ticket=claim)
        self.assertEqual(result['status'], 'terminal')
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service', 'claimed',
                                      'submit_service', 'read_service'])
        committed = _read(store, key)
        self.assertEqual(committed, _canonical({'version': 1, 'approval': asdict(self.authority._armed[0])}))

        self.plan = replace(self.plan, invocation_key='7'*64)
        self.stock_registration()
        self.order.clear()
        with patch('workeros.managed_service_guard._require_empty_leaf'):
            result = self.launch_under(('read_service', 'arm_service'), claim_ticket=claim)
        self.assertEqual(result['code'], 'launch_ticket_already_consumed')
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service', 'claimed'])
        self.assertEqual(_read(store, key), committed)

    def test_stock_guard_refuses_when_durable_ticket_consumption_is_uncertain(self):
        store = self.stock_registration()
        with patch('workeros.managed_service_guard._require_empty_leaf'), patch(
                'workeros.roles_cli._commit', return_value=Persistence.UNKNOWN):
            result = self.launch_under(('read_service', 'arm_service'),
                                       claim_ticket=partial(_claim_launch_ticket, store))
        self.assertEqual((result['effect'], result['code']), ('unknown', 'launch_ticket_consumption_unconfirmed'))
        self.assertEqual(self.order, ['read_service', 'reserved', 'arm_service'])
