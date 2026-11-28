"""Readback contract tests without dispatching a service or loading a venue credential."""

from dataclasses import replace
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import Mock

from workeros.managed_launch import (
    LaunchAuthorization, LaunchPlan, LaunchReadback, LaunchRegistration, ManagedServiceEvidence,
    ScopedLaunch, ServiceLimits, ServiceWindow,
)


class ManagedServiceReadbackTest(TestCase):
    def setUp(self):
        self.plan = LaunchPlan('managed-work', '1'*64, 'generation', 'report-updater', 'worker',
                               '2'*64, '3'*64, 'launcher', 'observer', '4'*64, '5'*64, 1001)
        self.scope = '6'*64
        self.authorize, self.dispatch, self.observe = Mock(), Mock(), Mock()
        self.registration = LaunchRegistration(self.plan, self.authorize, self.dispatch, self.observe,
                                               bounded=True, service_scope_sha256=self.scope)
        self.launch = ScopedLaunch(self.registration, '7'*64, 'clock', already_reserved=True)
        self.service = {'unit': f'workeros-{self.plan.invocation_key}.service',
                        'invocation_id': 'a'*32, 'scope_sha256': self.scope}

    def report(self, status, service):
        return LaunchReadback(self.launch.invocation, self.plan.authority, self.plan.authority_sha256, status,
                              self.plan.principal, self.plan.executable_sha256, self.plan.scope_sha256,
                              '8'*64, self.plan.principal_uid, service=service)

    def read(self):
        return self.launch.read(deadline_ns=monotonic_ns() + 2_000_000_000)

    def tearDown(self):
        self.authorize.assert_not_called()
        self.dispatch.assert_not_called()

    def test_service_wire_object_is_typed_and_cleanup_is_observed_separately(self):
        self.observe.return_value = self.report('started', self.service)
        self.assertIs(type(self.observe.return_value.service), ManagedServiceEvidence)
        started = self.read()
        self.assertEqual((started['status'], started['cleanup']), ('started', 'not_observed'))
        for group_empty, handles_closed in ((None, None), (True, None), (None, True),
                                           (False, True), (True, False), (True, True)):
            with self.subTest(group_empty=group_empty, handles_closed=handles_closed):
                self.observe.return_value = self.report('terminal', {
                    **self.service, 'group_empty': group_empty, 'handles_closed': handles_closed,
                })
                result = self.read()
                self.assertEqual((result['status'], result['effect']), ('terminal', 'dispatched'))
                self.assertEqual(result['cleanup'], 'verified' if group_empty and handles_closed else 'unconfirmed')
                self.assertEqual(result['service']['invocation_id'], self.service['invocation_id'])
                self.assertIs(result['service']['group_empty'], group_empty)
                self.assertIs(result['service']['handles_closed'], handles_closed)

    def test_missing_or_crossed_service_evidence_cannot_verify_effect(self):
        wrong = ({**self.service, 'unit': 'workeros-' + 'b'*64 + '.service'},
                 {**self.service, 'scope_sha256': 'b'*64}, None)
        for evidence in wrong:
            with self.subTest(evidence=evidence):
                self.observe.return_value = self.report('terminal', evidence)
                result = self.read()
                self.assertEqual((result['status'], result['effect']), ('unknown', 'unknown'))
                self.assertNotIn('cleanup', result)
        self.observe.return_value = replace(self.report('terminal', self.service), effective_principal_uid=1002)
        self.assertEqual(self.read()['status'], 'unknown')

    def test_malformed_or_premature_evidence_refuses(self):
        for invalid in ({'invocation_id': '0'*32}, {'invocation_id': 'A'*32},
                        {'invocation_id': 'a'*31}, {'scope_sha256': 'a'*63},
                        {'group_empty': 1}, {'handles_closed': 'yes'}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.report('terminal', self.service | invalid)
        with self.assertRaises(TypeError):
            self.report('terminal', self.service | {'unrecognized': True})
        with self.assertRaisesRegex(ValueError, 'requires? terminal'):
            self.report('started', self.service | {'group_empty': True})
        with self.assertRaisesRegex(ValueError, 'unexpected effective'):
            LaunchReadback(self.launch.invocation, self.plan.authority, self.plan.authority_sha256,
                           'not_started', service=self.service)

    def test_registration_keeps_strict_pin_opt_in(self):
        with self.assertRaises(ValueError):
            replace(self.registration, service_scope_sha256='bad')
        with self.assertRaisesRegex(ValueError, 'pinned Linux UID'):
            replace(self.registration, plan=replace(self.plan, principal_uid=None))
        legacy = ScopedLaunch(replace(self.registration, service_scope_sha256=None), '7'*64, 'clock')
        self.observe.return_value = self.report('terminal', None)
        self.assertEqual(legacy.read(deadline_ns=monotonic_ns() + 2_000_000_000), {
            'status': 'terminal', 'effect': 'dispatched', 'code': 'launch_readback_verified',
            'invocation_key': self.plan.invocation_key, 'receipt_sha256': '8'*64,
        })

    def select_window(self, *, limits=None, window=None):
        self.registration = replace(self.registration, service_limits=limits or {
            'active_ms': 25, 'cleanup_ms': 8, 'metered': True,
        })
        self.launch = ScopedLaunch(self.registration, '7'*64, 'clock', already_reserved=True,
                                   service_window=window or {
                                       'active_until_ns': 35_000_000, 'cleanup_until_ns': 42_000_000,
                                   })

    def lifecycle(self):
        group = {'device': 7, 'inode': 42, 'mount_id': 12}
        baseline = {'cgroup': group, 'observed_ns': 9_000_000, 'usage_usec': 1,
                    'memory_current_bytes': 4, 'memory_peak_bytes': 8, 'populated': False}
        final = {'cgroup': group, 'observed_ns': 33_000_000, 'usage_usec': 726,
                 'memory_current_bytes': 8, 'memory_peak_bytes': 19, 'populated': False}
        return {'clock_id': 'clock', 'start_ns': 10_000_000, 'cgroup': group,
                'terminal_ns': 30_000_000, 'terminal_disposition': 'exited', 'terminal_status': 0,
                'empty_ns': 31_000_000, 'retired_ns': 35_000_000, 'handles_closed_ns': 36_000_000,
                'meter_begin': baseline, 'meter_end': final}

    def observe_lifecycle(self, lifecycle):
        self.observe.side_effect = lambda _invocation, **_opts: self.report('terminal', {
            **self.service, 'group_empty': True, 'handles_closed': True, 'lifecycle': lifecycle,
        })
        return self.read()

    def test_selected_lifecycle_verifies_retained_meter_and_terminal_separately(self):
        self.select_window()
        self.assertIs(type(self.registration.service_limits), ServiceLimits)
        self.assertIs(type(self.launch.invocation.service_window), ServiceWindow)
        result = self.observe_lifecycle(self.lifecycle())
        self.assertEqual((result['status'], result['cleanup']), ('terminal', 'verified'))
        lifecycle = result['service']['lifecycle']
        self.assertEqual(lifecycle['meter_end']['usage_usec'], 726)
        self.assertEqual(lifecycle['meter_end']['cgroup'], lifecycle['cgroup'])
        self.assertEqual(lifecycle['terminal_disposition'], 'exited')

    def test_genuine_late_terminal_does_not_qualify_cleanup(self):
        for limits, window in (
                (ServiceLimits(19, 8, True), ServiceWindow(35_000_000, 42_000_000)),
                (ServiceLimits(25, 8, True), ServiceWindow(30_000_000, 37_000_000)),
                (ServiceLimits(25, 8, True), ServiceWindow(32_000_000, 36_000_000)),
                (ServiceLimits(25, 5, True), ServiceWindow(35_000_000, 40_000_000))):
            with self.subTest(limits=limits, window=window):
                self.select_window(limits=limits, window=window)
                result = self.observe_lifecycle(self.lifecycle())
                self.assertEqual((result['status'], result['cleanup']), ('terminal', 'unconfirmed'))

    def test_missing_selected_meter_and_close_cannot_verify_cleanup(self):
        self.select_window()
        for field in ('meter_begin', 'meter_end', 'handles_closed_ns', 'empty_ns', 'retired_ns'):
            with self.subTest(field=field):
                result = self.observe_lifecycle(self.lifecycle() | {field: None})
                self.assertEqual((result['status'], result['cleanup']), ('terminal', 'unconfirmed'))
        self.select_window(limits=ServiceLimits(25, 8, False))
        result = self.observe_lifecycle(self.lifecycle() | {'meter_begin': None, 'meter_end': None})
        self.assertEqual((result['status'], result['cleanup']), ('terminal', 'verified'))

    def test_crossed_clock_group_and_impossible_timing_stay_unknown(self):
        self.select_window()
        lifecycle = self.lifecycle()
        meter_end = lifecycle['meter_end']
        invalid = (
            {'clock_id': 'other-clock'}, {'retired_ns': 29_000_000},
            {'empty_ns': 34_000_000}, {'terminal_disposition': None},
            {'meter_end': {**meter_end, 'cgroup': {**meter_end['cgroup'], 'mount_id': 13}}},
            {'meter_end': {**meter_end, 'usage_usec': 0}},
            {'meter_end': {**meter_end, 'memory_peak_bytes': 7}},
            {'meter_end': {**meter_end, 'populated': True}},
        )
        for change in invalid:
            with self.subTest(change=change):
                result = self.observe_lifecycle(lifecycle | change)
                self.assertEqual((result['status'], result['effect']), ('unknown', 'unknown'))
        self.assertEqual(self.observe_lifecycle(None)['status'], 'unknown')

    def test_strict_dispatch_requires_an_authority_window_and_guard(self):
        now = monotonic_ns()
        until = now + 3_000_000_000
        window = ServiceWindow(now + 2_000_000_000, now + 2_002_000_000)

        def not_started(invocation, **_opts):
            return LaunchReadback(invocation, self.plan.authority, self.plan.authority_sha256, 'not_started')

        def unguarded(invocation, **_opts):
            return LaunchAuthorization(invocation, self.plan.authority, self.plan.authority_sha256, '9'*64, until-1)

        authority, dispatcher = Mock(side_effect=unguarded), Mock()
        registration = replace(self.registration, authorize=authority, dispatch_once=dispatcher,
                               readback=not_started, service_limits=ServiceLimits(2000, 2, False))
        unbounded = ScopedLaunch(registration, '7'*64, 'clock')
        self.assertEqual(unbounded.start(valid_until_ns=until, deadline_ns=until)['code'],
                         'service_window_unverified')
        authority.assert_not_called()
        scoped = ScopedLaunch(registration, '7'*64, 'clock', service_window=window)
        self.assertEqual(scoped.start(valid_until_ns=until, deadline_ns=until)['code'],
                         'service_reservation_required')
        authority.assert_not_called()
        self.assertEqual(scoped.start(valid_until_ns=until, deadline_ns=until, reserve=lambda: True)['code'],
                         'launch_authority_unverified')
        authority.assert_called_once()
        dispatcher.assert_not_called()
