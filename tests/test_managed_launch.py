"""Installed contract checks with no real launcher, grants or authority."""
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import Mock, patch

from workeros.aggregate_setup import ScopeSetup
from workeros.appointment_registry import definition_sha256
from workeros.enrollment import HostBindings
from workeros.managed_host import ManagedHostAdapter, RoleAppointment
from workeros.managed_launch import LaunchAuthorization, LaunchPlan, LaunchReadback, LaunchRegistration
from workeros.profile_setup import ProfileDefinition, ProfileRequirements, ProviderBinding
from test_aggregate_setup import Manager


class ManagedLaunchTest(TestCase):
    def setUp(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        self.wheel = Path(wheel)
        self.digest = sha256(self.wheel.read_bytes()).hexdigest()
        self.until = monotonic_ns() + 40_000_000_000
        self.name, self.scope, self.role = 'read-report', 'report-scope', 'operator'
        self.launcher, self.authority, self.principal = 'fixture-launcher', 'fixture-authority', 'fixture-worker'
        self.generation = 'generation-1'
        policy = json.dumps({'version': 1, 'roles': {self.role: {'operations': ['launch']}},
            'workflows': {self.name: {'role': self.role, 'operations': ['launch'],
                'require_supervision': True, 'bindings': {'executable': 'tool', 'supervisor': 'scoped'}}}}).encode()
        providers = (ProviderBinding('tool', '1'*64, self.scope, 'executable', self.launcher, 'executable'),
                     ProviderBinding('scoped', '2'*64, self.scope, 'scoped-launch', self.launcher, 'supervisor'))
        self.definition = ProfileDefinition(self.name, 'revision-1', '0.8.0', self.digest, sha256(policy).hexdigest(),
                                            'fixture-manager', self.scope, 'fixture-clock', self.until, providers)
        self.plan = LaunchPlan(self.name, definition_sha256(self.definition), self.generation, self.role,
                               self.principal, '1'*64, '2'*64, self.launcher, self.authority, '3'*64, '4'*64)
        self.manager = Manager(self.definition, policy)
        self.manager.evidence = replace(self.manager.evidence, clock_id=self.definition.clock_id,
                                        expires_ns=self.until - 1_000_000, source=self.authority)
        self.manager.verify_role_appointment = Mock(return_value=RoleAppointment(self.definition, self.role,
                                                            self.principal, self.generation))
        registry = HostBindings(executables={'tool': ('/usr/bin/true',)}, supervisors=frozenset({'scoped'}),
                                authorize=lambda _: False)
        self.setup_scope = ScopeSetup(self.name, self.definition.revision, ProfileRequirements(self.role, self.scope),
                                      self.manager, registry)
        self.store = Mock()
        self.guard = self.enterContext(patch('workeros.supervisor.DirectChildSupervisor.start_executable',
                                             side_effect=AssertionError('no real child may start')))
        self.authorize = Mock(side_effect=self.authorized)
        self.dispatch = Mock()
        self.readback = Mock(side_effect=lambda invocation: self.report(invocation, 'not_started'))

    def tearDown(self):
        self.guard.assert_not_called()
        self.assertEqual(self.manager.creates, 0)
        self.store.assert_not_called()
        self.assertEqual(self.store.mock_calls, [])

    def authorized(self, invocation):
        return LaunchAuthorization(invocation, self.authority, self.plan.authority_sha256, '5'*64,
                                   self.until - 2_000_000)

    def report(self, invocation, status):
        evidence = ((self.principal, self.plan.executable_sha256, self.plan.scope_sha256, '6'*64)
                    if status in ('started', 'terminal') else ())
        return LaunchReadback(invocation, self.authority, self.plan.authority_sha256, status, *evidence)

    def registration(self, plan=None):
        return LaunchRegistration(plan or self.plan, self.authorize, self.dispatch, self.readback)

    def adapter(self, registration=None):
        return ManagedHostAdapter(profile='reports', revision='r1', operation_key='7'*64,
                   scopes=(self.setup_scope,), definitions=(self.definition,), generations=(self.generation,),
                   wheel=self.wheel, wheel_sha256=self.digest, clock_id=self.definition.clock_id,
                   store=self.store, launch_registration=registration)

    def assert_refused(self, result, reason):
        self.assertEqual((result['status'], result['effect'], result['code']), ('refused', 'not_attempted', reason))

    def test_default_denial_and_installed_no_start_check(self):
        self.assert_refused(self.adapter().launch_approved(), 'launch_backend_unavailable')
        adapter = self.adapter(self.registration())
        self.assertEqual(adapter.check_bindings()['status'], 'bindings_verified')
        self.authorize.assert_not_called()
        self.dispatch.assert_not_called()
        self.readback.assert_not_called()

    def test_scope_executable_generation_role_principal_and_expiry_fail_before_backend(self):
        for change in ({'scope_sha256':'8'*64}, {'executable_sha256':'8'*64}, {'generation':'other'},
                       {'role':'other-role'}, {'principal':'other-worker'}, {'definition_sha256':'8'*64}):
            with self.subTest(change=change):
                self.assert_refused(self.adapter(self.registration(replace(self.plan, **change))).launch_approved(),
                                    'launch_scope_unverified')
        self.manager.evidence = replace(self.manager.evidence, expires_ns=1)
        self.assert_refused(self.adapter(self.registration()).launch_approved(), 'launch_scope_unverified')
        self.readback.assert_not_called()
        self.authorize.assert_not_called()
        self.dispatch.assert_not_called()

    def test_only_exact_current_independent_ticket_can_dispatch(self):
        for changes in ({'source':self.launcher}, {'source_sha256':'8'*64},
                        {'expires_ns':1}, {'expires_ns':self.until}):
            with self.subTest(changes=changes):
                self.authorize.side_effect = lambda invocation: replace(self.authorized(invocation), **changes)
                self.assert_refused(self.adapter(self.registration()).launch_approved(), 'launch_authority_unverified')
        self.authorize.side_effect = lambda _: None
        self.assert_refused(self.adapter(self.registration()).launch_approved(), 'launch_authority_unverified')
        self.dispatch.assert_not_called()

    def test_dispatch_reply_is_ignored_and_verified_readback_survives_adapter_recreation(self):
        state = 'not_started'

        def dispatch(invocation, ticket):
            nonlocal state
            self.assertEqual(invocation.plan, self.plan)
            self.assertEqual(ticket, self.authorized(invocation))
            state = 'terminal'
            raise OSError('synthetic lost dispatch response')

        self.dispatch.side_effect = dispatch
        self.readback.side_effect = lambda invocation: self.report(invocation, state)
        adapter = self.adapter(self.registration())
        result = adapter.launch_approved()
        self.assertEqual((result['status'], result['effect'], result['receipt_sha256']),
                         ('terminal', 'dispatched', '6'*64))
        self.assertEqual(self.adapter(self.registration()).read_launch(), result)
        self.assertEqual(self.adapter(self.registration()).launch_approved(), result)
        self.dispatch.assert_called_once()

    def test_lost_or_crossed_readback_stays_unknown_and_never_replays(self):
        for crossed in ({'source_sha256':'8'*64}, {'effective_scope_sha256':'8'*64},
                        {'effective_executable_sha256':'8'*64}, {'effective_principal':'other-worker'}, None):
            with self.subTest(crossed=crossed):
                self.dispatch.reset_mock()

                def observe(invocation):
                    if not self.dispatch.called:
                        return self.report(invocation, 'not_started')
                    if crossed is None:
                        raise OSError('synthetic observation loss')
                    return replace(self.report(invocation, 'terminal'), **crossed)

                self.readback.side_effect = observe
                self.dispatch.side_effect = None
                self.dispatch.return_value = 'claimed success'
                adapter = self.adapter(self.registration())
                self.assertEqual(adapter.launch_approved()['status'], 'unknown')
                self.assertEqual(adapter.read_launch()['status'], 'unknown')
                self.assertEqual(adapter.launch_approved()['status'], 'unknown')
                self.dispatch.assert_called_once()

    def test_unknown_preexisting_invocation_never_dispatches(self):
        self.readback.side_effect = lambda invocation: self.report(invocation, 'pending')
        result = self.adapter(self.registration()).launch_approved()
        self.assertEqual((result['status'], result['effect']), ('unknown', 'unknown'))
        self.authorize.assert_not_called()
        self.dispatch.assert_not_called()
