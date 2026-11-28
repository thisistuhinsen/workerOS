"""Installed stock approval and configuration with no-effect backend callbacks."""
from contextlib import ExitStack
from dataclasses import asdict, replace
from hashlib import sha256
from multiprocessing import get_context
import os
from pathlib import Path
import pwd
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic, monotonic_ns, time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from workeros import managed_bootstrap, managed_cli, managed_executor, roles_cli
from workeros.aggregate_setup import ScopeEvidence
from workeros.appointment_registry import (
    definition_sha256, launch_plan_sha256, launch_policy_sha256, launch_scope_sha256, register,
)
from workeros.managed_launch import (
    LaunchAuthorization, LaunchPlan, LaunchReadback, LaunchRegistration, LaunchRolePolicy, new_launch_request,
)
from workeros.profile_setup import ProfileDefinition, ProviderBinding


class StockLaunchTest(TestCase):
    def setUp(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel required')
        self.wheel = Path(wheel)
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.var = self.root/'var'
        self.etc = self.root/'etc'
        self.admin = self.etc/'workeros'
        self.var.mkdir(mode=0o700)
        self.admin.mkdir(mode=0o700, parents=True)
        self.uid = os.geteuid()
        self.principal = pwd.getpwuid(self.uid).pw_name
        other = next(pwd.getpwnam(name) for name in ('nobody', 'daemon') if pwd.getpwnam(name).pw_uid != self.uid)
        self.other = other
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(self.var), _UID=self.uid))
        self.enterContext(patch.multiple(managed_cli, _CONFIG_PARENT=str(self.etc), _TRUSTED_UID=self.uid))
        self.enterContext(patch.object(managed_bootstrap, 'setup_clock_id', return_value='fixture-clock'))
        self.guard = self.enterContext(patch('workeros.supervisor.DirectChildSupervisor.start_executable',
                                             side_effect=AssertionError('fixture must not start a worker')))
        self.source = self.root/'report'
        self.source.write_bytes(b'inert')
        self.source.chmod(0o600)
        self.held = self.enterContext(self.source.open('rb'))
        self.pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.pidfd)
        self.authorize = Mock(side_effect=self.ticket)
        self.dispatch = Mock()
        self.readback = Mock(side_effect=self.observe)
        self.terminal = False
        self.expires_ns = monotonic_ns() + 40_000_000_000
        self.attest = self.enterContext(patch.object(managed_bootstrap._EvidenceProvider, 'attest', autospec=True,
                                                    side_effect=self.scope_evidence))

    def tearDown(self):
        self.guard.assert_not_called()
        self.assertFalse((self.root/'setup-journal').exists())

    def configure(self, *, wrong_resource=False, include_launch_pin=True, observer_is_worker=False,
                  reusable=False, role_name='operator'):
        selected = 'report-scope'
        name = 'run-report'
        original = os.fstat(self.held.fileno())
        operations = ['launch', 'observe']
        worker, other = ((self.other.pw_name, self.principal) if observer_is_worker else
                         (self.principal, self.other.pw_name))
        role = {'name': role_name, 'principal': worker, 'operations': operations, 'scopes': [selected],
                'resources': {selected: {'device': str(original.st_dev), 'inode': str(original.st_ino + wrong_resource)}},
                'independent_of': other, 'expires_at': int(time())+100}
        scope_pin = launch_scope_sha256(role, selected, operations)
        observer = {'device':original.st_dev, 'inode':original.st_ino, 'pid':os.getpid(), 'uid':self.uid,
                    'slot':self.held.fileno(), 'scope_sha256':'1'*64}
        canonical = roles_cli._canonical
        policy = {'version': 1, 'roles': {role['name']: {'operations': operations}}, 'workflows': {
            name: {'role':role['name'], 'operations':operations, 'require_supervision':True,
                   'bindings': {'executable':'tool', 'supervisor':'launch-backend', 'observers': {'slot':'watch'}}}}}
        providers = (
            ProviderBinding('tool', '2'*64, selected, 'executable', 'fixture-launcher', 'executable'),
            ProviderBinding('launch-backend', scope_pin, selected, 'scoped-launch', 'fixture-launcher', 'supervisor'),
            ProviderBinding('watch', sha256(canonical(observer)).hexdigest(), selected, 'point',
                            'fixture-observer', 'observers', worker),
        )
        definition = ProfileDefinition(name, 'workflow-r1', '0.8.0', sha256(self.wheel.read_bytes()).hexdigest(),
                 sha256(canonical(policy)).hexdigest(), 'fixture-manager', selected, 'fixture-clock', self.expires_ns, providers)
        self.plan = LaunchPlan(name, definition_sha256(definition), 'generation-1', role['name'], worker,
                               '2'*64, scope_pin, 'fixture-launcher', 'fixture-authority', '3'*64, '4'*64)
        if reusable:
            fields = asdict(self.plan)
            fields.pop('invocation_key')
            fields['principal_uid'] = pwd.getpwnam(worker).pw_uid
            self.plan = LaunchRolePolicy(**fields)
        document = {'version': 1, 'profile': 'reports', 'revision': 'r1', 'roles': [role]}
        approved = roles_cli.apply(canonical(document))
        local = {'declaration_sha256': approved['digest'], 'intent_sha256': '5'*64}
        roles_cli.commission('reports', 'r1', **local)
        entry = {'workflow': name, 'workflow_revision': definition.revision, 'definition_sha256': definition_sha256(definition),
                 'role': role['name'], 'principal': worker, 'scope': selected, 'generation': self.plan.generation,
                 'operations': operations}
        if include_launch_pin:
            pin = ({'policy_sha256': launch_policy_sha256(self.plan)}
                   if reusable else {'plan_sha256': launch_plan_sha256(self.plan)})
            entry['launch'] = {**pin, 'scope_sha256': scope_pin}
        record = {'version':1, 'profile':'reports', 'revision':'r1', **local, 'appointments':[entry]}
        if not include_launch_pin:
            with self.assertRaisesRegex(roles_cli.Refusal, '^appointment_outside_declaration$'):
                register(canonical(record))
        else:
            self.assertEqual(register(canonical(record))['status'], 'registered')
        self.config = {'version':2, 'profile':'reports', 'revision':'r1', 'operation_key':'6'*64,
                       'authorized_uids':[self.uid], 'wheel_path':str(self.wheel), 'local_approval':local,
                       'journal_directory':str(self.root/'setup-journal'), 'scopes':[{
                           'definition':asdict(definition), 'policy':policy, 'role':self.plan.role,
                           'binding_generation':self.plan.generation, 'observer':{
                               **observer, 'original_fd':self.held.fileno(), 'pidfd':self.pidfd},
                           'provider':{'socket':str(self.root/'inert-observer.sock'), 'peer_uid':self.other.pw_uid}}]}
        self.config_file = self.admin/'managed-setup.json'
        self.config_file.write_bytes(canonical(self.config))
        self.config_file.chmod(0o600)

    def registration(self, *, plan=None, bounded=True):
        return LaunchRegistration(plan or self.plan, self.authorize, self.dispatch, self.readback, bounded=bounded)

    def scope_evidence(self, provider, selection, role, generation):
        self.assertEqual(provider.uid, self.other.pw_uid)
        self.assertEqual(provider.source, 'fixture-observer')
        return ScopeEvidence(selection.definition, role, provider.source, '7'*64, selection.clock_id,
                             self.expires_ns-1_000_000, True, generation)

    def ticket(self, invocation, *, deadline_ns):
        self.assertLess(monotonic_ns(), deadline_ns)
        return LaunchAuthorization(invocation, self.plan.authority, self.plan.authority_sha256, '8'*64,
                                   self.expires_ns-2_000_000)

    def observe(self, invocation, *, deadline_ns):
        self.assertLess(monotonic_ns(), deadline_ns)
        if self.terminal:
            return LaunchReadback(invocation, self.plan.authority, self.plan.authority_sha256, 'terminal',
                                  self.plan.principal, self.plan.executable_sha256, self.plan.scope_sha256, '9'*64)
        return LaunchReadback(invocation, self.plan.authority, self.plan.authority_sha256, 'not_started')

    def open(self, registration=None):
        return managed_bootstrap.open_approved_launch(registration or self.registration(), executable_argv=('/usr/bin/true',))

    def test_exact_stock_approval_supplies_appointment_and_one_bounded_dispatch(self):
        self.configure()
        before = {path: path.read_bytes() for path in self.var.rglob('*') if path.is_file()}

        def finish(invocation, ticket, *, deadline_ns):
            self.assertEqual(invocation.plan, self.plan)
            self.assertEqual(ticket.invocation, invocation)
            self.assertLess(monotonic_ns(), deadline_ns)
            self.terminal = True

        self.dispatch.side_effect = finish
        with self.open() as adapter:
            self.assertFalse(hasattr(adapter.scopes[0].manager, 'verify_role_appointment'))
            self.assertFalse(self.authorize.called)
            self.assertEqual(adapter.launch_approved()['receipt_sha256'], '9'*64)
            deadlines = [self.authorize.call_args.kwargs['deadline_ns'], self.dispatch.call_args.kwargs['deadline_ns'],
                         *(call.kwargs['deadline_ns'] for call in self.readback.call_args_list)]
            self.assertEqual(len(set(deadlines)), 1)
            self.assertEqual(adapter.read_launch()['status'], 'terminal')
        self.dispatch.assert_called_once()
        self.attest.assert_called()
        self.assertEqual({path: path.read_bytes() for path in self.var.rglob('*') if path.is_file()}, before)

    def test_stock_boundary_refuses_missing_or_crossed_approval(self):
        self.configure()
        with self.assertRaisesRegex(ValueError, '^trusted_launch_backend_unavailable$'), self.open(self.registration(bounded=False)):
            self.fail('stock path requires bounded backend')
        with self.assertRaisesRegex(PermissionError, '^role_appointment_mismatch$'), self.open(
                self.registration(plan=replace(self.plan, invocation_key='a'*64))):
            self.fail('crossed invocation must refuse')
        with ExitStack() as resources, self.assertRaises(managed_bootstrap._UnsupportedScopes):
            managed_bootstrap._build(self.config, resources, check_only=True)
        self.authorize.assert_not_called()
        self.dispatch.assert_not_called()

    def test_different_held_original_refuses_before_contacting_backend(self):
        self.configure(wrong_resource=True)
        with self.assertRaisesRegex(PermissionError, '^role_appointment_mismatch$'), self.open():
            self.fail('crossed resource must refuse')
        self.attest.assert_not_called()
        self.dispatch.assert_not_called()

    def test_provider_uid_cannot_match_appointed_worker(self):
        self.configure(observer_is_worker=True)
        with self.assertRaisesRegex(PermissionError, '^role_appointment_mismatch$'), self.open():
            self.fail('worker UID cannot be its own observer')
        self.attest.assert_not_called()
        self.dispatch.assert_not_called()

    def test_missing_independent_evidence_or_spent_budget_refuses(self):
        self.configure()
        self.attest.side_effect = None
        self.attest.return_value = None
        with self.open() as adapter:
            self.assertEqual(adapter.launch_approved()['code'], 'launch_scope_unverified')
            token = managed_cli._CHECK_WORK_DEADLINE.set(monotonic()-1)
            try:
                self.assertEqual(adapter.launch_approved()['code'], 'launch_scope_unverified')
            finally:
                managed_cli._CHECK_WORK_DEADLINE.reset(token)
        self.readback.assert_not_called()
        self.dispatch.assert_not_called()

    def test_missing_launch_appointment_cannot_open_backend(self):
        self.configure(include_launch_pin=False)
        with self.assertRaisesRegex(PermissionError, '^role_appointment_unverified$'), self.open():
            self.fail('missing approved launch record must refuse')
        self.dispatch.assert_not_called()

    def test_reusable_approval_reserves_distinct_requests_and_reads_back_in_separate_process(self):
        self.configure(reusable=True)
        first, second = new_launch_request(), new_launch_request()
        self.assertNotEqual(first, second)
        observed = {}

        def dispatch(invocation, _ticket, *, deadline_ns):
            self.assertLess(monotonic_ns(), deadline_ns)
            # The new durable record must already exist before any dispatch.
            store = roles_cli.LocalStore(self.var/'workeros'/'profiles')
            self.assertEqual(roles_cli._read(store, self.claim_key), self.claim_payload)
            self.assertEqual(invocation.plan.invocation_key, self.expected_key)
            observed[self.expected_key] = LaunchReadback(
                invocation, self.plan.authority, self.plan.authority_sha256, 'terminal',
                self.plan.principal, self.plan.executable_sha256, self.plan.scope_sha256, '9'*64,
                effective_principal_uid=self.plan.principal_uid)

        def observe(invocation, *, deadline_ns):
            return observed.get(invocation.plan.invocation_key) or self.observe(invocation, deadline_ns=deadline_ns)

        self.dispatch.side_effect = dispatch
        self.readback.side_effect = observe
        results = []
        for request_id in (first, second):
            with self.open() as adapter:
                registration, self.claim_key, self.claim_payload = adapter._reusable_attempt(request_id)
                self.expected_key = registration.plan.invocation_key
                self.assertEqual(adapter.read_launch(request_id=request_id)['code'], 'launch_not_reserved')
                result = adapter.launch_approved(request_id=request_id)
                self.assertEqual((result['status'], result['effect'], result['request_id'], result['invocation_key']),
                                 ('terminal', 'dispatched', request_id, self.expected_key))
                results.append(result)
        self.assertNotEqual(results[0]['invocation_key'], results[1]['invocation_key'])
        context = get_context('fork')
        receiver, sender = context.Pipe(duplex=False)

        def reconcile():
            receiver.close()
            self.dispatch.reset_mock()
            self.authorize.reset_mock()
            with self.open() as reopened:
                historical = reopened.read_launch(request_id=first)
                repeat = reopened.launch_approved(request_id=second)
            sender.send((historical, repeat, self.dispatch.call_count, self.authorize.call_count))
            sender.close()

        verifier = context.Process(target=reconcile)
        try:
            verifier.start()
            sender.close()
            self.assertTrue(receiver.poll(10), 'separate readback did not finish')
            self.assertEqual(receiver.recv(), (*results, 0, 0))
            verifier.join(timeout=2)
            self.assertEqual(verifier.exitcode, 0)
        finally:
            receiver.close()
            sender.close()
            if verifier.is_alive():
                verifier.kill()
                verifier.join(timeout=2)
            verifier.close()
        self.assertEqual(self.dispatch.call_count, 2)
        self.assertEqual(self.authorize.call_count, 2)

    def test_reusable_unknown_dispatch_and_mismatched_readback_never_replay(self):
        self.configure(reusable=True)
        request = new_launch_request()
        self.dispatch.side_effect = OSError('inert lost reply')
        with self.open() as adapter:
            uncertain = adapter.launch_approved(request_id=request)
            self.assertEqual((uncertain['status'], uncertain['effect']), ('unknown', 'unknown'))

        def wrong_uid(invocation, *, deadline_ns):
            plan = invocation.plan
            return LaunchReadback(invocation, plan.authority, plan.authority_sha256, 'terminal',
                                  plan.principal, plan.executable_sha256, plan.scope_sha256, '9'*64,
                                  effective_principal_uid=self.other.pw_uid)

        self.readback.side_effect = wrong_uid
        with self.open() as restarted:
            self.assertEqual(restarted.read_launch(request_id=request), uncertain)
            self.assertEqual(restarted.launch_approved(request_id=request), uncertain)
        self.dispatch.assert_called_once()
        self.authorize.assert_called_once()

    def test_in_process_worker_uses_durable_authority_ticket_before_the_stock_submit(self):
        self.configure(reusable=True, role_name='archive-reader')
        registered = {'profile': self.config['profile'], 'revision': self.config['revision'],
                      'wheel_path': self.config['wheel_path'],
                      'wheel_sha256': sha256(self.wheel.read_bytes()).hexdigest(),
                      'executable': '/approved/executable', 'principal_gid': pwd.getpwuid(self.uid).pw_gid}
        authority = SimpleNamespace(authorize=self.authorize, readback=self.readback)
        calls = []
        results = {}

        def observe(invocation, *, deadline_ns):
            return results.get(invocation.plan.invocation_key) or self.observe(invocation, deadline_ns=deadline_ns)

        self.readback.side_effect = observe

        def run(command, **_kwargs):
            if command[-1] == '--version':
                return subprocess.CompletedProcess(command, 0, stdout=b'bubblewrap 0.12.0\n')
            self.assertEqual(command[-1], '/worker')
            approval = self.authorize.call_args.args[0]
            key = roles_cli._key('launch-tickets', self.plan.authority_sha256, '8'*64)
            store = roles_cli.LocalStore(self.var/'workeros'/'profiles')
            self.assertIsNotNone(roles_cli._read(store, key))
            invocation = approval.plan.invocation_key
            calls.append(invocation)
            results[invocation] = LaunchReadback(
                approval, self.plan.authority, self.plan.authority_sha256, 'terminal',
                self.plan.principal, self.plan.executable_sha256, self.plan.scope_sha256, '9'*64,
                effective_principal_uid=self.plan.principal_uid)

        first, second = new_launch_request(), new_launch_request()
        self.config_file.unlink()
        with patch.object(managed_executor, '_registration', return_value=(registered, self.plan, authority)), patch(
                'workeros.managed_executor._open_protected', side_effect=lambda _path: os.dup(self.held.fileno())), patch(
                'workeros.managed_executor._snapshot', return_value=self.held.fileno()), patch(
                'workeros.managed_executor.subprocess.run', side_effect=run):
            with managed_executor.open_managed_worker(registered, host_config=self.config) as adapter:
                launched = adapter.launch_approved(request_id=first)
                self.assertEqual(launched['status'], 'terminal')
            with managed_executor.open_managed_worker(registered, host_config=self.config) as reopened:
                blocked = reopened.launch_approved(request_id=second)
                self.assertEqual((blocked['effect'], blocked['code']), ('not_attempted', 'launch_ticket_already_consumed'))
                self.assertEqual(reopened.read_launch(request_id=first), launched)
                self.assertEqual(reopened.launch_approved(request_id=first), launched)
        self.assertEqual(calls, [launched['invocation_key']])
        self.assertEqual(self.authorize.call_count, 2)

    def test_reusable_reservation_failure_and_revocation_refuse_before_dispatch(self):
        self.configure(reusable=True)
        request = new_launch_request()
        commit = roles_cli._commit

        def reserve_then_lose_readback(*args, **kwargs):
            commit(*args, **kwargs)
            raise OSError('inert lost storage result')

        with self.open() as adapter:
            self.assertEqual(adapter.launch_approved()['code'], 'invalid_launch_request_id')
            with patch.object(roles_cli, '_commit', side_effect=reserve_then_lose_readback):
                self.assertEqual(adapter.launch_approved(request_id=request)['code'],
                                 'launch_reservation_unconfirmed')
            self.assertEqual(adapter.launch_approved(request_id=request)['status'], 'unknown')
            roles_cli.revoke('reports', 'r1')
            self.assertEqual(adapter.launch_approved(request_id=new_launch_request())['code'], 'profile_revoked')
            self.assertEqual(adapter.read_launch(request_id=request)['status'], 'unknown')
        self.dispatch.assert_not_called()
        self.authorize.assert_not_called()

    def test_fresh_historical_reader_reconciles_after_revocation_without_live_handles(self):
        self.configure(reusable=True)
        request_id = new_launch_request()
        the_outcome = None

        def observe(invocation, *, deadline_ns):
            return the_outcome or self.observe(invocation, deadline_ns=deadline_ns)

        def lost_reply(invocation, _ticket, *, deadline_ns):
            nonlocal the_outcome
            the_outcome = LaunchReadback(
                invocation, self.plan.authority, self.plan.authority_sha256, 'terminal',
                self.plan.principal, self.plan.executable_sha256, self.plan.scope_sha256,
                '9'*64, effective_principal_uid=self.plan.principal_uid)
            raise OSError('inert reply loss')

        self.dispatch.side_effect = lost_reply
        with self.open() as adapter:
            uncertain = adapter.launch_approved(request_id=request_id)
            self.assertEqual(uncertain['status'], 'unknown')
        roles_cli.revoke('reports', 'r1')
        with self.assertRaisesRegex(PermissionError, '^profile_revoked$'), self.open():
            self.fail('revoked role must not open for dispatch')
        self.config_file.unlink()
        self.readback.side_effect = observe
        authorised = Mock(authorize=self.authorize, readback=self.readback)
        protected = {'profile': 'reports', 'revision': 'r1', 'wheel_path': str(self.wheel),
                     'wheel_sha256': sha256(self.wheel.read_bytes()).hexdigest()}
        with patch.object(managed_executor, '_registration', return_value=(protected, self.plan, authorised)), \
             patch.object(managed_executor, '_open_sandbox', side_effect=AssertionError('readback must not use sandbox')):
            historical = managed_executor.registered_launch(request_id, readback=True)
            self.assertEqual((historical['status'], historical['invocation_key']),
                             ('terminal', uncertain['invocation_key']))
        self.dispatch.assert_called_once()
        self.authorize.assert_called_once()

    def test_reusable_approval_refuses_changed_generation_or_principal_uid(self):
        self.configure(reusable=True)
        cases = (
            (replace(self.plan, generation='stale'), ValueError, 'launch_scope_unverified'),
            (replace(self.plan, principal_uid=self.other.pw_uid), PermissionError, 'role_appointment_mismatch'),
        )
        for plan, error, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(error, f'^{code}$'):
                with self.open(self.registration(plan=plan)):
                    self.fail('changed reusable policy must refuse')
        self.attest.assert_not_called()
        self.authorize.assert_not_called()
        self.dispatch.assert_not_called()
