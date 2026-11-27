"""Synthetic trusted managers; these are not independently qualified providers."""
from dataclasses import replace
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from workeros.aggregate_setup import AggregateSetup, ScopeEvidence, ScopeSetup
from workeros.enrollment import HostBindings
from workeros.profile_setup import AttemptHistory, ProfileDefinition, ProfileRequirements, ProviderBinding, ProviderRequirement
from workeros.verify_install import VerificationError
from test_profile_setup import SyntheticManager, CLOCK, EXPIRY, PACKAGE_HASH


class Observer:
    def sample(self):
        return None


class Manager(SyntheticManager):
    def __init__(self, definition, policy):
        super().__init__(definition, policy)
        self.evidence = ScopeEvidence(definition, 'operator', 'independent-checker', 'b'*64, CLOCK, EXPIRY, True, 'generation-1')
        self.history_state = 'pending'
        self.expected_observer = None
        self.generation = 'generation-1'

    def verify_bindings(self, selected, compiled, host):
        if self.expected_observer is not None:
            if compiled[selected.definition.name].observers.get('slot') is not self.expected_observer:
                raise ValueError('unrecognized actual resource')
        return self.generation

    def attest(self, selected, requirements, generation):
        return self.evidence

    def read_attempt(self, expected):
        return AttemptHistory(self.history_state, expected)


def make_scope(name='profile', run_scope='run-scope', wheel_hash=PACKAGE_HASH):
    policy = json.dumps({'version': 1, 'roles': {'operator': {'operations': ['observe']}},
       'workflows': {name: {'role':'operator', 'operations':['observe'],
                            'bindings': {'observers': {'slot':'trusted-observer'}}}}}, separators=(',', ':')).encode()
    provider = ProviderBinding('trusted-observer', 'appointment-1', 'scope-1', 'point',
                               'observer-user', 'observers', 'writer-user')
    definition = ProfileDefinition(name, 'revision-1', '0.8.0', wheel_hash, sha256(policy).hexdigest(),
                                   'manager', run_scope, CLOCK, EXPIRY, (provider,))
    req = ProfileRequirements('operator', run_scope, (ProviderRequirement('observers', 'trusted-observer', 'point', 'scope-1', 'writer-user'),))
    manager = Manager(definition, policy)
    bindings = HostBindings(authorize=lambda *_: True, observers={'trusted-observer': (Observer(), None, 'provider')})
    manager.expected_observer = bindings.observers['trusted-observer']
    return ScopeSetup(name, 'revision-1', req, manager, bindings)


class AggregateTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch('workeros.profile_setup.version', return_value='0.8.0'))
        self.verify = self.enterContext(patch('workeros.aggregate_setup.verify_install'))

    def aggregate(self, scopes):
        return AggregateSetup(tuple(scopes), wheel='trusted.whl', wheel_sha256=PACKAGE_HASH, clock_id=CLOCK)

    def test_three_scopes_are_read_back_without_launch(self):
        scopes = [make_scope('first','run-one'), make_scope('second','run-two'), make_scope('third','run-three')]
        aggregate = self.aggregate(scopes)
        result = aggregate.setup()
        self.assertEqual(result.status, 'ready')
        self.assertEqual([r.status for _,r in result.scopes], ['accepted']*3)
        self.assertEqual([s.manager.creates for s in scopes], [1,1,1])
        self.assertEqual([r.status for _,r in result.final_checks], ['accepted']*3)
        self.assertEqual([s.manager.starts for s in scopes], [0,0,0])
        self.assertEqual(aggregate.setup().status, 'ready')
        self.assertEqual([s.manager.creates for s in scopes], [1,1,1])

    def test_package_mismatch_refuses_before_manager_access(self):
        s = make_scope()
        self.verify.side_effect = VerificationError('mismatch')
        result = self.aggregate([s]).setup()
        self.assertEqual((result.status, result.scopes, s.manager.creates, s.manager.reads), ('refused', (), 0, 0))

    def test_missing_or_wrong_attestation_and_bindings_refuse_before_write(self):
        for issue in ('missing','false','wrong_scope','same_manager','same_writer','expired','bad_clock','null_observer','denied'):
            with self.subTest(issue=issue):
                s = make_scope()
                m = s.manager
                if issue == 'missing': m.evidence = None
                elif issue == 'false': m.evidence = replace(m.evidence, verified=False)
                elif issue == 'wrong_scope': m.evidence = replace(m.evidence, definition=replace(m.selection.definition, scope='other'))
                elif issue == 'same_manager': m.evidence = replace(m.evidence, source='manager')
                elif issue == 'same_writer': m.evidence = replace(m.evidence, source='writer-user')
                elif issue == 'expired': m.evidence = replace(m.evidence, expires_ns=1)
                elif issue == 'bad_clock': m.evidence = replace(m.evidence, clock_id='other')
                elif issue == 'null_observer': s = replace(s, bindings=replace(s.bindings, observers={'trusted-observer':None}))
                else: m.denied = True
                result = self.aggregate([s]).setup()
                self.assertEqual(result.status, 'incomplete')
                self.assertNotEqual(result.scopes[0][1].status, 'accepted')
                self.assertEqual((m.creates,m.starts), (0,0))

    def test_partial_result_keeps_committed_scope_and_refuses_other(self):
        a, b = make_scope('first','run-one'), make_scope('second','run-two')
        b.manager.denied = True
        result = self.aggregate([a,b]).setup()
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual([r.status for _,r in result.scopes], ['accepted','refused'])
        self.assertEqual([a.manager.creates,b.manager.creates], [1,0])

    def test_actual_binding_and_generation_are_pinned(self):
        s = make_scope()
        s.bindings.observers['trusted-observer'] = (Observer(), None, 'provider')
        self.assertEqual(self.aggregate([s]).setup().status, 'incomplete')
        self.assertEqual(s.manager.creates, 0)
        s = make_scope()
        s.manager.evidence = replace(s.manager.evidence, binding_generation='other')
        self.assertEqual(self.aggregate([s]).setup().status, 'incomplete')
        self.assertEqual(s.manager.creates, 0)

    def test_final_sweep_rejects_scope_revoked_after_initial_acceptance(self):
        a, b = make_scope('first','run-one'), make_scope('second','run-two')
        create = b.manager.create
        def later_create(selection):
            create(selection)
            a.manager.revoked = True
        b.manager.create = later_create
        result = self.aggregate([a,b]).setup()
        self.assertEqual([r.status for _,r in result.scopes], ['accepted','accepted'])
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual([r.status for _,r in result.final_checks], ['refused','accepted'])
        self.assertEqual([a.manager.creates,b.manager.creates], [1,1])

    def test_generation_change_during_final_sweep_refuses(self):
        a, b = make_scope('first','run-one'), make_scope('second','run-two')
        create = b.manager.create
        def later_create(selection):
            create(selection)
            a.manager.generation = 'generation-2'
        b.manager.create = later_create
        result = self.aggregate([a,b]).setup()
        self.assertEqual(result.status, 'incomplete')
        self.assertNotEqual(result.final_checks[0][1].status, 'accepted')

    def test_binding_swap_during_final_sweep_refuses(self):
        a, b = make_scope('first','run-one'), make_scope('second','run-two')
        create = b.manager.create
        def later_create(selection):
            create(selection)
            a.bindings.observers['trusted-observer'] = (Observer(), None, 'provider')
        b.manager.create = later_create
        result = self.aggregate([a,b]).setup()
        self.assertEqual(result.status, 'incomplete')
        self.assertNotEqual(result.final_checks[0][1].status, 'accepted')

    def test_expired_evidence_during_final_sweep_is_not_ready(self):
        a, b = make_scope('first','run-one'), make_scope('second','run-two')
        create = b.manager.create
        def later_create(selection):
            create(selection)
            a.manager.evidence = replace(a.manager.evidence, expires_ns=1)
        b.manager.create = later_create
        result = self.aggregate([a,b]).setup()
        self.assertEqual(result.status, 'incomplete')
        self.assertNotEqual(result.final_checks[0][1].status, 'accepted')

    def test_early_final_evidence_expires_before_last_check(self):
        from time import monotonic_ns, sleep
        a, b = make_scope('first','run-one'), make_scope('second','run-two')
        create = b.manager.create
        checks = b.manager.verify_bindings
        delayed = {'enabled':False, 'count':0}
        def later_create(selection):
            create(selection)
            a.manager.evidence = replace(a.manager.evidence, expires_ns=monotonic_ns()+40_000_000)
            delayed['enabled'] = True
        def delay_after_early_final(*args):
            if delayed['enabled']:
                delayed['count'] += 1
                if delayed['count'] == 2: sleep(0.06)
            return checks(*args)
        b.manager.create = later_create
        b.manager.verify_bindings = delay_after_early_final
        result = self.aggregate([a,b]).setup()
        self.assertEqual([r.status for _,r in result.final_checks], ['accepted','accepted'])
        self.assertEqual(result.status, 'incomplete')
        self.assertGreaterEqual(result.observed_end_ns, result.valid_until_ns)

    def test_plain_profile_does_not_require_optional_observer_or_meter(self):
        from test_profile_setup import DEFINITION
        policy = json.dumps({'version': 1, 'roles': {'operator': {'operations': ['launch']}},
            'workflows': {'profile': {'role': 'operator', 'operations': ['launch'],
                                      'bindings': {'executable': 'tool'}}}}).encode()
        provider = ProviderBinding('tool', 'executable-ref', 'run-scope', 'launch', 'operator', 'executable')
        definition = replace(DEFINITION, providers=(provider,), policy_sha256=sha256(policy).hexdigest())
        manager = Manager(definition, policy)
        bindings = HostBindings(authorize=lambda *_: True, executables={'tool': ('/bin/true',)})
        scope = ScopeSetup('profile', 'revision-1', ProfileRequirements('operator','run-scope'), manager, bindings)
        self.assertEqual(self.aggregate([scope]).setup().status, 'ready')
        self.assertEqual((manager.creates, manager.starts), (1,0))

    def test_uncertain_commit_never_replays_and_history_is_separate(self):
        s = make_scope()
        s.manager.lose_create_reply = True
        a = self.aggregate([s])
        result = a.setup().scopes[0][1]
        self.assertEqual(result.status, 'unknown')
        self.assertEqual(a.setup().scopes[0][1].status, 'unknown')
        self.assertEqual(s.manager.creates, 1)
        expected = s.manager.selection.definition
        self.assertEqual(a.resolve_attempt(s.name, expected=expected).status, 'unknown')
        s.manager.history_state = 'committed'
        self.assertEqual(a.resolve_attempt(s.name, expected=expected).status, 'recorded')
        self.assertEqual(a.reconcile(s.name, expected=expected).status, 'accepted')
        s.manager.revoked = True
        self.assertEqual(a.reconcile(s.name, expected=expected).status, 'refused')
        self.assertEqual(a.resolve_attempt(s.name, expected=expected).status, 'recorded')
        s.manager.history_state = 'not_committed'
        self.assertEqual(a.resolve_attempt(s.name, expected=expected).status, 'not_committed')
        self.assertEqual(s.manager.creates, 1)
        with self.assertRaises(ValueError):
            a.resolve_attempt(s.name, expected=replace(expected, scope='other'))
