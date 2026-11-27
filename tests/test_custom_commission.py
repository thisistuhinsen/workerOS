"""Custom names with synthetic authorities; not independent host qualification."""
from dataclasses import replace
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from workeros.aggregate_setup import AggregateSetup, ScopeEvidence, ScopeSetup
from workeros.enrollment import HostBindings
from workeros.profile_setup import ProfileDefinition, ProfileRequirements, ProviderBinding, ProviderRequirement
from test_aggregate_setup import Manager, Observer
from test_profile_setup import CLOCK, EXPIRY, PACKAGE_HASH


def custom_scope(operation='observe'):
    data = {'version':1, 'roles':{'archive_editor':{'operations':[operation]}},
            'workflows':{'catalog_review':{'role':'archive_editor','operations':[operation],
                'bindings':{'observers':{'slot':'independent_reader'}}}}}
    policy=json.dumps(data,separators=(',',':')).encode()
    binding=ProviderBinding('independent_reader','grant-27','collection-east','point',
                            'review-principal','observers','editor-principal')
    definition=ProfileDefinition('catalog_review','revision-7','0.8.0',PACKAGE_HASH,
                sha256(policy).hexdigest(),'host-manager','collection-east',CLOCK,EXPIRY,(binding,))
    requirements=ProfileRequirements('archive_editor','collection-east',
        (ProviderRequirement('observers','independent_reader','point','collection-east','editor-principal'),))
    manager=Manager(definition,policy)
    manager.evidence=ScopeEvidence(definition,'archive_editor','review-principal','c'*64,CLOCK,EXPIRY,True,'generation-1')
    host=HostBindings(authorize=lambda *_: True,observers={'independent_reader':(Observer(),None,'observer-ref')})
    manager.expected_observer=host.observers['independent_reader']
    return ScopeSetup('catalog_review','revision-7',requirements,manager,host)


class CustomCommissionTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch('workeros.profile_setup.version',return_value='0.8.0'))
        self.enterContext(patch('workeros.aggregate_setup.verify_install'))

    def setup_scope(self, scope):
        return AggregateSetup((scope,),wheel='fixture.whl',wheel_sha256=PACKAGE_HASH,clock_id=CLOCK)

    def test_custom_names_and_separate_principal_are_only_synthetic(self):
        scope=custom_scope(); service=self.setup_scope(scope)
        result=service.setup()
        self.assertEqual(result.status,'ready')
        self.assertEqual(scope.manager.selection.definition.providers[0].principal,'review-principal')
        self.assertEqual((scope.manager.creates,scope.manager.starts),(1,0))
        scope.manager.revoked=True
        self.assertEqual(service.reconcile(scope.name,expected=scope.manager.selection.definition).status,'refused')
        self.assertEqual((scope.manager.creates,scope.manager.starts),(1,0))

    def test_unsupported_operation_refuses_before_setup(self):
        scope=custom_scope('unrecognized_capability')
        result=self.setup_scope(scope).setup()
        self.assertEqual(result.status,'incomplete')
        self.assertNotEqual(result.scopes[0][1].status,'accepted')
        self.assertEqual((scope.manager.creates,scope.manager.starts),(0,0))

    def test_self_attesting_observer_refuses_before_setup(self):
        scope=custom_scope()
        scope.manager.evidence=replace(scope.manager.evidence,source='editor-principal')
        result=self.setup_scope(scope).setup()
        self.assertEqual(result.status,'incomplete')
        self.assertEqual((scope.manager.creates,scope.manager.starts),(0,0))
