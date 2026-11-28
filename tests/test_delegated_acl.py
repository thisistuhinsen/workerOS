"""No-privilege ACL schema and refusal tests; not a cross-UID grant."""
import errno
from contextlib import nullcontext, redirect_stdout
from dataclasses import replace
from hashlib import sha256
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import pwd
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from workeros import delegated_acl, managed_cli, roles_cli


class DelegatedAclTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.root.chmod(0o711)
        self.target=self.root/'owned'; self.target.write_bytes(b'W'); self.target.chmod(0o600)
        info=self.target.stat()
        self.doc={'version':1,'profile':'files','revision':'r1','role':'reader','scope':'scope1',
                  'path':str(self.target),'exclusive_admin':True}
        self.declaration={'status':'configured','digest':'a'*64,'roles':[{'name':'reader','principal':'nobody',
            'operations':['read'],'scopes':['scope1'],'expires_at':4102444800,
            'resources':{'scope1':{'device':str(info.st_dev),'inode':str(info.st_ino)}}}]}

    def test_kernel_acl_encoding_is_narrow_and_fixed(self):
        acl=delegated_acl._acl(1234)
        self.assertEqual(struct.unpack('<I',acl[:4])[0],2)
        entries=[struct.unpack('<HHI',acl[i:i+8]) for i in range(4,len(acl),8)]
        self.assertEqual(entries,[(1,6,0xffffffff),(2,4,1234),(4,0,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)])
        self.assertEqual(len(delegated_acl._base_acl()),28)

    def test_nonadministrator_refuses_before_mutation(self):
        if os.geteuid()==0: self.skipTest('fixture must run without administrator privilege')
        with self.assertRaisesRegex(delegated_acl.Refusal,'administrator_required'):
            delegated_acl.run('apply',json.dumps(self.doc).encode())
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o600)
        self.assertFalse((self.root/'.workeros-acl-grants').exists())

    def test_unmapped_distinct_principal_refuses_before_mutation(self):
        with patch.object(delegated_acl,'_ADMIN_UID',os.geteuid()), \
             patch.object(delegated_acl,'_uid_mapped',return_value=False), \
             patch.object(delegated_acl.roles_cli,'_store',return_value=nullcontext(object())), \
             patch.object(delegated_acl.roles_cli,'_inspect_store',return_value=self.declaration):
            with self.assertRaisesRegex(delegated_acl.Refusal,'principal_unmapped'):
                delegated_acl.run('apply',json.dumps(self.doc).encode())
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o600)
        self.assertFalse((self.root/'.workeros-acl-grants').exists())

    def test_approval_scope_and_exclusivity_are_not_optional(self):
        bad=dict(self.doc,exclusive_admin=False)
        with self.assertRaisesRegex(delegated_acl.Refusal,'invalid_or_nonexclusive_plan'):
            delegated_acl.run('apply',json.dumps(bad).encode())
        self.assertFalse((self.root/'.workeros-acl-grants').exists())

    def test_synthetic_preview_binds_declared_uid_and_inode_without_effect(self):
        try: uid=pwd.getpwnam('nobody').pw_uid
        except KeyError: self.skipTest('nobody account unavailable')
        if uid==os.geteuid(): self.skipTest('fixture needs distinct numeric principal')
        with patch.object(delegated_acl,'_ADMIN_UID',os.geteuid()), \
             patch.object(delegated_acl,'_uid_mapped',return_value=True), \
             patch.object(delegated_acl.roles_cli,'_store',return_value=nullcontext(object())), \
             patch.object(delegated_acl.roles_cli,'_inspect_store',return_value=self.declaration):
            result=delegated_acl.run('preview',json.dumps(self.doc).encode())
        self.assertEqual((result['status'],result['principal_uid'],result['inode']),
                         ('preview',uid,str(self.target.stat().st_ino)))
        self.assertEqual(result['independent_observer'],'not_verified')
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o600)
        self.assertFalse((self.root/'.workeros-acl-grants').exists())

    def test_replaced_resource_refuses_before_mutation(self):
        try: uid=pwd.getpwnam('nobody').pw_uid
        except KeyError: self.skipTest('nobody account unavailable')
        if uid==os.geteuid(): self.skipTest('fixture needs distinct numeric principal')
        self.declaration['roles'][0]['resources']['scope1']['inode']='1'
        with patch.object(delegated_acl,'_ADMIN_UID',os.geteuid()), \
             patch.object(delegated_acl,'_uid_mapped',return_value=True), \
             patch.object(delegated_acl.roles_cli,'_store',return_value=nullcontext(object())), \
             patch.object(delegated_acl.roles_cli,'_inspect_store',return_value=self.declaration):
            with self.assertRaisesRegex(delegated_acl.Refusal,'approved_resource_mismatch'):
                delegated_acl.run('preview',json.dumps(self.doc).encode())
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o600)
        self.assertFalse((self.root/'.workeros-acl-grants').exists())

    def test_existing_acl_and_unsupported_backend_refuse_without_setter(self):
        try: uid=pwd.getpwnam('nobody').pw_uid
        except KeyError: self.skipTest('nobody account unavailable')
        if uid==os.geteuid(): self.skipTest('fixture needs distinct numeric principal')
        real_get=os.getxattr
        for issue in ('existing','unsupported'):
            def getxattr(fd,name):
                if isinstance(fd,int) and os.fstat(fd).st_ino==self.target.stat().st_ino:
                    if issue=='existing': return b'existing unrelated ACL'
                    raise OSError(errno.ENOTSUP,'unsupported')
                return real_get(fd,name)
            with self.subTest(issue=issue), \
                 patch.object(delegated_acl,'_ADMIN_UID',os.geteuid()), \
                 patch.object(delegated_acl,'_uid_mapped',return_value=True), \
                 patch.object(delegated_acl.roles_cli,'_store',side_effect=lambda **kw:nullcontext(object())), \
                 patch.object(delegated_acl.roles_cli,'_inspect_store',return_value=self.declaration), \
                 patch.object(delegated_acl.os,'getxattr',side_effect=getxattr), \
                 patch.object(delegated_acl.os,'setxattr') as setter:
                for action in ('preview','apply'):
                    with self.assertRaises(delegated_acl.Refusal) as result:
                        delegated_acl.run(action,json.dumps(self.doc).encode())
                    self.assertEqual(str(result.exception),'acl_already_present' if issue=='existing' else 'acl_backend_unavailable')
                setter.assert_not_called()
            self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o600)
            self.assertFalse((self.root/'.workeros-acl-grants').exists())


class ManagedGrantTest(unittest.TestCase):
    """Use a real private journal with simulated ACL effects; grant no OS access."""

    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        parent = self.root / 'owned'
        parent.mkdir()
        parent.chmod(0o711)
        self.target = parent / 'report'
        self.target.write_bytes(b'report')
        self.target.chmod(0o600)
        self.info = self.target.stat()
        self.uid = os.geteuid() + 1
        self.acls = {self.info.st_ino: None}
        self.setter_calls = []
        self.document = {
            'version': 1, 'profile': 'reporting', 'revision': 'r1',
            'roles': [{
                'name': 'report-reviewer', 'principal': 'fixture-reviewer',
                'operations': ['read'], 'scopes': ['final-report'],
                'expires_at': 4102444800, 'resources': {'final-report': {
                    'device': str(self.info.st_dev), 'inode': str(self.info.st_ino),
                }},
                'privileged': [{'capability': 'named_uid_read_acl', 'scope': 'final-report', 'approved': True}],
            }],
            'grant': {
                'capability': 'named_uid_read_acl', 'role': 'report-reviewer',
                'scope': 'final-report', 'path': str(self.target), 'principal_uid': self.uid,
                'exclusive_admin': True,
            },
        }
        self.real_getxattr = os.getxattr
        self.enterContext(patch.multiple(roles_cli, _PARENT=directory, _UID=os.geteuid()))
        self.enterContext(patch.object(delegated_acl, '_ADMIN_UID', os.geteuid()))
        self.enterContext(patch.object(delegated_acl, '_uid_mapped', return_value=True))
        self.accounts = self.enterContext(patch.object(pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=self.uid)))
        self.enterContext(patch.object(os, 'getxattr', side_effect=self.getxattr))
        self.enterContext(patch.object(os, 'setxattr', side_effect=self.setxattr))

    def getxattr(self, fd, name):
        inode = os.fstat(fd).st_ino if isinstance(fd, int) else None
        if inode in self.acls and name == delegated_acl._XATTR:
            if self.acls[inode] is None:
                raise OSError(errno.ENODATA, 'absent')
            return self.acls[inode]
        return self.real_getxattr(fd, name)

    def setxattr(self, fd, name, raw, flags):
        inode = os.fstat(fd).st_ino
        self.assertIn(inode, self.acls)
        self.assertEqual(name, delegated_acl._XATTR)
        self.setter_calls.append(flags)
        self.acls[inode] = raw if flags == os.XATTR_CREATE else None
        mask = struct.unpack_from('<H', raw, 30)[0] if flags == os.XATTR_CREATE else 0
        os.fchmod(fd, 0o600 | mask << 3)

    def apply(self, *args, expected=0, registrations=None):
        payload = json.dumps(self.document).encode()
        output = StringIO()
        with patch.object(managed_cli.sys, 'stdin', SimpleNamespace(buffer=BytesIO(payload))), redirect_stdout(output):
            self.assertEqual(managed_cli.main(['apply-profile', *args], acl_registrations=registrations),
                             expected, output.getvalue())
        result = json.loads(output.getvalue())
        if 'intent_sha256' in result:
            self.assertEqual(result['intent_sha256'], sha256(payload).hexdigest())
        return result

    @property
    def raw(self):
        return self.acls[self.info.st_ino]

    def multi_role_profile(self):
        second = self.target.with_name('inventory')
        second.write_bytes(b'inventory')
        second.chmod(0o600)
        info = second.stat()
        self.acls[info.st_ino] = None
        self.accounts.side_effect = lambda name: SimpleNamespace(
            pw_uid=self.uid if name == 'fixture-reviewer' else self.uid + 1)
        self.document['roles'].extend([
            {'name': 'inventory-editor', 'principal': 'fixture-editor',
             'operations': ['edit-inventory'], 'scopes': ['inventory'], 'expires_at': 4102444800,
             'resources': {'inventory': {'device': str(info.st_dev), 'inode': str(info.st_ino)}},
             'privileged': [{'capability': 'inventory-write', 'scope': 'inventory', 'approved': True}]},
            {'name': 'job-owner', 'principal': 'fixture-reviewer', 'operations': ['launch'],
             'scopes': ['ordinary'], 'expires_at': 4102444800},
        ])
        self.document['grants'] = [self.document.pop('grant'), {
            'capability': 'inventory-write', 'role': 'inventory-editor', 'scope': 'inventory',
            'path': str(second), 'principal_uid': self.uid + 1, 'exclusive_admin': True,
        }]
        capabilities = (delegated_acl._BUILTIN, delegated_acl.FileAclCapability('inventory-write', 'edit-inventory', 2))
        return tuple(delegated_acl.FileAclRegistration(
            capability, 'reporting', 'r1', grant['role'], grant['scope'], grant['principal_uid'],
            grant['path'], str(file_info.st_dev), str(file_info.st_ino), capability.access, 4102444800,
        ) for grant, capability, file_info in zip(self.document['grants'], capabilities, (self.info, info), strict=True))

    def test_registered_multi_role_profile_readback_and_effective_revoke(self):
        registrations = self.multi_role_profile()
        self.assertEqual(self.apply(expected=1)['code'], 'file_acl_registration_required')
        self.document['grants'][1]['expiry'] = 'automatic'
        self.assertEqual(self.apply(expected=1, registrations=registrations)['code'], 'automatic_acl_expiry_unsupported')
        self.document['grants'][1]['expiry'] = 'manual'
        self.assertEqual(self.apply(expected=1, registrations=registrations[:1])['code'],
                         'unsupported_privileged_enforcement')
        self.assertEqual(self.apply('--preview', registrations=registrations)['status'], 'preview')
        self.assertFalse((self.root / 'workeros').exists())
        result = self.apply(registrations=registrations)
        self.assertEqual(result['status'], 'file_acl_verified')
        current = roles_cli.commission_status('reporting', 'r1')
        self.assertEqual([entry['grant']['access_mask'] for entry in current['file_access']], [4, 2])
        self.assertEqual(current['setup_attachment'], 'not_checked')
        self.assertEqual(self.apply(registrations=registrations)['grant_effect'], 'not_attempted')
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE] * 2)
        self.document['roles'][2]['name'] = 'different-job-owner'
        self.assertEqual(self.apply(expected=1, registrations=registrations)['code'], 'commission_intent_conflict')
        result = roles_cli.revoke_profile('reporting', 'r1')
        self.assertEqual(result['status'], 'revoked')
        self.assertEqual([entry['grant']['acl_presence'] for entry in result['file_access']], ['absent'] * 2)
        self.assertEqual(roles_cli.revoke_profile('reporting', 'r1')['grant_effect'], 'not_attempted')
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE] * 2 + [os.XATTR_REPLACE] * 2)

    def test_interrupted_multi_role_profile_reports_partial_state_without_replay(self):
        registrations = self.multi_role_profile()
        write_record = delegated_acl._write

        def lose_first_result(store, key, payload):
            if key.record_id == 'grant_result':
                raise OSError('fixture lost result')
            return write_record(store, key, payload)

        with patch.object(delegated_acl, '_write', new=lose_first_result):
            self.assertEqual(self.apply(expected=1, registrations=registrations)['status'], 'unknown')
        for observed in (roles_cli.commission_status('reporting', 'r1'),
                         self.apply(expected=1, registrations=registrations)):
            self.assertEqual(observed['status'], 'unknown')
            self.assertEqual([row['grant']['acl_presence'] for row in observed['file_access']], ['present_exact', 'absent'])
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE])
        self.assertEqual(roles_cli.revoke_profile('reporting', 'r1')['status'], 'revoked')
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE, os.XATTR_REPLACE])

    def test_preview_apply_readback_and_revoke(self):
        preview = self.apply('--preview')
        self.assertEqual((preview['status'], preview['grant']['principal_uid']), ('preview', self.uid))
        self.assertFalse((self.root / 'workeros').exists())
        self.assertEqual(self.setter_calls, [])
        result = self.apply()
        self.assertEqual((result['status'], result['readiness'], result['independence']),
                         ('file_acl_verified', 'not_checked', 'unverified'))
        self.assertEqual((result['grant_effect'], result['grant']['attempt']),
                         ('observed', preview['grant']['attempt']))
        observed = self.apply()
        self.assertEqual((observed['status'], observed['grant_effect']), ('file_acl_verified', 'not_attempted'))
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE])
        plan = json.dumps(result['grant_plan']).encode()
        roles_cli.revoke('reporting', 'r1')
        self.assertEqual(delegated_acl.run('check', plan)['status'], 'cleanup_due')
        receipt = delegated_acl.run('revoke', plan)
        self.assertEqual((receipt['status'], receipt['acl_presence']), ('acl_entry_removed', 'absent'))
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE, os.XATTR_REPLACE])

    def test_missing_capability_approval_refuses_before_any_write(self):
        self.document['grant']['capability'] = 'arbitrary-access'
        refused = self.apply(expected=1)
        self.assertEqual((refused['code'], refused['effect']), ('unsupported_privileged_enforcement', 'not_attempted'))
        self.assertFalse((self.root / 'workeros').exists())
        self.assertFalse(self.setter_calls)

    def test_identity_pins_refuse_before_creating_a_role_record(self):
        self.document['grant']['principal_uid'] += 1
        self.assertEqual(self.apply(expected=1)['code'], 'principal_uid_mismatch')
        self.assertFalse((self.root / 'workeros').exists())
        self.assertFalse(self.setter_calls)

    def test_explicit_registry_does_not_fall_back_to_stock_approval(self):
        self.assertEqual(self.apply(expected=1, registrations=())['code'], 'unsupported_privileged_enforcement')
        self.assertFalse((self.root / 'workeros').exists())
        self.assertFalse(self.setter_calls)

    def test_installed_parser_uses_only_the_fixed_admin_registry(self):
        parent = self.root / 'config'
        directory = parent / 'workeros'
        directory.mkdir(parents=True, mode=0o700)
        registry = directory / 'file-acl-registrations.json'
        grant = self.document['grant']
        role = self.document['roles'][0]
        grant['capability'] = role['privileged'][0]['capability'] = 'report-read'
        approval = {'profile': 'reporting', 'revision': 'r1', 'role': grant['role'],
                    'scope': grant['scope'], 'path': grant['path'], 'principal_uid': self.uid,
                    'device': str(self.info.st_dev), 'inode': str(self.info.st_ino),
                    'maximum_access': 4, 'expires_at': role['expires_at'],
                    'capability': {'name': 'report-read', 'operation': 'read', 'access': 4}}
        flag = '--registered-file-acl'
        with patch.multiple(managed_cli, _CONFIG_PARENT=parent, _TRUSTED_UID=os.geteuid()):
            self.assertEqual(self.apply(flag, expected=1)['code'], 'native_acl_registration_unavailable')
            registry.write_text(json.dumps({'version': 1, 'registrations': [approval]}))
            registry.chmod(0o666)
            self.assertEqual(self.apply(flag, expected=1)['code'], 'native_acl_registration_untrusted')
            registry.chmod(0o600)
            moved = registry.with_suffix('.other')
            registry.rename(moved)
            registry.symlink_to(moved)
            self.assertEqual(self.apply(flag, expected=1)['code'], 'native_acl_registration_untrusted')
            registry.unlink()
            moved.rename(registry)
            registry.write_text(json.dumps({'version': 1, 'registrations': [{**approval, 'revision': 'r2'}]}))
            self.assertEqual(self.apply(flag, expected=1)['code'], 'native_grant_outside_approval')
            registry.write_text(json.dumps({'version': 1, 'registrations': [approval, approval]}))
            self.assertEqual(self.apply(flag, expected=1)['code'], 'invalid_native_acl_registration')
            self.assertFalse((self.root / 'workeros').exists())
            self.assertFalse(self.setter_calls)
            registry.write_text(json.dumps({'version': 1, 'registrations': [approval]}))
            self.assertEqual(self.apply(expected=1)['code'], 'unsupported_privileged_enforcement')
            self.assertEqual(self.apply(flag, '--preview')['status'], 'preview')
            result = self.apply(flag)
            self.assertEqual(result['status'], 'file_acl_verified')
            registry.unlink()
            self.assertEqual(delegated_acl.run('revoke', json.dumps(result['grant_plan']).encode())['status'],
                             'acl_entry_removed')

    def test_registered_operation_is_limited_and_has_exact_readback_and_revoke(self):
        capability = delegated_acl.FileAclCapability('archive-data-write', 'replace-report-data', 2)
        registration = delegated_acl.FileAclRegistration(
            capability=capability, profile='reporting', revision='r1',
            role='report-reviewer', scope='final-report', principal_uid=self.uid,
            path=str(self.target), device=str(self.info.st_dev), inode=str(self.info.st_ino),
            maximum_access=2, expires_at=4102444800,
        )
        role = self.document['roles'][0]
        role['operations'] = [capability.operation]
        role['privileged'][0]['capability'] = capability.name
        self.document['grant']['capability'] = capability.name
        self.assertEqual(self.apply(expected=1)['code'], 'unsupported_privileged_enforcement')
        for ceiling in (replace(registration, maximum_access=4),
                        replace(registration, path=str(self.target) + '.different'),
                        replace(registration, expires_at=4102444799)):
            self.assertEqual(self.apply(expected=1, registrations=(ceiling,))['code'],
                             'native_grant_outside_approval')
        self.assertFalse((self.root / 'workeros').exists())
        self.assertFalse(self.setter_calls)
        preview = self.apply('--preview', registrations=(registration,))
        self.assertEqual(preview['grant']['after_mode'], '0620')
        self.assertFalse((self.root / 'workeros').exists())
        result = self.apply(registrations=(registration,))
        self.assertEqual((result['status'], result['grant']['access_mask']), ('file_acl_verified', 2))
        self.assertEqual(self.raw, delegated_acl._acl(self.uid, 2))
        self.assertEqual(roles_cli.inspect('reporting','r1')['roles'][0]['operations'], [capability.operation])
        changed = replace(registration, capability=replace(capability, access=6), maximum_access=6)
        stale = self.apply(expected=1, registrations=(changed,))
        self.assertEqual(stale['grant']['code'], 'grant_readback_mismatch')
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE])
        plan = result['grant_plan']
        readback = delegated_acl.run('check', json.dumps(plan).encode())
        self.assertEqual((readback['status'], readback['capability'], readback['access_mask']),
                         ('acl_entry_verified', capability.name, 2))
        with self.assertRaisesRegex(delegated_acl.Refusal, 'native_capability_not_registered'):
            delegated_acl.run('apply', json.dumps(plan).encode())
        wrong = delegated_acl.run('revoke', json.dumps({**plan,'capability':'different-capability'}).encode())
        self.assertEqual(wrong['code'], 'binding_mismatch')
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE])
        self.assertEqual(self.apply(registrations=(registration,))['grant_effect'], 'not_attempted')
        removed = delegated_acl.run('revoke', json.dumps(plan).encode())
        self.assertEqual((removed['status'], removed['acl_presence']), ('acl_entry_removed','absent'))

    def test_interrupted_grant_is_checked_without_replay(self):
        write = delegated_acl._write

        def lost_result(store, key, payload):
            if key.record_id == 'grant_result':
                raise OSError('synthetic result-write failure')
            return write(store, key, payload)

        with patch.object(delegated_acl, '_write', new=lost_result):
            interrupted = self.apply(expected=1)
        self.assertEqual((interrupted['status'], interrupted['grant_effect']), ('unknown', 'unknown'))
        recovery = self.apply(expected=1)
        self.assertEqual((recovery['status'], recovery['grant']['code'], recovery['grant']['acl_presence']),
                         ('unknown', 'claim_only_acl_present', 'present_exact'))
        self.assertEqual(self.setter_calls, [os.XATTR_CREATE])
