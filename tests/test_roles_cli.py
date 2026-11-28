"""Own-user declaration fixtures; no OS privileges or independent provider grants."""
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest


class RoleDeclarationTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.root.chmod(0o700)
        self.user=pwd.getpwuid(os.getuid()).pw_name
        self.doc={'version':1,'profile':'custom_archive','revision':'revision_1','roles':[
            {'name':'catalog_curator','principal':self.user,'operations':['read','observe'],
             'scopes':['east_archive'],'expires_at':4102444800}]}

    def command(self,args,doc=None,*,entry='workeros-roles',now=None,root=None,python=None,interrupt=''):
        python = Path(python or sys.executable)
        executable = str(python.parent/entry)
        code = """
import runpy
import sys
import workeros.roles_cli as roles

roles._PARENT = sys.argv[1]
roles._UID = int(sys.argv[2])
clock, interruption = sys.argv[3:5]
if clock:
    roles.time = lambda: int(clock)
if interruption:
    original = roles._commit
    def commit(store, key, payload, **kwargs):
        is_receipt = kwargs.get('kind') == roles._COMMISSION_KIND
        if is_receipt and interruption == 'before':
            raise OSError('fixture interruption')
        result = original(store, key, payload, **kwargs)
        if is_receipt and interruption == 'after':
            raise OSError('fixture reply loss')
        return result
    roles._commit = commit
sys.argv = sys.argv[5:]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
        payload = doc if isinstance(doc, str) else json.dumps(doc) if doc is not None else None
        return subprocess.run([str(python),'-I','-c',code,str(root or self.root),str(os.getuid()),
                               '' if now is None else str(now),interrupt,executable,*args],
                              input=payload,text=True,capture_output=True,timeout=5)

    def commission(self, *args, now=None, entry='workeros'):
        result = self.command(['managed', *args], entry=entry, now=now)
        return result.returncode, json.loads(result.stdout)

    def commission_document(self, raw, *options, **fixture):
        result = self.command(['managed', 'commission-apply', *options], raw, entry='workeros', **fixture)
        return result.returncode, json.loads(result.stdout)

    def test_commission_apply_from_empty_store_preserves_exact_input(self):
        raw = json.dumps(self.doc, indent=2) + '\n'
        code, preview = self.commission_document(raw, '--preview')
        self.assertEqual((code, preview['status'], preview['effect']), (0, 'preview', 'not_attempted'))
        self.assertEqual(list(self.root.iterdir()), [])
        code, result = self.commission_document(raw)
        self.assertEqual((code, result['status'], result['effect'], result['declaration_effect']),
                         (0, 'configured', 'recorded', 'recorded'))
        self.assertEqual((result['readiness'], result['independence']), ('not_checked', 'unverified'))
        self.assertIn('register and verify', result['next_action'])
        self.assertEqual(result['declaration_sha256'], preview['declaration_sha256'])
        self.assertEqual(result['intent_sha256'], sha256(raw.encode()).hexdigest())
        status = ('commission-status', self.doc['profile'], self.doc['revision'])
        code, observed = self.commission(*status)
        self.assertEqual((code, observed['status'], observed['intent_sha256']),
                         (0, 'configured', result['intent_sha256']))
        directory = self.root/'workeros'/'profiles'
        before = {item.name: item.read_bytes() for item in directory.iterdir()}
        code, repeated = self.commission_document(raw)
        self.assertEqual((code, repeated['effect'], repeated['declaration_effect']), (0, 'unchanged', 'unchanged'))
        code, conflict = self.commission_document(json.dumps(self.doc))
        self.assertEqual((code, conflict['code'], conflict['effect']),
                         (1, 'commission_intent_conflict', 'not_attempted'))
        self.assertEqual({item.name: item.read_bytes() for item in directory.iterdir()}, before)

    def test_commission_apply_matches_json_and_yaml_declaration(self):
        yaml_python = os.environ.get('WORKEROS_YAML_PYTHON')
        if not yaml_python:
            self.skipTest('optional installed PyYAML environment unavailable')
        yaml = ('version: 1\nprofile: custom_archive\nrevision: revision_1\nroles:\n'
                '  - name: catalog_curator\n'
                f'    principal: {json.dumps(self.user)}\n'
                '    operations: [read, observe]\n    scopes: [east_archive]\n    expires_at: 4102444800\n')
        code, json_receipt = self.commission_document(json.dumps(self.doc), python=yaml_python)
        self.assertEqual(code, 0)
        with tempfile.TemporaryDirectory() as yaml_store:
            code, yaml_receipt = self.commission_document(yaml, '--format', 'yaml', root=yaml_store,
                                                          python=yaml_python)
        self.assertEqual((code, yaml_receipt['status']), (0, 'configured'))
        self.assertEqual(yaml_receipt['declaration_sha256'], json_receipt['declaration_sha256'])
        self.assertEqual(yaml_receipt['intent_sha256'], sha256(yaml.encode()).hexdigest())
        self.assertNotEqual(yaml_receipt['intent_sha256'], json_receipt['intent_sha256'])

    def test_yaml_refuses_ambiguous_scalars_and_explicit_tags(self):
        yaml_python=os.environ.get('WORKEROS_YAML_PYTHON')
        if not yaml_python: self.skipTest('optional installed PyYAML environment unavailable')
        py=Path(yaml_python); entry=py.parent/'workeros'
        base=('version: 1\nprofile: custom_archive\nrevision: revision_1\nroles:\n'
              '  - name: catalog_curator\n    principal: '+json.dumps(self.user)+'\n'
              '    operations: [read]\n    scopes: [east_archive]\n    expires_at: 4102444800\n')
        cases=(('version: 01\n','legacy octal-like integer'),
               ('profile: on\n','YAML 1.1 boolean word'),
               ('revision: 2026-11-27\n','implicit timestamp'),
               ('profile: !!str custom_archive\n','explicit standard tag'),
               ('profile: !custom custom_archive\n','explicit custom tag'))
        for fragment,label in cases:
            with self.subTest(label=label):
                if fragment.startswith('profile:'):
                    raw=base.replace('profile: custom_archive\n',fragment)
                elif fragment.startswith('version:'):
                    raw=base.replace('version: 1\n',fragment)
                else:
                    raw=base.replace('revision: revision_1\n',fragment)
                result=self.command(['managed','commission-apply','--format','yaml'],raw,
                                    entry='workeros',python=py)
                self.assertEqual(result.returncode,1,result.stdout+result.stderr)
                receipt=json.loads(result.stdout)
                self.assertEqual((receipt['code'],receipt['effect']),('invalid_yaml','not_attempted'))
                self.assertFalse((self.root/'workeros').exists())

        # The JSON path remains dependency-free and keeps its original bytes
        # as the intent digest even when the YAML extra is installed.
        result=self.command(['managed','commission-apply'],json.dumps(self.doc),entry='workeros',python=py)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['intent_sha256'],sha256(json.dumps(self.doc).encode()).hexdigest())

    def test_commission_apply_reconciles_interruption_without_rollback(self):
        for interruption, expected in (('before', 'unconfigured'), ('after', 'configured')):
            with self.subTest(interruption=interruption):
                revision = f'interrupted_{interruption}'
                raw = json.dumps({**self.doc, 'revision': revision})
                code, partial = self.commission_document(raw, interrupt=interruption)
                self.assertEqual((code, partial['status'], partial['effect'], partial['declaration_effect']),
                                 (1, 'unknown', 'unknown', 'recorded'))
                self.assertIn('commission-status', partial['next_action'])
                code, observed = self.commission('commission-status', self.doc['profile'], revision)
                self.assertEqual(observed['status'], expected)
                self.assertEqual(observed['declaration_sha256'], partial['declaration_sha256'])
                if interruption == 'before':
                    self.assertEqual(observed['declaration_status'], 'configured')
                else:
                    self.assertEqual(observed['intent_sha256'], partial['intent_sha256'])
                code, result = self.commission_document(raw)
                self.assertEqual((code, result['status'], result['declaration_effect']),
                                 (0, 'configured', 'unchanged'))
                self.assertEqual(result['effect'], 'recorded' if interruption == 'before' else 'unchanged')

    def test_commission_exact_revision_and_separate_immutable_receipt(self):
        profile, revision = self.doc['profile'], self.doc['revision']
        status_args = ('commission-status', profile, revision)
        self.assertEqual(self.commission(*status_args)[1]['status'], 'unconfigured')
        self.assertFalse((self.root/'workeros').exists())
        applied = self.command(['apply'], self.doc)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        digest = json.loads(applied.stdout)['digest']
        command = ('commission', profile, revision, '--declaration-sha256', digest, '--intent-sha256')
        directory = self.root/'workeros'/'profiles'
        before = {item.name: item.read_bytes() for item in directory.iterdir()}

        code, result = self.commission('commission', profile, revision, '--declaration-sha256', 'c'*64,
                                       '--intent-sha256', 'a'*64)
        self.assertEqual((code, result['code'], result['effect']),
                         (1, 'declaration_digest_mismatch', 'not_attempted'))
        self.assertEqual({item.name: item.read_bytes() for item in directory.iterdir()}, before)

        code, result = self.commission(*command, 'a'*64)
        self.assertEqual((code, result['status'], result['effect']), (0, 'configured', 'recorded'))
        self.assertEqual((result['readiness'], result['independence']), ('not_checked', 'unverified'))
        self.assertEqual(result['declaration_sha256'], digest)
        self.assertEqual(result['intent_sha256'], 'a'*64)
        self.assertNotIn('roles', result)
        after = {item.name: item.read_bytes() for item in directory.iterdir()}
        self.assertEqual(len(after), len(before) + 1)
        self.assertTrue(before.items() <= after.items())
        receipt_name, = after.keys() - before.keys()
        self.assertNotIn(self.doc['roles'][0]['name'].encode(), after[receipt_name])

        # Each invocation uses a fresh process, with the alias taking the same path.
        self.assertEqual(self.commission(*status_args, entry='wos'),
                         (0, {**result, 'effect': 'not_attempted'}))
        self.assertEqual(self.commission(*command, 'a'*64), (0, {**result, 'effect': 'unchanged'}))
        code, conflict = self.commission(*command, 'b'*64)
        self.assertEqual((code, conflict['code'], conflict['effect']),
                         (1, 'commission_intent_conflict', 'not_attempted'))
        self.assertEqual({item.name: item.read_bytes() for item in directory.iterdir()}, after)

        code, expired = self.commission(*status_args, now=self.doc['roles'][0]['expires_at'])
        self.assertEqual((code, expired['status'], expired['effect']), (1, 'expired', 'not_attempted'))
        self.assertEqual({item.name: item.read_bytes() for item in directory.iterdir()}, after)
        self.assertEqual(self.command(['revoke', profile, revision]).returncode, 0)
        code, revoked = self.commission(*status_args)
        self.assertEqual((code, revoked['status'], revoked['effect']), (1, 'revoked', 'not_attempted'))
        code, refused = self.commission(*command, 'a'*64)
        self.assertEqual((code, refused['code'], refused['effect']), (1, 'revision_revoked', 'not_attempted'))

    def test_commission_status_reports_unresolved_record_without_modifying_it(self):
        profile, revision = self.doc['profile'], self.doc['revision']
        self.assertEqual(self.command(['apply'], self.doc).returncode, 0)
        from workeros.roles_cli import _key
        from workeros.recording import LocalStore
        directory = self.root/'workeros'/'profiles'
        pending = directory/LocalStore._staged_name(_key(profile, revision, 'commission'))
        pending.write_bytes(b'')
        before = {item.name: item.read_bytes() for item in directory.iterdir()}
        code, result = self.commission('commission-status', profile, revision)
        self.assertEqual((code, result['status'], result['effect']), (1, 'unknown', 'not_attempted'))
        self.assertEqual({item.name: item.read_bytes() for item in directory.iterdir()}, before)

    def test_custom_role_apply_show_update_revoke(self):
        result=self.command(['apply'],self.doc); self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual((receipt['status'],receipt['enforcement'],receipt['independence']),
                         ('configured','not_commissioned','unverified'))
        repeat=json.loads(self.command(['apply'],self.doc).stdout); self.assertEqual(repeat['effect'],'unchanged')
        shown=json.loads(self.command(['show','custom_archive','revision_1']).stdout)
        self.assertEqual(shown['roles'][0]['name'],'catalog_curator')
        original, = shown['admin_history']
        self.assertEqual((original['action'], original['revision'], original['disposition']),
                         ('apply', 'revision_1', 'recorded'))
        self.assertEqual(original['actor'], {'authentication': 'kernel_effective_uid', 'uid': os.getuid()})
        self.assertGreater(int(original['captured_at_unix_ns']), 0)
        for current in (receipt, repeat):
            self.assertEqual(current['admin_history'], [original])
        updated=json.loads(json.dumps(self.doc)); updated['revision']='revision_2'; updated['roles'][0]['operations']=['read']
        applied = json.loads(self.command(['apply'],updated).stdout)
        self.assertEqual(applied['status'], 'configured')
        self.assertEqual(applied['admin_history'][0]['revision'], 'revision_2')
        revoke = ['revoke', 'custom_archive', 'revision_1']
        revoked = json.loads(self.command(revoke).stdout)
        self.assertEqual(revoked['status'], 'revoked')
        history = revoked['admin_history']
        self.assertEqual(history[0], original)
        self.assertEqual(history[1]['action'], 'revoke')
        self.assertEqual(history[1]['revision'], 'revision_1')
        self.assertEqual(history[1]['actor'], original['actor'])
        repeated = json.loads(self.command(revoke).stdout)
        self.assertEqual((repeated['effect'], repeated['admin_history']), ('unchanged', history))
        shown = json.loads(self.command(['show','custom_archive','revision_1']).stdout)
        self.assertEqual((shown['status'], shown['admin_history']), ('revoked', history))
        retry=json.loads(self.command(['apply'],self.doc).stdout)
        self.assertEqual((retry['status'],retry['code']),('refused','revision_revoked'))
        self.assertEqual(json.loads(self.command(['show','custom_archive','revision_2']).stdout)['status'],'configured')

    def test_legacy_history_is_never_attributed_to_the_current_reader_or_retry(self):
        from unittest.mock import patch
        from workeros import roles_cli as roles

        profile, revision = self.doc['profile'], self.doc['revision']
        declaration = roles._canonical(self.doc)
        digest = sha256(declaration).hexdigest()
        intent = 'a' * 64
        with patch.multiple(roles, _PARENT=str(self.root), _UID=os.getuid()):
            with roles._store(create=True) as store:
                roles._commit(store, roles._key(profile, revision, 'profile'), declaration)
                commission = roles._commission_receipt(profile, revision, digest, intent)
                roles._commit(store, roles._key(profile, revision, 'commission'),
                              roles._canonical(commission), kind=roles._COMMISSION_KIND)
            repeated = roles.apply(declaration)
            repeated_commission = roles.commission(profile, revision, digest, intent)
            self.assertEqual((repeated['effect'], repeated_commission['effect']), ('unchanged', 'unchanged'))
            legacy = roles.commission_status(profile, revision)['admin_history']
            self.assertEqual(repeated_commission['admin_history'], legacy)
            self.assertEqual([row['action'] for row in legacy], ['apply', 'commission'])
            with roles._store(create=False) as store:
                roles._commit(store, roles._key(profile, revision, 'revoke'),
                              roles._revocation_payload(profile, revision, declaration))
            revoked = roles.revoke_profile(profile, revision)
            self.assertEqual(revoked['effect'], 'unchanged')
            self.assertEqual(revoked['admin_history'][:2], legacy)
            for row in revoked['admin_history']:
                self.assertEqual((row['actor'], row['captured_at_unix_ns']),
                                 ({'authentication': 'unverified'}, None))

    def test_custom_independent_principal_is_unqualified(self):
        other=next((x for x in pwd.getpwall() if x.pw_uid != os.getuid()),None)
        if other is None: self.skipTest('no separate existing OS principal')
        self.doc['roles'][0]['independent_of']=other.pw_name
        result=self.command(['apply'],self.doc)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['independence'],'unverified')

    def test_custom_scope_resource_identity_is_recorded_without_grant(self):
        resource=self.root/'sample'; resource.write_bytes(b'W'); resource.chmod(0o600)
        info=resource.stat()
        self.doc['roles'][0]['resources']={'east_archive':{'device':str(info.st_dev),'inode':str(info.st_ino)}}
        result=self.command(['apply'],self.doc)
        self.assertEqual(result.returncode,0,result.stderr)
        shown=json.loads(self.command(['show','custom_archive','revision_1']).stdout)
        self.assertEqual(shown['roles'][0]['resources'],self.doc['roles'][0]['resources'])
        self.assertEqual(resource.stat().st_mode & 0o777,0o600)
        self.assertEqual(shown['independence'],'unverified')

    def test_same_principal_and_unsupported_operations_refuse_before_store(self):
        self.doc['roles'][0]['independent_of']=self.user
        result=self.command(['apply'],self.doc)
        self.assertEqual(json.loads(result.stdout)['code'],'independence_mismatch')
        self.assertFalse((self.root/'workeros').exists())
        self.doc['roles'][0].pop('independent_of')
        self.doc['roles'][0]['operations']=['grant_arbitrary_privilege']
        result=self.command(['apply'],self.doc)
        self.assertEqual(json.loads(result.stdout)['code'],'unsupported_operation')
        self.assertFalse((self.root/'workeros').exists())

    def test_changed_same_revision_is_never_overwritten(self):
        self.assertEqual(self.command(['apply'],self.doc).returncode,0)
        changed=json.loads(json.dumps(self.doc)); changed['roles'][0]['scopes']=['other_archive']
        result=self.command(['apply'],changed)
        self.assertNotEqual(result.returncode,0)
        shown=json.loads(self.command(['show','custom_archive','revision_1']).stdout)
        self.assertEqual(shown['roles'][0]['scopes'],['east_archive'])

    def test_explicit_privileged_request_is_previewed_but_not_granted(self):
        self.doc['roles'][0]['privileged']=[{'capability':'special_resource_access',
                                           'scope':'east_archive','approved':True}]
        preview=self.command(['preview'],self.doc)
        receipt=json.loads(preview.stdout)
        self.assertEqual((preview.returncode,receipt['status'],receipt['effect']),(1,'unsupported','not_attempted'))
        self.assertEqual(receipt['roles'][0]['privileged'][0],self.doc['roles'][0]['privileged'][0])
        self.assertEqual(receipt['code'],'unsupported_privileged_enforcement')
        applied=self.command(['apply'],self.doc)
        self.assertEqual(json.loads(applied.stdout)['code'],'unsupported_privileged_enforcement')
        self.assertFalse((self.root/'workeros').exists())

    def test_privileged_request_requires_approval_and_matching_scope(self):
        self.doc['roles'][0]['privileged']=[{'capability':'special_resource_access',
                                           'scope':'east_archive','approved':False}]
        self.assertEqual(json.loads(self.command(['preview'],self.doc).stdout)['code'],'approval_required')
        self.doc['roles'][0]['privileged'][0].update(approved=True,scope='different_scope')
        self.assertEqual(json.loads(self.command(['preview'],self.doc).stdout)['code'],'scope_mismatch')
        self.assertFalse((self.root/'workeros').exists())
