"""Synthetic ACL state-machine tests; no cross-UID grant or qualification."""
from contextlib import nullcontext
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from worker_handoff import delegated_acl as acl
from worker_handoff.recording import Persistence, RecordKey


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.root.chmod(0o711)
        self.target=self.root/'input'; self.target.write_bytes(b'W'); self.target.chmod(0o600)
        info=self.target.stat()
        self.doc={'version':1,'profile':'files','revision':'r1','role':'reader','scope':'scope1',
                  'path':str(self.target),'exclusive_admin':True}
        self.decl={'status':'configured','digest':'a'*64,'roles':[{'name':'reader','principal':'fixture_user',
            'operations':['read'],'scopes':['scope1'],'expires_at':4102444800,
            'resources':{'scope1':{'device':str(info.st_dev),'inode':str(info.st_ino)}}}]}
        self.uid=12345; self.account=self.uid; self.raw=None; self.records={}; self.mutations=[]; self.fail_result=False; self.fail_revoke_result=False
        self.enterContext(patch.object(acl,'_ADMIN_UID',os.geteuid()))
        self.enterContext(patch.object(acl,'_uid_mapped',return_value=True))
        self.enterContext(patch.object(acl.roles_cli,'_store',side_effect=lambda **kw:nullcontext(object())))
        self.enterContext(patch.object(acl.roles_cli,'_inspect_store',side_effect=lambda *a:self.decl))
        self.enterContext(patch.object(acl.pwd,'getpwnam',side_effect=self.account_lookup))
        self.enterContext(patch.object(acl,'_journal',return_value=object()))
        self.enterContext(patch.object(acl,'_read',side_effect=lambda store,key:self.records.get(key)))
        self.enterContext(patch.object(acl,'_write',side_effect=self.write))
        self.real_getxattr=os.getxattr
        self.enterContext(patch.object(acl.os,'getxattr',side_effect=self.getxattr))
        self.enterContext(patch.object(acl.os,'setxattr',side_effect=self.setxattr))

    def account_lookup(self,name):
        if self.account is None: raise KeyError(name)
        return SimpleNamespace(pw_uid=self.account)

    def write(self,store,key,payload):
        if key.record_id=='grant_result' and self.fail_result: raise OSError('synthetic lost result')
        if key.record_id=='revoke_result' and self.fail_revoke_result: raise OSError('synthetic lost cleanup result')
        if key in self.records: return Persistence.EXISTING
        self.records[key]=payload; return Persistence.COMMITTED

    def getxattr(self,fd,name):
        if isinstance(fd,int) and os.fstat(fd).st_ino==self.target.stat().st_ino and name==acl._XATTR:
            if self.raw is None: raise OSError(errno.ENODATA,'absent')
            return self.raw
        return self.real_getxattr(fd,name)

    def setxattr(self,fd,name,value,flags=0):
        self.assertEqual(name,acl._XATTR)
        self.mutations.append((value,flags))
        if flags==os.XATTR_CREATE:
            self.assertIsNone(self.raw); self.raw=value; os.fchmod(fd,0o640)
        else:
            self.assertEqual(flags,os.XATTR_REPLACE); self.assertEqual(value,acl._base_acl())
            self.raw=None; os.fchmod(fd,0o600)

    def call(self,action): return acl.run(action,json.dumps(self.doc).encode())

    def test_lost_result_claim_only_reconciles_and_cleanup_uses_original_uid(self):
        self.fail_result=True
        first=self.call('apply'); self.assertEqual((first['status'],first['effect']),('unknown','unknown'))
        self.assertEqual(len(self.mutations),1)
        self.account=None
        check=self.call('check')
        self.assertEqual((check['status'],check['code'],check['acl_presence'],check['declaration'],check['cleanup']),
                         ('unknown','claim_only_acl_present','present_exact','principal_missing','available'))
        self.assertEqual(check['appointment'],'unverified')
        self.assertIn('grant-revoke',check['next_action'])
        self.assertNotIn('try again',check['next_action'])
        self.assertEqual(check['principal_uid'],self.uid)
        cleanup=self.call('revoke')
        self.assertEqual((cleanup['status'],cleanup['principal_uid'],cleanup['acl_presence']),('acl_entry_removed',self.uid,'absent'))
        self.assertEqual(len(self.mutations),2)
        self.assertEqual(self.call('check')['status'],'acl_entry_removed')
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o600)

    def test_reassigned_account_does_not_change_original_acl_target(self):
        self.assertEqual(self.call('apply')['status'],'acl_entry_verified')
        self.account=23456
        check=self.call('check')
        self.assertEqual((check['status'],check['declaration'],check['principal_uid']),('cleanup_due','principal_reassigned',self.uid))
        self.assertEqual(check['appointment'],'unverified')
        self.assertEqual(self.call('revoke')['status'],'acl_entry_removed')
        self.assertEqual(len(self.mutations),2)

    def test_expired_or_revoked_is_cleanup_due_not_active(self):
        first=self.call('apply')
        self.assertEqual((first['status'],first['declaration'],first['appointment']),
                         ('acl_entry_verified','current','unverified'))
        for state in ('expired','revoked'):
            self.decl['status']=state
            result=self.call('check')
            self.assertEqual((result['status'],result['declaration'],result['acl_presence']),('cleanup_due',state,'present_exact'))
            self.assertEqual(result['appointment'],'unverified')
        self.assertEqual(len(self.mutations),1)

    def test_unexpected_acl_never_clobbered(self):
        self.assertEqual(self.call('apply')['status'],'acl_entry_verified')
        self.raw=acl._acl(23456)
        self.account=None
        for action in ('check','revoke'):
            result=self.call(action)
            self.assertEqual((result['status'],result['acl_presence']),('unknown','unexpected'))
        self.assertEqual(len(self.mutations),1)
        self.assertEqual(self.raw,acl._acl(23456))

    def test_missing_role_store_does_not_prevent_exact_cleanup(self):
        self.assertEqual(self.call('apply')['status'],'acl_entry_verified')
        with patch.object(acl.roles_cli,'_store',side_effect=OSError('unavailable')):
            result=self.call('check')
            self.assertEqual((result['status'],result['declaration'],result['appointment']),
                             ('cleanup_due','unavailable','unverified'))
            self.assertEqual(self.call('revoke')['status'],'acl_entry_removed')
        self.assertEqual(len(self.mutations),2)

    def test_cleanup_does_not_resolve_the_mutable_account_name(self):
        self.assertEqual(self.call('apply')['status'],'acl_entry_verified')
        with patch.object(acl.pwd,'getpwnam',side_effect=AssertionError('must not resolve')):
            result=self.call('revoke')
        self.assertEqual((result['status'],result['principal_uid']),('acl_entry_removed',self.uid))
        self.assertEqual(result['appointment'],'unverified')

    def test_missing_binding_stays_unknown_without_mutation(self):
        result=self.call('check')
        self.assertEqual((result['status'],result['code']),('unknown','binding_missing'))
        self.assertEqual(self.mutations,[])

    def test_lost_cleanup_result_reports_observed_absence_without_replay_loop(self):
        self.assertEqual(self.call('apply')['status'],'acl_entry_verified')
        self.fail_revoke_result=True
        result=self.call('revoke')
        self.assertEqual((result['status'],result['acl_presence'],result['cleanup']),('unknown','absent','unconfirmed'))
        check=self.call('check')
        self.assertEqual((check['status'],check['acl_presence'],check['cleanup']),('unknown','absent','unconfirmed'))
        self.assertIn('Historical completion is unconfirmed',check['next_action'])
        self.assertNotIn('grant-check',check['next_action'])
        self.assertEqual(self.call('revoke')['status'],'unknown')
        self.assertEqual(len(self.mutations),2)

    def test_cleanup_failure_before_post_mutation_read_reports_unknown_presence(self):
        self.assertEqual(self.call('apply')['status'],'acl_entry_verified')
        with patch.object(acl.os,'fsync',side_effect=OSError('lost sync')):
            result=self.call('revoke')
        self.assertEqual((result['status'],result['acl_presence']),('unknown','unknown'))
        self.assertEqual(self.call('check')['acl_presence'],'absent')
        self.assertEqual(len(self.mutations),2)
