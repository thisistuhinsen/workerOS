"""No-privilege ACL schema and refusal tests; not a cross-UID grant."""
import errno
from contextlib import nullcontext
import json
import os
from pathlib import Path
import pwd
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

from workeros import delegated_acl


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
