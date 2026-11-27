"""Real owner-read changes on disposable owned files; not cross-UID custody."""
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


class OwnerAccessTest(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0: self.skipTest('owner backend deliberately refuses root')
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.parent=Path(self.tmp.name); self.parent.chmod(0o700)
        self.file=self.parent/'owned'; self.file.write_bytes(b'W'); self.file.chmod(0o200)
        self.sentinel=self.parent/'unrelated'; self.sentinel.write_bytes(b'U'); self.sentinel.chmod(0o640)
        self.request={'version':1,'path':str(self.file),'principal':pwd.getpwuid(os.geteuid()).pw_name,
                      'role':'custom_reader','scope':'owned_test','exclusive_owner':True}
        self.exe=str(Path(sys.prefix)/'bin'/'workeros-owner-access')

    def command(self,operation,document):
        result=subprocess.run([self.exe,operation],input=json.dumps(document),capture_output=True,text=True,timeout=5)
        try: receipt=json.loads(result.stdout)
        except Exception: self.fail(f'bad receipt: {result.stdout} {result.stderr}')
        return result,receipt

    def test_real_apply_check_revoke_and_retained_handle(self):
        result,preview=self.command('preview',self.request)
        self.assertEqual((result.returncode,preview['status']),(0,'preview'))
        plan=preview['plan']; self.assertEqual(plan['inode'],str(self.file.stat().st_ino))
        with self.assertRaises(PermissionError): self.file.open('rb')
        result,grant=self.command('apply',plan)
        self.assertEqual((result.returncode,grant['status'],grant['effect']),(0,'grant_verified','observed'))
        reader=self.file.open('rb'); self.addCleanup(reader.close)
        self.assertEqual(reader.read(),b'W'); reader.seek(0)
        result,again=self.command('apply',plan)
        self.assertEqual((result.returncode,again['code'],again['effect']),(0,'already_applied','not_attempted'))
        result,checked=self.command('check',plan); self.assertEqual(checked['status'],'grant_verified')
        result,revoked=self.command('revoke',plan)
        self.assertEqual((result.returncode,revoked['status']),(0,'owner_read_removed'))
        with self.assertRaises(PermissionError): self.file.open('rb')
        self.assertEqual(reader.read(),b'W')
        self.assertEqual(stat.S_IMODE(self.sentinel.stat().st_mode),0o640)
        self.assertEqual(self.sentinel.read_bytes(),b'U')
        result,again=self.command('revoke',plan); self.assertEqual(again['code'],'already_removed')
        result,checked=self.command('check',plan); self.assertEqual(checked['status'],'owner_read_removed')

    def test_wrong_inode_refuses_before_grant(self):
        _,preview=self.command('preview',self.request); plan=preview['plan']; plan['inode']='1'
        result,receipt=self.command('apply',plan)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(receipt['code'],'resource_changed')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o200)
        self.assertFalse((self.parent/'.workeros-grants').exists())

    def test_one_command_apply_returns_plan_for_revoke(self):
        result,grant=self.command('apply',self.request)
        self.assertEqual((result.returncode,grant['status']),(0,'grant_verified'))
        self.assertEqual(grant['plan']['inode'],str(self.file.stat().st_ino))
        self.assertEqual(self.command('check',self.request)[1]['plan'],grant['plan'])
        self.assertEqual(self.command('revoke',grant['plan'])[1]['status'],'owner_read_removed')

    def test_missing_exclusive_control_is_refused(self):
        request=dict(self.request,exclusive_owner=False)
        result,receipt=self.command('apply',request)
        self.assertEqual((result.returncode,receipt['code']),(1,'exclusive_control_required'))
        self.assertFalse((self.parent/'.workeros-grants').exists())
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o200)

    def test_missing_proc_backend_refuses_before_journal(self):
        code=('import sys,runpy,errno; import workeros.owner_access as m; old=m.os.open; '
              'fake=lambda path,*a,**kw: (_ for _ in ()).throw(OSError(errno.ENOENT,"missing")) '
              'if str(path).startswith("/proc/self/fd/") else old(path,*a,**kw); '
              'm.os.open=fake; sys.argv=[sys.argv[1],"apply"]; runpy.run_path(sys.argv[0],run_name="__main__")')
        result=subprocess.run([sys.executable,'-I','-c',code,self.exe],input=json.dumps(self.request),
                              capture_output=True,text=True,timeout=5)
        self.assertEqual((result.returncode,json.loads(result.stdout)['code']),(1,'backend_unavailable'))
        self.assertFalse((self.parent/'.workeros-grants').exists())

    def test_changed_mode_refuses_and_preserves_unrelated_file(self):
        _,preview=self.command('preview',self.request); plan=preview['plan']; self.file.chmod(0o220)
        result,receipt=self.command('apply',plan)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(receipt['code'],'baseline_not_write_only')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o220)
        self.assertEqual(stat.S_IMODE(self.sentinel.stat().st_mode),0o640)
        self.assertFalse((self.parent/'.workeros-grants').exists())

    def test_wrong_principal_and_unrecorded_revoke_are_refused(self):
        wrong=dict(self.request,principal='root')
        result,receipt=self.command('preview',wrong)
        self.assertEqual(receipt['code'],'principal_not_current_owner')
        _,preview=self.command('preview',self.request)
        result,receipt=self.command('revoke',preview['plan'])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(receipt['code'],'journal_missing')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o200)

    def test_symlink_is_not_followed(self):
        link=self.parent/'link'; link.symlink_to(self.file.name)
        result,receipt=self.command('preview',dict(self.request,path=str(link)))
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o200)

    def test_revoke_refuses_external_mode_change(self):
        _,preview=self.command('preview',self.request); plan=preview['plan']
        self.assertEqual(self.command('apply',plan)[1]['status'],'grant_verified')
        self.file.chmod(0o640)
        result,receipt=self.command('revoke',plan)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(receipt['code'],'resource_changed')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o640)

    def test_post_effect_journal_failure_is_unknown_and_not_replayed(self):
        _,preview=self.command('preview',self.request); plan=preview['plan']
        code=('import sys,runpy; import workeros.owner_access as m; old=m._write; '
              'defect=lambda store,key,payload: (_ for _ in ()).throw(OSError("lost")) '
              'if key.record_id=="grant_result" else old(store,key,payload); '
              'm._write=defect; sys.argv=[sys.argv[1],"apply"]; runpy.run_path(sys.argv[0],run_name="__main__")')
        result=subprocess.run([sys.executable,'-I','-c',code,self.exe],input=json.dumps(plan),
                              capture_output=True,text=True,timeout=5)
        self.assertEqual(json.loads(result.stdout)['status'],'unknown')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o600)
        self.assertEqual(self.command('apply',plan)[1]['code'],'reconcile_required')
        self.assertEqual(self.command('check',plan)[1]['status'],'unknown')
        self.assertEqual(self.command('check',self.request)[1]['status'],'unknown')

    def test_post_chmod_sync_failure_is_unknown_and_not_replayed(self):
        _,preview=self.command('preview',self.request); plan=preview['plan']
        code=('import sys,runpy; import workeros.owner_access as m; old=m.os.fsync; '
              'inode=int(sys.argv[2]); '
              'fake=lambda fd: (_ for _ in ()).throw(OSError("sync lost")) '
              'if m.os.fstat(fd).st_ino==inode else old(fd); '
              'm.os.fsync=fake; sys.argv=[sys.argv[1],"apply"]; runpy.run_path(sys.argv[0],run_name="__main__")')
        result=subprocess.run([sys.executable,'-I','-c',code,self.exe,plan['inode']],input=json.dumps(plan),
                              capture_output=True,text=True,timeout=5)
        self.assertEqual(json.loads(result.stdout)['status'],'unknown')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o600)
        self.assertEqual(self.command('apply',plan)[1]['code'],'reconcile_required')
        self.assertEqual(self.command('check',plan)[1]['status'],'unknown')
        self.assertEqual(self.command('check',self.request)[1]['status'],'unknown')
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o600)

    def test_unexpected_access_acl_is_refused(self):
        tool=shutil.which('setfacl')
        if not tool: self.skipTest('setfacl unavailable')
        result=subprocess.run([tool,'-m','u:'+str(os.geteuid())+':r--',str(self.file)],capture_output=True)
        if result.returncode: self.skipTest('filesystem does not support mapped-UID access ACL')
        result,receipt=self.command('preview',self.request)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(receipt['code'],'acl_present')
