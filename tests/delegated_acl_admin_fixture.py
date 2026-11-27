"""Run only in an authorized disposable Linux VM as root; changes its temp files only.

Usage: python3 delegated_acl_admin_fixture.py WHEEL SHA256
The installed package and its base Python must be administrator-owned. Requires
an existing nobody account and /usr/bin/setpriv; creates no users or services.
"""
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from time import time

from worker_handoff.verify_install import verify_install


def main():
    if len(sys.argv)!=3 or os.geteuid()!=0: raise SystemExit('requires root in an authorized disposable VM and exact wheel/SHA')
    verify_install(sys.argv[1],sys.argv[2])
    target=pwd.getpwnam('nobody')
    if target.pw_uid==0 or target.pw_gid==0: raise SystemExit('nobody is not a distinct non-root principal')
    setpriv='/usr/bin/setpriv'
    system_python=str(Path(sys.base_prefix)/'bin'/'python3')
    for program in (setpriv,system_python):
        try: info=os.stat(program)
        except OSError: raise SystemExit('required fixed system tool unavailable') from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise SystemExit('required fixed system tool is not administrator-owned')
    entry=Path(sys.prefix)/'bin'/'workeros'
    if not entry.is_file(): raise SystemExit('installed workeros missing')
    with tempfile.TemporaryDirectory(prefix='workeros-acl-fixture-') as raw:
        base=Path(raw); base.chmod(0o711)
        config=base/'config'; config.mkdir(mode=0o700)
        data=base/'data'; data.mkdir(mode=0o711)
        file=data/'input'; file.write_bytes(b'W'); file.chmod(0o600)
        other=data/'other'; other.write_bytes(b'U'); other.chmod(0o640)
        info=file.stat()
        declaration={'version':1,'profile':'fixture','revision':'v1','roles':[{'name':'reader',
            'principal':'nobody','operations':['read'],'scopes':['input'],'expires_at':int(time())+300,
            'resources':{'input':{'device':str(info.st_dev),'inode':str(info.st_ino)}}}]}
        plan={'version':1,'profile':'fixture','revision':'v1','role':'reader','scope':'input',
              'path':str(file),'exclusive_admin':True}
        # Only the product's trusted-root configuration parent is redirected
        # to this disposable fixture; the installed console script is executed.
        wrapper=('import sys,runpy; import worker_handoff.roles_cli as m; '
                 'm._PARENT=sys.argv[1]; sys.argv=[sys.argv[2]]+sys.argv[3:]; '
                 'runpy.run_path(sys.argv[0],run_name="__main__")')
        def command(op,document):
            result=subprocess.run([sys.executable,'-I','-c',wrapper,str(config),str(entry),'roles',op],
                 input=json.dumps(document),capture_output=True,text=True,timeout=10)
            if result.returncode: raise RuntimeError(op+' refused: '+result.stdout)
            return json.loads(result.stdout)
        def try_read():
            command=[setpriv,'--reuid='+str(target.pw_uid),'--regid='+str(target.pw_gid),'--clear-groups',
                     system_python,'-I','-c',
                     'import sys\ntry:\n with open(sys.argv[1],"rb") as source: print(source.read().decode())\n'
                     'except PermissionError: sys.exit(77)',str(file)]
            return subprocess.run(command,capture_output=True,text=True,timeout=10)
        command('apply',declaration)
        if try_read().returncode!=77: raise RuntimeError('baseline fresh open was not denied')
        preview=command('grant-preview',plan)
        grant=command('grant-apply',plan)
        checked=command('grant-check',plan)
        during=try_read()
        if (grant['status']!='acl_entry_verified' or checked['status']!='acl_entry_verified'
                or checked['acl_presence']!='present_exact' or checked['effect']!='not_attempted'
                or during.returncode!=0 or during.stdout.strip()!='W'):
            raise RuntimeError('grant or separate-principal read failed')
        revoked=command('grant-revoke',plan)
        retired=command('grant-check',plan)
        if (revoked['status']!='acl_entry_removed' or retired['status']!='acl_entry_removed'
                or retired['acl_presence']!='absent' or retired['effect']!='not_attempted'
                or stat.S_IMODE(file.stat().st_mode)!=0o600 or try_read().returncode!=77):
            raise RuntimeError('revocation did not block a fresh open')
        binding=('principal_uid','device','inode','attempt')
        expected=(target.pw_uid,str(info.st_dev),str(info.st_ino),preview['attempt'])
        for receipt in (preview,grant,checked,revoked,retired):
            if (tuple(receipt[key] for key in binding)!=expected
                    or receipt['independent_observer']!='not_verified'):
                raise RuntimeError('receipt did not retain the exact principal and file binding')
        if stat.S_IMODE(other.stat().st_mode)!=0o640 or other.read_bytes()!=b'U':
            raise RuntimeError('unrelated fixture changed')
        print(json.dumps({'status':'passed','fixture':'disposable','provider_independence':'not_tested',
             'principal_uid':target.pw_uid,'device':str(info.st_dev),'inode':str(info.st_ino),
             'preview':preview['status'],'grant':grant['status'],'grant_readback':checked['acl_presence'],
             'separate_principal_fresh_opens':['denied','allowed','denied'],
             'revocation':revoked['status'],'revocation_readback':retired['acl_presence']}))


if __name__=='__main__': main()
