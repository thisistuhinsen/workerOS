"""Installed unified entry points; YAML loader is optional and fixture-only."""
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import pwd
import pty
import shutil
import subprocess
import sys
import tempfile
import unittest


class UnifiedCliTest(unittest.TestCase):
    def setUp(self):
        self.bin=Path(sys.prefix)/'bin'
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.root.chmod(0o700)
        self.principal=pwd.getpwuid(os.geteuid()).pw_name
        self.document={'version':1,'profile':'custom','revision':'v1','roles':[{'name':'reader',
            'principal':self.principal,'operations':['read'],'scopes':['archive'],'expires_at':4102444800}]}
        self.yaml=('version: 1\nprofile: custom\nrevision: v1\nroles:\n  - name: reader\n'
                   '    principal: '+self.principal+'\n    operations: [read]\n    scopes: [archive]\n'
                   '    expires_at: 4102444800\n')

    def call(self,name,args=(),data=None,env=None):
        return subprocess.run([str(self.bin/name),*args],input=data,text=True,capture_output=True,timeout=8,env=env)

    def patched(self,python,entry,args,data):
        code=('import sys,runpy; import workeros.roles_cli as r; '
              'r._PARENT=sys.argv[1]; r._UID=int(sys.argv[2]); '
              'sys.argv=[sys.argv[3]]+sys.argv[4:]; runpy.run_path(sys.argv[0],run_name="__main__")')
        return subprocess.run([str(python),'-I','-c',code,str(self.root),str(os.getuid()),str(entry),*args],
                              input=data,text=True,capture_output=True,timeout=8)

    def test_bare_alias_help_and_redirected_no_color(self):
        environment=dict(os.environ,NO_COLOR='1',TERM='dumb')
        left=self.call('workeros',env=environment); right=self.call('wos',env=environment)
        self.assertEqual((left.returncode,right.returncode),(0,0))
        self.assertEqual(left.stdout,right.stdout)
        self.assertIn('Run a job. Know how it ended.',left.stdout)
        self.assertIn('workeros help config',left.stdout)
        self.assertIn('workeros roles guide',left.stdout)
        self.assertIn('workeros help formats',left.stdout)
        self.assertIn('workeros managed reconcile',left.stdout)
        self.assertIn('First run:',left.stdout)
        self.assertIn(f'Version: {version("workeros")}\n',left.stdout)
        self.assertIn('  hello\n  job: exited 0',left.stdout)
        self.assertIn('install-0.8.0.md',left.stdout)
        self.assertIn('support.md#troubleshooting',left.stdout)
        self.assertNotIn('\x1b',left.stdout)
        self.assertEqual(left.stderr,'')
        for name in ('workeros','wos'):
            for args in (('-h',),('--help',),('help',),('help','start')):
                with self.subTest(name=name,args=args):
                    result=self.call(name,args,env=environment)
                    self.assertEqual((result.returncode,result.stdout,result.stderr),(0,left.stdout,''))

    def test_topics_and_subcommand_help_are_actionable(self):
        for args,expected in ((['help','install'],'--no-index'),(['help','run'],'workeros run --'),(['help','file'],'run_inherited_fd.py'),(['help','formats'],'duplicate keys'),
                              (['help','install'],'v0.7.0/docs/install.md'),(['help','install'],'use its release assets after publication'),
                              (['help','install'],'upgrade-and-roll-back'),(['help','install'],'support.md#troubleshooting'),
                              (['roles','grant-apply','--help'],'grant-read-access-to-one-linux-file'),
                              (['help','config'],'docs/start/config.md#run-from-json-v080'),
                              (['help','config'],'docs/start/config.md#run-from-yaml'),
                              (['help','formats'],'yaml_dependency_missing'),
                              (['roles','--help'],'grant-check'),(['roles','apply','--help'],'creates no principal'),
                              (['help','managed'],'named_uid_read_acl'),
                              (['help','managed'],'apply-a-profile-and-verify-a-file-grant'),
                              (['help','managed'],'does not replay it'),
                              (['managed','--help'],'reconcile')):
            with self.subTest(args=args):
                result=self.call('workeros',args)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn(expected,result.stdout)
                self.assertNotIn('\x1b',result.stdout)

    def test_installed_run_alias_and_legacy_parity(self):
        outputs=[]
        for name,args in (('workeros',['run','--','/usr/bin/printf','hello\n']),
                          ('wos',['run','--','/usr/bin/printf','hello\n']),
                          ('workeros-demo',['--','/usr/bin/printf','hello\n'])):
            result=self.call(name,args); self.assertEqual(result.returncode,0,result.stderr); outputs.append(result.stdout)
        self.assertEqual(outputs,['hello\njob: exited 0\n']*3)

    def test_version_flag_and_structured_run_output(self):
        version=self.call('workeros',['--version'])
        self.assertEqual(version.returncode,0)
        self.assertTrue(version.stdout.startswith('WorkerOS 0.8.0'))
        result=self.call('workeros',['run','--json','--','/usr/bin/printf','hello\n'])
        self.assertEqual(result.returncode,0,result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual((receipt['status'],receipt['effect']),('reported','unknown'))
        self.assertEqual(receipt['result']['terminal']['lifecycle'],'exited')
        self.assertEqual(receipt['result']['terminal']['returncode'],'0')
        self.assertEqual(receipt['result']['terminal']['cleanup']['status'],'reaped')
        self.assertEqual(result.stderr,'hello\n')
        malformed=self.call('workeros',['run','--json','/usr/bin/printf','must-not-run'])
        self.assertEqual(malformed.returncode,1)
        refused=json.loads(malformed.stdout)
        self.assertEqual((refused['code'],refused['effect']),('json_command_required','not_attempted'))
        missing=self.call('workeros',['run','--json','--','/definitely/not/a/worker'])
        self.assertEqual(missing.returncode,1)
        receipt=json.loads(missing.stdout)
        self.assertEqual((receipt['code'],receipt['effect']),('command_start_failed','not_attempted'))

    def test_structured_run_timeout_reports_cleanup_separately(self):
        command = shutil.which('sleep')
        self.assertIsNotNone(command, 'sleep is required on PATH for the timeout test')
        result=self.call('workeros',['run','--json','--',command,'10'])
        self.assertEqual(result.returncode,1)
        receipt=json.loads(result.stdout)
        self.assertEqual((receipt['status'],receipt['effect']),('reported','unknown'))
        self.assertEqual(receipt['result']['terminal']['lifecycle'],'timed_out')
        self.assertEqual(receipt['result']['terminal']['cleanup']['status'],'reaped')

    def test_structured_run_passes_piped_stdin_without_mixing_the_receipt(self):
        data = 'first line\nsecond line\n'
        command = shutil.which('cat')
        self.assertIsNotNone(command, 'cat is required on PATH for the piped input test')
        result=self.call('workeros',['run','--json','--',command],data=data)
        self.assertEqual((result.returncode,result.stderr),(0,data))
        receipt=json.loads(result.stdout)
        self.assertEqual((receipt['status'],receipt['result']['terminal']['returncode']),('reported','0'))

    def test_tty_guide_refuses_when_output_is_redirected(self):
        master,slave=pty.openpty()
        process=subprocess.Popen([str(self.bin/'workeros'),'roles','guide'],stdin=slave,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        os.close(slave)
        try:
            out,err=process.communicate(timeout=3)
        finally:
            os.close(master)
        self.assertEqual(process.returncode,1)
        receipt=json.loads(out)
        self.assertEqual((receipt['code'],receipt['effect']),('tty_required','not_attempted'))
        self.assertEqual(err,'')

    def test_fresh_offline_install_first_job(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact wheel path not supplied')
        local=self.root/Path(wheel).name; shutil.copyfile(wheel,local)
        venv = self.root/"reader's test env"
        created=subprocess.run([sys.executable,'-m','venv',str(venv)],capture_output=True,text=True,timeout=20)
        self.assertEqual(created.returncode,0,created.stderr)
        py=venv/'bin'/'python'
        installed=subprocess.run([str(py),'-m','pip','install','--no-index','--no-deps',str(local)],
                                 capture_output=True,text=True,timeout=20)
        self.assertEqual(installed.returncode,0,installed.stderr)
        cli=venv/'bin'/'workeros'
        result=subprocess.run([str(cli),'run','--','/usr/bin/printf','hello\n'],
                              cwd=self.root,capture_output=True,text=True,timeout=8)
        self.assertEqual((result.returncode,result.stdout),(0,'hello\njob: exited 0\n'))
        help_result = subprocess.run([str(cli),'help','file'], cwd=self.root,
                                     capture_output=True,text=True,timeout=8)
        self.assertEqual(help_result.returncode,0,help_result.stderr)
        alias_result = subprocess.run([str(cli.with_name('wos')),'help','file'], cwd=self.root,
                                      capture_output=True,text=True,timeout=8)
        self.assertEqual((alias_result.returncode,alias_result.stdout),(0,help_result.stdout))
        literal = next(line.strip() for line in help_result.stdout.splitlines() if line.startswith('  '))
        example = subprocess.run(['sh','-c',literal], cwd=self.root,
                                 capture_output=True,text=True,timeout=12)
        self.assertEqual(example.returncode,0,example.stderr)
        self.assertIn('Python: PASSED',example.stdout)

    def test_json_schema_and_managed_preview_match_legacy(self):
        self.assertEqual(self.call('workeros',['config','--schema']).stdout,self.call('workeros-config',['--schema']).stdout)
        new=self.call('workeros',['managed','preview']); old=self.call('workeros-managed',['preview'])
        self.assertEqual((new.returncode,new.stdout),(old.returncode,old.stdout))

    def test_role_preview_matches_legacy_and_status_alias(self):
        python=Path(sys.executable)
        document=json.dumps(self.document)
        new=self.patched(python,self.bin/'workeros',['roles','preview'],document)
        old=self.patched(python,self.bin/'workeros-roles',['preview'],document)
        self.assertEqual((new.returncode,new.stdout),(old.returncode,old.stdout))
        apply=self.patched(python,self.bin/'workeros',['roles','apply'],document)
        self.assertEqual(apply.returncode,0,apply.stderr)
        status=self.patched(python,self.bin/'workeros',['roles','status','custom','v1'],None)
        show=self.patched(python,self.bin/'workeros-roles',['show','custom','v1'],None)
        self.assertEqual((status.returncode,status.stdout),(show.returncode,show.stdout))

    def test_missing_yaml_is_actionable_and_no_effect(self):
        result=self.call('workeros',['roles','preview','--format','yaml'],self.yaml)
        if result.returncode==0: self.skipTest('default test environment has PyYAML')
        receipt=json.loads(result.stdout)
        self.assertEqual((receipt['code'],receipt['effect']),('yaml_dependency_missing','not_attempted'))
        self.assertIn('PyYAML',receipt['next_action'])
        self.assertNotIn('\x1b',result.stdout)
        self.assertFalse((self.root/'workeros').exists())
        policy=self.root/'policy.yaml'
        policy.write_text('version: 1\n')
        result=self.call('workeros',['config','--check-policy',str(policy),'--format','yaml'])
        self.assertEqual((result.returncode,json.loads(result.stdout),result.stderr),
                         (1,{'status':'refused','code':'yaml_dependency_missing'},''))

    def test_workflow_yaml_uses_common_compiler_and_raw_pin(self):
        yaml_python=os.environ.get('WORKEROS_YAML_PYTHON')
        if not yaml_python: self.skipTest('optional preinstalled YAML test environment unavailable')
        entry=Path(yaml_python).parent/'workeros'
        policy={
            'version':1,
            'roles':{'runner':{'operations':['launch']}},
            'workflows':{'ordinary':{'role':'runner','operations':['launch'],
                                      'bindings':{'executable':'sample'}}},
        }
        json_policy=self.root/'policy.json'
        json_policy.write_text(json.dumps(policy))
        yaml_policy=self.root/'policy.yaml'
        raw=b'''# The original file bytes are the evidence pin.
version: 1
roles:
  runner:
    operations: [launch]
workflows:
  ordinary:
    role: runner
    operations: [launch]
    bindings: {executable: sample}
'''
        yaml_policy.write_bytes(raw)
        digest=sha256(raw).hexdigest()
        json_digest=sha256(json_policy.read_bytes()).hexdigest()

        def run(mode, document, *, flags=(), data=''):
            result=subprocess.run([str(entry),'config',mode,str(document),'--executable','sample',
                                   sys.executable,*flags],input=data,text=True,capture_output=True,timeout=8)
            self.assertEqual(result.stderr,'')
            return result.returncode,json.loads(result.stdout)

        json_exit,json_reply=run('--check-policy',json_policy,flags=('--explain',))
        yaml_flags=('--format','yaml','--policy-sha256',digest)
        yaml_exit,yaml_reply=run('--check-policy',yaml_policy,flags=(*yaml_flags,'--explain'))
        self.assertEqual((json_exit,yaml_exit),(0,0))
        self.assertEqual((json_reply.pop('policy_sha256'),yaml_reply.pop('policy_sha256')),(json_digest,digest))
        self.assertEqual(json_reply,yaml_reply)
        self.assertEqual(yaml_reply['status'],'checked')

        invalid=(1,{'status':'refused','code':'invalid_json'})
        self.assertEqual(run('--check-policy',yaml_policy),invalid)
        self.assertEqual(run('--check-policy',yaml_policy,flags=('--format','yaml','--policy-sha256',json_digest)),
                         (1,{'status':'refused','code':'policy_digest_mismatch'}))
        request=json.dumps({'version':1,'workflow':'missing','role':'runner','operation':'launch',
                            'options':{'name':'probe'}})
        self.assertEqual(run('--run-policy',yaml_policy,flags=yaml_flags,data=request),
                         (1,{'status':'refused','code':'workflow_operation_not_enrolled','policy_sha256':digest}))
        self.assertEqual(run('--run-policy',yaml_policy,flags=yaml_flags,data='version: 1\n'),
                         (1,{'status':'refused','code':'invalid_json','policy_sha256':digest}))
        for malformed in (b'version: 1\nversion: 1\n', b'version: !!int 1\n', b'version: 01\n'):
            yaml_policy.write_bytes(malformed)
            self.assertEqual(run('--check-policy',yaml_policy,flags=('--format','yaml')),
                             (1,{'status':'refused','code':'invalid_yaml'}))

    def test_json_yaml_same_schema_and_revision(self):
        yaml_python=os.environ.get('WORKEROS_YAML_PYTHON')
        if not yaml_python: self.skipTest('optional preinstalled YAML test environment unavailable')
        py=Path(yaml_python); entry=py.parent/'workeros'
        source=json.dumps(self.document)
        preview_json=self.patched(py,entry,['roles','preview'],source)
        preview_yaml=self.patched(py,entry,['roles','preview','--format','yaml'],self.yaml)
        self.assertEqual((preview_json.returncode,preview_yaml.returncode),(0,0),preview_yaml.stderr)
        self.assertEqual(json.loads(preview_json.stdout),json.loads(preview_yaml.stdout))
        apply_json=self.patched(py,entry,['roles','apply'],source)
        apply_yaml=self.patched(py,entry,['roles','apply','--format','yaml'],self.yaml)
        one,two=json.loads(apply_json.stdout),json.loads(apply_yaml.stdout)
        self.assertEqual((apply_json.returncode,apply_yaml.returncode),(0,0))
        self.assertEqual(one['digest'],two['digest'])
        self.assertEqual((one['effect'],two['effect']),('recorded','unchanged'))

    def test_unsafe_yaml_and_duplicate_json_refuse_without_store(self):
        yaml_python=os.environ.get('WORKEROS_YAML_PYTHON')
        if not yaml_python: self.skipTest('optional preinstalled YAML test environment unavailable')
        py=Path(yaml_python); entry=py.parent/'workeros'
        cases=['version: 1\nversion: 1\n','a: &x 1\nb: *x\n','a: 1\n---\na: 2\n',
               'a: !!python/object:builtins.object {}\n','true: value\n', 'a: '+('x'*65537)]
        for value in cases:
            with self.subTest(value=value[:40]):
                result=self.patched(py,entry,['roles','apply','--format','yaml'],value)
                receipt=json.loads(result.stdout)
                self.assertEqual(result.returncode,1)
                self.assertEqual(receipt['effect'],'not_attempted')
                self.assertIn(receipt['code'],('invalid_yaml','document_too_large'))
                self.assertFalse((self.root/'workeros').exists())
        duplicate='{"version":1,"version":1}'
        result=self.patched(py,entry,['roles','apply'],duplicate)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'workeros').exists())

    def test_unknown_command_and_missing_action_return_json(self):
        for args,code in ((['nope'],'unknown_command'),(['run'],'command_required'),
                          (['roles','preview','--format','toml'],'invalid_format')):
            result=self.call('workeros',args)
            self.assertEqual(result.returncode,1)
            self.assertEqual(json.loads(result.stdout)['code'],code)
            self.assertNotIn('\x1b',result.stdout)

    def test_draft_is_valid_profile_without_writes_or_authority(self):
        args=['roles','draft','--profile','custom','--revision','v1','--role','reader',
              '--principal',self.principal,'--scope','archive','--expires-at','4102444800']
        result=self.call('wos',args)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),self.document)
        self.assertFalse((self.root/'workeros').exists())
        bad=self.call('workeros',['roles','draft','--profile','custom'])
        self.assertEqual((bad.returncode,json.loads(bad.stdout)['code']),(1,'invalid_draft'))

    def guided(self,entries):
        in_master,in_slave=pty.openpty()
        out_master,out_slave=pty.openpty()
        try:
            process=subprocess.Popen([str(self.bin/'workeros'),'roles','guide'],stdin=in_slave,
                                     stdout=out_slave,stderr=subprocess.PIPE,text=True,
                                     env=dict(os.environ,NO_COLOR='1',TERM='dumb'))
            os.close(in_slave); in_slave=None
            os.close(out_slave); out_slave=None
            os.write(in_master,entries.encode())
            try: _,err=process.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate(); raise
            chunks=[]
            while True:
                try: chunk=os.read(out_master,4096)
                except OSError: break
                if not chunk: break
                chunks.append(chunk)
            out=b''.join(chunks).decode()
            return process.returncode,out,err
        finally:
            if in_slave is not None: os.close(in_slave)
            if out_slave is not None: os.close(out_slave)
            os.close(in_master); os.close(out_master)

    def test_tty_guide_back_output_and_runnable_preview(self):
        entries='custom\nv1\noldrole\nback\nreader\n'+self.principal+'\narchive\n4102444800\n\n\nn\n'
        code,out,err=self.guided(entries)
        self.assertEqual(code,0,err)
        self.assertEqual(json.loads(out),self.document)
        self.assertIn('No files or access changed.',err)
        self.assertNotIn('\x1b',err)
        self.assertIn('independently installed, trusted WorkerOS',err)
        command=err.split('then preview:\n  ',1)[1].strip()
        self.assertIn('"$ADMIN_WORKEROS" roles preview',command)
        self.assertNotIn(str(self.bin),command)
        result=subprocess.run(['sh','-c',command],capture_output=True,text=True,timeout=8,
                              env=dict(os.environ,ADMIN_WORKEROS=str(self.bin/'workeros')))
        if os.geteuid()!=0:
            self.assertEqual((result.returncode,json.loads(result.stdout)['code']),(1,'administrator_required'))
        self.assertFalse((self.root/'workeros').exists())

    def test_tty_guide_custom_operations(self):
        other=pwd.getpwnam('nobody')
        if other.pw_uid == os.getuid(): self.skipTest('distinct fixture principal unavailable')
        entries='custom\nv1\nreader\n'+self.principal+'\narchive\n4102444800\nread,write,observe\nnobody\nn\n'
        code,out,err=self.guided(entries)
        self.assertEqual(code,0,err)
        self.assertEqual(json.loads(out)['roles'][0]['operations'],['read','write','observe'])
        self.assertEqual(json.loads(out)['roles'][0]['independent_of'],'nobody')
        self.assertFalse((self.root/'workeros').exists())

    def test_tty_guide_multiple_roles_human_expiry_and_validation(self):
        entries=('custom\nv2\nreader\nmissing-worker\n'+self.principal+'\narchive, reports\n'
                 '2099-12-31\nread,observe\n\ny\nwriter\n'+self.principal+'\narchive\n'
                 '+30d\nwrite\n\nn\n')
        code,out,err=self.guided(entries)
        self.assertEqual(code,0,err)
        document=json.loads(out)
        self.assertEqual([role['name'] for role in document['roles']],['reader','writer'])
        self.assertEqual([role['principal'] for role in document['roles']],[self.principal,self.principal])
        self.assertIn(f'reader (account {self.principal}):',err)
        self.assertIn(f'writer (account {self.principal}):',err)
        self.assertEqual(document['roles'][0]['scopes'],['archive','reports'])
        self.assertEqual(document['roles'][0]['expires_at'],4102444800)
        self.assertGreater(document['roles'][1]['expires_at'],int(__import__('time').time())+29*86400)
        self.assertIn('That account does not exist',err)
        self.assertIn('expires 2100-01-01 00:00 UTC',err)
        self.assertIn('no record, grant, or worker is created',err)
        self.assertFalse((self.root/'workeros').exists())

    def test_tty_guide_large_future_timestamp_and_invalid_answer_reprompt(self):
        timestamp=2**52
        entries=f'custom\nv3\nreader\n{self.principal}\narchive\n{timestamp}\nread\n\nmaybe\nn\n'
        code,out,err=self.guided(entries)
        self.assertEqual(code,0,err)
        self.assertEqual(json.loads(out)['roles'][0]['expires_at'],timestamp)
        self.assertIn(f'Unix {timestamp} seconds (outside calendar display range)',err)
        self.assertEqual(err.count('Add another role?'),2)
        self.assertIn('Answer y or n, back, or cancel.',err)
        self.assertFalse((self.root/'workeros').exists())

    def test_tty_guide_cancel_and_non_tty_refusal(self):
        code,out,err=self.guided('cancel\n')
        self.assertEqual((code,json.loads(out)),(1,{'status':'cancelled','effect':'not_attempted'}))
        result=self.call('workeros',['roles','guide'],data='')
        self.assertEqual((result.returncode,json.loads(result.stdout)['code']),(1,'tty_required'))
        self.assertFalse((self.root/'workeros').exists())
