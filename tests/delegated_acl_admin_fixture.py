"""Run only in an authorized disposable Linux VM as root; changes its temp files only.

Usage: python3 delegated_acl_admin_fixture.py WHEEL SHA256 [--registered|--stock-registered|--stock-profile]
The installed package and its base Python must be administrator-owned. Requires
an existing nobody account and /usr/bin/setpriv; creates no users or services.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from time import time

from workeros.verify_install import verify_install


def verify_profile(entry, registry, base, setpriv, system_python):
    data = base / 'data'
    data.mkdir(mode=0o711)
    expiry = int(time()) + 180
    parties = [pwd.getpwnam(name) for name in ('nobody', 'daemon')]
    if len({party.pw_uid for party in parties} | {0}) != 3:
        raise RuntimeError('two existing unprivileged fixture principals required')
    files = [data / name for name in ('report', 'inventory', 'result')]
    roles, grants, registrations = [], [], []
    for index, (file, party) in enumerate(zip(files, (*parties, parties[0]), strict=True)):
        file.write_bytes(b'fixture\n')
        file.chmod(0o600)
        info = file.stat()
        scope, role, operation = file.name, f'role-{index}', f'check-{file.name}'
        cap = {'name': f'fixture-{file.name}', 'operation': operation, 'access': 2 if index == 2 else 4}
        device, inode = str(info.st_dev), str(info.st_ino)
        if index < 2:
            roles.append({'name': role, 'principal': party.pw_name, 'operations': [operation], 'scopes': [scope],
                          'expires_at': expiry, 'resources': {}, 'privileged': []})
        else:
            role = roles[0]['name']
            roles[0]['operations'].append(operation)
            roles[0]['scopes'].append(scope)
        approved = roles[0] if index == 2 else roles[index]
        approved['resources'][scope] = {'device': device, 'inode': inode}
        approved['privileged'].append({'capability': cap['name'], 'scope': scope, 'approved': True})
        grants.append({'capability': cap['name'], 'role': role, 'scope': scope, 'path': str(file),
                       'principal_uid': party.pw_uid, 'exclusive_admin': True, 'expiry': 'manual'})
        registrations.append({'capability': cap, 'profile': 'fixture', 'revision': 'v1', 'role': role, 'scope': scope,
                              'principal_uid': party.pw_uid, 'path': str(file), 'device': device, 'inode': inode,
                              'maximum_access': cap['access'], 'expires_at': expiry})
    roles[0]['operations'].append('launch')
    document = {'version': 1, 'profile': 'fixture', 'revision': 'v1', 'roles': roles, 'grants': grants}
    raw = json.dumps(document)
    store = Path('/var/lib/workeros')

    def manage(*args, payload=None, code=0):
        result = subprocess.run([entry, 'managed', *args], input=payload, capture_output=True, text=True, timeout=10)
        if result.returncode != code:
            raise RuntimeError(f'{args}: unexpected result {result.returncode} {result.stdout}')
        return json.loads(result.stdout)

    def ordinary(party, *args, payload=None):
        return subprocess.run([setpriv, f'--reuid={party.pw_uid}', f'--regid={party.pw_gid}', '--clear-groups', *args],
                              input=payload, capture_output=True, text=True, timeout=10)

    def opens():
        check = ('import sys\ntry:\n with open(sys.argv[1], "rb") as stream: assert stream.read() == b"fixture\\n"\n'
                 'except PermissionError: sys.exit(77)')
        return [[ordinary(party, system_python, '-I', '-c', check, file).returncode for file in files]
                for party in parties]

    denied = [[77, 77, 77], [77, 77, 77]]
    restricted = [[0, 77, 77], [77, 0, 77]]
    assert opens() == denied
    assert manage('apply-profile', '--registered-file-acl', payload=raw, code=1)['code'] == 'native_acl_registration_unavailable'
    registry.parent.mkdir(mode=0o700)
    registry.write_text(json.dumps({'version': 1, 'registrations': registrations}))
    registry.chmod(0o600)
    grants[0]['expiry'] = 'automatic'
    assert manage('apply-profile', '--registered-file-acl', payload=json.dumps(document),
                  code=1)['code'] == 'automatic_acl_expiry_unsupported'
    grants[0]['expiry'] = 'manual'
    grants[0]['enforcement'] = 'process'
    assert manage('apply-profile', '--registered-file-acl', payload=json.dumps(document),
                  code=1)['code'] == 'process_scoped_enforcement_unavailable'
    del grants[0]['enforcement']
    preview = manage('apply-profile', '--registered-file-acl', '--preview', payload=raw)
    assert preview['status'] == 'preview' and not store.exists() and opens() == denied
    # Discard this reply as a client disconnect would. The next command reads
    # the pinned state from an independent process, with no second mutation.
    manage('apply-profile', '--registered-file-acl', payload=raw)
    status = manage('profile-status', 'fixture', 'v1')
    assert status['status'] == 'file_acl_verified' and status['grant_effect'] == 'not_attempted'
    assert status['setup_attachment'] == 'not_checked' and status['runtime_evidence'] == 'not_requested'
    assert opens() == restricted
    repeat = manage('apply-profile', '--registered-file-acl', payload=raw)
    assert repeat['status'] == 'file_acl_verified' and repeat['grant_effect'] == 'not_attempted'

    # The trusted fixture launches installed WorkerOS as the existing worker
    # UID. The same policy runs a fixed inert executable with an authorized
    # file, one writable output and a crossed file. The executable checks the
    # real child UID and writes only to the disposable output.
    worker = base / 'worker'
    worker.write_text(f'#!{system_python}\nimport os, sys\n'
                      f'assert os.getuid() == os.geteuid() == {parties[0].pw_uid}\n'
                      f'try:\n with open({str(files[1])!r}, "rb"): sys.exit(78)\n'
                      'except PermissionError: pass\n'
                      f'try:\n with open({str(files[0])!r}, "rb") as source: assert source.read() == b"fixture\\n"\n'
                      'except PermissionError: sys.exit(77)\n'
                      f'try:\n with open({str(files[2])!r}, "wb") as output: output.write(b"written\\n")\n'
                      'except PermissionError: sys.exit(79)\n')
    worker.chmod(0o555)
    executable_sha256 = sha256(worker.read_bytes()).hexdigest()

    def check_executable():
        info = worker.stat()
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o555
        assert sha256(worker.read_bytes()).hexdigest() == executable_sha256

    policy = {'version': 1, 'roles': {'role-0': {'operations': ['launch']}},
              'workflows': {'job': {'role': 'role-0', 'operations': ['launch'],
                                    'bindings': {'executable': 'worker', 'supervisor': 'direct-child'},
                                    'timeout_ms': 3000, 'cleanup_ms': 1000, 'require_supervision': True}}}
    policy_path = base / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    yaml_path = base / 'policy.yaml'
    yaml_path.write_text("""version: 1
roles:
  role-0:
    operations: [launch]
workflows:
  job:
    role: role-0
    operations: [launch]
    bindings:
      executable: worker
      supervisor: direct-child
    timeout_ms: 3000
    cleanup_ms: 1000
    require_supervision: true
""")
    invocation = {'version': 1, 'workflow': 'job', 'role': 'role-0', 'operation': 'launch',
                  'options': {'name': 'fixture-worker', 'supervise': True}}

    def run_worker(expected_returncode, *, path=policy_path, format='json', command=entry):
        check_executable()
        run = ordinary(parties[0], command, 'config', '--run-policy', path, '--format', format,
                       '--policy-sha256', sha256(path.read_bytes()).hexdigest(),
                       '--executable', 'worker', worker, payload=json.dumps(invocation))
        reply = json.loads(run.stdout)
        terminal = reply['result']['terminal']
        assert (terminal['returncode'], terminal['cleanup']['status']) == (str(expected_returncode), 'reaped'), reply
        return run.returncode

    assert run_worker(0) == 0
    assert files[2].read_bytes() == b'written\n'
    assert run_worker(0, path=yaml_path, format='yaml', command=entry.with_name('wos')) == 0
    denied_role = ordinary(parties[0], entry, 'config', '--run-policy', policy_path, '--executable', 'worker', worker,
                           payload=json.dumps({**invocation, 'role': 'unapproved-role'}))
    refusal = json.loads(denied_role.stdout)
    assert (denied_role.returncode, refusal['status'], refusal['code']) == (
        1, 'refused', 'workflow_operation_not_enrolled'), refusal

    api_source = """
import json, pathlib, sys
from workeros.configuration import decode_request
from workeros.enrollment import HostBindings, compile_policy, decode_policy

path, worker = sys.argv[1:]
host = HostBindings(executables={'worker': (worker,)}, supervisors=frozenset({'direct-child'}),
                    authorize=lambda req: (req.workflow, req.role, req.operation) == ('job', 'role-0', 'launch'))
policy = compile_policy(decode_policy(pathlib.Path(path).read_bytes()), host)
request = decode_request(sys.stdin.buffer.read())
result = policy.execute(request)
workflow = policy[request.workflow]
name = request.options['name']
terminal = workflow.supervisor.wait(name, due_ns=workflow.deadline_ns, cleanup_due_ns=workflow.cleanup_deadline_ns)
cleanup = workflow.supervisor.cleanup(name, due_ns=workflow.cleanup_deadline_ns)
print(json.dumps({'delivery': result['delivery'], 'returncode': terminal.returncode, 'cleanup': cleanup.status.value}))
"""
    check_executable()
    api = ordinary(parties[0], entry.parent / 'python', '-I', '-c', api_source, policy_path, worker,
                   payload=json.dumps(invocation))
    assert api.returncode == 0 and json.loads(api.stdout) == {'delivery': 'dispatched', 'returncode': 0, 'cleanup': 'reaped'}, api.stderr
    registry.unlink()
    revoked = manage('revoke-profile', 'fixture', 'v1')
    assert revoked['status'] == 'revoked' and opens() == denied
    assert [row['grant']['acl_presence'] for row in revoked['file_access']] == ['absent'] * 3
    assert manage('revoke-profile', 'fixture', 'v1')['grant_effect'] == 'not_attempted'
    assert manage('profile-status', 'fixture', 'v1', code=1)['status'] == 'revoked'
    denied_job_status = run_worker(77)
    assert denied_job_status == 3
    print(json.dumps({'status': 'passed', 'fixture': 'disposable', 'profile': 'fixture',
                      'principal_uids': [party.pw_uid for party in parties],
                      'file_access': ['denied', 'scoped', 'denied'], 'crossed_file': 'denied',
                      'apply_repeat': 'readback_only', 'revocation': 'readback_verified',
                      'worker': {'granted_exit': 0, 'revoked_exit': 77, 'revoked_cli_exit': denied_job_status,
                                 'operations': ['launch', 'scoped-read', 'scoped-write'], 'executable_sha256': executable_sha256,
                                 'surfaces': ['config-json', 'wos-config-yaml', 'python-api'],
                                 'supervision_cleanup': 'reaped'}, 'provider_independence': 'not_tested'}))


def main():
    multi = sys.argv[3:] == ['--stock-profile']
    stock = multi or sys.argv[3:] == ['--stock-registered']
    registered = stock or sys.argv[3:] == ['--registered']
    if (len(sys.argv)!=3 and not registered) or os.geteuid()!=0:
        raise SystemExit('requires root in an authorized disposable VM and exact wheel/SHA')
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
    if stock:
        registry = Path('/etc/workeros/file-acl-registrations.json')
        if (not Path('/.dockerenv').is_file() or registry.parent.exists()
                or Path('/var/lib/workeros').exists()):
            raise SystemExit('stock fixture needs a clean disposable container')
    with tempfile.TemporaryDirectory(prefix='workeros-acl-fixture-') as raw:
        base=Path(raw); base.chmod(0o711)
        if multi:
            verify_profile(entry, registry, base, setpriv, system_python)
            return
        config=Path('/var/lib') if stock else base/'config'
        if not stock:
            config.mkdir(mode=0o700)
        data=base/'data'; data.mkdir(); data.chmod(0o711)
        file=data/'input'; file.write_bytes(b'W'); file.chmod(0o600)
        other=data/'other'; other.write_bytes(b'U'); other.chmod(0o640)
        info=file.stat()
        capability='fixture-native-file-read' if registered else 'named_uid_read_acl'
        operation='inspect-fixture-report' if registered else 'read'
        expiry=int(time())+300
        declaration={'version':1,'profile':'fixture','revision':'v1','roles':[{'name':'reader',
            'principal':'nobody','operations':[operation],'scopes':['input'],'expires_at':expiry,
            'privileged':[{'capability':capability,'scope':'input','approved':True}],
            'resources':{'input':{'device':str(info.st_dev),'inode':str(info.st_ino)}}}]}
        document={**declaration,'grant':{'capability':capability,'role':'reader','scope':'input',
                  'path':str(file),'principal_uid':target.pw_uid,'exclusive_admin':True}}
        approval=json.dumps({
            'capability': {'name':capability,'operation':operation,'access':4},
            'profile':'fixture','revision':'v1','role':'reader','scope':'input',
            'principal_uid':target.pw_uid,'path':str(file),'device':str(info.st_dev),
            'inode':str(info.st_ino),'maximum_access':4,'expires_at':expiry,
        }) if registered else ''
        # Only the product's trusted-root configuration parent is redirected
        # to this disposable fixture; the installed console script is executed.
        wrapper='''
import json, runpy, sys
from workeros import roles_cli
roles_cli._PARENT, entry, approval, *args = sys.argv[1:]
if approval and args[:2] == ['managed', 'apply-profile']:
    from workeros.delegated_acl import FileAclCapability, FileAclRegistration
    from workeros.managed_cli import main
    policy = json.loads(approval)
    capability = FileAclCapability(**policy.pop('capability'))
    raise SystemExit(main(args[1:], acl_registrations=(FileAclRegistration(capability=capability, **policy),)))
sys.argv = [entry, *args]
runpy.run_path(entry, run_name="__main__")
'''
        def command(*args,document,code=0):
            if stock:
                command_args = [str(entry), *args]
                if args[:2] == ('managed', 'apply-profile'):
                    command_args.append('--registered-file-acl')
            else:
                command_args = [sys.executable,'-I','-c',wrapper,str(config),str(entry),approval,*args]
            result=subprocess.run(command_args,
                 input=json.dumps(document),capture_output=True,text=True,timeout=10)
            if result.returncode != code: raise RuntimeError(' '.join(args)+' unexpected: '+result.stdout)
            return json.loads(result.stdout)
        def try_read():
            command=[setpriv,'--reuid='+str(target.pw_uid),'--regid='+str(target.pw_gid),'--clear-groups',
                     system_python,'-I','-c',
                     'import sys\ntry:\n with open(sys.argv[1],"rb") as source: print(source.read().decode())\n'
                     'except PermissionError: sys.exit(77)',str(file)]
            return subprocess.run(command,capture_output=True,text=True,timeout=10)
        if try_read().returncode!=77: raise RuntimeError('baseline fresh open was not denied')
        if stock:
            refused = command('managed','apply-profile',document=document,code=1)
            if refused['code'] != 'native_acl_registration_unavailable':
                raise RuntimeError('missing administrator registry was not refused')
            registry.parent.mkdir(mode=0o700)
            policy=json.loads(approval)
            registry.write_text(json.dumps({'version':1,'registrations':[policy]}))
            registry.chmod(0o600)
            wrong = command('managed','apply-profile',document={**document,'revision':'wrong'},code=1)
            if wrong['code'] != 'native_grant_outside_approval' or (config/'workeros').exists():
                raise RuntimeError('wrong revision was not refused before writing')
        preview=command('managed','apply-profile','--preview',document=document)
        if (preview['status']!='preview' or preview['effect']!='not_attempted'
                or (config/'workeros').exists() or (data/'.workeros-acl-grants').exists()
                or try_read().returncode!=77):
            raise RuntimeError('preview changed state or file access')
        applied=command('managed','apply-profile',document=document)
        plan=applied['grant_plan']
        if applied['status']!='file_acl_verified' or plan!=preview['grant_plan']:
            raise RuntimeError('integrated apply did not verify the exact previewed grant')
        repeated=command('managed','apply-profile',document=document)
        if repeated['status']!='file_acl_verified' or repeated['grant_effect']!='not_attempted':
            raise RuntimeError('repeated apply did not perform readback only')
        grant=applied['grant']
        checked=command('roles','grant-check',document=plan)
        during=try_read()
        if (grant['status']!='acl_entry_verified' or checked['status']!='acl_entry_verified'
                or checked['acl_presence']!='present_exact' or checked['effect']!='not_attempted'
                or during.returncode!=0 or during.stdout.strip()!='W'):
            raise RuntimeError('grant or separate-principal read failed')
        if stock:
            registry.unlink()  # Historical journal pins must still support cleanup.
        revoked=command('roles','grant-revoke',document=plan)
        retired=command('roles','grant-check',document=plan)
        if (revoked['status']!='acl_entry_removed' or retired['status']!='acl_entry_removed'
                or retired['acl_presence']!='absent' or retired['effect']!='not_attempted'
                or stat.S_IMODE(file.stat().st_mode)!=0o600 or try_read().returncode!=77):
            raise RuntimeError('revocation did not block a fresh open')
        binding=('principal_uid','device','inode','attempt')
        expected=(target.pw_uid,str(info.st_dev),str(info.st_ino),preview['grant']['attempt'])
        for receipt in (preview['grant'],grant,repeated['grant'],checked,revoked,retired):
            if (tuple(receipt[key] for key in binding)!=expected
                    or receipt['independent_observer']!='not_verified'):
                raise RuntimeError('receipt did not retain the exact principal and file binding')
        if stat.S_IMODE(other.stat().st_mode)!=0o640 or other.read_bytes()!=b'U':
            raise RuntimeError('unrelated fixture changed')
        print(json.dumps({'status':'passed','fixture':'disposable','provider_independence':'not_tested',
             'stock_admin_registry':stock,
             'capability':capability,'operation':operation,
             'principal_uid':target.pw_uid,'device':str(info.st_dev),'inode':str(info.st_ino),
             'preview':preview['status'],'integrated_apply':applied['status'],'grant_readback':checked['acl_presence'],
             'separate_principal_fresh_opens':['denied','allowed','denied'],
             'revocation':revoked['status'],'revocation_readback':retired['acl_presence']}))


if __name__=='__main__': main()
