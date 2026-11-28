"""Installed no-start host with inherited handles and a separate synthetic provider."""
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys
import tempfile
from threading import Event, Thread
from time import monotonic, monotonic_ns, time
import unittest

from workeros.appointment_registry import definition_sha256
from workeros.evidence import EvidenceScope, RunBinding
from workeros.managed_bootstrap import _observer, setup_clock_id
from workeros.managed_provider import _serve
from workeros.scope_meter import _cgroup_mount, _mount_id, monotonic_clock_id
from workeros.managed_cli import _read_exact
from workeros.profile_setup import ProfileDefinition, ProviderBinding
from workeros.roles_cli import _canonical


ENTRY = """
import json, os, runpy, sys
from workeros import managed_bootstrap, managed_cli, roles_cli, scope_meter
roles_cli._PARENT = managed_cli._CONFIG_PARENT = sys.argv[1]
roles_cli._UID = managed_cli._TRUSTED_UID = os.getuid()
if sys.argv[2]:
    managed_bootstrap._provider_is_independent = lambda uid: uid == os.getuid()
if sys.argv[2] in ('interval-fixture', 'interval-lost-reply', 'interval-meter-fixture', 'interval-meter-lost'):
    # Substitute only the separate-principal prerequisite in this single-UID
    # fixture; the actual SO_PEERCRED check is still enforced.
    managed_bootstrap._provider_is_independent = lambda uid: True
if sys.argv[2] in ('interval-meter-fixture', 'interval-meter-lost'):
    managed_bootstrap._meter_peer_is_distinct = lambda observer, meter: True
if sys.argv[2] in ('interval-lost-reply', 'interval-meter-lost'):
    serve = managed_cli.serve_connection
    class LostReply:
        def __init__(self, connection): self.connection = connection
        def __getattr__(self, name): return getattr(self.connection, name)
        def sendall(self, _): raise OSError('fixture reply lost after binding check')
    def drop_reply(connection, **options):
        return serve(LostReply(connection), **options)
    managed_cli.serve_connection = drop_reply
if sys.argv[2] == 'synthetic':
    managed_bootstrap._meter_peer_is_distinct = lambda observer, meter: True
if sys.argv[2] == 'interrupt-before-finish':
    from workeros.managed_journal import ManagedJournal
    ManagedJournal.finish = lambda *_args: os._exit(81)
if sys.argv[3]:
    managed_bootstrap.setup_clock_id = lambda: fixture_clock
    managed_bootstrap.monotonic_clock_id = scope_meter.monotonic_clock_id = lambda: 'fixture-monotonic'
fixture_clock = sys.argv[3]
if sys.argv[4] == 'client-config-pipe':
    client_config = json.load(sys.stdin)
    read_admin_json = managed_cli._read_admin_json
    def read_fixture_json(filename):
        if filename == 'managed-host.json':
            return client_config
        return read_admin_json(filename)
    managed_cli._read_admin_json = read_fixture_json
sys.argv = sys.argv[5:]
runpy.run_path(sys.argv[0],run_name='__main__')
"""


class OrdinaryProfileBoundaryTest(unittest.TestCase):
    def test_no_attester_and_other_unsupported_scopes_are_reported_before_binding(self):
        from unittest.mock import patch
        from workeros.managed_bootstrap import _build, _UnsupportedScopes

        def entry(name, providers):
            definition = ProfileDefinition(name, 'revision-1', '0.8.0', 'a'*64, 'b'*64,
                                           'manager', name, 'clock', monotonic_ns()+1_000_000_000,
                                           tuple(providers))
            return {'definition': asdict(definition), 'policy': {'workflows': {
                name: {'bindings': {}}}}, 'role': 'role', 'binding_generation': 'generation'}

        interval = ProviderBinding('witness', 'reference', 'interval-scope', 'interval',
                                   'provider', 'observers', 'writer')
        scopes = [entry('ordinary-scope', ()), entry('interval-scope', (interval,))]
        config = {'version': 2, 'profile': 'profile', 'revision': 'revision-1',
                  'operation_key': 'c'*64, 'authorized_uids': [os.getuid()],
                  'wheel_path': 'unused', 'journal_directory': 'unused',
                  'local_approval': {}, 'scopes': scopes}
        with ExitStack() as resources, \
             patch('workeros.managed_bootstrap.setup_clock_id') as clock, \
             patch('workeros.managed_bootstrap.ManagedJournal') as journal, \
             patch('workeros.managed_bootstrap._bound_scope') as bind:
            with self.assertRaises(_UnsupportedScopes) as caught:
                _build(config, resources)
        clock.assert_not_called()
        journal.assert_not_called()
        bind.assert_not_called()
        self.assertEqual(caught.exception.scopes, [
            {'name': 'ordinary-scope', 'status': 'unavailable',
             'code': 'independent_attester_unavailable'},
            {'name': 'interval-scope', 'status': 'unavailable',
             'code': 'interval_custody_unsupported'},
        ])

    def test_empty_operation_set_cannot_be_compiled_as_authorized_workflow(self):
        from workeros.configuration import ConfigurationError
        from workeros.enrollment import _operations
        with self.assertRaisesRegex(ConfigurationError, '^invalid_operation_list$'):
            _operations([])


class InstalledHostTest(unittest.TestCase):
    def test_interval_provider_is_checked_without_setup_or_runtime(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        for peer_offset in (0, 1):
            with self.subTest(peer_offset=peer_offset), tempfile.TemporaryDirectory() as directory:
                self.exercise(Path(directory), wheel, multiple=False, interval_peer_offset=peer_offset)

    def test_installed_interval_and_meter_share_one_exact_check_only_scope(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        with tempfile.TemporaryDirectory() as directory:
            self.exercise(Path(directory), wheel, multiple=False, interval_peer_offset=0, interval_meter=True)

    def test_apply_serve_restart_and_require_external_evidence(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        with tempfile.TemporaryDirectory() as directory:
            self.exercise(Path(directory), wheel, multiple=False)

    def test_distinct_scopes_with_named_original_and_separately_attested_meter(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        with tempfile.TemporaryDirectory() as directory:
            self.exercise(Path(directory), wheel, multiple=True)

    def test_stock_point_provider_completes_setup_and_authoritative_readback(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        with tempfile.TemporaryDirectory() as directory:
            self.exercise(Path(directory), wheel, multiple=False, stock_provider=True)

    def test_installed_history_recovers_commit_after_host_dies_before_finish(self):
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel:
            self.skipTest('exact installed wheel path required')
        with tempfile.TemporaryDirectory() as directory:
            self.exercise(Path(directory), wheel, multiple=False, stock_provider='interrupt-before-finish')

    def exercise(self, root, wheel, *, multiple, stock_provider=False, interval_peer_offset=None,
                 interval_meter=False):
        config_dir = root/'workeros'
        config_dir.mkdir(mode=0o700)
        journal = root/'journal'
        journal.mkdir(mode=0o700)
        executable = str(Path(sys.prefix)/'bin'/'workeros')
        try:
            clock_id = setup_clock_id()
            fixture_clock = ''
        except ValueError:
            # Some ordinary CI sandboxes hide time namespaces. The provider
            # and host share this synthetic clock label only for conformance.
            clock_id = fixture_clock = 'f'*64

        def command(*args, synthetic=True, client_config=False):
            return [sys.executable, '-I', '-c', ENTRY, str(root), ('synthetic' if synthetic is True else synthetic) or '',
                    fixture_clock, 'client-config-pipe' if client_config else '', executable, 'managed', *args]

        def run(*args, data=None, passed=(), code=0, synthetic=True, client_config=None):
            if client_config is not None:
                self.assertIsNone(data)
                data = json.dumps(client_config)
            result = subprocess.run(command(*args, synthetic=synthetic, client_config=client_config is not None),
                                    input=data, pass_fds=passed,
                                    capture_output=True, text=True, timeout=8, cwd=root)
            self.assertEqual(result.returncode, code, result.stdout + result.stderr)
            return json.loads(result.stdout)

        with ExitStack() as stack:
            server, provider = [stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                                for _ in range(2)]
            server.bind(str(root/'host.sock'))
            server.listen(4)
            provider.bind(str(root/'provider.sock'))
            provider.listen(4)
            provider.settimeout(0.2)
            meter = None
            if multiple or interval_meter:
                meter = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                meter.bind(str(root/'meter.sock'))
                meter.listen(4)
                meter.settimeout(0.2)
            uid = os.getuid()
            clock_id_raw = monotonic_clock_id() or 'fixture-monotonic'
            expiry = monotonic_ns() + 45_000_000_000
            names = ('original','named','metered','meter-only') if multiple else (
                'metered' if interval_meter else 'workflow',)
            passed, scopes, appointments, expected = [], [], [], {}
            for name in names:
                scope_id = f'{name}-scope'
                original_path = root/(name+'.input')
                original_path.write_bytes(b'fixture')
                held = stack.enter_context(original_path.open('rb'))
                original_fd = held.fileno()
                pidfd = os.pidfd_open(os.getpid())
                stack.callback(os.close,pidfd)
                passed.extend((original_fd,pidfd))
                info = os.fstat(original_fd)
                plan = {'device':info.st_dev,'inode':info.st_ino,'pid':os.getpid(),'uid':uid,
                        'slot':original_fd,'scope_sha256':sha256(name.encode()).hexdigest()}
                if multiple:
                    plan['require_readable'] = True
                inherited_directory = None
                if name == 'named':
                    directory_fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                    stack.callback(os.close,directory_fd)
                    passed.append(directory_fd)
                    directory = os.fstat(directory_fd)
                    plan['directory'] = {'device':directory.st_dev,'inode':directory.st_ino,'leaf':original_path.name}
                    inherited_directory = {**plan['directory'],'directory_fd':directory_fd}
                endpoint = {'socket':str(root/'provider.sock'),'peer_uid':uid}
                interval = interval_peer_offset is not None
                if interval:
                    endpoint['peer_uid'] += interval_peer_offset
                    plan['require_readable'] = True
                bound_plan = {'observer':plan,'interval_provider':endpoint} if interval else plan
                bindings = [ProviderBinding('observer',sha256(_canonical(bound_plan)).hexdigest(),scope_id,
                                            'interval' if interval else 'point',
                                            'fixture-provider','observers','fixture-writer')]
                registration = {'observer':{**plan,'original_fd':original_fd,'pidfd':pidfd},
                                'interval_provider' if interval else 'provider':endpoint}
                if inherited_directory is not None:
                    registration['observer']['directory'] = inherited_directory
                operations = ['observe']
                refs = {'observers':{'slot':'observer'}}
                if name in ('metered', 'meter-only'):
                    try:
                        meter_fd = os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY)
                    except OSError as exc:
                        self.skipTest(f'read-only cgroup v2 fixture unavailable: {exc.errno}')
                    stack.callback(os.close,meter_fd)
                    mount_id = _mount_id(meter_fd)
                    if not _cgroup_mount(mount_id):
                        self.skipTest('read-only cgroup v2 fixture unavailable')
                    passed.append(meter_fd)
                    identity = os.fstat(meter_fd)
                    start_ns = monotonic_ns()
                    evidence_scope = EvidenceScope(RunBinding('fixture-run','fixture-artifact',
                        clock_id_raw,start_ns,expiry),scope_id,start_ns,expiry)
                    meter_plan = {'device':identity.st_dev,'inode':identity.st_ino,'mount_id':mount_id,
                                  'scope':asdict(evidence_scope)}
                    meter_endpoint = {'socket':str(root/'meter.sock'),'peer_uid':uid}
                    pinned_meter = meter_plan
                    if interval_meter:
                        plan['scope_sha256'] = sha256(_canonical(asdict(evidence_scope))).hexdigest()
                        registration['observer']['scope_sha256'] = plan['scope_sha256']
                        bindings[0] = replace(bindings[0], reference=sha256(_canonical(bound_plan)).hexdigest())
                        pinned_meter = {'meter': meter_plan, 'meter_provider': meter_endpoint}
                    bindings.append(ProviderBinding('meter',sha256(_canonical(pinned_meter)).hexdigest(),scope_id,
                                                    'cgroup-v2','fixture-meter','meters','fixture-writer'))
                    registration['meter'] = {**meter_plan,'directory_fd':meter_fd}
                    registration['meter_provider'] = meter_endpoint
                    operations.append('meter')
                    refs['meters'] = {'counter':'meter'}
                if name == 'meter-only':
                    bindings.pop(0)
                    del registration['observer'], registration['provider']
                    operations.remove('observe')
                    del refs['observers']
                policy = {'version':1,'roles':{'operator':{'operations':operations}},
                          'workflows':{name:{'role':'operator','operations':operations,'bindings':refs}}}
                definition = ProfileDefinition(name,'revision-1','0.8.0',
                    sha256(Path(wheel).read_bytes()).hexdigest(),sha256(_canonical(policy)).hexdigest(),
                    'fixture-manager',scope_id,clock_id,expiry,tuple(bindings))
                definition_digest = definition_sha256(definition)
                expected[definition_digest] = {'version':1,'definition_sha256':definition_digest,
                    'role':'operator','clock_id':clock_id,'generation':'generation-1'}
                appointments.append({'workflow':name,'workflow_revision':'revision-1',
                    'definition_sha256':definition_digest,'role':'operator','principal':pwd.getpwuid(uid).pw_name,
                    'scope':scope_id,'generation':'generation-1','operations':operations})
                scopes.append({**registration,'definition':asdict(definition),'policy':policy,
                               'role':'operator','binding_generation':'generation-1'})
            self.handshake(root,config_dir,journal,wheel,passed,server,provider,meter,command,run,
                           scopes,appointments,expected,expiry,uid,stock_provider,interval_peer_offset,
                           interval_meter)

    def handshake(self,root,config_dir,journal,wheel,passed,server,provider,meter,command,run,
                  scopes,appointments,expected,expiry,uid,stock_provider,interval_peer_offset,interval_meter):
        document = {'version':1,'profile':'fixture','revision':'revision-1',
                    'roles':[{'name':'operator','principal':pwd.getpwuid(uid).pw_name,
                              'operations':['observe','meter'] if meter else ['observe'],
                              'scopes':[item['scope'] for item in appointments],'expires_at':int(time())+120}],
                    'appointments':appointments}
        receipt = run('apply-profile',data=json.dumps(document))
        self.assertEqual((receipt['status'],receipt['independence']),('configured','unverified'))
        self.assertEqual(run('profile-status','fixture','revision-1'),
                         run('commission-status','fixture','revision-1'))
        approval = {key:receipt[key] for key in ('declaration_sha256','intent_sha256')}
        multiscopes = meter is not None or interval_peer_offset is not None
        setup_config = {'version':2 if multiscopes else 1,'profile':'fixture','revision':'revision-1',
                        'operation_key':'b'*64,'authorized_uids':[uid],'wheel_path':wheel,
                        'journal_directory':str(journal),'local_approval':approval}
        setup_config.update({'scopes':scopes} if multiscopes else scopes[0])
        setup_path = config_dir/'managed-setup.json'
        setup_path.write_text(json.dumps(setup_config))
        if interval_meter:
            self.check_interval_meter_pair(setup_config, setup_path, journal, server, provider, meter,
                                           run, command, passed, expected, expiry, uid)
            return
        if interval_peer_offset is not None:
            self.check_interval_registration(setup_config, setup_path, journal, provider, run,
                                             passed, expected, expiry, interval_peer_offset,
                                             server, command, document, uid)
            return
        refused = run('serve-setup','--describe',passed=passed,code=1,synthetic=False)
        self.assertEqual((refused['status'],refused['code']),('unavailable','provider_requires_distinct_uid'))
        if stock_provider:
            self.check_stock_provider(root, journal, passed, server, provider, command, run,
                                      setup_config, scopes[0], uid, stock_provider == 'interrupt-before-finish')
            return
        interval = json.loads(json.dumps(setup_config))
        interval_scope = interval['scopes'][0] if meter else interval
        interval_scope['definition']['providers'][0]['capability'] = 'interval'
        setup_path.write_text(json.dumps(interval))
        refused = run('serve-setup','--check-bindings',passed=passed,code=1)
        self.assertEqual((refused['status'],refused['code'],refused['effect']),
                         ('unavailable','interval_custody_unsupported','not_attempted'))
        self.assertEqual(list(journal.iterdir()),[])
        setup_path.write_text(json.dumps(setup_config))
        if meter:
            no_provider = json.loads(json.dumps(setup_config))
            scope = no_provider['scopes'][-1]
            scope['definition']['providers'] = []
            del scope['meter'], scope['meter_provider']
            setup_path.write_text(json.dumps(no_provider))
            refusal = run('serve-setup', '--check-bindings', passed=passed, code=1)
            self.assertEqual(refusal['scopes'][-1]['code'], 'independent_attester_unavailable')
            self.assertEqual(refusal['effect'], 'not_attempted')
            self.assertEqual(list(journal.iterdir()), [])
            bad_shape = json.loads(json.dumps(setup_config))
            del bad_shape['scopes'][-1]['meter_provider']
            setup_path.write_text(json.dumps(bad_shape))
            refusal = run('serve-setup', '--check-bindings', passed=passed, code=1)
            self.assertEqual(refusal['scopes'][-1]['code'], 'unsupported_setup_binding')
            self.assertEqual(list(journal.iterdir()), [])
            changed = json.loads(json.dumps(setup_config))
            changed['scopes'][1]['definition']['providers'][0]['capability'] = 'interval'
            setup_path.write_text(json.dumps(changed))
            refusal = run('serve-setup', '--check-bindings', passed=passed, code=1)
            self.assertEqual(refusal['scopes'], [
                {'name': appointments[0]['workflow'], 'status': 'not_checked'},
                {'name': appointments[1]['workflow'], 'status': 'unavailable',
                 'code': 'interval_custody_unsupported'},
                {'name': appointments[2]['workflow'], 'status': 'not_checked'},
                {'name': appointments[3]['workflow'], 'status': 'not_checked'}])
            self.assertEqual((refusal['effect'], refusal['readiness']), ('not_attempted', 'not_checked'))
            self.assertEqual(list(journal.iterdir()), [])
            changed['scopes'][2]['definition']['providers'][0]['capability'] = 'unsupported'
            setup_path.write_text(json.dumps(changed))
            refusal = run('serve-setup', '--check-bindings', passed=passed, code=1)
            self.assertEqual([item.get('code') for item in refusal['scopes']],
                             [None, 'interval_custody_unsupported', 'unsupported_setup_binding', None])
            self.assertEqual(list(journal.iterdir()), [])
            setup_path.write_text(json.dumps(setup_config))
            refusal = run('serve-setup','--describe',passed=passed,code=1,synthetic='same-uid-only')
            self.assertEqual(refusal['code'],'meter_provider_requires_separate_principal')
            for request in ('interval_observer', 'custody_binding', 'custody_policy'):
                changed = json.loads(json.dumps(setup_config))
                scope = changed['scopes'][0]
                if request == 'interval_observer':
                    scope['definition']['providers'][0]['capability'] = 'interval'
                elif request == 'custody_binding':
                    scope['definition']['providers'][0]['kind'] = 'custody'
                else:
                    scope['policy']['workflows']['original']['require_custody'] = True
                setup_path.write_text(json.dumps(changed))
                refusal = run('serve-setup','--listen-fd',str(server.fileno()),
                              passed=(*passed,server.fileno()),code=1)
                self.assertEqual((refusal['status'],refusal['code'],refusal['effect']),
                                 ('unavailable','interval_custody_unsupported','not_attempted'))
                self.assertEqual(list(journal.iterdir()),[])
            metadata_fd = os.open(root/'original.input', os.O_PATH)
            try:
                changed = json.loads(json.dumps(setup_config))
                changed['scopes'][0]['observer']['original_fd'] = metadata_fd
                setup_path.write_text(json.dumps(changed))
                refusal = run('serve-setup','--describe',passed=(*passed,metadata_fd),code=1)
                self.assertEqual(refusal['code'],'point_observer_requires_readable_original')
            finally:
                os.close(metadata_fd)
            setup_path.write_text(json.dumps(setup_config))
        metadata = run('serve-setup','--describe',passed=passed)
        # The client receives synthetic correlation values through a pipe.
        # The owned configuration file checks live in test_managed_cli.
        client_config = {
            'version':1,'socket':str(root/'host.sock'),'peer_uid':uid,'profile':'fixture',
            'scopes':[item['workflow'] for item in appointments],'identity':metadata['identity'],'operation_key':'b'*64,
        }

        stop, deny, wrong_generation = Event(), Event(), Event()
        requests, errors = [], []
        metered_digests = {item['definition_sha256'] for item in appointments[-2:]} if meter else set()

        def respond(listener, source):
            while not stop.is_set():
                try:
                    connection,_ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    try:
                        deadline = monotonic() + 4
                        size, = struct.unpack('!I',_read_exact(connection,4,deadline))
                        request = json.loads(_read_exact(connection,size,deadline))
                        request_id = request.pop('request_id')
                        digest = request['definition_sha256']
                        if request != expected.get(digest) or listener is meter and digest not in metered_digests:
                            raise ValueError('synthetic registration does not match request')
                        requests.append(request_id)
                        if not (deny.is_set() and (meter is None or listener is meter)):
                            reply = {**request,'request_id':request_id,'source':source,'status':'verified',
                                     'evidence_sha256':'c'*64,'valid_until_ns':str(expiry)}
                            if wrong_generation.is_set() and (meter is None or listener is meter):
                                reply['generation'] = 'other-generation'
                            del reply['version']
                            payload = _canonical(reply)
                            connection.sendall(struct.pack('!I',len(payload))+payload)
                    except Exception as exc:
                        errors.append(str(exc))

        threads = [Thread(target=respond,args=(provider,'fixture-provider'),daemon=True)]
        if meter is not None:
            threads.append(Thread(target=respond,args=(meter,'fixture-meter'),daemon=True))
        for worker in threads:
            worker.start()
        try:
            def check_bindings(expected_status, code=0):
                result = run('serve-setup','--check-bindings',passed=passed,code=code)
                self.assertEqual((result['status'],result['effect'],result['readiness'],
                                  result['runtime_evidence'],result['independence']),
                                 (expected_status,'not_attempted','not_checked','not_requested','unverified'))
                self.assertEqual(list(journal.iterdir()),[])
                return result

            profile_store = config_dir/'profiles'
            approved_state = {path.name:path.read_bytes() for path in profile_store.iterdir()}
            bad_approval = {**setup_config,'local_approval':{**approval,'intent_sha256':'d'*64}}
            setup_path.write_text(json.dumps(bad_approval))
            refused = check_bindings('refused',code=1)
            self.assertEqual(refused['code'],'commissioned_mapping_mismatch')
            self.assertEqual(requests,[])  # The provider is not asked to qualify an unapproved input.
            setup_path.write_text(json.dumps(setup_config))

            verified = check_bindings('bindings_verified')
            self.assertEqual((verified['profile'],verified['revision']),('fixture','revision-1'))
            self.assertEqual([(scope['name'],scope['status'],scope['definition_sha256'])
                              for scope in verified['scopes']],
                             [(item['workflow'],'bindings_verified',item['definition_sha256'])
                              for item in appointments])
            window = verified['observation']
            self.assertEqual(window['clock_id'],scopes[0]['definition']['clock_id'])
            start, end, valid_until = (int(window[key]) for key in ('start_ns','end_ns','valid_until_ns'))
            self.assertTrue(start <= end < valid_until <= expiry)
            self.assertTrue(requests)
            for failure in (wrong_generation, deny):
                failure.set()
                unavailable = check_bindings('incomplete',code=1)
                self.assertEqual([scope['name'] for scope in unavailable['scopes']
                                  if scope['status'] != 'bindings_verified'],
                                 [item['workflow'] for item in appointments[-2:]] if meter else
                                 [appointments[-1]['workflow']])
                failure.clear()
            self.assertEqual({path.name:path.read_bytes() for path in profile_store.iterdir()},
                             approved_state)

            def exchange(operation, code=0):
                host = subprocess.Popen(command('serve-setup','--listen-fd',str(server.fileno())),
                    pass_fds=(*passed,server.fileno()), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    receipt = run(operation,code=code,client_config=client_config)
                    out, err = host.communicate(timeout=8)
                    self.assertEqual(host.returncode,0,out+err)
                    return receipt
                finally:
                    if host.poll() is None:
                        host.kill()
                        host.wait(timeout=3)

            first = exchange('setup')
            self.assertEqual(first['status'],'ready')
            before = {path.name:path.read_bytes() for path in journal.iterdir()}
            self.assertEqual(len(before),len(scopes)+2)  # mappings plus claim and result
            second = exchange('readback')
            self.assertEqual((second['status'],second['identity'],second['scopes']),
                             ('ready',first['identity'],first['scopes']))
            deny.set()
            unavailable = exchange('readback',code=1)
            self.assertEqual(unavailable['status'],'incomplete')
            if meter:
                outcomes = {item['name']:item['final'] for item in unavailable['scopes']}
                self.assertEqual(outcomes['original'],'accepted')
                self.assertEqual(outcomes['named'],'accepted')
                self.assertNotEqual(outcomes['metered'],'accepted')
            self.assertEqual({path.name:path.read_bytes() for path in journal.iterdir()},before)
        finally:
            stop.set()
            for worker in threads:
                worker.join(5)
        self.assertFalse(errors)
        self.assertFalse((config_dir/'managed-host.json').exists())
        self.assertGreaterEqual(len(requests),4)
        self.assertEqual(len(requests),len(set(requests)))

    def check_interval_registration(self, config, path, journal, provider, run, passed,
                                    expected, expiry, peer_offset, server, command, document, uid):
        original = config['scopes'][0]
        self.assertEqual(len(expected), 1)
        request_pins, = expected.values()
        request_pins = {**request_pins, 'version': 2, 'capability': 'interval'}

        def check(scope, code=1, *, real_peer=False):
            path.write_text(json.dumps({**config, 'scopes':[scope]}))
            result = run('serve-setup', '--check-bindings', passed=passed, code=code,
                         synthetic=False if real_peer else 'interval-fixture')
            self.assertEqual((result['effect'],result['readiness'],result['independence'],result['runtime_evidence']),
                             ('not_attempted','not_checked','unverified','not_requested'))
            self.assertEqual(list(journal.iterdir()), [])
            return result

        def respond(changes):
            provider.settimeout(5)
            connection, _ = provider.accept()
            with connection:
                deadline = monotonic() + 5
                if peer_offset:
                    # The client must close without sending a challenge.
                    connection.settimeout(5)
                    self.assertEqual(connection.recv(1), b'')
                    return
                size, = struct.unpack('!I', _read_exact(connection, 4, deadline))
                request = json.loads(_read_exact(connection, size, deadline))
                challenge = request.pop('request_id')
                self.assertRegex(challenge, r'^[0-9a-f]{32}$')
                self.assertEqual(request, request_pins)
                if changes is None:
                    return
                reply = _canonical({**request, 'request_id':challenge, 'source':'fixture-provider',
                    'status':'verified', 'evidence_sha256':'1'*64, 'valid_until_ns':str(expiry), **changes})
                connection.sendall(struct.pack('!I', len(reply)) + reply)

        if peer_offset:
            with ThreadPoolExecutor(max_workers=1) as replies:
                rejected = replies.submit(respond, {})
                result = check(original, real_peer=True)
                rejected.result()
            self.assertEqual(result['scopes'][0]['code'], 'manager_selection_denied')
            return

        # Every other entry mode refuses before opening or consulting a provider.
        for mode in (('--describe',), ('--listen-fd', '1'), ('--recover-interrupted',)):
            with self.subTest(mode=mode):
                outcome = run('serve-setup', *mode, code=1, synthetic=False)
                self.assertEqual(outcome['code'], 'interval_check_only')
        self.assertEqual(check(original, real_peer=True)['code'], 'provider_requires_distinct_uid')
        missing = {name:value for name,value in original.items() if name != 'interval_provider'}
        self.assertEqual(check(missing)['code'], 'interval_custody_unsupported')
        for field,value in (('scope','unrelated-scope'), ('independent_of',None)):
            definition = original['definition']
            misplaced = {**definition['providers'][0], field:value}
            scope = {**original,'definition':{**definition, 'providers':[misplaced]}}
            self.assertEqual(check(scope)['code'], 'interval_registration_mismatch')
        endpoint = {**original['interval_provider'], 'socket':str(path.parent/'unapproved.sock')}
        self.assertEqual(check({**original,'interval_provider':endpoint})['code'], 'observer_plan_mismatch')
        provider.settimeout(0.02)
        with self.assertRaises(TimeoutError):
            provider.accept()
        for changes,expected_code in (({}, 'bindings_verified'),
                ({'status':'unverified'}, 'independent_evidence_invalid'),
                ({'definition_sha256':'0'*64}, 'independent_evidence_invalid'),
                ({'request_id':'0'*32}, 'independent_evidence_invalid'),
                ({'generation':'wrong-generation'}, 'independent_evidence_invalid'),
                ({'valid_until_ns':'1'}, 'independent_evidence_invalid'),
                ({'capability':'point'}, 'independent_evidence_invalid')):
            with self.subTest(changes=changes), ThreadPoolExecutor(max_workers=1) as replies:
                sent = replies.submit(respond, changes)
                result = check(original, code=int(bool(changes)))
                sent.result()
                self.assertEqual(result['scopes'][0]['code'], expected_code)
                self.assertEqual(result['status'], 'incomplete' if changes else 'bindings_verified')

        def describe():
            return run('serve-setup', '--check-bindings', '--describe', passed=passed,
                       synthetic='interval-fixture')

        def exchange(metadata, operation='check-bindings', *, code=1, lost=False):
            client = {'version': 1, 'socket': server.getsockname(), 'peer_uid': uid,
                      'profile': metadata['profile'], 'scopes': metadata['scopes'],
                      'identity': metadata['identity'], 'operation_key': config['operation_key'],
                      'binding_check': metadata['binding_check']}
            host = subprocess.Popen(command('serve-setup', '--check-bindings', '--listen-fd',
                                            str(server.fileno()),
                                            synthetic='interval-lost-reply' if lost else 'interval-fixture'),
                                    pass_fds=(*passed, server.fileno()), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            try:
                result = run(operation, code=code, client_config=client)
                out, err = host.communicate(timeout=8)
                self.assertEqual(host.returncode, int(lost), out + err)
                return result
            finally:
                if host.poll() is None:
                    host.kill()
                    host.wait(timeout=3)

        no_journal = {k: v for k, v in config.items() if k != 'journal_directory'}
        no_appointments = {k: v for k, v in document.items() if k != 'appointments'}
        no_appointments['profile'] = 'no-appointment'
        receipt = run('apply-profile', data=json.dumps(no_appointments))
        approval = {k: receipt[k] for k in ('declaration_sha256', 'intent_sha256')}
        path.write_text(json.dumps({**no_journal, 'profile': 'no-appointment', 'local_approval': approval}))
        records = path.parent / 'profiles'
        before = {record.name: record.read_bytes() for record in records.iterdir()}
        denied = exchange(describe())
        self.assertEqual((denied['code'], denied['effect']), ('role_appointment_unverified', 'not_attempted'))

        path.write_text(json.dumps(no_journal))
        metadata = describe()
        self.assertEqual(metadata['binding_check']['scope_digests'],
                         {original['definition']['name']: request_pins['definition_sha256']})
        for operation in ('setup', 'readback', 'reconcile'):
            denied = exchange(metadata, operation)
            self.assertEqual((denied['status'], denied['effect'], denied['scopes'][0]['code']),
                             ('refused', 'not_attempted', 'binding_check_only'))
        provider.settimeout(0.02)
        with self.assertRaises(TimeoutError):
            provider.accept()
        for changes, status, code in (({}, 'bindings_verified', None),
                                      ({'generation': 'wrong-generation'}, 'incomplete', 'independent_evidence_invalid'),
                                      (None, 'incomplete', 'manager_selection_unavailable'),
                                      ({}, 'unknown', 'response_unconfirmed')):
            with self.subTest(status=status, code=code), ThreadPoolExecutor(max_workers=1) as replies:
                sent = replies.submit(respond, changes)
                result = exchange(metadata, code=int(status != 'bindings_verified'), lost=status == 'unknown')
                sent.result()
                self.assertEqual((result['status'], result['effect'], result['readiness']),
                                 (status, 'not_attempted', 'not_checked'))
                self.assertEqual(result['scopes'][0]['code'] if status == 'incomplete' else result['code'], code)
        self.assertEqual({record.name: record.read_bytes() for record in records.iterdir()}, before)
        self.assertEqual(list(journal.iterdir()), [])

    def check_interval_meter_pair(self, config, path, journal, server, observer, meter,
                                  run, command, passed, expected, expiry, uid):
        missing_journal = path.parent / 'check-only-must-not-open'
        config = {**config, 'journal_directory': str(missing_journal)}
        path.write_text(json.dumps(config))
        before = {record.name: record.read_bytes() for record in (path.parent/'profiles').iterdir()}
        arguments = ('serve-setup', '--check-bindings')
        mode = 'interval-meter-fixture'
        unavailable = run('serve-setup', '--describe', code=1, synthetic=mode, passed=passed)
        self.assertEqual(unavailable['code'], 'interval_check_only')
        metadata = run(*arguments, '--describe', synthetic=mode, passed=passed)
        self.assertEqual(len(metadata['scopes']), 1)
        meter_pins, = expected.values()
        self.assertEqual(metadata['binding_check']['scope_digests'],
                         {metadata['scopes'][0]: meter_pins['definition_sha256']})

        def configured_refusal(edit, code, *, synthetic=mode):
            changed = json.loads(json.dumps(config))
            edit(changed['scopes'][0])
            path.write_text(json.dumps(changed))
            result = run(*arguments, code=1, synthetic=synthetic, passed=passed)
            self.assertEqual((result['status'], result['effect'], result['code']),
                             ('unavailable', 'not_attempted', code))
            self.assertEqual(result['runtime_evidence'], 'not_requested')

        configured_refusal(lambda scope: scope.pop('meter_provider'), 'interval_registration_mismatch')
        configured_refusal(lambda scope: None, 'meter_provider_requires_separate_principal',
                           synthetic='interval-fixture')
        configured_refusal(lambda scope: scope['meter_provider'].update(socket='/unapproved/meter.sock'),
                           'meter_plan_mismatch')

        def crossed(scope):
            # Keep the same scope name, but bind the meter to a different run.
            scope['meter']['scope']['run']['run_id'] = 'different-run'
            meter_plan = {key:value for key,value in scope['meter'].items() if key != 'directory_fd'}
            scope['definition']['providers'][1]['reference'] = sha256(_canonical({
                'meter': meter_plan, 'meter_provider': scope['meter_provider']})).hexdigest()

        configured_refusal(crossed, 'interval_meter_scope_mismatch')
        for listener in (observer, meter):
            listener.settimeout(0.02)
            with self.assertRaises(TimeoutError):
                listener.accept()
        path.write_text(json.dumps(config))

        client = {'version': 1, 'socket': server.getsockname(), 'peer_uid': uid,
                  'profile': metadata['profile'], 'scopes': metadata['scopes'],
                  'identity': metadata['identity'], 'operation_key': config['operation_key'],
                  'binding_check': metadata['binding_check']}

        def reply(listener, changes):
            interval = listener is observer
            listener.settimeout(5)
            connection, _ = listener.accept()
            with connection:
                deadline = monotonic() + 5
                size, = struct.unpack('!I', _read_exact(connection, 4, deadline))
                request = json.loads(_read_exact(connection, size, deadline))
                challenge = request.pop('request_id')
                self.assertRegex(challenge, r'^[0-9a-f]{32}$')
                pins = {**meter_pins, 'version': 2, 'capability': 'interval'} if interval else meter_pins
                self.assertEqual(request, pins)
                if changes is None:
                    return
                if not interval:
                    del request['version']
                body = _canonical({**request, 'request_id': challenge,
                    'source': 'fixture-provider' if interval else 'fixture-meter',
                    'status': 'verified', 'evidence_sha256': ('1' if interval else '2') * 64,
                    'valid_until_ns': str(expiry if interval else expiry - 1_000_000_000), **changes})
                connection.sendall(struct.pack('!I', len(body)) + body)

        for first, second, status, reason in (
                ({}, {}, 'bindings_verified', 'bindings_verified'),
                ({'valid_until_ns': '1'}, False, 'incomplete', 'independent_evidence_invalid'),
                ({}, {'generation': 'different'}, 'incomplete', 'manager_selection_unavailable'),
                ({}, None, 'incomplete', 'manager_selection_unavailable'),
                ({}, {}, 'unknown', 'response_unconfirmed')):
            lost = status == 'unknown'
            with self.subTest(status=status, reason=reason), ThreadPoolExecutor(max_workers=2) as replies:
                sent = [replies.submit(reply, observer, first)]
                if second is not False:
                    sent.append(replies.submit(reply, meter, second))
                host = subprocess.Popen(command(*arguments, '--listen-fd', str(server.fileno()),
                                                synthetic='interval-meter-lost' if lost else mode),
                                        pass_fds=(*passed, server.fileno()), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
                try:
                    result = run('check-bindings', code=int(status != 'bindings_verified'), client_config=client)
                    out, err = host.communicate(timeout=8)
                    self.assertEqual(host.returncode, int(lost), out + err)
                finally:
                    if host.poll() is None:
                        host.kill()
                        host.wait(timeout=3)
                for future in sent:
                    future.result()
                self.assertEqual((result['status'], result['effect'], result['readiness'],
                                  result['independence'], result['runtime_evidence']),
                                 (status, 'not_attempted', 'not_checked', 'unverified', 'not_requested'))
                self.assertEqual(result['code'] if lost else result['scopes'][0]['code'], reason)
                if status == 'bindings_verified':
                    self.assertEqual(result['observation']['valid_until_ns'], str(expiry - 1_000_000_000))
                if second is False:
                    meter.settimeout(0.02)
                    with self.assertRaises(TimeoutError):
                        meter.accept()
        self.assertEqual({record.name: record.read_bytes() for record in (path.parent/'profiles').iterdir()}, before)
        self.assertEqual(list(journal.iterdir()), [])
        self.assertFalse(missing_journal.exists())

    def check_stock_provider(self, root, journal, passed, server, provider, command, run,
                             setup_config, scope, uid, interrupt):
        metadata = run('serve-setup', '--describe', passed=passed)
        client_config = {
            'version': 1, 'socket': str(root/'host.sock'), 'peer_uid': uid,
            'profile': setup_config['profile'], 'scopes': metadata['scopes'],
            'identity': metadata['identity'], 'operation_key': setup_config['operation_key'],
            'binding_check': metadata['binding_check'],
        }
        binding = ProviderBinding(**scope['definition']['providers'][0])
        definition = ProfileDefinition(**{**scope['definition'], 'providers': (binding,)})
        registration = {'host_uid': uid, 'provider_uid': uid, 'observer': scope['observer'],
                        'role': scope['role'], 'binding_generation': scope['binding_generation']}
        errors = []

        def serve():
            try:
                # The fixture has one UID. Exercise the real provider's
                # authenticated socket loop and live observation directly.
                # The separate bootstrap process above refuses this same UID
                # with its ordinary production admission path.
                with ExitStack() as resources:
                    observer = _observer(scope['observer'], binding, definition, resources, set())
                    _serve(provider, registration, definition, binding, observer, max_requests=16)
            except Exception as exc:
                errors.append(exc)

        def exchange(operation, *, interrupt=False):
            mode = 'interrupt-before-finish' if interrupt else 'synthetic'
            with subprocess.Popen(command('serve-setup', '--listen-fd', str(server.fileno()), synthetic=mode),
                                  pass_fds=(*passed, server.fileno()), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) as host:
                try:
                    receipt = run(operation, code=1 if interrupt else 0, client_config=client_config)
                    out, err = host.communicate(timeout=7)
                    self.assertEqual(host.returncode, 81 if interrupt else 0, out + err)
                    return receipt
                finally:
                    if host.poll() is None:
                        host.kill()
                        host.wait(timeout=3)

        thread = Thread(target=serve, daemon=True)
        thread.start()
        try:
            checked = exchange('check-bindings')
            self.assertEqual((checked['status'], checked['readiness'], checked['effect']),
                             ('bindings_verified', 'not_checked', 'not_attempted'))
            self.assertEqual(list(journal.iterdir()), [])
            applied = exchange('setup', interrupt=interrupt)
            committed = {path.name: path.read_bytes() for path in journal.iterdir()}
            if interrupt:
                self.assertEqual((applied['status'], applied['effect']), ('unknown', 'unknown'))
                self.assertEqual(len(committed), 2)  # Only the claim and mapping.
            else:
                self.assertEqual(applied['status'], 'ready')
                self.assertEqual([(scope['setup'], scope['final']) for scope in applied['scopes']],
                                 [('accepted', 'accepted')])
                self.assertEqual(len(committed), 3)  # One claim, mapping, and result.
                # Each exchange gets a new installed host. Current evidence
                # comes from the same enrolled provider, not the journal.
                confirmed = exchange('readback')
                self.assertEqual((confirmed['status'], confirmed['identity'], confirmed['scopes']),
                                 ('ready', applied['identity'], applied['scopes']))
        finally:
            thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors, errors)
        if interrupt:
            provider.close()
            server.close()
            recovered = run('serve-setup', '--recover-interrupted', code=1, synthetic=False)
            self.assertEqual((recovered['status'], recovered['identity'], recovered['operation_key'],
                              recovered['readiness'], recovered['effect']),
                             ('incomplete', applied['identity'], applied['operation_key'], 'not_checked', 'unknown'))
            self.assertEqual(recovered['scopes'], [{'name':'workflow', 'status':'recorded',
                                                   'effect':'committed', 'code':'scope_commit_verified'}])
        self.assertEqual({path.name: path.read_bytes() for path in journal.iterdir()}, committed)
