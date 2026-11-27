"""Installed command with an ordinary-user, separately operated synthetic host."""
import hashlib
import json
import multiprocessing
import os
from dataclasses import replace
from pathlib import Path
import pickle
import pwd
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from worker_handoff import managed_cli, roles_cli
from worker_handoff.appointment_registry import definition_sha256
from worker_handoff.managed_host import AttemptRecord, LocalProfileApproval, ManagedHostAdapter, RoleAppointment
from worker_handoff.profile_setup import ManagerReadback
from worker_handoff.managed_journal import ManagedJournal
from test_aggregate_setup import make_scope


class FixtureStore:
    """Disposable SQLite fixture. This does not qualify a real host store."""
    def __init__(self, path):
        self.path = path
        with sqlite3.connect(path) as c:
            c.execute('create table if not exists attempts (identity text, key text, state text, results blob, primary key(identity,key))')
    def read(self, identity, key):
        with sqlite3.connect(self.path) as c:
            row = c.execute('select state,results from attempts where identity=? and key=?',(identity,key)).fetchone()
        if row is None: return AttemptRecord(identity,key,'not_started')
        return AttemptRecord(identity,key,row[0],pickle.loads(row[1]) if row[1] else ())
    def claim(self, identity, key):
        try:
            with sqlite3.connect(self.path) as c:
                c.execute('insert into attempts values (?,?,?,?)',(identity,key,'pending',None))
            return 'claimed'
        except sqlite3.IntegrityError: return 'existing'
    def finish(self, identity, key, results):
        with sqlite3.connect(self.path) as c:
            cur=c.execute('update attempts set state=?,results=? where identity=? and key=? and state=?',
                          ('recorded',pickle.dumps(results),identity,key,'pending'))
        return cur.rowcount == 1


class DropReply:
    def __init__(self, connection): self.connection = connection
    def __getattr__(self, name): return getattr(self.connection, name)
    def sendall(self, data): raise OSError('synthetic lost reply')


def make_transport_scope(name, digest, *, interval=False):
    scope = make_scope(name, 'run-'+name, digest)
    if not interval or name != 'two':
        return scope
    # A typed interval requirement supplied by the synthetic host. Nothing
    # samples the observer or assesses an actual runtime custody interval.
    selection = scope.manager.selection
    provider, = selection.definition.providers
    requirement, = scope.requirements.providers
    definition = replace(selection.definition, providers=(replace(provider, capability='interval'),))
    scope.manager.selection = replace(selection, definition=definition)
    scope.manager.evidence = replace(scope.manager.evidence, definition=definition)
    return replace(scope, requirements=replace(scope.requirements,
                                               providers=(replace(requirement, capability='interval'),)))


def make_adapter(wheel, path, *, wrong=False, local_approval=None, local_appointments=False, interval=False):
    digest=hashlib.sha256(Path(wheel).read_bytes()).hexdigest()
    scopes=tuple(make_transport_scope(name,digest,interval=interval) for name in ('one','two','three'))
    definitions=tuple(s.manager.selection.definition for s in scopes)
    adapter=ManagedHostAdapter(profile='fixture',revision='revision-1',operation_key='b'*64,
        scopes=scopes, definitions=definitions, generations=('generation-1',)*3,
        wheel=wheel,wheel_sha256=digest,clock_id='fixture-clock',store=FixtureStore(path),
        local_approval=local_approval, local_appointments=local_appointments)
    if wrong: scopes[0].manager.generation='generation-2'
    return adapter,scopes


def host(path, db, wheel, pipe, drop_first, mismatch, request_limit, approval, no_evidence,
         appointed_principal, appointment_case, local_appointments, binding_check, self_attested):
    store_db=db+'-fixture.db'
    if approval is not None:
        roles_cli._PARENT = str(Path(path).parent)
        roles_cli._UID = os.getuid()
    adapter, scopes = make_adapter(wheel,store_db,wrong=mismatch,local_approval=approval,
                                   local_appointments=local_appointments,interval=binding_check)
    if not os.path.isdir(db): os.mkdir(db,0o700)
    adapter.store=ManagedJournal(Path(db),definitions=adapter.definitions)
    # A separate fixture authority persists mappings independently of the
    # product journal. This is synthetic and grants no real host authority.
    authority=db+'-authority.db'
    with sqlite3.connect(authority) as c:
        c.execute('create table if not exists mappings (name text primary key, definition blob)')
    for scope in scopes:
        manager=scope.manager
        if approval is not None and not local_appointments and appointment_case != 'missing':
            definition = manager.selection.definition
            appointment = RoleAppointment(definition, 'operator', appointed_principal, 'generation-1')
            if appointment_case == 'revision':
                appointment = replace(appointment, definition=replace(definition, revision='other-revision'))
            if appointment_case == 'scope':
                appointment = replace(appointment, definition=replace(definition, scope='other-scope'))
            if appointment_case == 'generation':
                appointment = replace(appointment, generation='generation-2')
            # This fixture registry contains its own fixed record. It does not
            # build an appointment from the queried values or the declaration.
            manager.verify_role_appointment = lambda *_args, record=appointment: record
        if no_evidence:
            manager.evidence = None
        elif self_attested and scope.name == 'two':
            manager.evidence = replace(manager.evidence,source=manager.selection.definition.manager)
        def readback(name, revision, manager=manager):
            manager.reads += 1
            with sqlite3.connect(authority) as c:
                row=c.execute('select definition from mappings where name=?',(name,)).fetchone()
            return ManagerReadback('present',pickle.loads(row[0])) if row else ManagerReadback('absent')
        def create(selection, manager=manager):
            manager.creates += 1
            with sqlite3.connect(authority) as c:
                c.execute('insert into mappings values (?,?)',
                          (selection.definition.name,pickle.dumps(selection.definition)))
        manager.readback=readback; manager.create=create
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(path); listener.listen(5); listener.settimeout(8)
    pins = adapter.binding_check_pins() if binding_check else None
    pipe.send((adapter.identity,adapter.operation_key,os.getpid(),pins))
    count=0
    try:
        while count < request_limit:
            count+=1
            try:
                if not drop_first:
                    managed_cli.serve_listener_once(listener,authorized_uids=frozenset({os.getuid()}),adapter=adapter)
                else:
                    conn,_=listener.accept()
                    with conn:
                        peer = DropReply(conn) if drop_first and count == 1 else conn
                        managed_cli.serve_connection(peer,authorized_uids=frozenset({os.getuid()}),adapter=adapter)
            except (OSError,ValueError,PermissionError,EOFError): pass
    except socket.timeout: pass
    finally:
        pipe.send(([s.manager.creates for s in scopes],[s.manager.starts for s in scopes]))
        listener.close(); os.unlink(path); pipe.close()


class TransportTest(unittest.TestCase):
    def setUp(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        self.wheel=wheel
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.root.chmod(0o700)
        (self.root/'workeros').mkdir(mode=0o700)
        self.path=str(self.root/'sock'); self.db=str(self.root/'history.db')
        self.config_path=self.root/'workeros'/'managed-host.json'
        self.child=None

    def start(self, *, lost=False, mismatch=False, request_limit=3, approval=None, no_evidence=False,
              appointed_principal=None, appointment_case='exact', local_appointments=False,
              binding_check=False, self_attested=False):
        parent,child=multiprocessing.get_context('fork').Pipe()
        self.child=multiprocessing.get_context('fork').Process(target=host,
            args=(self.path,self.db,self.wheel,child,lost,mismatch,request_limit,approval,no_evidence,
                  appointed_principal or pwd.getpwuid(os.getuid()).pw_name,appointment_case,local_appointments,
                  binding_check,self_attested))
        self.child.start(); child.close(); self.pipe=parent
        identity,key,pid,pins=parent.recv()
        self.config={'version':1,'socket':self.path,'peer_uid':os.getuid(),'profile':'fixture',
                     'scopes':['one','two','three'],'identity':identity,'operation_key':key}
        if pins is not None:
            self.config['binding_check'] = pins
        self.write_config(); self.assertNotEqual(pid,os.getpid())

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config)); self.config_path.chmod(0o600)

    def command(self, operation='setup', *, altered=True, canonical=False):
        script=str(Path(sys.prefix)/'bin'/('workeros' if canonical else 'workeros-managed'))
        entry=[script,'managed',operation] if canonical else [script,operation]
        if altered:
            code=('import sys,runpy; import worker_handoff.managed_cli as m; '
                  'm._CONFIG_PARENT=sys.argv[1]; m._TRUSTED_UID=int(sys.argv[2]); '
                  + ('' if canonical else 'm._TIMEOUT=0.8; ')
                  + 'sys.argv=sys.argv[3:]; runpy.run_path(sys.argv[0],run_name="__main__")')
            args=[sys.executable,'-I','-c',code,str(self.root),str(os.getuid()),*entry]
        else: args=entry
        return subprocess.run(args,capture_output=True,text=True,timeout=8 if canonical else 4)

    def finish(self):
        if self.child:
            self.child.terminate(); self.child.join(3)
            self.pipe.close(); self.child=None
    def tearDown(self): self.finish()

    def local_command(self, args, data=None, *, expected_exit=0, fail_appointments=False):
        script = str(Path(sys.prefix)/'bin'/'workeros')
        code = """
import os, runpy, sys
from worker_handoff import roles_cli
roles_cli._PARENT, roles_cli._UID = sys.argv[1], os.getuid()
if sys.argv[2] == 'fail':
    from worker_handoff import appointment_registry
    def fail_registration(*args):
        raise OSError('synthetic interruption before appointment write')
    appointment_registry._register_store = fail_registration
sys.argv = sys.argv[3:]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
        result = subprocess.run([sys.executable,'-I','-c',code,str(self.root),
                                 'fail' if fail_appointments else '',script,*args],
                                input=data,text=True,capture_output=True,timeout=5)
        self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def declaration(self, *, operation='observe'):
        (self.root/'workeros').chmod(0o700)
        return {'version':1, 'profile':'fixture', 'revision':'revision-1',
                'roles':[{'name':'operator', 'principal':pwd.getpwuid(os.getuid()).pw_name,
                          'operations':[operation], 'scopes':['run-one','run-two','run-three','scope-1'],
                          'expires_at':8_000_000_000}]}

    def approve(self, *, operation='observe'):
        receipt = self.local_command(['managed','commission-apply'],json.dumps(self.declaration(operation=operation)))
        self.assertEqual(receipt['status'], 'configured')
        return LocalProfileApproval(receipt['declaration_sha256'],receipt['intent_sha256'])

    def collect_host(self, expected_creates):
        self.child.join(4)
        self.assertEqual(self.child.exitcode, 0)
        self.assertTrue(self.pipe.poll(1))
        self.assertEqual(self.pipe.recv(), (expected_creates,[0,0,0]))
        self.child=None
        self.pipe.close()

    def appointment_entries(self, *, interval=False):
        digest = hashlib.sha256(Path(self.wheel).read_bytes()).hexdigest()
        entries = []
        for workflow in ('one','two','three'):
            scope = make_transport_scope(workflow,digest,interval=interval)
            definition = scope.manager.selection.definition
            entries.append({'workflow':workflow, 'workflow_revision':definition.revision,
                            'definition_sha256':definition_sha256(definition), 'role':'operator',
                            'principal':pwd.getpwuid(os.getuid()).pw_name, 'scope':definition.scope,
                            'generation':'generation-1', 'operations':['observe']})
        return entries

    def appointments(self, approval):
        return {'version':1, 'profile':'fixture', 'revision':'revision-1',
                'declaration_sha256':approval.declaration_sha256, 'intent_sha256':approval.intent_sha256,
                'appointments':self.appointment_entries()}

    def approve_interval_fixture(self):
        entries = self.appointment_entries(interval=True)
        result = self.local_command(['managed','apply-profile'],
                                    json.dumps({**self.declaration(),'appointments':entries}))
        self.assertEqual((result['status'],result['readiness'],result['independence']),
                         ('configured','not_checked','unverified'))
        return (LocalProfileApproval(result['declaration_sha256'],result['intent_sha256']),
                {entry['workflow']:entry['definition_sha256'] for entry in entries})

    def collect_binding_check(self):
        self.collect_host([0,0,0])
        self.assertEqual(list(Path(self.db).iterdir()),[])
        with sqlite3.connect(self.db+'-authority.db') as conn:
            self.assertEqual(conn.execute('select count(*) from mappings').fetchone(),(0,))

    def test_installed_binding_check_uses_pins_without_committing_setup(self):
        approval, digests = self.approve_interval_fixture()
        self.start(approval=approval,local_appointments=True,binding_check=True,request_limit=1)
        pins = self.config.pop('binding_check')
        self.assertEqual(pins,{'revision':'revision-1','clock_id':'fixture-clock','scope_digests':digests})
        self.write_config()
        result = self.command('check-bindings',canonical=True)
        refused = json.loads(result.stdout)
        self.assertEqual((result.returncode,refused['code'],refused['effect']),
                         (1,'binding_check_pins_required','not_attempted'))
        # The single-request listener must still serve the approved check.
        self.config['binding_check'] = pins
        self.write_config()
        result = self.command('check-bindings',canonical=True)
        receipt = json.loads(result.stdout)
        self.assertEqual((result.returncode,receipt['status'],receipt['operation'],receipt['effect'],
                          receipt['readiness'],receipt['runtime_evidence'],receipt['independence']),
                         (0,'bindings_verified','check-bindings','not_attempted','not_checked',
                          'not_requested','unverified'))
        self.assertEqual({item['name']:item['definition_sha256'] for item in receipt['scopes']},digests)
        self.assertEqual([item['status'] for item in receipt['scopes']],['bindings_verified']*3)
        observation = receipt['observation']
        self.assertEqual(observation['clock_id'],pins['clock_id'])
        start,end,expiry = (int(observation[key]) for key in ('start_ns','end_ns','valid_until_ns'))
        self.assertTrue(start <= end < expiry)
        for changed in (
            {'effect':'committed'},
            {'observation':{**observation,'clock_id':'other-clock'}},
            {'scopes':[*receipt['scopes'],receipt['scopes'][0]]},
        ):
            malformed = json.dumps({**receipt,**changed}).encode()
            with self.assertRaisesRegex(managed_cli.Refusal,'response_invalid'):
                managed_cli._binding_response(malformed,self.config)
        self.collect_binding_check()

    def test_installed_binding_check_refuses_a_different_definition_pin(self):
        approval, digests = self.approve_interval_fixture()
        self.start(approval=approval,local_appointments=True,binding_check=True,request_limit=1)
        wrong = 'e'*64
        self.assertNotEqual(digests['two'],wrong)
        self.config['binding_check']['scope_digests']['two'] = wrong
        self.write_config()
        result = self.command('check-bindings',canonical=True)
        receipt = json.loads(result.stdout)
        self.assertEqual((result.returncode,receipt['code'],receipt['effect']),
                         (1,'response_unconfirmed','not_attempted'))
        self.collect_binding_check()

    def test_installed_binding_check_requires_current_independent_sources(self):
        approval, _ = self.approve_interval_fixture()
        for options,status,code,scope_codes in (
            ({'mismatch':True},'refused','binding_generation_changed',[]),
            ({'self_attested':True},'incomplete',None,
             ['bindings_verified','independent_evidence_invalid','bindings_verified']),
            ({'no_evidence':True},'incomplete',None,['independent_evidence_missing']*3),
        ):
            with self.subTest(options=options):
                self.start(approval=approval,local_appointments=True,binding_check=True,request_limit=1,
                           **options)
                result = self.command('check-bindings',canonical=True)
                receipt = json.loads(result.stdout)
                self.assertEqual((result.returncode,receipt['status'],receipt['effect']),
                                 (1,status,'not_attempted'))
                self.assertEqual(receipt['code'],code)
                self.assertEqual([item['code'] for item in receipt['scopes']],scope_codes)
                self.assertIsNone(receipt['observation'])
                self.collect_binding_check()

    def test_one_approved_input_restarts_and_checks_fixture_providers(self):
        entries = self.appointment_entries()
        document = {**self.declaration(), 'appointments':entries}
        approved_input = json.dumps(document)
        args = ['managed','commission-apply']
        preview = self.local_command([*args,'--preview'],approved_input)
        self.assertEqual((preview['status'],preview['effect'],preview['appointments']),
                         ('preview','not_attempted',entries))
        self.assertFalse((self.root/'workeros'/'profiles').exists())
        result = self.local_command(args,approved_input)
        self.assertEqual((result['status'],result['readiness'],result['independence']),
                         ('configured','not_checked','unverified'))
        self.assertEqual((result['declaration_effect'],result['appointment_effect']), ('recorded','recorded'))
        self.assertEqual(result['appointments_sha256'], preview['appointments_sha256'])
        self.assertEqual(result['intent_sha256'],hashlib.sha256(approved_input.encode()).hexdigest())
        repeated = self.local_command(args,approved_input)
        self.assertEqual((repeated['effect'],repeated['appointment_effect']), ('unchanged','unchanged'))

        status_args = ['managed','commission-status','fixture','revision-1']
        status = self.local_command(status_args)
        self.assertEqual((status['status'],status['appointment_status'],status['appointments_sha256']),
                         ('configured','registered',result['appointments_sha256']))
        approval = LocalProfileApproval(status['declaration_sha256'],status['intent_sha256'])
        self.start(approval=approval,local_appointments=True,request_limit=1)
        setup = json.loads(self.command().stdout)
        self.assertEqual((setup['status'],[scope['setup'] for scope in setup['scopes']]), ('ready',['accepted']*3))
        self.collect_host([1,1,1])
        self.start(approval=approval,local_appointments=True,request_limit=1)
        observed = json.loads(self.command('readback').stdout)
        self.assertEqual((observed['status'],observed['identity'],observed['scopes']),
                         ('ready',setup['identity'],setup['scopes']))
        self.collect_host([0,0,0])
        self.start(approval=approval,local_appointments=True,no_evidence=True,request_limit=1)
        unverified = json.loads(self.command('readback').stdout)
        self.assertEqual(unverified['status'], 'incomplete')
        self.collect_host([0,0,0])

    def test_bundled_receipt_remains_incomplete_until_exact_registry_is_written(self):
        entries = self.appointment_entries()
        approved_input = json.dumps({**self.declaration(), 'appointments':entries})
        args = ['managed','commission-apply']
        partial = self.local_command(args,approved_input,expected_exit=1,fail_appointments=True)
        self.assertEqual((partial['status'],partial['effect'],partial['commission_effect'],
                          partial['appointment_effect']), ('unknown','unknown','recorded','unknown'))
        status_args = ['managed','commission-status','fixture','revision-1']
        status = self.local_command(status_args,expected_exit=1)
        self.assertEqual((status['status'],status['appointment_status']), ('incomplete','unregistered'))
        self.assertEqual(status['appointments_sha256'], partial['appointments_sha256'])
        approval = LocalProfileApproval(status['declaration_sha256'],status['intent_sha256'])
        self.start(approval=approval,local_appointments=True,request_limit=1)
        refused = json.loads(self.command().stdout)
        self.assertEqual((refused['status'],refused['scopes'][0]['code']), ('refused','role_appointment_unverified'))
        self.assertEqual(list(Path(self.db).iterdir()), [])
        self.collect_host([0,0,0])

        changed = self.appointments(approval)
        changed['appointments'][0]['generation'] = 'generation-2'
        rejected = self.local_command(['managed','appointment-register'],json.dumps(changed),expected_exit=1)
        self.assertEqual(rejected['code'],'appointment_approval_mismatch')
        result = self.local_command(args,approved_input)
        self.assertEqual((result['status'],result['declaration_effect'],result['appointment_effect']),
                         ('configured','unchanged','recorded'))

    def test_builtin_registry_registration_and_managed_readback_after_restart(self):
        approval = self.approve()
        status_args = ['managed','appointment-status','fixture','revision-1']
        self.assertEqual(self.local_command(status_args, expected_exit=1)['status'], 'unregistered')
        self.start(approval=approval,local_appointments=True,request_limit=1)
        absent = json.loads(self.command().stdout)
        self.assertEqual((absent['status'], absent['effect']), ('refused', 'not_attempted'))
        self.assertEqual(absent['scopes'][0]['code'], 'role_appointment_unverified')
        self.assertEqual(list(Path(self.db).iterdir()), [])
        self.collect_host([0,0,0])

        document = self.appointments(approval)
        args = ['managed','appointment-register']
        registration = self.local_command(args, json.dumps(document))
        self.assertEqual((registration['status'], registration['effect'], registration['independence']),
                         ('registered', 'recorded', 'unverified'))
        self.assertEqual(self.local_command(args, json.dumps(document))['effect'], 'unchanged')
        changed = json.loads(json.dumps(document))
        changed['appointments'][0]['generation'] = 'generation-2'
        conflict = self.local_command(args, json.dumps(changed), expected_exit=1)
        self.assertEqual(conflict['code'], 'appointment_registration_conflict')
        self.assertEqual(self.local_command(status_args)['appointments'], document['appointments'])

        self.start(approval=approval,local_appointments=True,request_limit=1)
        first = json.loads(self.command().stdout)
        self.assertEqual(first['status'], 'ready')
        self.collect_host([1,1,1])
        self.start(approval=approval,local_appointments=True,request_limit=1)
        second = json.loads(self.command('readback').stdout)
        self.assertEqual((second['status'],second['identity'],second['scopes']),
                         ('ready',first['identity'],first['scopes']))
        self.collect_host([0,0,0])

        self.start(approval=approval,local_appointments=True,mismatch=True,request_limit=1)
        stale = json.loads(self.command('readback').stdout)
        self.assertEqual((stale['status'], stale['scopes'][0]['code']), ('refused', 'binding_generation_changed'))
        self.collect_host([0,0,0])
        self.local_command(['roles','revoke','fixture','revision-1'])
        self.assertEqual(self.local_command(status_args, expected_exit=1)['status'], 'revoked')

    def test_registry_rejects_other_principal_and_cannot_supply_evidence(self):
        approval = self.approve()
        document = self.appointments(approval)
        invalid = json.loads(json.dumps(document))
        invalid['appointments'][0]['principal'] = 'unapproved-fixture-principal'
        args = ['managed','appointment-register']
        store = self.root/'workeros'/'profiles'
        before = {path.name: path.read_bytes() for path in store.iterdir()}
        bad = self.local_command(args, json.dumps(invalid), expected_exit=1)
        self.assertEqual((bad['code'], bad['effect']), ('appointment_outside_declaration', 'not_attempted'))
        self.assertEqual({path.name: path.read_bytes() for path in store.iterdir()}, before)
        self.local_command(args, json.dumps(document))
        self.start(approval=approval,local_appointments=True,no_evidence=True,request_limit=1)
        result = json.loads(self.command().stdout)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual([entry['setup'] for entry in result['scopes']], ['refused']*3)
        self.collect_host([0,0,0])

    def test_local_approval_binds_pre_registered_scopes_across_restart(self):
        approval = self.approve()
        self.start(approval=approval,request_limit=1)
        result = self.command()
        first = json.loads(result.stdout)
        self.assertEqual((result.returncode, first['status']), (0, 'ready'))
        self.assertEqual([scope['setup'] for scope in first['scopes']], ['accepted']*3)
        self.collect_host([1,1,1])
        self.start(approval=approval,request_limit=1)
        observed = json.loads(self.command('readback').stdout)
        self.assertEqual(observed['identity'], first['identity'])
        self.assertEqual(observed['scopes'], first['scopes'])
        self.assertEqual(observed['status'], 'ready')
        self.collect_host([0,0,0])
        self.start(approval=approval,appointment_case='missing',request_limit=1)
        unverified = json.loads(self.command('readback').stdout)
        self.assertEqual((unverified['status'], unverified['effect']), ('refused', 'not_attempted'))
        self.assertEqual([entry['code'] for entry in unverified['scopes']], ['role_appointment_unverified']*3)
        self.collect_host([0,0,0])
        self.local_command(['roles','revoke','fixture','revision-1'])
        self.start(approval=approval,request_limit=1)
        revoked = json.loads(self.command('readback').stdout)
        self.assertEqual((revoked['status'], revoked['effect']), ('refused', 'not_attempted'))
        self.assertEqual([entry['code'] for entry in revoked['scopes']], ['profile_revoked']*3)
        self.collect_host([0,0,0])

    def test_setup_refuses_missing_or_mismatched_role_appointment_before_claim(self):
        approval = self.approve()
        for case, options, expected_code in (
            ('missing', {'appointment_case':'missing'}, 'role_appointment_unverified'),
            ('principal', {'appointed_principal':'different-fixture-principal'}, 'role_appointment_mismatch'),
            ('revision', {'appointment_case':'revision'}, 'role_appointment_mismatch'),
            ('scope', {'appointment_case':'scope'}, 'role_appointment_mismatch'),
            ('appointment generation', {'appointment_case':'generation'}, 'role_appointment_mismatch'),
            ('live generation', {'mismatch':True}, 'binding_generation_changed'),
        ):
            with self.subTest(case=case):
                self.start(approval=approval,request_limit=1,**options)
                result = self.command()
                denied = json.loads(result.stdout)
                self.assertEqual((result.returncode, denied['status'], denied['effect']), (1, 'refused', 'not_attempted'))
                self.assertEqual(denied['scopes'][0]['code'], expected_code)
                self.assertEqual(list(Path(self.db).iterdir()), [])
                self.collect_host([0,0,0])

    def test_declared_role_operations_cannot_be_widened(self):
        approval = self.approve(operation='read')
        self.start(approval=approval,request_limit=1)
        denied = json.loads(self.command().stdout)
        self.assertEqual((denied['status'], denied['effect']), ('refused', 'not_attempted'))
        self.assertEqual([entry['code'] for entry in denied['scopes']], ['commissioned_mapping_mismatch']*3)
        self.assertEqual(list(Path(self.db).iterdir()), [])
        self.collect_host([0,0,0])

    def test_local_approval_requires_the_exact_intent_digest(self):
        approval = self.approve()
        wrong = replace(approval, intent_sha256='0'*64)
        self.start(approval=wrong,request_limit=1)
        denied = json.loads(self.command().stdout)
        self.assertEqual((denied['status'], denied['effect']), ('refused', 'not_attempted'))
        self.assertEqual([entry['code'] for entry in denied['scopes']], ['commissioned_mapping_mismatch']*3)
        self.assertEqual(list(Path(self.db).iterdir()), [])
        self.collect_host([0,0,0])

    def test_local_approval_cannot_replace_independent_evidence(self):
        approval = self.approve()
        self.start(approval=approval,no_evidence=True,request_limit=1)
        observed = json.loads(self.command().stdout)
        self.assertEqual(observed['status'], 'incomplete')
        self.assertEqual([entry['setup'] for entry in observed['scopes']], ['refused']*3)
        self.collect_host([0,0,0])

    def test_separate_host_exact_setup_and_read_only_reconcile(self):
        self.start()
        first=self.command(); second=self.command('readback'); third=self.command('reconcile')
        for result in (first,second,third):
            self.assertEqual(result.returncode,0,result.stderr)
            receipt=json.loads(result.stdout)
            self.assertEqual((receipt['identity'],receipt['operation_key']),(self.config['identity'],self.config['operation_key']))
            self.assertEqual(receipt['status'],'ready')
            self.assertEqual(len(receipt['scopes']),3)
            self.assertLess(int(receipt['observation']['end_ns']),int(receipt['observation']['valid_until_ns']))
        self.child.join(3)
        self.assertEqual(self.pipe.recv(),([1,1,1],[0,0,0]))
        self.assertEqual(self.child.exitcode,0)
        self.child=None; self.pipe.close()

    def test_lost_committed_reply_only_exact_readback(self):
        self.start(lost=True)
        first=self.command(); self.assertEqual((first.returncode,json.loads(first.stdout)['effect']),(1,'unknown'))
        self.assertEqual(json.loads(first.stdout)['operation_key'],self.config['operation_key'])
        second=self.command('reconcile'); self.assertEqual(json.loads(second.stdout)['status'],'ready')
        third=self.command('readback'); self.assertEqual(json.loads(third.stdout)['status'],'ready')
        self.child.join(3); self.assertEqual(self.pipe.recv(),([1,1,1],[0,0,0]))
        self.child=None; self.pipe.close()

    def test_journal_and_authority_survive_synthetic_host_restart(self):
        self.start(request_limit=1)
        first=self.command(); self.assertEqual(json.loads(first.stdout)['status'],'ready')
        identity=self.config['identity']; self.child.join(3)
        self.assertEqual(self.pipe.recv(),([1,1,1],[0,0,0]))
        self.child=None; self.pipe.close()
        self.start()
        self.assertEqual(self.config['identity'],identity)
        for operation in ('readback','reconcile','setup'):
            result=self.command(operation)
            self.assertEqual((result.returncode,json.loads(result.stdout)['status']),(0,'ready'))
        self.child.join(3)
        self.assertEqual(self.pipe.recv(),([0,0,0],[0,0,0]))
        self.assertEqual(self.child.exitcode,0)
        self.child=None; self.pipe.close()

    def test_wrong_commission_identity_has_no_effect(self):
        self.start(); self.config['identity']='c'*64; self.write_config()
        result=self.command(); self.assertEqual((result.returncode,json.loads(result.stdout)['effect']),(1,'unknown'))
        self.assertFalse(list(Path(self.db).iterdir()))

    def test_wrong_key_has_no_effect(self):
        self.start(); self.config['operation_key']='d'*64; self.write_config()
        result=self.command(); self.assertEqual((result.returncode,json.loads(result.stdout)['effect']),(1,'unknown'))
        self.assertFalse(list(Path(self.db).iterdir()))

    def test_stale_generation_refuses_scope(self):
        self.start(mismatch=True); result=self.command()
        self.assertEqual((result.returncode,json.loads(result.stdout)['status']),(1,'incomplete'))
        self.assertNotEqual(json.loads(result.stdout)['scopes'][0]['setup'],'accepted')

    def test_peer_mismatch_refuses_before_request(self):
        self.start(); self.config['peer_uid']=os.getuid()+1; self.write_config()
        result=self.command(); self.assertEqual((result.returncode,json.loads(result.stdout)['effect']),(1,'not_attempted'))
        self.assertFalse(list(Path(self.db).iterdir()))

    def test_untrusted_configuration_and_symlink_refused(self):
        self.start(); self.config_path.chmod(0o666)
        self.assertEqual(json.loads(self.command().stdout)['effect'],'not_attempted')
        self.config_path.chmod(0o600); target=self.config_path.with_name('original')
        self.config_path.rename(target); self.config_path.symlink_to(target.name)
        self.assertEqual(json.loads(self.command().stdout)['effect'],'not_attempted')

    def test_no_authorized_entry_refuses(self):
        if Path('/etc/workeros/managed-host.json').exists(): self.skipTest('real host configured; do not contact it')
        result=self.command(altered=False)
        self.assertEqual((result.returncode,json.loads(result.stdout)['effect']),(1,'not_attempted'))

    def test_preview_resolves_config_without_contact_or_setup(self):
        self.start()
        result=self.command('preview')
        receipt=json.loads(result.stdout)
        self.assertEqual((result.returncode,receipt['status'],receipt['effect']),(0,'configured','not_attempted'))
        self.assertEqual(receipt['identity'],self.config['identity'])
        self.assertFalse(list(Path(self.db).iterdir()))

    def test_preview_without_host_gives_next_action(self):
        if Path('/etc/workeros/managed-host.json').exists(): self.skipTest('real host configured; do not contact it')
        result=self.command('preview',altered=False)
        receipt=json.loads(result.stdout)
        self.assertEqual((result.returncode,receipt['status'],receipt['effect']),(1,'refused','not_attempted'))
        self.assertIn('administrator',receipt['next_action'])


class AdapterTest(unittest.TestCase):
    def test_listener_once_refuses_bad_registration_and_bounds_idle_wait(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        with tempfile.TemporaryDirectory() as p:
            adapter,scopes=make_adapter(wheel,str(Path(p)/'store'))
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(str(Path(p)/'sock')); listener.listen(1); listener.settimeout(2)
                with self.assertRaises(ValueError):
                    managed_cli.serve_listener_once(listener,authorized_uids=frozenset(),adapter=adapter)
                with self.assertRaises(ValueError):
                    managed_cli.serve_listener_once(listener,authorized_uids=frozenset({os.getuid()}),adapter=adapter,accept_timeout=6)
                with self.assertRaises(TimeoutError):
                    managed_cli.serve_listener_once(listener,authorized_uids=frozenset({os.getuid()}),adapter=adapter,accept_timeout=0.01)
                self.assertEqual(listener.gettimeout(),2)
            self.assertEqual([s.manager.creates for s in scopes],[0,0,0])

    def test_expiry_immediately_before_response_refuses_ready(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        with tempfile.TemporaryDirectory() as p:
            adapter,scopes=make_adapter(wheel,str(Path(p)/'store'))
            self.assertEqual(adapter.setup()['status'],'ready')
            left,right=socket.socketpair()
            self.addCleanup(left.close); self.addCleanup(right.close)
            payload=json.dumps({'version':1,'operation':'readback','profile':adapter.profile,
                                'identity':adapter.identity,'operation_key':adapter.operation_key}).encode()
            right.sendall(struct.pack('!I',len(payload))+payload)
            with patch('worker_handoff.managed_cli.monotonic_ns',return_value=2**62):
                managed_cli.serve_connection(left,authorized_uids=frozenset({os.getuid()}),adapter=adapter)
            length=struct.unpack('!I',right.recv(4))[0]
            result=json.loads(right.recv(length))
            self.assertEqual(result['status'],'incomplete')
            self.assertEqual([s.manager.creates for s in scopes],[1,1,1])

    def test_store_unavailable_never_claims_or_starts(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        with tempfile.TemporaryDirectory() as p:
            adapter,scopes=make_adapter(wheel,str(Path(p)/'store'))
            with patch.object(adapter.store,'read',side_effect=OSError('unavailable')):
                self.assertEqual(adapter.setup()['status'],'unknown')
            self.assertEqual([s.manager.creates for s in scopes],[0,0,0])

    def test_selected_mapping_change_refuses_before_scope_create(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        with tempfile.TemporaryDirectory() as p:
            adapter,scopes=make_adapter(wheel,str(Path(p)/'store'))
            s=scopes[0].manager.selection
            scopes[0].manager.selection=replace(s,definition=replace(s.definition,policy_sha256='c'*64))
            result=adapter.setup()
            self.assertEqual(result['status'],'incomplete')
            self.assertNotEqual(result['scopes'][0]['setup'],'accepted')
            self.assertEqual(scopes[0].manager.creates,0)

    def test_lost_store_finish_reply_reconciles_without_replay(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        with tempfile.TemporaryDirectory() as p:
            adapter,scopes=make_adapter(wheel,str(Path(p)/'store'))
            finish=adapter.store.finish
            def lost(*args):
                finish(*args)
                raise OSError('synthetic acknowledgement loss')
            with patch.object(adapter.store,'finish',side_effect=lost):
                self.assertEqual(adapter.setup()['status'],'unknown')
            self.assertEqual(adapter.reconcile()['status'],'ready')
            self.assertEqual(adapter.setup()['status'],'ready')
            self.assertEqual([s.manager.creates for s in scopes],[1,1,1])

    def test_lost_claim_is_pending_and_is_never_replayed(self):
        wheel=os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel: self.skipTest('exact installed wheel path not supplied')
        with tempfile.TemporaryDirectory() as p:
            adapter,scopes=make_adapter(wheel,str(Path(p)/'store'))
            claim=adapter.store.claim
            def lost(*args):
                claim(*args)
                raise OSError('synthetic acknowledgement loss')
            with patch.object(adapter.store,'claim',side_effect=lost) as called:
                self.assertEqual(adapter.setup()['status'],'unknown')
                self.assertEqual(adapter.setup()['status'],'unknown')
                self.assertEqual(adapter.reconcile()['status'],'unknown')
                self.assertEqual(called.call_count,1)
            self.assertEqual([s.manager.creates for s in scopes],[0,0,0])
