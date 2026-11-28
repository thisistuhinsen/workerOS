"""Exercise the managed launch socket and its no-effect boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext, redirect_stdout
from dataclasses import asdict
import errno
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import socket
import struct
from tempfile import TemporaryDirectory
from time import monotonic, monotonic_ns, time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from workeros import managed_cli, managed_executor, managed_registration, managed_service_client, roles_cli
from workeros.appointment_registry import definition_sha256, launch_policy_sha256, launch_scope_sha256
from workeros.managed_executor import authority_pin
from workeros.managed_launch import GUARDED_SERVICE, LaunchRolePolicy, ScopedLaunch, ServiceWindow
from workeros.managed_service import ServiceScope
from workeros.managed_service_guard import GuardedServiceAuthority, ServicePhaseObservation
from workeros.managed_service_scope import ServiceBundle
from workeros.profile_setup import ProfileDefinition, ProviderBinding


class ManagedServiceClientTest(TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.directory = root / 'workeros'
        self.directory.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.other_uid = 1 if self.uid != 1 else 2
        self.enterContext(patch.multiple(managed_cli, _CONFIG_PARENT=str(root), _TRUSTED_UID=self.uid))
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(root), _UID=self.uid))
        self.endpoint = str(root / 'launch.sock')
        self.workflow = 'inventory-updater'
        self.request_id = 'a' * 64
        authority_socket = str(root / 'authority.sock')
        policy = LaunchRolePolicy(self.workflow, '1'*64, 'generation', 'write-role', 'worker',
                                  '2'*64, '3'*64, 'launcher', 'observer',
                                  authority_pin('observer', authority_socket, self.other_uid), 1001)
        self.client = {
            'version': 1, 'profile': 'reports', 'revision': 'review-1', 'socket': self.endpoint,
            'peer_uid': self.uid, 'workflows': {self.workflow: launch_policy_sha256(policy)},
        }
        self.server = {
            'version': 2, 'profile': 'reports', 'revision': 'review-1',
            'wheel_path': str(root / 'unused-fixture.whl'), 'wheel_sha256': '5'*64,
            'workflows': {
                self.workflow: {
                    'policy': asdict(policy), 'authority': {'socket': authority_socket, 'uid': self.other_uid},
                    'service': {'root_directory': '/approved/worker', 'root_device': 1, 'root_inode': 2,
                                'executable': '/worker', 'principal_gid': 1001, 'mode': 'read-write',
                                'original_device': 3, 'original_inode': 4, 'original_fd': 9},
                    'run_uids': [self.uid], 'result_uids': [self.other_uid],
                },
            },
        }

    def write_config(self):
        for basename, content in (('launch-client.json', self.client), ('launch-executor.json', self.server)):
            path = self.directory / basename
            path.write_text(json.dumps(content), encoding='utf-8')
            path.chmod(0o600)

    def exchange(self, handler, *, readback=False, invoke=None):
        self.write_config()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, ThreadPoolExecutor(1) as server:
                listener.bind(self.endpoint)
                listener.listen(1)
                listener.settimeout(4)

                def handle_one():
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(4)
                        return handler(connection)

                future = server.submit(handle_one)
                result = (managed_service_client.request_service(self.workflow, self.request_id, readback=readback)
                          if invoke is None else invoke())
                return result, future.result(timeout=4)
        finally:
            Path(self.endpoint).unlink(missing_ok=True)

    def test_wrong_real_peer_receives_no_request(self):
        self.client['peer_uid'] = self.other_uid
        # Supply the enrollment after its file check here so the enrolled
        # owner can differ from this ordinary fixture's real listener UID.
        with patch.multiple(managed_cli, _TRUSTED_UID=self.other_uid), patch.object(
                managed_cli, '_read_admin_json', return_value=self.client):
            result, request = self.exchange(lambda connection: connection.recv(1))
        self.assertEqual(request, b'')
        self.assertEqual(result, {'status': 'refused', 'effect': 'not_attempted', 'code': 'service_peer_untrusted'})

    def test_lost_reply_after_real_request_preserves_unknown(self):
        def discard_reply(connection):
            deadline = monotonic() + 4
            size, = struct.unpack('!I', managed_cli._read_exact(connection, 4, deadline))
            return json.loads(managed_cli._read_exact(connection, size, deadline))

        result, request = self.exchange(discard_reply)
        self.assertEqual(request['workflow'], self.workflow)
        self.assertEqual(request['request_id'], self.request_id)
        self.assertEqual(request['policy_sha256'], self.client['workflows'][self.workflow])
        self.assertEqual(result, {'status': 'unknown', 'effect': 'unknown', 'code': 'service_reply_unconfirmed',
                                  'request_id': self.request_id})

    def test_real_peer_result_right_does_not_grant_run(self):
        entry = self.server['workflows'][self.workflow]
        entry['run_uids'] = [self.other_uid]
        entry['result_uids'] = [self.uid]
        scope = ServiceScope(**entry['service'])
        key = 'b' * 64
        receipt = {
            'status': 'terminal', 'effect': 'dispatched', 'code': 'launch_readback_verified',
            'request_id': self.request_id, 'invocation_key': key, 'receipt_sha256': 'c'*64,
            'service': {'unit': f'workeros-{key}.service', 'invocation_id': 'd'*32,
                        'scope_sha256': scope.digest, 'group_empty': True, 'handles_closed': False},
            'cleanup': 'unconfirmed',
        }

        def history(registration, profile, revision, request_id, _deadline):
            self.assertEqual((profile, revision, request_id),
                             (self.server['profile'], self.server['revision'], self.request_id))
            self.assertEqual(registration.plan.workflow, self.workflow)
            self.assertEqual(registration.service_scope_sha256, scope.digest)
            return receipt

        with patch.object(managed_service_client, 'verify_install') as verify, patch.object(
                managed_service_client, '_read_historical_launch', side_effect=history) as historical, patch.object(
                managed_service_client.managed_service, 'prepare') as prepare:
            result, _ = self.exchange(managed_service_client.serve_connection)
            self.assertEqual(result['code'], 'service_caller_denied')
            historical.assert_not_called()
            verify.assert_not_called()
            observed, _ = self.exchange(managed_service_client.serve_connection, readback=True)
            self.assertEqual(observed, {**receipt, 'selection': {
                'workflow': self.workflow, 'role': 'write-role', 'scope_sha256': scope.digest,
                'resource_scopes': []}})
            historical.assert_called_once()
            prepare.assert_not_called()

    def test_run_right_does_not_grant_result_and_crossed_pin_refuses_run(self):
        with patch.object(managed_service_client, '_read_historical_launch') as historical, patch.object(
                managed_service_client.managed_service, 'prepare') as prepare:
            result, _ = self.exchange(managed_service_client.serve_connection, readback=True)
            self.assertEqual(result['code'], 'service_caller_denied')
            self.assertNotIn('selection', result)
            self.assertNotIn('phase_observation', result)
            self.client['workflows'][self.workflow] = 'e' * 64
            result, _ = self.exchange(managed_service_client.serve_connection)
            self.assertEqual(result, {'status': 'refused', 'effect': 'not_attempted',
                                      'code': 'service_registration_mismatch'})
            historical.assert_not_called()
            prepare.assert_not_called()

    def test_run_only_peer_gets_no_effective_status_in_run_reply(self):
        host = {'profile': self.server['profile'], 'revision': self.server['revision'],
                'version': 2, 'wheel_path': self.server['wheel_path'],
                'scopes': [{'definition': {'name': self.workflow, 'package_sha256': self.server['wheel_sha256']}}]}
        setup = self.directory / 'managed-setup.json'
        setup.write_text(json.dumps(host), encoding='utf-8')
        setup.chmod(0o600)
        adapter = Mock()
        adapter.launch_approved.return_value = {'status': 'terminal', 'effect': 'dispatched',
                                                'receipt_sha256': 'c'*64}
        with patch.object(managed_service_client.managed_service, 'prepare'), patch.object(
                managed_service_client.managed_bootstrap, '_open_approved_launch', return_value=nullcontext(adapter)):
            result, _ = self.exchange(managed_service_client.serve_connection)
        adapter.launch_approved.assert_called_once_with(request_id=self.request_id)
        self.assertEqual(result, {'status': 'unknown', 'effect': 'unknown', 'code': 'service_result_not_granted',
                                  'request_id': self.request_id})

    def test_guarded_readback_reports_exact_phase_only_to_result_reader(self):
        entry = self.server['workflows'][self.workflow]
        entry['authority']['enforcement'] = GUARDED_SERVICE
        entry['service'].update(
            limits={'active_ms': 2000, 'cleanup_ms': 1000, 'metered': False},
            parent={'unit': 'report-guard.service', 'control_group': '/reports.slice/report-guard.service',
                    'device': 7, 'inode': 100, 'mount_id': 25})
        scope = ServiceScope(**entry['service'])
        key = 'b'*64
        now = monotonic_ns()
        phase = ServicePhaseObservation(key, 'clock', scope.digest, {'device': 7, 'inode': 200, 'mount_id': 25},
                                        now - 1, now, True)

        def scoped_history(registration, _profile, _revision, request_id, _deadline):
            owner = registration.readback.__self__
            self.assertIsInstance(owner, GuardedServiceAuthority)
            owner.phase_observation = asdict(phase)
            return {'status': 'unknown', 'effect': 'unknown', 'code': 'launch_readback_unconfirmed',
                    'request_id': request_id, 'invocation_key': key}

        with patch('workeros.managed_registration.require_pinned_pair', return_value=None), patch.object(
                managed_service_client, 'verify_install'), patch.object(
                managed_service_client, '_read_historical_launch', side_effect=scoped_history) as history:
            refused, _ = self.exchange(managed_service_client.serve_connection, readback=True)
            self.assertEqual(refused['code'], 'service_caller_denied')
            self.assertNotIn('phase_observation', refused)
            history.assert_not_called()
            entry['result_uids'] = [self.uid]
            observed, _ = self.exchange(managed_service_client.serve_connection, readback=True)
        self.assertEqual((observed['status'], observed['effect']), ('unknown', 'unknown'))
        self.assertEqual(observed['phase_observation'], asdict(phase))
        self.assertEqual(observed['selection']['scope_sha256'], phase.scope_sha256)

    def test_stock_authentication_and_parent_read_do_not_reserve_or_submit_without_a_guard(self):
        host = {'profile': self.server['profile'], 'revision': self.server['revision'],
                'version': 2, 'wheel_path': self.server['wheel_path'],
                'scopes': [{'definition': {'name': self.workflow, 'package_sha256': self.server['wheel_sha256']}}]}
        setup = self.directory / 'managed-setup.json'
        setup.write_text(json.dumps(host), encoding='utf-8')
        setup.chmod(0o600)
        service = self.server['workflows'][self.workflow]['service']
        service['limits'] = {'active_ms': 2000, 'cleanup_ms': 1000, 'metered': False}
        before = frozenset(self.directory.iterdir()) | {
            self.directory / name for name in ('launch-client.json', 'launch-executor.json')
        }
        adapter = managed_service_client.managed_service
        with patch.object(adapter, '_system_manager') as manager, patch.object(
                adapter.managed_system_bus, 'verify_parent') as verify, patch.object(
                managed_service_client.managed_bootstrap, '_open_approved_launch') as open_adapter, patch.object(
                managed_service_client._Authority, 'authorize') as ticket:
            result, _ = self.exchange(managed_service_client.serve_connection)
            self.assertEqual(result['code'], 'service_parent_registration_required')
            manager.assert_not_called()
            verify.assert_not_called()
            service['parent'] = {'unit': 'reports.slice', 'control_group': '/reports.slice',
                                 'device': 7, 'inode': 100, 'mount_id': 25}
            result, _ = self.exchange(managed_service_client.serve_connection)
            self.assertEqual(result, {'status': 'refused', 'effect': 'not_attempted',
                                      'code': 'service_deadline_guard_provider_unavailable'})
            manager.assert_called_once()
            self.assertEqual(asdict(verify.call_args.args[0]), service['parent'])
            open_adapter.assert_not_called()
            ticket.assert_not_called()
        self.assertEqual(frozenset(self.directory.iterdir()), before)

    def test_guarded_front_doors_use_the_same_no_effect_stock_adapter(self):
        host = {'profile': self.server['profile'], 'revision': self.server['revision'],
                'version': 2, 'wheel_path': self.server['wheel_path'],
                'scopes': [{'definition': {'name': self.workflow, 'package_sha256': self.server['wheel_sha256']}}]}
        setup = self.directory / 'managed-setup.json'
        setup.write_text(json.dumps(host), encoding='utf-8')
        setup.chmod(0o600)
        entry = self.server['workflows'][self.workflow]
        entry['authority']['enforcement'] = GUARDED_SERVICE
        entry['result_uids'] = [self.uid]
        original = self.enterContext((self.directory / 'original').open('w+b'))
        identity = os.fstat(original.fileno())
        entry['service'].update(
            limits={'active_ms': 2000, 'cleanup_ms': 1000, 'metered': False},
            parent={'unit': 'report-guard.service', 'control_group': '/reports.slice/report-guard.service',
                    'device': 7, 'inode': 100, 'mount_id': 25},
            original_device=identity.st_dev, original_inode=identity.st_ino, original_fd=original.fileno())
        calls = []

        def provider(_authority, operation, invocation, deadline, **fields):
            calls.append(operation)
            self.assertEqual(fields['service']['enforcement'], GUARDED_SERVICE)
            if operation == 'read_service':
                return {'arm': None, 'observation': {
                    'invocation': asdict(invocation), 'source': invocation.plan.authority,
                    'source_sha256': invocation.plan.authority_sha256, 'status': 'not_started'}}
            self.assertEqual(operation, 'arm_service')
            return None  # The appointed provider declines before arming or admitting.

        def adapter(_host, registration, **_):
            self.assertEqual(registration.service_enforcement, GUARDED_SERVICE)
            self.assertTrue(registration.require_ticket_claim)
            registered = registration._for_attempt('b'*64)

            def launch_approved(*, request_id):
                self.assertEqual(request_id, self.request_id)
                deadline = monotonic_ns() + 2_000_000_000
                window = ServiceWindow(deadline, deadline + 1_000_000_000)
                launch = ScopedLaunch(registered, 'c'*64, 'fixture-clock', service_window=window)
                def claim_ticket(_):
                    self.fail('the refusing authority did not issue a ticket')

                return launch.start(valid_until_ns=deadline, deadline_ns=deadline, reserve=lambda: True,
                                    claim_ticket=claim_ticket)

            return nullcontext(Mock(launch_approved=launch_approved))

        def cli(arguments, document=b''):
            result = io.StringIO()
            with redirect_stdout(result), patch.object(
                    managed_executor.sys, 'stdin', io.TextIOWrapper(io.BytesIO(document))):
                managed_executor.main('run-approved', arguments)
            return json.loads(result.getvalue())

        body = {'version': 1, 'request_id': self.request_id, 'workflow': self.workflow}
        routes = {
            'python': lambda: managed_executor.registered_launch(self.request_id, workflow=self.workflow),
            'flags': lambda: cli(['--request-id', self.request_id, '--workflow', self.workflow]),
            'json': lambda: cli(['--format', 'json'], json.dumps(body).encode()),
        }
        if importlib.util.find_spec('yaml') is not None:
            routes['yaml'] = lambda: cli(['--format', 'yaml'], (
                f'version: 1\nrequest_id: "{self.request_id}"\nworkflow: {self.workflow}\n').encode())
        service = managed_service_client.managed_service
        with patch('workeros.managed_registration.require_pinned_pair', return_value=host), patch.object(
                service, '_system_manager'), patch.object(
                service.managed_system_bus, 'verify_parent'), patch.object(
                managed_service_client._Authority, '_exchange', new=provider), patch.object(
                managed_service_client.managed_bootstrap, '_open_approved_launch', side_effect=adapter):
            for name, invoke in routes.items():
                with self.subTest(route=name):
                    result, _ = self.exchange(managed_service_client.serve_connection, invoke=invoke)
                    self.assertEqual((result['status'], result['effect'], result['code']),
                                     ('refused', 'not_attempted', 'launch_authority_unverified'))
        self.assertEqual(calls, ['read_service', 'arm_service'] * len(routes))
        self.assertEqual(os.fstat(original.fileno()).st_size, 0)

    def test_scoped_operation_alias_uses_the_same_installed_guarded_path(self):
        self.exercise_scoped_operation(elevated=False)

    def test_registered_elevated_operation_uses_the_installed_guarded_path(self):
        self.exercise_scoped_operation(elevated=True)

    def test_registered_result_observer_uses_the_installed_guarded_path(self):
        self.exercise_scoped_operation(elevated=True, observe_result=True)

    def exercise_scoped_operation(self, *, elevated, observe_result=False):
        wheel_path = os.environ.get('WORKEROS_TEST_WHEEL')
        if not wheel_path:
            self.skipTest('exact installed wheel required')
        wheel_sha256 = sha256(Path(wheel_path).read_bytes()).hexdigest()
        encode = roles_cli._canonical
        original = self.directory / 'original'
        original.write_bytes(b'fixture')
        held = self.enterContext(original.open('rb'))
        identity = os.fstat(held.fileno())
        scope_name = 'inventory-source'
        service = {
            'root_directory': '/approved/worker', 'root_device': 1, 'root_inode': 2,
            'executable': '/reader', 'principal_gid': 1, 'active_ms': 2000, 'cleanup_ms': 1000, 'metered': False,
            'parent': {'unit': 'report-guard.service', 'control_group': '/reports.slice/report-guard.service',
                       'device': 7, 'inode': 100, 'mount_id': 25},
            'descriptors': [
                {'slot': 'stdin', 'scope': scope_name, 'mode': 'read', 'owner_uid': self.uid,
                 'device': identity.st_dev, 'inode': identity.st_ino, 'fd': held.fileno()},
            ],
        }
        if elevated:
            service['principal_gid'] = pwd.getpwuid(self.uid).pw_gid
            service['elevated_capabilities'] = [
                {'name': 'index_inventory', 'scope': scope_name, 'operation': 'read'}]
        bundle_pin = ServiceBundle(**service).digest
        entry = self.server['workflows'][self.workflow]
        entry['service'] = service
        entry['authority']['enforcement'] = GUARDED_SERVICE
        entry['result_uids'] = [self.uid]
        if observe_result:
            entry['result_observer'] = {'source': 'inventory-witness', 'socket': str(self.directory / 'witness.sock'),
                                        'uid': 50 if self.uid != 50 else 51, 'expected_effect_sha256': 'e'*64}
        self.server.update(wheel_path=wheel_path, wheel_sha256=wheel_sha256)
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(self.directory.parent), _UID=self.uid))
        bootstrap = managed_service_client.managed_bootstrap
        self.enterContext(patch.object(bootstrap, 'setup_clock_id', return_value='fixture-clock'))

        def cli(command, args, payload=b''):
            captured = io.StringIO()
            with redirect_stdout(captured), patch.object(
                    managed_cli.sys, 'stdin', io.TextIOWrapper(io.BytesIO(payload))):
                status = managed_cli.main([command, *args])
            return status, json.loads(captured.getvalue())

        calls = []

        def provider(_authority, operation, invocation, _deadline, **fields):
            calls.append(operation)
            self.assertEqual(fields['service']['scope_sha256'], bundle_pin)
            self.assertEqual(invocation.plan.scope_sha256, entry['policy']['scope_sha256'])
            self.assertEqual(os.pread(held.fileno(), 7, 0), b'fixture')
            if operation == 'read_service':
                return {'arm': None, 'observation': {
                    'invocation': asdict(invocation), 'source': invocation.plan.authority,
                    'source_sha256': invocation.plan.authority_sha256, 'status': 'not_started'}}
            self.assertEqual(operation, 'arm_service')
            return None

        def approve(revision, *, pin=bundle_pin, inode=identity.st_ino, capability='read',
                    alias=True, appointment=True, refusal=None):
            principal = pwd.getpwuid(self.uid).pw_name
            role_name = 'inventory-indexer'
            role = {'name': role_name, 'principal': principal, 'operations': ['launch', 'index_inventory'],
                    'scopes': [scope_name], 'expires_at': int(time()) + 100,
                    'resources': {scope_name: {'device': str(identity.st_dev), 'inode': str(inode)}}}
            if alias:
                role['operation_aliases'] = {'index_inventory': {
                    'capability': capability, 'scope': scope_name, 'provider_sha256': pin}}
            if elevated:
                role['privileged'] = [{'capability': 'index_inventory', 'scope': scope_name, 'approved': True}]
            scope_pin = launch_scope_sha256(role, scope_name, ['launch'])
            policy = {'version': 1, 'roles': {role_name: {'operations': ['launch']}},
                      'workflows': {self.workflow: {'role': role_name, 'operations': ['launch'],
                      'bindings': {'executable': 'program', 'supervisor': 'launcher',
                                   'streams': {'stdin': 'inventory.stdin'}}}}}
            definition = ProfileDefinition(self.workflow, 'r1', '0.8.0', wheel_sha256, sha256(encode(policy)).hexdigest(),
                'manager', scope_name, 'fixture-clock', monotonic_ns() + 40_000_000_000, (
                    ProviderBinding('program', '2'*64, scope_name, 'executable', 'launcher', 'executable'),
                    ProviderBinding('launcher', scope_pin, scope_name, 'scoped-launch', 'launcher', 'supervisor'),
                    ProviderBinding('inventory', bundle_pin, scope_name, 'systemd-fd', 'launcher', 'streams')))
            plan = LaunchRolePolicy(self.workflow, definition_sha256(definition), 'generation', role_name,
                                    principal, '2'*64, scope_pin, 'launcher', 'observer',
                                    authority_pin('observer', entry['authority']['socket'], self.other_uid), self.uid)
            plan_pin = launch_policy_sha256(plan)
            doc = {'version': 1, 'profile': self.server['profile'], 'revision': revision,
                   'roles': [role]}
            if appointment:
                doc['appointments'] = [{
                    'workflow': self.workflow, 'workflow_revision': definition.revision,
                    'definition_sha256': definition_sha256(definition), 'role': role_name,
                    'principal': principal, 'scope': scope_name, 'generation': plan.generation,
                    'operations': ['launch'], 'launch': {'scope_sha256': scope_pin, 'policy_sha256': plan_pin},
                }]
            local = {'declaration_sha256': sha256(encode({key: doc[key] for key in ('version', 'profile',
                      'revision', 'roles')})).hexdigest(), 'intent_sha256': sha256(encode(doc)).hexdigest()}
            host = {'version': 2, 'profile': doc['profile'], 'revision': revision, 'operation_key': '7'*64,
                    'authorized_uids': [self.uid], 'wheel_path': wheel_path, 'local_approval': local,
                    'scopes': [{'definition': asdict(definition), 'role': role_name, 'policy': policy,
                                'binding_generation': plan.generation}]}
            path = self.directory / 'managed-setup.json'
            if elevated:
                entry['policy'] = asdict(plan)
                self.client['workflows'][self.workflow] = plan_pin
                self.server['revision'] = self.client['revision'] = revision
                provision = {'version': 1, 'profile': doc, 'managed_setup': host, 'launch_executor': self.server}
                payload = encode(provision)
                if refusal:
                    status, result = cli('apply-profile', ['--preview', '--provision-managed'], payload)
                    self.assertEqual((status, result['code'], result['effect']), (1, refusal, 'not_attempted'))
                    return
                flags = ['--preview', '--provision-managed']
                status, preview = cli('apply-profile', flags, payload)
                self.assertEqual((status, preview['status'], preview['effect']), (0, 'preview', 'not_attempted'))
                self.assertEqual(preview['managed_registration']['enforcement'], 'not_checked')
                self.assertEqual(preview['managed_registration']['elevated_capabilities'][0]['operation'], 'read')
                if importlib.util.find_spec('yaml') is not None:
                    import yaml
                    status, yaml_preview = cli('apply-profile', ['--format', 'yaml', *flags],
                                               yaml.safe_dump(json.loads(payload)).encode())
                    self.assertEqual((status, yaml_preview), (0, preview))
                python_preview = managed_registration.apply(payload, input_sha256=sha256(payload).hexdigest(),
                                                           preview=True, provision=True)
                self.assertEqual(python_preview, preview)
                self.assertEqual(calls, [])
                self.assertFalse(path.exists())
                status, receipt = cli('apply-profile', ['--provision-managed'], payload)
                self.assertEqual((status, receipt['status'], receipt['managed_configuration_effect']),
                                 (0, 'configured', 'recorded'), receipt)
                status, observed = cli('profile-status', [doc['profile'], revision, '--registered-managed'])
                self.assertEqual((status, observed['managed_registration']), (0, preview['managed_registration']))
                self.assertEqual(observed['service_grants_sha256'], receipt['service_grants_sha256'])
                self.assertEqual(managed_registration.readback(doc['profile'], revision), observed)
                if importlib.util.find_spec('yaml') is not None:
                    status, yaml_repeat = cli('apply-profile', ['--format', 'yaml', '--provision-managed'],
                                              yaml.safe_dump(json.loads(payload)).encode())
                    self.assertEqual((status, yaml_repeat['effect'], yaml_repeat['service_grants_sha256']),
                                     (0, 'unchanged', receipt['service_grants_sha256']))
                repeat = managed_registration.apply(payload, input_sha256=sha256(payload).hexdigest(), provision=True)
                self.assertEqual((repeat['effect'], repeat['managed_configuration_effect']), ('unchanged', 'unchanged'))
                return
            status, receipt = cli('apply-profile', [], encode(doc))
            if refusal:
                self.assertEqual((status, receipt['code'], receipt['effect']), (1, refusal, 'not_attempted'))
                return
            self.assertEqual((status, receipt['status']), (0, 'configured'), receipt)
            if importlib.util.find_spec('yaml') is not None:
                import yaml
                status, preview = cli('apply-profile', ['--format', 'yaml', '--preview'],
                                      yaml.safe_dump(doc).encode())
                self.assertEqual((status, preview['status']), (0, 'preview'))
                self.assertEqual(preview['declaration_sha256'], receipt['declaration_sha256'])
            entry['policy'] = asdict(plan)
            self.client['workflows'][self.workflow] = plan_pin
            self.server['revision'] = self.client['revision'] = revision
            self.assertEqual(local, {key: receipt[key] for key in local})
            path.write_bytes(encode(host))
            path.chmod(0o600)

        def invoke(route, index, *, readback=False):
            request_id = sha256(str(index).encode()).hexdigest()
            body = {'version': 1, 'request_id': request_id, 'workflow': self.workflow}
            command = 'launch-status' if readback else 'run-approved'
            if route == 'python':
                return managed_executor.registered_launch(request_id, workflow=self.workflow, readback=readback)
            if route == 'flags':
                return cli(command, ['--request-id', request_id, '--workflow', self.workflow])[1]
            data = (encode(body) if route == 'json' else
                    f'version: 1\nrequest_id: "{request_id}"\nworkflow: {self.workflow}\n'.encode())
            return cli(command, ['--format', route], data)[1]

        store = self.directory.parent / 'workeros' / 'profiles'
        if observe_result:
            observer = entry['result_observer']
            distinct_uid = observer['uid']
            observer['uid'] = entry['authority']['uid']
            approve('crossed-observer', refusal='managed_registration_mismatch')
            self.assertFalse(store.exists())
            observer['uid'] = distinct_uid
            approve('with-observer')
            self._assert_result_observer(entry, bundle_pin, invoke, cli, store)
            self.assertEqual(original.read_bytes(), b'fixture')
            return
        if elevated:
            approve('wrong-mode', capability='write', refusal='unsupported_privileged_enforcement')
            approve('wrong-original', inode=identity.st_ino + 1, refusal='unsupported_privileged_enforcement')
            approve('wrong-pin', pin='f'*64, refusal='unsupported_privileged_enforcement')
            entry['authority'].pop('enforcement')
            approve('unguarded', refusal='managed_registration_mismatch')
            entry['authority']['enforcement'] = GUARDED_SERVICE
            self.assertFalse(store.exists())
            self.assertFalse((self.directory / 'launch-executor.json').exists())
            approve('valid-elevated')
            service_module = managed_service_client.managed_service
            with patch.object(service_module, '_system_manager'), patch.object(
                    service_module.managed_system_bus, 'verify_parent'), patch.object(
                    managed_service_client._Authority, '_exchange', new=provider):
                routes = ['python', 'flags', 'json']
                if importlib.util.find_spec('yaml') is not None:
                    routes.append('yaml')
                for index, route in enumerate(routes):
                    result, _ = self.exchange(managed_service_client.serve_connection, invoke=lambda: invoke(route, index))
                    self.assertEqual((result['code'], result['effect']),
                                     ('launch_authority_unverified', 'not_attempted'))
                self.assertEqual(calls, ['read_service', 'arm_service'] * len(routes))
                calls.clear()
                status, revoked = cli('revoke-profile', [self.client['profile'], self.client['revision']])
                self.assertEqual((status, revoked['status'], revoked['service_grants']),
                                 (0, 'revoked', 'new_use_denied'))
                result, _ = self.exchange(managed_service_client.serve_connection)
                self.assertEqual((result['code'], result['effect']), ('managed_registration_inactive', 'not_attempted'))
                self.assertIsNone(managed_registration.require_pinned_pair(self.server, required=True, readback=True))
                self.assertEqual(calls, [])
                repeat = roles_cli.revoke_profile(self.client['profile'], self.client['revision'])
                self.assertEqual((repeat['effect'], repeat['service_grants']), ('unchanged', 'new_use_denied'))
                historical, _ = self.exchange(managed_service_client.serve_connection, readback=True)
                self.assertEqual((historical['status'], historical['code']), ('not_started', 'launch_not_reserved'))
                self.assertEqual(calls, [])
            self.assertEqual(original.read_bytes(), b'fixture')
            return
        approve('unknown-label', alias=False, refusal='unsupported_operation')
        approve('unknown-capability', capability='launch', refusal='unsupported_alias_capability')
        approve('missing-appointment', appointment=False, refusal='operation_alias_appointment_required')
        self.assertFalse(store.exists())
        approve('valid-alias')
        service_module = managed_service_client.managed_service
        # This fixture isolates alias compilation and guarded client framing.
        # Real local registration and drift are covered in test_managed_registration.
        with patch('workeros.managed_registration.require_pinned_pair', return_value=None), patch.object(
                service_module, '_system_manager'), patch.object(
                service_module.managed_system_bus, 'verify_parent'), patch.object(
                managed_service_client._Authority, '_exchange', new=provider):
            routes = ['python', 'flags', 'json']
            if importlib.util.find_spec('yaml') is not None:
                routes.append('yaml')
            for index, route in enumerate(routes):
                with self.subTest(route=route):
                    result, _ = self.exchange(managed_service_client.serve_connection,
                                              invoke=lambda: invoke(route, index))
                    self.assertEqual((result['code'], result['effect']),
                                     ('launch_authority_unverified', 'not_attempted'))
            self.assertEqual(calls, ['read_service', 'arm_service'] * len(routes))
            calls.clear()
            for revision, change in (
                ('crossed-provider', {'pin': 'f'*64}), ('crossed-original', {'inode': identity.st_ino + 1}),
                ('write-on-reader', {'capability': 'write'}),
            ):
                with self.subTest(revision=revision):
                    approve(revision, **change)
                    before = {path: path.read_bytes() for path in store.rglob('*') if path.is_file()}
                    result, _ = self.exchange(managed_service_client.serve_connection)
                    self.assertEqual(result, {'status': 'refused', 'effect': 'not_attempted',
                                              'code': 'service_binding_unavailable'})
                    self.assertEqual({path: path.read_bytes() for path in store.rglob('*') if path.is_file()}, before)
            self.assertEqual(calls, [])
        with self.assertRaises(OSError) as error:
            os.pwrite(held.fileno(), b'x', 0)
        self.assertEqual(error.exception.errno, errno.EBADF)
        self.assertEqual(original.read_bytes(), b'fixture')

    def _assert_result_observer(self, entry, bundle_pin, invoke, cli, store):
        from workeros.service_history import read_history, retain_history

        # Only physical side effects and the remote providers are supplied as
        # fixtures. This uses actual commissioned pins, reservations, CLI
        # dispatch, policy decoding and request/response framing.
        records, calls = {}, []
        mode = 'valid'
        observer = entry['result_observer']
        pin = authority_pin(observer['source'], observer['socket'], observer['uid'])
        leaf = {'device': 7, 'inode': 19, 'mount_id': 25}
        exchange = managed_service_client._Authority._exchange

        def exchange_observer(endpoint, invocation, deadline_ns, result):
            # Exercise the installed frame and credential checks with a real
            # socket. Only the expected UID in the positive fixture is set to
            # this process's UID. This venue has no independent actual peer.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, ThreadPoolExecutor(1) as workers:
                listener.bind(endpoint.endpoint)
                listener.listen()
                listener.settimeout(2)

                def receive():
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        if mode == 'wrong-peer':
                            self.assertEqual(connection.recv(1), b'')
                            return
                        deadline = deadline_ns / 1_000_000_000
                        request = managed_service_client._frame_read(connection, deadline)
                        self.assertEqual(set(request), {'version', 'operation', 'nonce', 'invocation'})
                        self.assertEqual((request['operation'], request['invocation']),
                                         ('read_result', asdict(invocation)))
                        managed_service_client._frame_write(connection, {
                            'version': 1, 'operation': 'read_result', 'nonce': request['nonce'], 'result': result,
                        }, deadline)

                job = workers.submit(receive)
                peer = endpoint if mode == 'wrong-peer' else SimpleNamespace(endpoint=endpoint.endpoint, uid=self.uid)
                try:
                    return exchange(peer, 'read_result', invocation, deadline_ns)
                finally:
                    job.result(timeout=2)
                    Path(endpoint.endpoint).unlink()

        def provider(endpoint, operation, invocation, _deadline, **fields):
            calls.append(operation)
            key = invocation.plan.invocation_key
            wire = asdict(invocation)
            existing = records.get(key)
            if operation == 'read_result':
                self.assertEqual((endpoint.uid, fields), (observer['uid'], {}))
                if mode == 'missing':
                    return exchange_observer(endpoint, invocation, _deadline, None)
                proof = json.loads(json.dumps(existing['observation']))
                proof.update(source=observer['source'], source_sha256=pin, receipt_sha256='d'*64)
                now = monotonic_ns()
                if mode.startswith('split'):
                    service = proof['service']
                    life = service['lifecycle']
                    witness = {'scope_sha256': service['scope_sha256'],
                               'manager_run_id': service['manager_run_id'], 'cgroup': life['cgroup'],
                               'reaped_process': service['reaped_process'],
                               'live_ns': life['start_ns'], 'exit_ready_ns': life['terminal_ns'],
                               'empty_ns': life['empty_ns'], 'retired_ns': life['retired_ns'],
                               'effect_observed_ns': life['retired_ns'],
                               'handles_closed_ns': life['handles_closed_ns']}
                    if mode == 'split-wrong-process':
                        witness['reaped_process']['start_ticks'] += 1
                    if mode == 'split-wrong-clock-cut':
                        witness['live_ns'] = life['terminal_ns']
                    if mode == 'split-fake-wait-status':
                        witness['terminal_status'] = 0
                    proof = {key: proof[key] for key in ('invocation', 'source', 'source_sha256', 'receipt_sha256')}
                    proof['cleanup'] = witness
                    return exchange_observer(endpoint, invocation, _deadline, {
                        'observation': proof, 'effect_sha256': 'e'*64,
                        'verified_ns': now, 'expires_ns': now + 1_000_000_000,
                    })
                if mode == 'crossed-run':
                    proof['service']['manager_run_id'] = 'a'*32
                if mode == 'crossed-profile':
                    proof['invocation']['profile_identity'] = 'a'*64
                if mode == 'incomplete':
                    proof['service']['handles_closed'] = None
                    proof['service']['lifecycle']['handles_closed_ns'] = None
                if mode == 'crossed-cuts':
                    life = proof['service']['lifecycle']
                    for key in ('start_ns', 'terminal_ns', 'empty_ns', 'retired_ns', 'handles_closed_ns'):
                        life[key] += 10
                return exchange_observer(endpoint, invocation, _deadline, {
                    'observation': proof, 'effect_sha256': ('f' if mode == 'wrong-effect' else 'e')*64,
                    'verified_ns': now, 'expires_ns': now + (0 if mode == 'stale' else 1_000_000_000),
                })
            self.assertEqual(fields['service']['scope_sha256'], bundle_pin)
            state = {'invocation': wire, 'source': invocation.plan.authority,
                     'source_sha256': invocation.plan.authority_sha256, 'status': 'not_started'}
            if operation == 'read_service':
                return existing or {'arm': None, 'observation': state}
            if operation == 'arm_service':
                arm = {'binding_sha256': sha256(roles_cli._canonical(
                           {'invocation': wire, 'service': fields['service']})).hexdigest(),
                       'guard_sha256': 'd'*64, 'armed_ns': monotonic_ns(), 'leaf': leaf}
                records[key] = {'arm': arm, 'observation': state}
                return {'arm': arm, 'approval': {'invocation': wire, 'source': invocation.plan.authority,
                        'source_sha256': invocation.plan.authority_sha256,
                        'ticket_sha256': sha256(key.encode()).hexdigest(),
                        'expires_ns': invocation.service_window.active_until_ns, 'guard_sha256': arm['guard_sha256']}}
            self.assertEqual(operation, 'submit_service')
            self.assertEqual(fields['arm'], existing['arm'])
            now = monotonic_ns()
            life = {'clock_id': invocation.clock_id, 'cgroup': leaf, 'start_ns': now - 4, 'terminal_ns': now - 3,
                    'terminal_disposition': 'exited', 'terminal_status': 0, 'empty_ns': now - 2,
                    'retired_ns': now - 1, 'handles_closed_ns': now}
            service = {'unit': fields['service']['unit'], 'scope_sha256': bundle_pin, 'manager_run_id': 'b'*32,
                       'invocation_id': None, 'group_empty': True, 'handles_closed': True, 'lifecycle': life,
                       'reaped_process': {'pid': 94, 'start_ticks': 17, 'pid_namespace_inode': 402}}
            existing['observation'].update(status='terminal', service=service, receipt_sha256='c'*64,
                effective_principal=invocation.plan.principal, effective_principal_uid=invocation.plan.principal_uid,
                effective_executable_sha256=invocation.plan.executable_sha256,
                effective_scope_sha256=invocation.plan.scope_sha256)
            raise OSError('fixture submit reply lost')

        module = managed_service_client.managed_service
        with patch.object(module, '_system_manager'), patch.object(module.managed_system_bus, 'verify_parent'), patch.object(
                module, '_retired_leaf_absent', return_value=True) as retired, patch(
                'workeros.managed_service_guard._require_empty_leaf'), patch.object(
                managed_service_client._Authority, '_exchange', new=provider), patch(
                'workeros.service_history.retain_history', side_effect=lambda _, __, ___, result: result) as retain:
            result, _ = self.exchange(managed_service_client.serve_connection, invoke=lambda: invoke('flags', 1))
            self.assertEqual((result['status'], result['effect'], result['cleanup'], result['code']),
                             ('terminal', 'dispatched', 'verified', 'independent_service_result_verified'))
            self.assertEqual(result['observer_result']['effect_sha256'], 'e'*64)
            self.assertEqual(result['receipt_sha256'], 'd'*64)
            self.assertEqual(calls, ['read_service', 'arm_service', 'submit_service', 'read_service', 'read_result'])
            self.assertEqual(cli('revoke-profile', [self.client['profile'], self.client['revision']])[1]['status'],
                             'revoked')
            before = {path: path.read_bytes() for path in store.rglob('*') if path.is_file()}
            routes = ['python', 'flags', 'json']
            if importlib.util.find_spec('yaml') is not None:
                routes.append('yaml')
            for route in routes:
                with self.subTest(route=route):
                    observed, _ = self.exchange(managed_service_client.serve_connection,
                                                 invoke=lambda: invoke(route, 1, readback=True))
                    self.assertEqual((observed['code'], observed['invocation_key']),
                                     (result['code'], result['invocation_key']))
            for mode in ('missing', 'stale', 'crossed-run', 'crossed-profile', 'wrong-effect', 'incomplete',
                         'wrong-peer', 'crossed-cuts'):
                with self.subTest(mode=mode):
                    unknown, _ = self.exchange(managed_service_client.serve_connection,
                                                invoke=lambda: invoke('python', 1, readback=True))
                    self.assertEqual((unknown['effect'], unknown['code']), ('unknown', 'service_terminal_reported'))
                    self.assertNotIn('observer_result', unknown)
            mode = 'split'
            for route in routes:
                with self.subTest(split_route=route):
                    split, _ = self.exchange(managed_service_client.serve_connection,
                                              invoke=lambda: invoke(route, 1, readback=True))
                    self.assertEqual(split['code'], 'independent_service_result_verified')
                    self.assertEqual(split['receipt_sha256'], 'c'*64)
                    self.assertEqual(split['terminal_source']['source'], entry['policy']['authority'])
                    self.assertEqual(split['observer_result']['receipt_sha256'], 'd'*64)
                    self.assertEqual(split['service']['lifecycle']['terminal_status'], 0)
                    self.assertNotIn('terminal_status', split['observer_result']['cleanup_observation'])
            for mode in ('split-wrong-process', 'split-wrong-clock-cut', 'split-fake-wait-status'):
                with self.subTest(mode=mode):
                    unknown, _ = self.exchange(managed_service_client.serve_connection,
                                                 invoke=lambda: invoke('python', 1, readback=True))
                    self.assertEqual((unknown['effect'], unknown['code']), ('unknown', 'service_terminal_reported'))
                    self.assertNotIn('observer_result', unknown)
            mode = 'valid'
            retired.return_value = False
            unretired, _ = self.exchange(managed_service_client.serve_connection,
                                          invoke=lambda: invoke('python', 1, readback=True))
            self.assertEqual((unretired['effect'], unretired['code']),
                             ('unknown', 'service_native_readback_unconfirmed'))
            cutoff = len(calls)
            new, _ = self.exchange(managed_service_client.serve_connection, invoke=lambda: invoke('python', 2))
            self.assertEqual((new['effect'], new['code']), ('not_attempted', 'managed_registration_inactive'))
            self.assertEqual(len(calls), cutoff)
            self.assertEqual(calls.count('submit_service'), 1)
            self.assertEqual({path: path.read_bytes() for path in store.rglob('*') if path.is_file()}, before)
            # The alternate attestation fixtures above all target one logical
            # attempt. Commit only the final verified result before switching
            # the installed client to a different revision and removing its witness.
            retain.side_effect = retain_history
            mode = 'split'
            retired.return_value = True
            verified, _ = self.exchange(managed_service_client.serve_connection,
                                         invoke=lambda: invoke('python', 1, readback=True))
            old_revision = self.client['revision']
            self.assertEqual(verified['history'], {'status': 'recorded', 'revision': old_revision,
                                                   'profile': self.client['profile']})
            request = {'profile': self.client['profile'], 'revision': old_revision,
                       'workflow': self.workflow, 'request_id': verified['request_id']}
            unknown = {'status': 'unknown', 'effect': 'unknown', 'code': 'service_history_unavailable'}
            self.assertEqual(read_history(request, self.other_uid), unknown)
            self.assertEqual(read_history({**request, 'request_id': '0'*64}, self.other_uid), unknown)
            self.client['revision'] = 'successor'
            self.client['workflows'] = {'another-workflow': 'a'*64}
            mode = 'missing'
            cutoff = len(calls)
            key = verified['request_id']
            call = lambda summary: managed_executor.registered_launch(
                key, workflow=self.workflow, revision=old_revision, readback=True, summary_ids=summary)
            for requested, count in ((None, None), ([key, key], 1), (['0'*64], None)):
                with self.subTest(summary=requested):
                    archived, _ = self.exchange(lambda connection: managed_service_client.serve_connection(
                        connection, history_only=True), invoke=lambda: call(requested))
                    self.assertEqual(archived['history'], verified['history'])
                    self.assertEqual(archived['receipt_sha256'], verified['receipt_sha256'])
                    if requested is not None:
                        self.assertEqual(archived['summary']['verified_count'], count)
            doc = {'version': 1, 'workflow': self.workflow, 'revision': old_revision,
                   'request_id': key, 'summary_ids': [key]}
            lookup = {
                'flags': lambda: cli('launch-status', ['--workflow', self.workflow, '--request-id', key,
                                                       '--revision', old_revision, '--summary-id', key])[1],
                'json': lambda: cli('launch-status', ['--format', 'json'], json.dumps(doc).encode())[1],
            }
            if importlib.util.find_spec('yaml') is not None:
                import yaml
                lookup['yaml'] = lambda: cli('launch-status', ['--format', 'yaml'], yaml.safe_dump(doc).encode())[1]
            for route, request_history in lookup.items():
                with self.subTest(history_route=route):
                    observed, _ = self.exchange(managed_service_client.serve_connection, invoke=request_history)
                    self.assertEqual(observed['history'], verified['history'])
                    self.assertEqual(observed['summary']['verified_count'], 1)
            self.assertEqual(len(calls), cutoff)
