"""No-start commissioning of already-protected administrator registrations."""

from dataclasses import asdict
from hashlib import sha256
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import pwd
import socket
from time import monotonic
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from workeros import managed_cli, managed_registration, managed_service_client, roles_cli
from workeros.appointment_registry import definition_sha256, launch_policy_sha256, launch_scope_sha256
from workeros.managed_executor import ExecutorRefusal, authority_pin
from workeros.managed_launch import LaunchRolePolicy
from workeros.managed_service import ServiceScope
from workeros.profile_setup import ProfileDefinition, ProviderBinding
from workeros.verify_install import VerificationError


class ManagedRegistrationTest(TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.state = root / 'state'
        self.state.mkdir()
        etc = root / 'etc'
        self.config = etc / 'workeros'
        self.config.mkdir(parents=True)
        self.enterContext(patch.multiple(managed_cli, _CONFIG_PARENT=str(etc), _TRUSTED_UID=os.getuid()))
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(self.state), _UID=os.getuid()))
        forbidden = AssertionError('registration check tried to open a live backend')
        for target in ('workeros.managed_service.prepare', 'workeros.managed_executor._open_sandbox',
                       'workeros.managed_bootstrap._open_approved_launch'):
            self.enterContext(patch(target, side_effect=forbidden))
        self.enterContext(patch.object(socket.socket, 'connect', side_effect=forbidden))
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        if wheel is None:
            wheel = str(root / 'fixture.whl')
            Path(wheel).write_bytes(b'source-test-only')
            self.enterContext(patch.object(managed_registration, 'verify_install', return_value={'version': '0.8.0'}))
        self.wheel = str(Path(wheel).resolve())
        self.wheel_sha256 = sha256(Path(wheel).read_bytes()).hexdigest()

    def prepare(self, *, backend='systemd-fd', package_version='0.8.0', revision='v1', write=True):
        worker = pwd.getpwuid(os.getuid()) if os.getuid() else pwd.getpwnam('nobody')
        role = {'name': 'auditor', 'principal': worker.pw_name, 'scopes': ['document'],
                'operations': ['read', 'write', 'observe', 'launch'], 'expires_at': 4_000_000_000,
                'resources': {'document': {'device': '10', 'inode': '20'}}}
        name, scope = 'review', 'document'
        operations = ['launch', 'observe'] if backend == 'bubblewrap' else ['launch']
        pin = launch_scope_sha256(role, scope, operations)
        refs = {'executable': 'worker', 'supervisor': 'dispatch'}
        bindings = [ProviderBinding('worker', 'a'*64, scope, 'executable', 'launcher', 'executable'),
                    ProviderBinding('dispatch', pin, scope, 'scoped-launch', 'launcher', 'supervisor')]
        optional = {}
        service = ServiceScope('/protected/jobs', 33, 44, '/review', worker.pw_gid, 'read-write',
                               10, 20, 2_000_000)
        if backend == 'bubblewrap':
            refs['observers'] = {'document': 'observation'}
            bindings.append(ProviderBinding('observation', 'b'*64, scope, 'point', 'observer', 'observers',
                                            'another-principal'))
            optional = {'observer': {'device': 10, 'inode': 20}, 'provider': {}}
        else:
            refs['streams'] = {'stdin': 'input'}
            bindings.append(ProviderBinding('input', service.digest, scope, 'systemd-fd', 'launcher', 'streams'))
        document = {'version': 1, 'roles': {'auditor': {'operations': operations}},
                    'workflows': {name: {'role': 'auditor', 'operations': operations, 'bindings': refs}}}
        digest = sha256(roles_cli._canonical(document)).hexdigest()
        definition = ProfileDefinition(name, revision, package_version, self.wheel_sha256, digest, 'coordinator', scope,
                                       'clock', 1_000_000_000, tuple(bindings))
        source = 'approved-reporter'
        endpoint = str(self.config / 'offline-authority.sock')
        authority_uid = next(uid for uid in (2, 3, 4) if uid not in (os.getuid(), worker.pw_uid))
        policy = LaunchRolePolicy(name, definition_sha256(definition), 'generation', 'auditor', worker.pw_name,
                                  'a'*64, pin, 'launcher', source, authority_pin(source, endpoint, authority_uid),
                                  worker.pw_uid)
        appointment = {'workflow': name, 'workflow_revision': revision, 'definition_sha256': policy.definition_sha256,
                       'role': role['name'], 'principal': worker.pw_name, 'generation': 'generation', 'scope': scope,
                       'operations': operations, 'launch': {'scope_sha256': pin, 'policy_sha256': launch_policy_sha256(policy)}}
        profile = {'version': 1, 'profile': 'review-set', 'revision': revision, 'roles': [role]}
        identity = {'profile': 'review-set', 'revision': revision, 'wheel_path': self.wheel}
        self.data = roles_cli._canonical({**profile, 'appointments': [appointment]})
        local = {'declaration_sha256': sha256(roles_cli._canonical(profile)).hexdigest(),
                 'intent_sha256': sha256(self.data).hexdigest()}
        self.host = {'version': 2, **identity, 'local_approval': local, 'operation_key': 'd'*64,
                     'authorized_uids': [os.getuid()], 'scopes': [{
                         'definition': asdict(definition), 'policy': document, 'role': 'auditor',
                         'binding_generation': 'generation', **optional}]}
        common = {**identity, 'wheel_sha256': self.wheel_sha256}
        authority = {'socket': endpoint, 'uid': authority_uid}
        if backend == 'bubblewrap':
            self.executor = {'version': 1, **common, 'policy': asdict(policy), 'authority': authority,
                             'principal_gid': worker.pw_gid, 'executable': '/protected/review'}
        else:
            self.executor = {'version': 2, **common, 'workflows': {name: {
                'policy': asdict(policy), 'service': asdict(service), 'authority': authority,
                'run_uids': [os.getuid()], 'result_uids': [os.getuid()]}}}
        if write:
            self.write_files()

    def write_files(self):
        (self.config / 'managed-setup.json').write_bytes(roles_cli._canonical(self.host))
        (self.config / 'launch-executor.json').write_bytes(roles_cli._canonical(self.executor))

    def invoke(self, *args, data=None):
        output = StringIO()
        stream = SimpleNamespace(buffer=BytesIO(self.data if data is None else data))
        with patch('sys.stdin', stream), patch('sys.stdout', output):
            code = managed_cli.main(list(args))
        return code, json.loads(output.getvalue())

    def test_preview_apply_and_actual_role_readback_agree_without_live_handles(self):
        self.prepare()
        before = {file.name: file.read_bytes() for file in self.config.iterdir()}
        code, preview = self.invoke('apply-profile', '--preview', '--registered-managed')
        self.assertEqual((code, preview['status'], preview['effect'], preview['readiness']),
                         (0, 'preview', 'not_attempted', 'not_checked'))
        self.assertFalse((self.state / 'workeros').exists())
        code, applied = self.invoke('apply-profile', '--registered-managed')
        self.assertEqual((code, applied['status'], applied['appointment_status']), (0, 'configured', 'registered'))
        code, observed = self.invoke('profile-status', 'review-set', 'v1', '--registered-managed')
        self.assertEqual((code, observed['status'], observed['effect']), (0, 'configured', 'not_attempted'))
        pins = observed['managed_registration']
        self.assertEqual(pins, preview['managed_registration'])
        self.assertEqual(pins, applied['managed_registration'])
        self.assertEqual(observed['managed_registration_pins'], {
            key: pins[key] for key in ('managed_setup_sha256', 'launch_executor_sha256')})
        self.assertEqual((pins['status'], pins['backend'], pins['enforcement']),
                         ('pins_matched', 'systemd-fd', 'not_checked'))
        self.assertEqual(pins['wheel_sha256'], self.wheel_sha256)
        self.assertEqual({file.name: file.read_bytes() for file in self.config.iterdir()}, before)
        self.assertNotIn('offline-authority', json.dumps(observed))

    def test_readback_refuses_crossed_registration_after_apply(self):
        self.prepare()
        self.assertEqual(self.invoke('apply-profile', '--registered-managed')[0], 0)
        self.executor['revision'] = 'crossed'
        self.write_files()
        code, result = self.invoke('profile-status', 'review-set', 'v1', '--registered-managed')
        self.assertEqual((code, result['status'], result['code']),
                         (1, 'refused', 'managed_registration_drift'))
        self.assertEqual(self.invoke('profile-status', 'review-set', 'v1')[1]['status'], 'configured')

    def test_plain_static_executor_uses_its_existing_registration_policy(self):
        self.prepare(backend='bubblewrap')
        code, result = self.invoke('apply-profile', '--preview', '--registered-managed')
        self.assertEqual((code, result['status'], result['managed_registration']['backend']),
                         (0, 'preview', 'bubblewrap'))

    def test_approved_definition_with_wrong_installed_package_version_is_refused(self):
        self.prepare(package_version='0.8.1')
        code, result = self.invoke('apply-profile', '--registered-managed')
        self.assertEqual((code, result['code']), (1, 'managed_registration_mismatch'))
        self.assertFalse((self.state / 'workeros').exists())

    def test_crossed_pins_untrusted_file_or_grant_leave_store_unwritten(self):
        self.prepare()
        original = self.executor['wheel_sha256']
        self.executor['wheel_sha256'] = '1'*64
        self.write_files()
        code, result = self.invoke('apply-profile', '--registered-managed')
        self.assertEqual((code, result['code']), (1, 'managed_registration_mismatch'))
        self.executor['wheel_sha256'] = original
        self.write_files()
        path = self.config / 'launch-executor.json'
        path.chmod(0o666)
        code, result = self.invoke('apply-profile', '--registered-managed')
        self.assertEqual((code, result['code']), (1, 'managed_registration_untrusted'))
        document = {**json.loads(self.data), 'grant': {}}
        code, result = self.invoke('apply-profile', '--registered-managed', data=roles_cli._canonical(document))
        self.assertEqual((code, result['code']),
                         (1, 'managed_registration_requires_appointments_without_file_acls'))
        self.assertFalse((self.state / 'workeros').exists())

    def test_verification_and_post_apply_readback_fail_closed(self):
        self.prepare()
        with patch.object(managed_registration, 'verify_install', side_effect=VerificationError('test')):
            code, result = self.invoke('apply-profile', '--registered-managed')
            self.assertEqual((code, result['code']), (1, 'installed_package_unverified'))
        self.assertFalse((self.state / 'workeros').exists())
        with patch.object(managed_registration, 'readback', side_effect=OSError('test')):
            code, result = self.invoke('apply-profile', '--registered-managed')
            self.assertEqual((code, result['status'], result['code'], result['effect']),
                             (1, 'incomplete', 'managed_registration_readback_unconfirmed', 'recorded'))
        self.assertEqual(self.invoke('profile-status', 'review-set', 'v1')[1]['status'], 'configured')

    def clean_provision_bundle(self):
        self.prepare()
        for path in self.config.iterdir():
            path.unlink()
        self.config.rmdir()
        return roles_cli._canonical({'version': 1, 'profile': json.loads(self.data),
                                     'managed_setup': self.host, 'launch_executor': self.executor})

    def test_clean_provision_and_revoke_keep_historical_pins(self):
        bundle = self.clean_provision_bundle()
        code, preview = self.invoke('apply-profile', '--preview', '--provision-managed', data=bundle)
        self.assertEqual((code, preview['effect']), (0, 'not_attempted'))
        self.assertFalse(self.config.exists())
        self.assertFalse((self.state / 'workeros').exists())
        code, applied = self.invoke('apply-profile', '--provision-managed', data=bundle)
        self.assertEqual((code, applied['status'], applied['managed_configuration_effect']),
                         (0, 'configured', 'recorded'))
        self.assertEqual(preview['managed_registration'], applied['managed_registration'])
        self.assertEqual(managed_registration.require_pinned_pair(self.executor, required=True),
                         json.loads(roles_cli._canonical(self.host)))
        self.assertFalse(any(path.stat().st_mode & 0o077 for path in self.config.iterdir()))
        code, repeat = self.invoke('apply-profile', '--provision-managed', data=bundle)
        self.assertEqual((code, repeat['effect'], repeat['managed_configuration_effect']),
                         (0, 'unchanged', 'unchanged'))
        self.assertEqual(self.invoke('revoke-profile', 'review-set', 'v1')[1]['status'], 'revoked')
        (self.config / 'managed-setup.json').unlink()
        code, status = self.invoke('profile-status', 'review-set', 'v1', '--registered-managed')
        self.assertEqual((code, status['status'], status['managed_registration_pins']),
                         (1, 'revoked', applied['managed_registration_pins']))
        self.assertIsNone(managed_registration.require_pinned_pair(self.executor, required=True, readback=True))
        with self.assertRaisesRegex(ExecutorRefusal, '^managed_registration_inactive$'):
            managed_registration.require_pinned_pair(self.executor, required=True)
        refused = self.stock_request('run')
        self.assertEqual((refused['effect'], refused['code']), ('not_attempted', 'managed_registration_inactive'))

    def test_same_revision_uid_only_drift_denies_readback_and_run(self):
        self.prepare()
        code, applied = self.invoke('apply-profile', '--registered-managed')
        self.assertEqual(code, 0)
        self.executor['workflows']['review']['run_uids'].append(11)
        self.executor['workflows']['review']['result_uids'].append(11)
        self.write_files()
        code, result = self.invoke('profile-status', 'review-set', 'v1', '--registered-managed')
        self.assertEqual((code, result['code']), (1, 'managed_registration_drift'))
        for readback in (False, True):
            with self.subTest(readback=readback), self.assertRaisesRegex(ExecutorRefusal, '^managed_registration_drift$'):
                managed_registration.require_pinned_pair(self.executor, required=True, readback=readback)
        for operation in ('run', 'readback'):
            result = self.stock_request(operation)
            self.assertEqual((result['effect'], result['code']), ('not_attempted', 'managed_registration_drift'))
        code, result = self.invoke('apply-profile', '--registered-managed')
        self.assertEqual((code, result['code']), (1, 'commission_intent_conflict'))
        older = self.invoke('profile-status', 'review-set', 'v1')[1]
        self.assertEqual(older['managed_registration_pins'], applied['managed_registration_pins'])

    def test_provision_separately_exposes_only_matched_client_routing(self):
        bundle = json.loads(self.clean_provision_bundle())
        executor = bundle['launch_executor']
        policy = LaunchRolePolicy(**executor['workflows']['review']['policy'])
        client = {'version': 1, 'profile': 'review-set', 'revision': 'v1',
                  'socket': str(self.config.parent / 'launcher.sock'), 'peer_uid': os.geteuid(),
                  'workflows': {'review': launch_policy_sha256(policy)}}
        bundle['launch_client'] = {**client, 'workflows': {'review': 'f' * 64}}
        code, refused = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(bundle))
        self.assertEqual((code, refused['code']), (1, 'managed_client_registration_mismatch'))
        self.assertFalse(self.config.exists())
        bundle['launch_client'] = client
        data = roles_cli._canonical(bundle)
        path = self.config.parent / managed_service_client._PUBLIC_CLIENT_CONFIG
        self.assertEqual(self.invoke('apply-profile', '--preview', '--provision-managed', data=data)[0], 0)
        self.assertFalse(path.exists())
        self.assertEqual(self.invoke('apply-profile', '--provision-managed', data=data)[0], 0)
        self.assertEqual(managed_service_client._client_registration(), client)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(item.stat().st_mode & 0o077 == 0 for item in self.config.iterdir()))
        bundle['launch_client'] = {**client, 'socket': str(self.config.parent / 'changed.sock')}
        code, refused = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(bundle))
        self.assertEqual((code, refused['code']), (1, 'managed_registration_file_conflict'))
        self.assertEqual(managed_service_client._client_registration(), client)

    def test_setup_only_drift_before_stock_launch(self):
        self.prepare()
        self.assertEqual(self.invoke('apply-profile', '--registered-managed')[0], 0)
        self.host['authorized_uids'].append(11)
        self.write_files()
        with self.assertRaisesRegex(ExecutorRefusal, '^managed_registration_drift$'):
            managed_registration.require_pinned_pair(self.executor, required=True)
        self.assertIsNone(managed_registration.require_pinned_pair(self.executor, required=True, readback=True))

    def stock_request(self, operation):
        policy = LaunchRolePolicy(**self.executor['workflows']['review']['policy'])
        request = {'operation': operation, 'profile': 'review-set', 'revision': 'v1',
                   'workflow': 'review', 'policy_sha256': launch_policy_sha256(policy), 'request_id': '1'*64}
        return managed_service_client._handle(request, os.getuid(), monotonic() + 2)

    def test_legacy_receipts_still_work_but_do_not_authorize_guarded_launch(self):
        self.prepare()
        self.assertEqual(self.invoke('apply-profile')[0], 0)
        code, legacy = self.invoke('profile-status', 'review-set', 'v1')
        self.assertEqual((code, legacy['status']), (0, 'configured'))
        self.assertNotIn('managed_registration_pins', legacy)
        self.assertIsNone(managed_registration.require_pinned_pair(self.executor))
        with self.assertRaisesRegex(ExecutorRefusal, '^managed_registration_unpinned$'):
            managed_registration.require_pinned_pair(self.executor, required=True)

    def test_provision_checks_both_and_refuses_replacement_before_role_write(self):
        bundle = self.clean_provision_bundle()
        crossed = json.loads(bundle)
        crossed['launch_executor']['revision'] = 'crossed'
        code, result = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(crossed))
        self.assertEqual((code, result['code']), (1, 'managed_registration_mismatch'))
        self.assertFalse(self.config.exists())
        self.config.mkdir()
        path = self.config / 'managed-setup.json'
        path.write_bytes(b'{}')
        code, result = self.invoke('apply-profile', '--provision-managed', data=bundle)
        self.assertEqual((code, result['code']), (1, 'managed_registration_file_conflict'))
        self.assertEqual(path.read_bytes(), b'{}')
        self.assertFalse((self.config / 'launch-executor.json').exists())
        self.assertFalse((self.state / 'workeros').exists())

    def test_provision_partial_write_preserves_pins_and_allows_exact_repeat(self):
        bundle = self.clean_provision_bundle()
        real_link = os.link

        def fail_second(source, target, **options):
            if source.startswith('.managed-registration-') and target == 'launch-executor.json':
                raise OSError('fixture failure on second file')
            return real_link(source, target, **options)

        with patch.object(os, 'link', side_effect=fail_second):
            code, partial = self.invoke('apply-profile', '--provision-managed', data=bundle)
        self.assertEqual((code, partial['status'], partial['effect'], partial['managed_configuration_effect']),
                         (1, 'incomplete', 'recorded', 'unknown'))
        self.assertEqual([path.name for path in self.config.iterdir()], ['managed-setup.json'])
        code, missing = self.invoke('profile-status', 'review-set', 'v1', '--registered-managed')
        self.assertEqual((code, missing['code']), (1, 'managed_registration_unavailable'))
        code, recovered = self.invoke('apply-profile', '--provision-managed', data=bundle)
        self.assertEqual((code, recovered['status'], recovered['effect'], recovered['managed_configuration_effect']),
                         (0, 'configured', 'unchanged', 'recorded'))
        self.assertEqual(partial['managed_registration_pins'], recovered['managed_registration_pins'])

    def named_bundle(self, revision):
        self.prepare(revision=revision, write=False)
        policy = LaunchRolePolicy(**self.executor['workflows']['review']['policy'])
        client = {'version': 1, 'profile': 'review-set', 'revision': revision,
                  'socket': str(self.config.parent / f'launcher-{revision}.sock'), 'peer_uid': os.geteuid(),
                  'workflows': {'review': launch_policy_sha256(policy)}}
        return {'version': 1, 'profile': json.loads(self.data), 'managed_setup': self.host,
                'launch_executor': self.executor, 'launch_client': client}

    def rotation_fixture(self):
        old, new = self.named_bundle('v1'), self.named_bundle('v2')
        code, applied = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(old))
        self.assertEqual((code, applied['status']), (0, 'configured'))
        new['rotate_from'] = {'revision': 'v1', **applied['managed_registration_pins'],
                              'launch_client_sha256': managed_registration._fingerprint(old['launch_client'])}
        return old, new

    def test_explicit_revision_rotation_changes_only_revoked_exact_registration(self):
        old, new = self.rotation_fixture()
        existing = self.config.parent / managed_service_client._PUBLIC_CLIENT_CONFIG
        files = (self.config / 'managed-setup.json', self.config / 'launch-executor.json', existing)
        before = tuple(path.read_bytes() for path in files)
        data = roles_cli._canonical(new)
        code, refused = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, refused['effect'], refused['code']),
                         (1, 'not_attempted', 'managed_rotation_source_not_verified_revoked'))
        self.assertEqual(self.invoke('profile-status', 'review-set', 'v2')[1]['status'], 'unconfigured')
        self.assertEqual(tuple(path.read_bytes() for path in files), before)
        self.assertEqual(self.invoke('revoke-profile', 'review-set', 'v1')[0], 0)
        code, preview = self.invoke('apply-profile', '--preview', '--provision-managed', data=data)
        self.assertEqual((code, preview['effect']), (0, 'not_attempted'))
        self.assertEqual(preview['managed_rotation'], {'status': 'preview', 'source_revision': 'v1',
                                                       'revision': 'v2', 'matched_files': 0})
        self.assertEqual(tuple(path.read_bytes() for path in files), before)
        missing = dict(new)
        del missing['rotate_from']
        code, refused = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(missing))
        self.assertEqual((code, refused['code']), (1, 'managed_registration_file_conflict'))
        self.assertEqual(self.invoke('profile-status', 'review-set', 'v2')[1]['status'], 'unconfigured')
        stale = {**new, 'rotate_from': {**new['rotate_from'], 'launch_client_sha256': 'f' * 64}}
        code, refused = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(stale))
        self.assertEqual((code, refused['effect'], refused['code']),
                         (1, 'not_attempted', 'managed_rotation_registration_drift'))
        self.assertEqual(tuple(path.read_bytes() for path in files), before)

        # Use explicit new run rights, keeping the prior history role distinct from new dispatch.
        new['launch_executor']['workflows']['review']['run_uids'] = [os.getuid() + 1]
        data = roles_cli._canonical(new)
        code, rotated = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, rotated['status'], rotated['managed_configuration_effect']),
                         (0, 'configured', 'recorded'))
        self.assertEqual(rotated['managed_rotation'], {**preview['managed_rotation'], 'status': 'verified',
                                                        'matched_files': 3})
        self.assertEqual(tuple(path.read_bytes() for path in files), tuple(roles_cli._canonical(new[key])
                         for key in ('managed_setup', 'launch_executor', 'launch_client')))
        self.assertEqual(managed_registration.require_pinned_pair(new['launch_executor'], required=True),
                         json.loads(roles_cli._canonical(new['managed_setup'])))
        self.assertEqual(managed_service_client._client_registration(), new['launch_client'])
        for bundle, reason in ((old, 'service_registration_mismatch'), (new, 'service_caller_denied')):
            request = {'operation': 'run', 'profile': 'review-set', 'revision': bundle['profile']['revision'],
                       'workflow': 'review', 'policy_sha256': bundle['launch_client']['workflows']['review'],
                       'request_id': '1' * 64}
            refused = managed_service_client._handle(request, os.getuid(), monotonic() + 2)
            self.assertEqual((refused['effect'], refused['code']), ('not_attempted', reason))
        self.assertEqual(self.invoke('profile-status', 'review-set', 'v1', '--registered-managed')[1]['status'],
                         'revoked')
        after = tuple((path.stat().st_ino, path.read_bytes()) for path in files)
        code, repeat = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, repeat['effect'], repeat['managed_configuration_effect']),
                         (0, 'unchanged', 'unchanged'))
        self.assertEqual(repeat['admin_history'], rotated['admin_history'])
        self.assertEqual(tuple((path.stat().st_ino, path.read_bytes()) for path in files), after)

    def test_revision_rotation_partial_publication_reconciles_exactly(self):
        old, new = self.rotation_fixture()
        self.assertEqual(self.invoke('revoke-profile', 'review-set', 'v1')[0], 0)
        data = roles_cli._canonical(new)
        real_replace = os.replace

        def fail_public(source, target, **options):
            if source.startswith('.managed-registration-') and target == managed_service_client._PUBLIC_CLIENT_CONFIG:
                raise OSError('fixture public routing publication interruption')
            return real_replace(source, target, **options)

        with patch.object(os, 'replace', side_effect=fail_public):
            code, partial = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, partial['status'], partial['code'], partial['managed_configuration_effect']),
                         (1, 'incomplete', 'managed_rotation_incomplete', 'unknown'))
        self.assertEqual(managed_service_client._client_registration(), old['launch_client'])
        code, status = self.invoke('profile-status', 'review-set', 'v2', '--registered-managed')
        self.assertEqual((code, status['status'], status['effect']), (1, 'incomplete', 'not_attempted'))
        self.assertEqual(status['managed_rotation']['matched_files'], 2)
        with self.assertRaisesRegex(ExecutorRefusal, '^managed_rotation_incomplete$'):
            managed_registration.require_pinned_pair(new['launch_executor'], required=True)
        changed = {**new, 'launch_client': {**new['launch_client'], 'socket': str(self.config / 'other.sock')}}
        code, refused = self.invoke('apply-profile', '--provision-managed', data=roles_cli._canonical(changed))
        self.assertEqual((code, refused['effect'], refused['code']),
                         (1, 'not_attempted', 'managed_rotation_intent_conflict'))
        code, repeat = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, repeat['status'], repeat['effect'], repeat['managed_configuration_effect']),
                         (0, 'configured', 'unchanged', 'recorded'))
        self.assertEqual(repeat['admin_history'], partial['admin_history'])
        self.assertEqual(managed_service_client._client_registration(), new['launch_client'])
        self.assertEqual(self.invoke('profile-status', 'review-set', 'v2', '--registered-managed')[1]
                         ['managed_rotation']['matched_files'], 3)

    def test_revision_rotation_requires_durable_completion_even_if_all_files_match(self):
        _, new = self.rotation_fixture()
        self.assertEqual(self.invoke('revoke-profile', 'review-set', 'v1')[0], 0)
        data = roles_cli._canonical(new)
        completion = roles_cli._key('review-set', 'v2', 'registration-rotation-completed')
        real_commit = roles_cli._commit

        def lose_completion(store, key, payload, **options):
            if key == completion:
                raise OSError('fixture completion interruption')
            return real_commit(store, key, payload, **options)

        with patch.object(roles_cli, '_commit', side_effect=lose_completion):
            code, partial = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, partial['status'], partial['code']), (1, 'incomplete', 'managed_rotation_incomplete'))
        self.assertEqual(managed_service_client._client_registration(), new['launch_client'])
        code, status = self.invoke('profile-status', 'review-set', 'v2', '--registered-managed')
        self.assertEqual((code, status['status'], status['managed_rotation']['matched_files']),
                         (1, 'incomplete', 3))
        with self.assertRaisesRegex(ExecutorRefusal, '^managed_rotation_incomplete$'):
            managed_registration.require_pinned_pair(new['launch_executor'], required=True)
        files = [*self.config.iterdir(), self.config.parent / managed_service_client._PUBLIC_CLIENT_CONFIG]
        before = tuple((path.stat().st_ino, path.read_bytes()) for path in files)
        code, result = self.invoke('apply-profile', '--provision-managed', data=data)
        self.assertEqual((code, result['status'], result['effect'], result['managed_configuration_effect']),
                         (0, 'configured', 'unchanged', 'recorded'))
        self.assertEqual(result['managed_rotation']['status'], 'verified')
        self.assertEqual(tuple((path.stat().st_ino, path.read_bytes()) for path in files), before)
