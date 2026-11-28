"""Stock v1 ingress joins real protected receipts without dispatching a worker."""

from contextlib import contextmanager
from importlib.util import find_spec
import json
import os
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, call, patch

from workeros import managed_executor, managed_host, roles_cli
from workeros.managed_launch import LaunchInvocation, LaunchReadback, LaunchRegistration
import test_managed_registration as registration_cases


class StockExecutorRegistrationTest(TestCase):
    request = 'e'*64

    def setUp(self):
        self.fixture = registration_cases.ManagedRegistrationTest()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.prepare(backend='bubblewrap')
        if os.environ.get('WORKEROS_TEST_WHEEL') is None:
            self.enterContext(patch.object(managed_executor, 'verify_install'))

    def commission(self, *, pinned=True):
        options = ('--registered-managed',) if pinned else ()
        code, result = self.fixture.invoke('apply-profile', *options)
        self.assertEqual((code, result['status']), (0, 'configured'))
        return result

    def assert_run_refused(self, code):
        with patch.object(managed_executor, '_open_registered_worker') as worker:
            self.assertEqual(managed_executor.registered_launch(self.request),
                             {'version': 1, 'request_id': self.request,
                              'status': 'refused', 'effect': 'not_attempted', 'code': code})
            worker.assert_not_called()

    def test_stock_live_uses_the_exact_bound_setup_snapshot(self):
        self.commission()
        expected = json.loads(roles_cli._canonical(self.fixture.host))
        outcome = {'status': 'terminal', 'effect': 'dispatched', 'code': 'fixture'}
        public = {'version': 1, 'request_id': self.request, **outcome}
        submit = Mock(return_value=outcome)

        @contextmanager
        def inert_adapter(_config, _policy, _authority, host):
            self.assertEqual(host, expected)
            yield SimpleNamespace(launch_approved=submit)

        with patch.object(managed_executor, '_open_registered_worker', side_effect=inert_adapter):
            self.assertEqual(managed_executor.registered_launch(self.request), public)
            self.assertEqual(self.fixture.invoke('run-approved', '--request-id', self.request), (0, public))
            self.assertEqual(self.fixture.invoke('run-approved', '--format', 'json',
                                                  data=roles_cli._canonical({
                                                      'version': 1, 'request_id': self.request,
                                                  })), (0, public))
            expected_count = 3
            if find_spec('yaml') is not None:
                raw = f'version: 1\nrequest_id: "{self.request}"\n'.encode('ascii')
                self.assertEqual(self.fixture.invoke('run-approved', '--format', 'yaml', data=raw), (0, public))
                expected_count += 1
        self.assertEqual(submit.call_args_list, [call(request_id=self.request)] * expected_count)

    def test_stock_live_rejects_setup_or_executor_drift_before_opening_worker(self):
        self.commission()
        original = self.fixture.host['authorized_uids'][:]
        self.fixture.host['authorized_uids'].append(11)
        self.fixture.write_files()
        self.assert_run_refused('managed_registration_drift')
        self.fixture.host['authorized_uids'] = original
        self.fixture.executor['executable'] = '/protected/crossed'
        self.fixture.write_files()
        self.assert_run_refused('managed_registration_drift')
        with patch.object(managed_executor, '_read_historical_launch') as read:
            observed = managed_executor.registered_launch(self.request, readback=True)
            self.assertEqual((observed['status'], observed['effect'], observed['request_id'], observed['code']),
                             ('unknown', 'unknown', self.request, 'managed_registration_drift'))
            read.assert_not_called()

    def test_lookup_without_executor_configuration_remains_unknown(self):
        (self.fixture.config / 'launch-executor.json').unlink()
        self.assert_run_refused('launch_executor_registration_missing')
        with patch.object(managed_executor, '_read_historical_launch') as read:
            observed = managed_executor.registered_launch(self.request, readback=True)
        self.assertEqual((observed['status'], observed['effect'], observed['request_id'], observed['code']),
                         ('unknown', 'unknown', self.request, 'launch_executor_registration_missing'))
        read.assert_not_called()

    def test_stock_live_rejects_unpinned_expired_or_revoked_approval(self):
        self.assert_run_refused('managed_registration_unpinned')
        self.commission()
        with patch.object(roles_cli, 'time', return_value=4_000_000_001):
            self.assert_run_refused('managed_registration_inactive')
        roles_cli.revoke_profile('review-set', 'v1')
        self.assert_run_refused('managed_registration_inactive')

    def test_historical_after_revoke_correlates_the_durable_key_without_live_setup(self):
        self.commission()
        config, policy, authority = managed_executor._registration()
        registration = LaunchRegistration(
            policy, authority.authorize, managed_executor._read_only_dispatch, authority.readback, bounded=True)
        identity = '7'*64
        bound, payload = managed_host._launch_record(registration, identity, 'clock', self.request)
        with roles_cli._store(create=False) as store:
            key = managed_host._launch_reservation_key(config['profile'], config['revision'], registration, self.request)
            roles_cli._commit(store, key, payload, kind=managed_host._LAUNCH_RESERVATION)
        roles_cli.revoke_profile('review-set', 'v1')
        (self.fixture.config / 'managed-setup.json').unlink()

        invocation = LaunchInvocation(identity, 'clock', bound.plan)
        returned = LaunchReadback(invocation, policy.authority, policy.authority_sha256, 'terminal',
                                  policy.principal, policy.executable_sha256, policy.scope_sha256, '9'*64,
                                  effective_principal_uid=policy.principal_uid)
        with (
            patch.object(managed_executor._Authority, 'readback', return_value=returned) as authority_result,
            patch.object(managed_executor._Authority, 'authorize') as authorize,
            patch.object(managed_executor, '_open_registered_worker') as worker,
        ):
            historical = managed_executor.registered_launch(self.request, readback=True)
        self.assertEqual((historical['status'], historical['request_id'], historical['invocation_key']),
                         ('terminal', self.request, bound.plan.invocation_key))
        self.assertEqual(authority_result.call_args.args, (invocation,))
        authorize.assert_not_called()
        worker.assert_not_called()

    def test_legacy_retained_lookup_and_entitled_object_api_remain_scoped(self):
        self.commission(pinned=False)
        self.assert_run_refused('managed_registration_unpinned')
        outcome = {'status': 'not_started', 'effect': 'not_attempted', 'code': 'launch_not_reserved'}
        with patch.object(managed_executor, '_read_historical_launch', return_value=outcome) as historical:
            self.assertEqual(managed_executor.registered_launch(self.request, readback=True),
                             {'version': 1, 'request_id': self.request, **outcome})
        self.assertEqual(historical.call_args.args[1:4], ('review-set', 'v1', self.request))
        adapter = object()

        @contextmanager
        def inert_worker(_config, _policy, _authority, host):
            self.assertIs(host, self.fixture.host)
            yield adapter

        with patch.object(managed_executor, '_open_registered_worker', side_effect=inert_worker):
            with managed_executor.open_managed_worker(self.fixture.executor, host_config=self.fixture.host) as worker:
                self.assertIs(worker, adapter)

    def test_entitled_object_api_cannot_bypass_an_existing_host_pin(self):
        self.commission()
        changed = {**self.fixture.host, 'authorized_uids': [11]}
        with patch.object(managed_executor, '_open_registered_worker') as worker:
            with self.assertRaisesRegex(managed_executor.ExecutorRefusal, '^managed_registration_drift$'):
                with managed_executor.open_managed_worker(self.fixture.executor, host_config=changed):
                    self.fail('crossed object reached the worker')
        worker.assert_not_called()
