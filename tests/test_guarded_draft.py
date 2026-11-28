"""Check the shipped draft producer against the protected no-start consumer."""

from copy import deepcopy
from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import pwd
import stat
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns, time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from workeros import managed_cli, managed_registration, roles_cli


class GuardedDraftTest(TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.host = root / 'etc'
        self.host.mkdir()
        self.state = root / 'state'
        self.state.mkdir()
        uid = os.getuid()
        self.enterContext(patch.multiple(managed_cli, _CONFIG_PARENT=str(self.host), _TRUSTED_UID=uid))
        self.enterContext(patch.multiple(roles_cli, _PARENT=str(self.state), _UID=uid))
        wheel = os.environ.get('WORKEROS_TEST_WHEEL')
        example = (Path(sys.prefix) / 'share/workeros/examples/draft_guarded_profile.py' if wheel else
                   Path(__file__).resolve().parents[1] / 'examples/draft_guarded_profile.py')
        spec = importlib.util.spec_from_file_location('guarded_profile_example', example)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.enterContext(patch.object(self.helper, 'setup_clock_id', return_value='fixture-clock'))
        if wheel is None:
            wheel = root / 'test.whl'
            wheel.write_bytes(b'fixture only')
            self.enterContext(patch.object(self.helper, 'verify_install', return_value={'version': '0.8.0'}))
            self.enterContext(patch.object(managed_registration, 'verify_install', return_value={'version': '0.8.0'}))
        worker = pwd.getpwuid(uid) if uid else pwd.getpwnam('daemon')
        self.spec = {
            'profile': 'fixture', 'revision': 'r1', 'workflow': 'check', 'workflow_revision': 'v1',
            'generation': 'one', 'role': 'check-role', 'principal': worker.pw_name,
            'launcher': 'launcher', 'manager': 'manager', 'authority': 'guard', 'authority_uid': 24170,
            'authority_socket': '/run/workeros-test/guard.sock', 'wheel_path': str(wheel),
            'wheel_sha256': sha256(Path(wheel).read_bytes()).hexdigest(),
            'executable_sha256': 'a'*64, 'expires_at': int(time())+180,
            'expires_ns': monotonic_ns()+60_000_000_000, 'operation_key': 'd'*64,
            'run_uids': [uid], 'result_uids': [uid], 'journal_directory': '/run/workeros-test/setup-journal',
            'client_socket': '/run/workeros-test/launcher.sock',
            'service': {'root_directory': '/approved/job', 'root_device': 3, 'root_inode': 4, 'executable': '/worker',
                        'principal_gid': worker.pw_gid, 'active_ms': 2000, 'cleanup_ms': 1000, 'metered': False,
                        'parent': {'unit': 'guard.service', 'control_group': '/apps.slice/guard.service',
                                   'device': 17, 'inode': 19, 'mount_id': 23},
                        'descriptors': [{'slot': 'stdin', 'scope': 'input', 'owner_uid': 24172,
                                         'mode': 'read', 'device': 3, 'inode': 40, 'fd': 3},
                                        {'slot': 'stdout', 'scope': 'output', 'owner_uid': 24173,
                                         'mode': 'write', 'device': 3, 'inode': 41, 'fd': 4}],
                        'elevated_capabilities': [{'name': 'read-approved', 'scope': 'input', 'operation': 'read'},
                                                  {'name': 'write-approved', 'scope': 'output', 'operation': 'write'}]},
        }

    def test_draft_passes_no_start_consumer_then_guard_binds_only_applied_pins(self):
        bundle = self.helper.draft(self.spec)
        raw = roles_cli._canonical(bundle)
        flags = {'input_sha256': sha256(raw).hexdigest(), 'provision': True}
        preview = managed_registration.apply(raw, preview=True, **flags)
        self.assertEqual((preview['status'], preview['effect']), ('preview', 'not_attempted'))
        self.assertFalse(list(self.state.iterdir()))
        self.assertFalse(list(self.host.iterdir()))
        lock = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700, st_dev=31, st_ino=37)
        with self.assertRaises(ValueError):
            self.helper.guard(bundle, preview, 'check', journal='/run/guard/journal', lock=lock)
        applied = managed_registration.apply(raw, **flags)
        self.assertEqual(applied['status'], 'configured')
        status = managed_registration.readback('fixture', 'r1')
        result = self.helper.guard(bundle, status, 'check', journal='/run/guard/journal', lock=lock)
        self.assertEqual(result['role_store_lock'], {'device': 31, 'inode': 37})
        self.assertEqual(result['launch_executor_sha256'], status['managed_registration_pins']['launch_executor_sha256'])
        with self.assertRaises(ValueError):
            self.helper.guard(bundle, {**status, 'revision': 'r2'}, 'check', journal='/run/guard/journal', lock=lock)

    def test_multiple_workflows_share_registration_and_recompute_approval(self):
        other = deepcopy(self.spec)
        other.update(workflow='check-next', role='next-role', authority_socket='/run/workeros-test/next.sock')
        other['service']['descriptors'][0]['inode'] += 20
        other['service']['descriptors'][1]['inode'] += 20
        other['service']['elevated_capabilities'].pop(0)
        bundle = self.helper.draft({'workflows': [self.spec, other]})
        raw = roles_cli._canonical(bundle)
        status = managed_registration.apply(raw, input_sha256=sha256(raw).hexdigest(), preview=True, provision=True)
        self.assertEqual(status['local_client_routing'], 'preview')
        self.assertEqual(set(bundle['launch_executor']['workflows']), {'check', 'check-next'})
        self.assertIn('read', bundle['profile']['roles'][1]['operations'])
        with self.assertRaises(ValueError):
            self.helper.draft({'workflows': [self.spec, {**other, 'revision': 'r2'}]})
