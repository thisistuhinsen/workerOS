"""Verify protected guarded payload selection without launching a worker."""
from contextlib import ExitStack
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import pwd
import struct
from tempfile import TemporaryDirectory
from time import monotonic_ns
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import call, patch

from workeros import managed_cli, managed_executor as executor
from workeros.delegated_service_leaf import DelegatedServiceLeaf
from workeros.managed_launch import LaunchInvocation, LaunchPlan, ServiceLimits, ServiceWindow
from workeros.managed_service import ServiceScope
from workeros.managed_service_parent import ServiceParent
from workeros.managed_service_scope import ServiceBundle, ServiceDescriptor, ServiceRefusal


class GuardedReleaseInputsTest(TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.scope_root = self.root / 'approved-root'
        self.scope_root.mkdir()
        app = self.scope_root / 'jobs' / 'report'
        app.parent.mkdir()
        self.app = app
        machine = {'x86_64': 62, 'aarch64': 183}[os.uname().machine]
        image = bytearray(120)
        image[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HH', image, 16, 2, machine)
        struct.pack_into('<Q', image, 32, 64)
        struct.pack_into('<HH', image, 54, 56, 1)
        struct.pack_into('<I', image, 64, 1)
        app.write_bytes(image)
        self.image = bytes(image)
        self.parent = ServiceParent('reports.slice', '/reports.slice', 1, 2, 7)
        self.limits = ServiceLimits(2000, 1000, False)
        self.account = pwd.getpwuid(os.getuid())
        self.original = self.root / 'original'
        self.original.write_bytes(b'approved input')
        owned = executor._OWNED_BWRAP
        self.sandbox_path = str(owned) if owned.is_file() else executor._BWRAP
        self.sandbox_fixture = owned if owned.is_file() else Path('/bin/true')
        self.deadline = monotonic_ns() + 2_000_000_000

    def guard(self, scope):
        plan = LaunchPlan('report', 'a'*64, 'generation', 'writer', self.account.pw_name,
                          sha256(self.image).hexdigest(), 'b'*64, 'launcher', 'authority',
                          'c'*64, 'd'*64, self.account.pw_uid)
        scope_guard = object.__new__(DelegatedServiceLeaf)
        scope_guard._scope_sha256 = scope.digest
        scope_guard._parent = self.parent
        scope_guard._limits = self.limits
        scope_guard._invocation = LaunchInvocation(
            'e'*64, 'test-clock', plan, ServiceWindow(self.deadline, self.deadline + 1_000_000_000),
        )
        return scope_guard

    def open_fixture(self, path):
        # Only the administrator directory walk is modeled. The snapshot,
        # SHA-256, memfd seals, and retained descriptor checks remain real.
        paths = {str(self.app): self.app, self.sandbox_path: self.sandbox_fixture}
        return os.open(paths[path], os.O_RDONLY | os.O_CLOEXEC)

    def test_protected_config_path_and_selected_output_descriptor_are_preserved(self):
        root = self.scope_root.stat()
        with self.original.open('wb') as output, ExitStack() as held:
            info = os.fstat(output.fileno())
            scope = ServiceBundle(str(self.scope_root), root.st_dev, root.st_ino, '/jobs/report',
                                  self.account.pw_gid, (ServiceDescriptor(
                                      'stdout', 'report', info.st_uid, 'write', info.st_dev, info.st_ino, output.fileno(),
                                  ),), self.limits.active_ms, self.limits.cleanup_ms, False, parent=self.parent)
            guard = self.guard(scope)
            with patch.object(managed_cli, '_TRUSTED_UID', root.st_uid), patch.object(
                    executor, '_open_protected', side_effect=self.open_fixture) as protected, patch(
                    'workeros.delegated_service_leaf.subprocess.run',
                    return_value=SimpleNamespace(stdout=b'bubblewrap 0.12.0\n')):
                account, (sandbox, image, stdin, stdout, stderr) = guard._release_inputs(scope, self.deadline, held)
            self.assertEqual(protected.call_args_list, [call(str(self.app)), call(self.sandbox_path)])
            self.assertEqual(account.pw_uid, self.account.pw_uid)
            self.assertIsNone(stdin)
            self.assertIsNone(stderr)
            self.assertEqual(fcntl.fcntl(stdout, fcntl.F_GETFL) & os.O_ACCMODE, os.O_WRONLY)
            self.assertEqual(os.fstat(stdout).st_ino, info.st_ino)
            self.assertEqual(os.pread(image, len(self.image), 0), self.image)
            self.assertEqual(fcntl.fcntl(image, executor._GET_SEALS) & executor._REQUIRED_SEALS,
                             executor._REQUIRED_SEALS)
            self.assertTrue(os.path.samefile(f'/proc/self/fd/{sandbox}', self.sandbox_fixture))

    def test_bundle_rechecks_approved_owner_before_snapshot_or_sandbox(self):
        root = self.scope_root.stat()
        with self.original.open('wb') as output, ExitStack() as held:
            info = os.fstat(output.fileno())
            scope = ServiceBundle(str(self.scope_root), root.st_dev, root.st_ino, '/jobs/report',
                                  self.account.pw_gid, (ServiceDescriptor(
                                      'stdout', 'report', info.st_uid + 1, 'write', info.st_dev, info.st_ino,
                                      output.fileno(),
                                  ),), self.limits.active_ms, self.limits.cleanup_ms, False, parent=self.parent)
            with patch.object(managed_cli, '_TRUSTED_UID', root.st_uid), patch.object(
                    executor, '_open_protected') as protected:
                with self.assertRaisesRegex(ServiceRefusal, 'service_descriptor_mismatch'):
                    self.guard(scope)._release_inputs(scope, self.deadline, held)
            protected.assert_not_called()

    def test_legacy_readwrite_scope_keeps_the_exact_admin_owned_stdin(self):
        root = self.scope_root.stat()
        with self.original.open('r+b') as original, ExitStack() as held:
            info = os.fstat(original.fileno())
            scope = ServiceScope(str(self.scope_root), root.st_dev, root.st_ino, '/jobs/report',
                                 self.account.pw_gid, 'read-write', info.st_dev, info.st_ino, original.fileno(),
                                 limits=self.limits, parent=self.parent)
            with patch.object(managed_cli, '_TRUSTED_UID', root.st_uid), patch.object(
                    executor, '_open_protected', side_effect=self.open_fixture), patch(
                    'workeros.delegated_service_leaf.subprocess.run',
                    return_value=SimpleNamespace(stdout=b'bubblewrap 0.12.0\n')):
                _, (_, _, stdin, stdout, stderr) = self.guard(scope)._release_inputs(scope, self.deadline, held)
            self.assertEqual(os.fstat(stdin).st_ino, info.st_ino)
            self.assertEqual(fcntl.fcntl(stdin, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDWR)
            self.assertIsNone(stdout)
            self.assertIsNone(stderr)
