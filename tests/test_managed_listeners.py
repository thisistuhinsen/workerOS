"""Check finite listener and descriptor activation without starting a worker."""

from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory, gettempdir
from unittest import TestCase

from workeros.delegated_acl import _acl, _XATTR
from workeros.managed_listeners import (HolderEndpointRefusal, _grant_guard_connect, _require_guard_traversal,
                                       _require_holder_directory, bind_originals, open_registered_original,
                                       registered_listener)
from workeros.managed_service import ServiceScope
from workeros.managed_service_scope import ServiceDescriptor


class ManagedListenersTest(TestCase):
    def test_owner_open_retains_exact_modes_and_existing_file(self):
        directory = Path(self.enterContext(TemporaryDirectory())).resolve()
        path = directory / 'protected output'
        path.write_bytes(b'prior record')
        original = path.stat()
        pin = ServiceDescriptor('stdout', 'record', original.st_uid, 'write',
                                original.st_dev, original.st_ino, 3)
        with ExitStack() as held:
            writer = open_registered_original(str(path), pin, held)
            reader = open_registered_original(str(path), pin, held, observe=True)
            self.assertEqual(fcntl.fcntl(writer, fcntl.F_GETFL) & os.O_ACCMODE, os.O_WRONLY)
            self.assertEqual(fcntl.fcntl(reader, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertEqual(os.pread(reader, 20, 0), b'prior record')
            alias = directory / 'alias'
            alias.symlink_to(path)
            foreign = directory / 'unapproved'
            foreign.write_bytes(b'untouched')
            for target in (alias, foreign):
                with self.assertRaisesRegex(ValueError, 'service_original_activation_mismatch'):
                    open_registered_original(str(target), pin, held)
            self.assertEqual(foreign.read_bytes(), b'untouched')
        with self.assertRaises(OSError):
            os.fstat(writer)

    def test_holder_acl_checks_and_sets_only_requested_socket_access(self):
        directory = Path(self.enterContext(TemporaryDirectory(prefix='.wm-acl-')))
        owner = os.geteuid()
        named = owner or os.getuid() or 1
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaisesRegex(HolderEndpointRefusal, 'holder_endpoint_directory_acl_unverified'):
            _require_holder_directory(fd, named)
        with self.assertRaisesRegex(HolderEndpointRefusal, 'holder_endpoint_guard_traversal_unverified'):
            _require_guard_traversal(fd)
        original_acl = _acl(named, 1, owner_access=7)
        os.setxattr(fd, _XATTR, original_acl, os.XATTR_CREATE)
        _require_holder_directory(fd, named)
        path = directory / 'holder.sock'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o600)
            _grant_guard_connect(fd, path.name, named, path.stat())
            self.assertEqual(os.getxattr(path, _XATTR), _acl(named, 2))
            self.assertEqual(path.stat().st_mode & 0o777, 0o620)
            self.assertEqual(os.getxattr(fd, _XATTR), original_acl)
        with self.assertRaisesRegex(HolderEndpointRefusal, 'holder_endpoint_guard_untrusted'):
            with registered_listener(str(path), owner, guard_uid=owner):
                self.fail('holder UID can serve as its own guard')

    def test_listener_owns_only_the_socket_it_bound(self):
        temp = Path(gettempdir()).resolve()
        parent = temp if temp.stat().st_uid == 0 else Path.cwd()
        directory = Path(self.enterContext(TemporaryDirectory(prefix='.wm-', dir=parent)))
        path = directory / 'guard'
        with registered_listener(str(path), os.geteuid()) as listener:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(OSError), registered_listener(str(path), os.geteuid()):
                self.fail('a second listener replaced the first')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(path))
                accepted, _ = listener.accept()
                with accepted:
                    connection.sendall(b'x')
                    self.assertEqual(accepted.recv(1), b'x')
            path.rename(directory / 'moved')
            path.write_bytes(b'independent file')
        self.assertEqual(path.read_bytes(), b'independent file')
        path.unlink()
        with registered_listener(str(path), os.geteuid()):
            self.assertTrue(path.is_socket())
        self.assertFalse(path.exists())
        directory.chmod(0o770)
        with self.assertRaises(PermissionError), registered_listener(str(path), os.geteuid()):
            self.fail('a group-writable socket directory was accepted')

    def test_named_original_rebind_checks_exact_file_and_access(self):
        with TemporaryDirectory() as path:
            original = Path(path) / 'original'
            original.write_bytes(b'x')
            info = original.stat()
            scope = ServiceScope('/approved', 1, 2, '/worker', 1, 'read', info.st_dev, info.st_ino, 999)
            with original.open('rb') as read, original.open('r+b') as read_write:
                bound = bind_originals(scope, {'workeros-original-stdin': read.fileno()})
                self.assertEqual((bound.original_fd, bound.digest), (read.fileno(), scope.digest))
                with self.assertRaisesRegex(ValueError, 'service_original_mismatch'):
                    bind_originals(scope, {'workeros-original-stdin': read_write.fileno()})
                with self.assertRaisesRegex(ValueError, 'service_original_activation_mismatch'):
                    bind_originals(scope, {'workeros-original-stdout': read.fileno()})

    def test_names_and_pid_are_checked_on_actual_inherited_descriptors(self):
        program = '''\
import os
from workeros.managed_listeners import activation_descriptors
fd = os.open('/dev/null', os.O_RDONLY)
if fd != 3:
    os.dup2(fd, 3)
os.set_inheritable(3, True)
os.environ.update(LISTEN_PID=str(os.getpid() + 1), LISTEN_FDS='1', LISTEN_FDNAMES='guard')
try:
    activation_descriptors({'guard'}, set())
except ValueError:
    pass
else:
    raise AssertionError('wrong process accepted')
os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='1', LISTEN_FDNAMES='guard')
assert activation_descriptors({'guard'}, set()) == {'guard': 3}
assert not os.get_inheritable(3) and 'LISTEN_FDNAMES' not in os.environ
'''
        run = subprocess.run((sys.executable, '-c', program), check=False, capture_output=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr.decode())
