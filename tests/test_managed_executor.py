"""Stock executor boundary tests. An actual namespace needs an eligible host."""
from contextlib import ExitStack
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
from time import monotonic_ns
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from workeros import managed_cli, managed_executor as executor
from workeros.managed_launch import LaunchInvocation, LaunchPlan, LaunchRolePolicy


class ExecutorBoundaryTest(TestCase):
    def test_original_is_a_read_only_non_executable_exact_descriptor(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path = Path(directory) / 'input'
            path.write_bytes(b'input')
            original = stack.enter_context(path.open('rb'))
            initial = os.fstat(original.fileno())
            observer = {'original_fd': original.fileno(), 'device': initial.st_dev, 'inode': initial.st_ino}
            with patch.object(managed_cli, '_TRUSTED_UID', os.getuid()):
                held = executor._binding_fd(observer, stack)
                path.rename(path.with_suffix('.retained'))
                path.write_bytes(b'new pathname object')
                self.assertEqual(os.fstat(held).st_ino, initial.st_ino)
                with self.assertRaisesRegex(executor.ExecutorRefusal, '^launch_original_unavailable$'):
                    executor._binding_fd({**observer, 'inode': initial.st_ino+1}, stack)
                os.fchmod(original.fileno(), 0o700)
                with self.assertRaisesRegex(executor.ExecutorRefusal, '^launch_original_unavailable$'):
                    executor._binding_fd(observer, stack)

    def test_snapshot_pins_elf_and_rejects_an_interpreter(self):
        machine = {'x86_64': 62, 'aarch64': 183}[os.uname().machine]
        image = bytearray(120)
        image[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HH', image, 16, 2, machine)
        struct.pack_into('<Q', image, 32, 64)
        struct.pack_into('<HH', image, 54, 56, 1)
        for loaded_type in (1, 3):
            with self.subTest(elf_program_header=loaded_type), ExitStack() as stack:
                struct.pack_into('<I', image, 64, loaded_type)
                source = stack.enter_context(tempfile.TemporaryFile())
                source.write(image)
                source.seek(0)
                with patch.object(executor, '_open_protected', side_effect=lambda _value: os.dup(source.fileno())):
                    pin = sha256(image).hexdigest()
                    if loaded_type == 3:
                        with self.assertRaisesRegex(executor.ExecutorRefusal, '^launch_executable_unsupported$'):
                            executor._snapshot('/admin/worker', pin, stack)
                    else:
                        frozen = executor._snapshot('/admin/worker', pin, stack)
                        self.assertEqual(os.pread(frozen, len(image), 0), image)
                        self.assertEqual(fcntl.fcntl(frozen, executor._GET_SEALS) & executor._REQUIRED_SEALS,
                                         executor._REQUIRED_SEALS)
                        with self.assertRaisesRegex(executor.ExecutorRefusal, '^launch_executable_changed$'):
                            source.seek(0)
                            executor._snapshot('/admin/worker', 'b'*64, stack)
        command = executor._sandbox_command(31, 32)
        self.assertEqual(command.count('--ro-bind-fd'), 1)
        self.assertEqual(command[command.index('--ro-bind-fd')+1:][:2], ['32', '/input'])
        self.assertEqual(command[-2:], ['--', '/worker'])
        self.assertTrue({'--unshare-user', '--unshare-net', '--disable-userns', '--clearenv'} <= set(command))
        self.assertTrue({'--dev', '--proc', '--ro-bind', '--share-net'}.isdisjoint(command))

    def test_wrong_real_peer_receives_no_ticket_request(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            endpoint = str(Path(directory) / 'authority.sock')
            listener.bind(endpoint)
            listener.listen()
            uid = 1 if os.getuid() != 1 else 2
            worker_uid = 3
            authority_pin = executor.authority_pin('authority', endpoint, uid)
            policy = LaunchRolePolicy('report', 'b'*64, 'gen', 'reader', 'worker',
                                      'c'*64, 'd'*64, 'launcher', 'authority', authority_pin, worker_uid)
            invocation = LaunchInvocation('e'*64, 'clock', LaunchPlan(
                'report', 'b'*64, 'gen', 'reader', 'worker', 'c'*64, 'd'*64,
                'launcher', 'authority', authority_pin, 'a'*64, worker_uid))
            authority = executor._Authority(endpoint, uid, policy)
            with self.assertRaisesRegex(executor.ExecutorRefusal, '^launch_authority_peer_untrusted$'):
                authority.authorize(invocation, deadline_ns=monotonic_ns()+1_000_000_000)
            listener.settimeout(1)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1)
                self.assertEqual(connection.recv(1), b'')

    def test_approved_cleanup_budget_reaps_the_real_owned_child(self):
        children = []

        def spawn(command, **options):
            self.assertEqual(options.pop('user'), os.getuid())
            self.assertEqual(options.pop('group'), os.getgid())
            self.assertEqual(options.pop('extra_groups'), [])
            # Only the credential transition is modelled. This fixture
            # actually starts and reaps its own ordinary isolated child.
            child = subprocess.Popen(command, **options)
            children.append(child)
            return child

        fixture = SimpleNamespace(Popen=spawn, DEVNULL=subprocess.DEVNULL,
                                  CalledProcessError=subprocess.CalledProcessError)
        plan = SimpleNamespace(invocation_key='a'*64, role='custom-reader')
        with patch.object(executor, 'subprocess', fixture):
            deadline = monotonic_ns() + 2_000_000_000
            executor._run_pinned_sandbox(
                [sys.executable, '-I', '-B', '-c', 'pass'], plan=plan, deadline_ns=deadline,
                cleanup_ns=1_000_000_000, uid=os.getuid(), gid=os.getgid(), handles=())
            self.assertEqual(children[0].returncode, 0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(children[0].pid, os.WNOHANG)
            deadline = monotonic_ns() + 1_000_000_000
            try:
                with self.assertRaisesRegex(TimeoutError, 'approved_launch_exit_unconfirmed'):
                    executor._run_pinned_sandbox(
                        [sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'],
                        plan=plan, deadline_ns=deadline, cleanup_ns=800_000_000,
                        uid=os.getuid(), gid=os.getgid(), handles=())
                self.assertLess(children[1].returncode, 0)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(children[1].pid, os.WNOHANG)
            finally:
                if len(children) > 1 and children[1].returncode is None:
                    children[1].kill()
                    children[1].wait(timeout=2)

    def test_installed_terminal_and_json_share_refusal_before_setup(self):
        command = str(Path(sys.prefix) / 'bin' / 'workeros')
        identifier = 'a'*64
        terminal = [command, 'managed', 'run-approved', '--request-id', identifier]
        from_json = [command, 'managed', 'run-approved', '--format', 'json']
        results = []
        for argv, data in ((terminal, b''), (from_json, json.dumps({'version':1,'request_id':identifier}).encode())):
            result = subprocess.run(argv, input=data, capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 1)
            value = json.loads(result.stdout)
            self.assertEqual(value['effect'], 'not_attempted')
            results.append(value)
        self.assertEqual(*results)
        forged = json.dumps({'version':1,'request_id':identifier,'executable':'/usr/bin/true'}).encode()
        result = subprocess.run(from_json, input=forged, capture_output=True, timeout=8)
        self.assertEqual(json.loads(result.stdout)['code'], 'invalid_launch_request')
