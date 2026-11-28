"""Detached Linux checks. These processes hold no live role or deployment authority."""
from dataclasses import replace
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import patch

from workeros.evidence import EvidenceScope, RunBinding
from workeros.incumbent import (
    DirectoryPin, IncumbentHandles, IncumbentPins, IncumbentRefusal, PhasePin,
    ProcessPin, retain_incumbent,
)
from workeros.original import Identity
from workeros.scope_meter import CgroupIdentity, _mount_id, monotonic_clock_id


class IncumbentTest(TestCase):
    def child(self):
        process = subprocess.Popen(
            [sys.executable, '-I', '-B', '-c', 'import sys; sys.stdin.buffer.read(1)'],
            stdin=subprocess.PIPE,
        )

        def finish():
            if not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        self.addCleanup(finish)
        fd = os.pidfd_open(process.pid)
        self.addCleanup(os.close, fd)
        rest = Path(f'/proc/{process.pid}/stat').read_bytes().rpartition(b') ')[2]
        return process, fd, ProcessPin(process.pid, os.getuid(), int(rest.split()[19]))

    def directory(self, path, *, flags=os.O_RDONLY):
        fd = os.open(path, flags | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        info = os.fstat(fd)
        return fd, DirectoryPin(Identity(info.st_dev, info.st_ino), _mount_id(fd))

    def setUp(self):
        self.writer_proc, writer_fd, writer = self.child()
        self.reader_proc, reader_fd, reader = self.child()
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / 'original'
        self.path.mkdir()
        original_fd, original = self.directory(self.path)
        (self.path / 'untouched').write_bytes(b'detached fixture')
        meter_fd, meter = self.directory('/sys/fs/cgroup')
        self.phase, self.peer = [self.enterContext(s) for s in socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)]
        info = os.fstat(self.phase.fileno())
        phase = PhasePin(Identity(info.st_dev, info.st_ino), os.getpid(), os.getuid(), socket.SOCK_SEQPACKET)
        start = monotonic_ns()
        clock = monotonic_clock_id()
        if clock is None:
            clock = 'detached-test-clock'
            self.enterContext(patch('workeros.incumbent.monotonic_clock_id', return_value=clock))
        run = RunBinding('incumbent-fixture', 'fixture', clock, start, start + 10_000_000_000)
        scope = EvidenceScope(run, 'fixture-scope', start, start+20_000_000_000)
        self.pins = IncumbentPins('a'*64, scope, original, writer, reader, phase,
                                  CgroupIdentity(meter.identity.device, meter.identity.inode, meter.mount_id))
        self.handles = IncumbentHandles(original_fd, writer_fd, reader_fd, self.phase.fileno(), meter_fd)

    def test_retains_exact_resources_through_local_outer_close(self):
        self.peer.sendall(b'unconsumed')
        with retain_incumbent(self.pins, self.handles) as retained:
            self.assertIs(retained.pins, self.pins)
            self.assertEqual(retained.pins.scope.run.run_id, 'incumbent-fixture')
            held = retained.handles._fds()
            for original, duplicate in zip(self.handles._fds(), held, strict=True):
                self.assertNotEqual(original, duplicate)
                self.assertFalse(os.get_inheritable(duplicate))
                self.assertEqual(os.fstat(original), os.fstat(duplicate))
            renamed = self.root / 'moved'
            self.path.rename(renamed)
            self.path.mkdir()
            (self.path / 'untouched').write_bytes(b'replacement')
            self.assertEqual(os.stat('untouched', dir_fd=retained.handles.original),
                             (renamed / 'untouched').stat())
            self.reader_proc.stdin.close()
            self.reader_proc.wait(timeout=3)
            os.fstat(retained.handles.reader)
        self.assertEqual(self.phase.recv(80), b'unconsumed')
        self.assertEqual((renamed / 'untouched').read_bytes(), b'detached fixture')
        self.assertIsNone(self.writer_proc.poll())
        with self.assertRaisesRegex(IncumbentRefusal, 'incumbent_handles_closed'):
            _ = retained.handles
        for fd in held:
            with self.assertRaises(OSError):
                os.fstat(fd)
        for fd in self.handles._fds():
            os.fstat(fd)

    def test_refuses_crossed_process_socket_directory_and_clock(self):
        cases = (
            (self.pins, replace(self.handles, reader=self.handles.writer, writer=self.handles.reader),
             'incumbent_process_mismatch'),
            (replace(self.pins, reader=replace(self.pins.reader, start_ticks=0)), self.handles,
             'incumbent_process_mismatch'),
            (replace(self.pins, phase=replace(self.pins.phase, peer_uid=1001 + os.getuid())), self.handles,
             'incumbent_phase_mismatch'),
            (replace(self.pins, original=replace(self.pins.original, mount_id=self.pins.original.mount_id + 1)),
             self.handles, 'incumbent_directory_mismatch'),
            (replace(self.pins, scope=replace(self.pins.scope, run=replace(self.pins.scope.run, clock_id='other'))),
             self.handles, 'incumbent_scope_not_active'),
        )
        baseline = len(os.listdir('/proc/self/fd'))
        for pins, handles, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(IncumbentRefusal, code):
                with retain_incumbent(pins, handles):
                    self.fail('crossed pin retained')
            self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)

    def test_refuses_dead_handle_and_non_cgroup_meter(self):
        false_meter, directory = self.directory(self.path / '..')
        bad_pins = replace(self.pins, meter=CgroupIdentity(
            directory.identity.device, directory.identity.inode, directory.mount_id))
        with self.assertRaisesRegex(IncumbentRefusal, 'incumbent_meter_not_cgroup'):
            with retain_incumbent(bad_pins, replace(self.handles, meter=false_meter)):
                self.fail('ordinary directory accepted as cgroup')
        self.reader_proc.stdin.close()
        self.reader_proc.wait(timeout=3)
        with self.assertRaisesRegex(IncumbentRefusal, 'incumbent_process_mismatch'):
            with retain_incumbent(self.pins, self.handles):
                self.fail('exited reader was accepted')

    def test_unavailable_clock_refuses_before_holding_handles(self):
        with patch('workeros.incumbent.monotonic_clock_id', return_value=None), patch(
                'workeros.incumbent._duplicate') as duplicate:
            with self.assertRaisesRegex(IncumbentRefusal, 'incumbent_scope_not_active'):
                with retain_incumbent(self.pins, self.handles):
                    self.fail('unclocked invocation was accepted')
            duplicate.assert_not_called()

    def test_outer_close_releases_phase_copy_before_peer_eof(self):
        with retain_incumbent(self.pins, self.handles) as retained:
            self.phase.close()
            self.peer.settimeout(1)
            retained.close()
            self.assertEqual(self.peer.recv(16), b'')
            self.assertIs(retained.pins, self.pins)
            with self.assertRaisesRegex(IncumbentRefusal, 'incumbent_handles_closed'):
                _ = retained.handles
