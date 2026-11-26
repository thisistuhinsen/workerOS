"""Disposable Linux regular-file profile. No elevated access, service or network."""
from contextlib import ExitStack
from dataclasses import asdict
import errno
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
from time import monotonic_ns
from unittest import TestCase, mock, skipUnless

from worker_handoff import Identity, Worker, observe, send_original
from worker_handoff.lifecycle import Match, ProcessState, RegularFileObserver

_SCOPE = '1a' * 32
_QUALIFY = os.environ.get("WORKER_HANDOFF_OBSERVER_QUALIFY") == "1"
_PYTHON = [sys.executable, "-I"] if sys.flags.isolated else [sys.executable]
_CHILD = """
import os, socket, sys
from worker_handoff import Identity, Worker, receive_original

s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
print("ready", flush=True)
r = receive_original(s, peer=Worker("sender", "writer", int(sys.argv[2]), os.getuid()),
                     identity=Identity(int(sys.argv[3]), int(sys.argv[4])),
                     token=b"sample", due_ns=int(sys.argv[5]))
os.dup2(r.fileno(), 42, inheritable=False)
r.close()
print("read:" + os.pread(42, 5, 0).decode(), flush=True)
if sys.stdin.readline() != 'close\\n':
    raise SystemExit(2)
os.close(42)
print("closed", flush=True)
sys.stdin.readline()
"""


@skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class LifecycleTests(TestCase):
    def setUp(self):
        self.owned = self.enterContext(ExitStack())
        self.tmp = Path(self.owned.enter_context(tempfile.TemporaryDirectory()))
        self.path = self.tmp / "report"
        self.path.write_bytes(b"hello")
        self.ref = self.fd(self.path, os.O_RDONLY)
        self.ident = observe(self.ref).identity
        self.dir = self.fd(self.tmp, os.O_DIRECTORY | os.O_RDONLY)
        self.due = monotonic_ns() + 10_000_000_000

    def fd(self, path, flags):
        fd = os.open(path, flags | os.O_CLOEXEC)
        self.owned.callback(os.close, fd)
        return fd

    def pin(self, pid):
        fd = os.pidfd_open(pid)
        self.owned.callback(os.close, fd)
        return fd

    def bind(self, **changes):
        config = dict(scope=_SCOPE, due_ns=self.due, original_fd=self.ref,
                      identity=self.ident, pidfd=self.pin(os.getpid()),
                      worker=Worker("example", "reader", os.getpid(), os.getuid()),
                      slot=self.ref, directory_fd=self.dir, leaf='report')
        config.update(changes)
        return self.owned.enter_context(RegularFileObserver(**config))

    def test_real_regular_file_handoff_read_close_and_name_cleanup(self):
        # This is a real transfer/read across processes, NOT independent custody.
        try:
            endpoint = self.owned.enter_context(socket.socket(socket.AF_UNIX))
        except PermissionError:
            if _QUALIFY:
                raise  # No skipped socket profile can qualify the target runtime.
            self.skipTest("local Unix sockets are disabled by this host")
        endpoint.bind(str(self.tmp / "worker.sock"))
        endpoint.listen(1)
        endpoint.settimeout(5)
        child = subprocess.Popen(
            [*_PYTHON, "-c", _CHILD, str(self.tmp / "worker.sock"),
             str(os.getpid()), str(self.ident.device), str(self.ident.inode), str(self.due)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

        def finish():
            child.stdin.close()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            child.stdout.close()
        self.addCleanup(finish)

        def line():
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "child timed out")
            return child.stdout.readline().strip()

        worker = Worker("consumer", "reader", child.pid, os.getuid())
        provider = self.bind(worker=worker, pidfd=self.pin(child.pid), slot=42)
        channel, _ = endpoint.accept()
        self.owned.enter_context(channel)
        self.assertEqual(line(), "ready")
        before = provider.sample()
        self.assertEqual((before.process, before.slot_match, before.name_match),
                         (ProcessState.LIVE, Match.ABSENT, Match.ORIGINAL))
        send_original(channel, self.ref, identity=self.ident, peer=worker,
                      token=b"sample", due_ns=self.due)
        self.assertEqual(line(), "read:hello")
        during = provider.sample()
        self.assertEqual(during.slot_match, Match.ORIGINAL)
        self.assertEqual(during.flags & (os.O_PATH | os.O_ACCMODE), os.O_RDONLY)
        self.assertEqual(during.reference_flags & (os.O_PATH | os.O_ACCMODE), os.O_RDONLY)
        child.stdin.write("close\n")
        child.stdin.flush()
        self.assertEqual(line(), "closed")
        os.unlink(self.path)
        after = provider.sample()
        self.assertEqual((after.process, after.slot_match, after.name_match),
                         (ProcessState.LIVE, Match.ABSENT, Match.ABSENT))
        self.assertEqual((before.session, before.scope), (after.session, after.scope))
        self.assertLessEqual(before.finished_ns, during.started_ns)
        self.assertLessEqual(during.finished_ns, after.started_ns)
        child.stdin.write("exit\n")
        child.stdin.flush()
        self.assertEqual(child.wait(timeout=5), 0)
        terminal = provider.sample()
        self.assertEqual((terminal.process, terminal.slot_match), (ProcessState.EXITED, Match.UNKNOWN))
        if _QUALIFY:
            print(json.dumps({
                "profile": "same_uid_local_socket",
                "samples": {phase: asdict(sample) for phase, sample in (
                    ("before_grant", before), ("after_read", during),
                    ("after_slot_close_and_unlink", after), ("after_exit", terminal),
                )},
            }), flush=True)

    def test_real_inherited_original_child_reads_then_retires_named_slot(self):
        # Separate process, ordinary exec inheritance. The child is a test
        # synchronization oracle; its messages do not feed the observer.
        code = ("import os,sys; fd=int(sys.argv[1]); print(os.pread(fd,5,0).decode(), flush=True); "
                "sys.stdin.readline(); os.close(fd); print('closed', flush=True); sys.stdin.readline()")
        child = subprocess.Popen([sys.executable, "-c", code, str(self.ref)], pass_fds=(self.ref,),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        def finish():
            child.stdin.close()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            child.stdout.close()
        self.addCleanup(finish)

        def line():
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "child timed out")
            return child.stdout.readline().strip()
        self.assertEqual(line(), "hello")
        provider = self.bind(worker=Worker("child", "reader", child.pid, os.getuid()),
                             pidfd=self.pin(child.pid), slot=self.ref)
        held = provider.sample()
        self.assertEqual((held.process, held.slot_match, held.name_match),
                         (ProcessState.LIVE, Match.ORIGINAL, Match.ORIGINAL))
        self.assertFalse(held.flags & (os.O_PATH | os.O_ACCMODE))
        child.stdin.write("close\n")
        child.stdin.flush()
        self.assertEqual(line(), "closed")
        os.unlink(self.path)
        retired = provider.sample()
        self.assertEqual((retired.process, retired.slot_match, retired.name_match),
                         (ProcessState.LIVE, Match.ABSENT, Match.ABSENT))
        child.stdin.write("exit\n")
        child.stdin.flush()
        self.assertEqual(child.wait(timeout=5), 0)
        exited = provider.sample()
        self.assertEqual((exited.process, exited.slot_match), (ProcessState.EXITED, Match.UNKNOWN))
        self.assertEqual((held.scope, held.session), (exited.scope, exited.session))

    def test_standalone_observer_runs_as_its_own_process(self):
        # Use a child pre-authorized by its controller. A host may legitimately
        # deny observation of its parent. Identity-only is still worth reporting.
        pin = self.pin(os.getpid())
        plan = dict(scope=_SCOPE, due_ns=self.due, original_fd=self.ref, pidfd=pin,
                    pid=os.getpid(), uid=os.getuid(), device=self.ident.device, inode=self.ident.inode,
                    slot=self.ref, directory_fd=self.dir, leaf='report')
        child = subprocess.run([*_PYTHON, "-m", "worker_handoff.observer_cli"],
                               input=json.dumps(plan) + "\n", capture_output=True, text=True, timeout=5,
                               pass_fds=(self.ref, pin, self.dir), check=True)
        out = json.loads(child.stdout)
        self.assertNotEqual(out["observer_pid"], os.getpid())
        self.assertEqual((out["scope"], out["worker_pid"], out["name_match"]),
                         (_SCOPE, os.getpid(), "original"))
        if out["slot_match"] == "unknown":
            self.assertTrue(out["reasons"])
            self.assertIsNone(out["flags"])
        else:
            self.assertEqual(out["slot_match"], "original")
        if _QUALIFY:
            print(json.dumps({"profile": "separate_process_same_uid", "sample": out}), flush=True)

    def test_metadata_only_or_read_write_slot_and_unrelated_slot(self):
        path_ref = self.fd(self.path, os.O_PATH)
        writable = self.fd(self.path, os.O_RDWR)
        provider = self.bind(original_fd=path_ref, slot=writable)
        seen = provider.sample()
        self.assertEqual(seen.slot_match, Match.ORIGINAL)
        self.assertTrue(seen.reference_flags & os.O_PATH)
        self.assertEqual(seen.flags & os.O_ACCMODE, os.O_RDWR)
        self.assertEqual(self.bind(slot=self.dir).sample().slot_match, Match.OTHER)
        self.assertTrue(self.bind(slot=path_ref).sample().flags & os.O_PATH)

    def test_refuses_wrong_original_binding_or_pidfd(self):
        for changes in (dict(original_fd=self.dir), dict(original_fd=self.fd(self.path, os.O_RDWR)),
                        dict(pidfd=self.ref), dict(scope="123"), dict(leaf="../report"),
                        dict(directory_fd=None), dict(identity=Identity(0, 123)),
                        dict(worker=Worker("other", "reader", os.getpid()+100, os.getuid()))):
            with self.subTest(changes=tuple(changes)), self.assertRaises((ValueError, OSError)):
                self.bind(**changes)

    def test_permission_denial_or_vanished_metadata_does_not_mean_absence(self):
        provider = self.bind()
        for fail in (PermissionError(errno.EACCES, "denied"), FileNotFoundError(errno.ENOENT, "gone")):
            with self.subTest(fail=fail.errno), mock.patch.object(provider, "_slot_sample", side_effect=fail):
                seen = provider.sample()
                self.assertEqual(seen.slot_match, Match.UNKNOWN)
                self.assertEqual(seen.reasons, (f"slot_errno:{fail.errno}",))
                self.assertEqual(seen.name_match, Match.ORIGINAL)

    def test_unavailable_process_credentials_not_revalidated(self):
        provider = self.bind()
        with mock.patch.object(provider, "_uids", side_effect=PermissionError(errno.EACCES, "denied")):
            seen = provider.sample()
        self.assertEqual(seen.process, ProcessState.LIVE)  # pidfd only
        self.assertIsNone(seen.sampled_worker_uids)
        self.assertEqual(seen.expected_worker_uid, os.getuid())
        self.assertEqual(seen.slot_match, Match.UNKNOWN)

    def test_vanishing_leader_file_table_not_an_empty_slot(self):
        provider = self.bind(slot=424242)
        with mock.patch.object(provider, "_leader_available", side_effect=[True, False]):
            seen = provider.sample()
        self.assertIn("leader_file_table_unavailable", seen.reasons)
        self.assertEqual(seen.slot_match, Match.UNKNOWN)

    def test_failed_credential_recheck_clears_first_matching_uid(self):
        provider = self.bind()
        for failure in (
            PermissionError(errno.EACCES, "denied"),
            FileNotFoundError(errno.ENOENT, "gone"),
            ValueError("malformed UID field"),
        ):
            with self.subTest(failure=failure), mock.patch.object(
                provider, "_uids", side_effect=[(os.getuid(),) * 4, failure]
            ) as read_uids:
                seen = provider.sample()
                self.assertEqual(read_uids.call_count, 2)
                self.assertIsNone(seen.sampled_worker_uids)
                self.assertEqual(seen.expected_worker_uid, os.getuid())
                self.assertEqual(seen.slot_match, Match.UNKNOWN)
                self.assertIsNone(seen.flags)
                self.assertEqual(seen.name_match, Match.ORIGINAL)

    def test_expired_end_does_not_return_earlier_positive(self):
        provider = self.bind()
        with mock.patch("worker_handoff.lifecycle.monotonic_ns", side_effect=[self.due-1, self.due]):
            seen = provider.sample()
        self.assertEqual((seen.slot_match, seen.name_match, seen.reasons),
                         (Match.UNKNOWN, Match.UNKNOWN, ("expired",)))

    def test_replacement_name_or_uid_mismatch_is_not_a_close(self):
        other = self.tmp / "other"
        other.write_bytes(b"same")
        os.replace(other, self.path)
        candidate = self.bind(worker=Worker("example", "reader", os.getpid(), os.getuid()+1)).sample()
        self.assertEqual((candidate.process, candidate.slot_match, candidate.name_match),
                         (ProcessState.UNKNOWN, Match.UNKNOWN, Match.OTHER))
        self.assertIn("worker_uid_mismatch", candidate.reasons)
        self.assertEqual(candidate.expected_worker_uid, os.getuid()+1)
        self.assertEqual(candidate.sampled_worker_uids, (os.getuid(),)*4)

    def test_close_does_not_close_borrowed_handles(self):
        provider = self.bind()
        provider.close()
        provider.close()
        with self.assertRaises(ValueError):
            provider.sample()
        self.assertEqual(observe(self.ref).identity, self.ident)
