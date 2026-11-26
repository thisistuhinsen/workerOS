"""Compose the installed Linux APIs with disposable, caller-owned fixtures.

The processes and receipt records are ordinary test participants. Scope is one
named slot or direct child, and coverage concerns the named reported phases.
"""

from contextlib import ExitStack
from dataclasses import replace
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns, sleep
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import uuid4

import worker_handoff
import worker_handoff.lifecycle as lifecycle
from worker_handoff import (
    CleanupStatus, DeliveryStatus, DirectChildSupervisor, EffectStatus,
    LifecycleStatus, PositionalWrite, ReleasePlan, SupervisionStartError, Worker,
    observe, receive_original, release_executable, send_original,
)
from worker_handoff.evidence import (
    EvidenceObservation, EvidenceState, RunBinding, RunEvent, validate_run_evidence,
)
from worker_handoff.lifecycle import Match, ProcessState, RegularFileObserver


_CHILD_COMMON = """
import errno, os, sys
from pathlib import Path
from time import monotonic_ns, sleep
from worker_handoff import Identity

control, due = Path(sys.argv[1]), int(sys.argv[2])
identity = Identity(*map(int, sys.argv[3:5]))

def wait_for(name):
    while not (control / name).exists():
        if monotonic_ns() >= due:
            raise TimeoutError(name)
        sleep(0.01)

def report(name, value):
    pending = control / (name + ".tmp")
    pending.write_text(value)
    pending.replace(control / name)

def require_closed(fd):
    try:
        os.fstat(fd)
    except OSError as exc:
        assert exc.errno == errno.EBADF
    else:
        raise AssertionError("the named descriptor is still open")
"""

_INHERITED_READER = _CHILD_COMMON + """
from io import BytesIO
from worker_handoff import Original

expected = bytes.fromhex(sys.argv[5])
assert os.environ["WORKER_HANDOFF_ABI"] == "1"
assert os.environ["WORKER_HANDOFF_ACCESS_INPUT"] == "read"
fd = int(os.environ["WORKER_HANDOFF_FD_INPUT"])
os.set_inheritable(fd, False)
with Original(fd, identity) as original:
    report("held", str(fd))
    wait_for("read")
    sink = BytesIO()
    read = original.read_and_close(sink, due_ns=due, expected_size=len(expected))
    assert read.original == identity
    assert read.bytes_read == len(expected)
    assert read.eof_observed_ns <= read.closed_ns
    assert sink.getvalue() == expected
require_closed(fd)
report("validated", sink.getvalue().hex())
wait_for("exit")
"""


@skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class AcceptanceProfiles(TestCase):
    def setUp(self):
        self.stack = self.enterContext(ExitStack())
        self.tmp = Path(self.stack.enter_context(TemporaryDirectory()))
        self.started = monotonic_ns()
        self.due = self.started + 15_000_000_000
        self.supervisor = DirectChildSupervisor()

    def fd(self, path, flags):
        fd = os.open(path, flags | os.O_CLOEXEC)
        self.stack.callback(os.close, fd)
        return fd

    @staticmethod
    def command(code, *args):
        if not sys.flags.isolated:
            # Source-tree test runs pass the import location explicitly. The
            # installed suite uses isolated child imports from that same wheel.
            package_path = str(Path(worker_handoff.__file__).resolve().parents[1])
            code = f"import sys\nsys.path.insert(0, {package_path!r})\n" + code
        return (sys.executable, "-I", "-c", code, *map(str, args))

    @staticmethod
    def stop_unadopted(process):
        process.kill()
        process.wait(timeout=5)

    def _cleanup(self, name):
        result = self.supervisor.cleanup(name, due_ns=monotonic_ns() + 5_000_000_000)
        self.assertEqual(result.status, CleanupStatus.REAPED)

    def start(self, name, argv, fds=None):
        try:
            worker = self.supervisor.start_executable(
                name, name, argv, due_ns=self.due, fds=fds, uid=os.getuid(),
            )
        except SupervisionStartError as exc:
            self.stop_unadopted(exc.process)
            raise
        self.stack.callback(self._cleanup, worker.name)
        return worker

    def adopt(self, worker):
        try:
            adopted = self.supervisor.adopt(
                worker.name, worker.role, worker.process, uid=os.getuid(),
            )
        except BaseException:
            self.stop_unadopted(worker.process)
            raise
        self.stack.callback(self._cleanup, adopted.name)
        return adopted

    def note(self, path):
        while not path.exists():
            self.assertLess(monotonic_ns(), self.due, f"worker did not report {path.name}")
            sleep(0.01)
        return path.read_text()

    def binding(self, identity, payload):
        artifact = f"{identity.device}:{identity.inode}:{sha256(payload).hexdigest()}"
        return RunBinding(uuid4().hex, artifact, "launcher-monotonic", self.started, self.due)

    @staticmethod
    def scope(binding):
        return sha256(repr(binding).encode()).hexdigest()

    def observer(self, binding, worker, slot, ref, path):
        pin = os.pidfd_open(worker.pid)
        self.stack.callback(os.close, pin)
        directory = self.fd(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        return self.stack.enter_context(RegularFileObserver(
            scope=self.scope(binding), due_ns=self.due,
            original_fd=ref, identity=observe(ref).identity, pidfd=pin,
            worker=worker, slot=slot, directory_fd=directory, leaf=path.name,
        ))

    def point(self, binding, provider, seq, subject):
        sample = provider.sample()
        self.assertEqual(sample.scope, self.scope(binding))
        state = {
            Match.ORIGINAL: EvidenceState.OBSERVED,
            Match.ABSENT: EvidenceState.CONFIRMED_ABSENT,
            Match.OTHER: EvidenceState.INDETERMINATE,
            Match.UNKNOWN: EvidenceState.INDETERMINATE,
            Match.NOT_REQUESTED: EvidenceState.NOT_REQUESTED,
        }[sample.slot_match]
        event = RunEvent(
            binding, "observer", seq, sample.started_ns, sample.finished_ns,
            observations=(EvidenceObservation(subject, state, sample.slot_match.value),),
        )
        return sample, event

    def reap(self, binding, worker, control, seq):
        before = monotonic_ns()
        (control / "exit").touch()
        waited = self.supervisor.wait(worker.name, due_ns=self.due)
        self.assertEqual((waited.lifecycle, waited.returncode), (LifecycleStatus.EXITED, 0))
        self.assertEqual(waited.cleanup.status, CleanupStatus.NOT_REQUESTED)
        receipt = self.supervisor.cleanup(worker.name, due_ns=self.due)
        self.assertEqual((receipt.status, receipt.returncode), (CleanupStatus.REAPED, 0))
        self.assertFalse(receipt.terminate_sent or receipt.kill_sent)
        return RunEvent.from_result(binding, "supervisor", seq, before, monotonic_ns(), receipt)

    def test_prebound_reader_needs_exact_readable_original_and_recipient_read(self):
        payload = b"synthetic report"
        path, other = self.tmp / "original", self.tmp / "other"
        for file in (path, other):
            file.write_bytes(payload)
        original = self.fd(path, os.O_RDONLY)
        identity = observe(original).identity
        wrong = self.fd(other, os.O_RDONLY)
        self.assertNotEqual(observe(wrong).identity, identity)
        self.assertEqual(os.pread(wrong, len(payload), 0), payload)
        control = self.tmp / "reader"
        control.mkdir()
        plan = ReleasePlan(
            "reader", "read", self.command(
                _INHERITED_READER, control, self.due, identity.device, identity.inode, payload.hex(),
            ), identity, self.due,
        )
        path_only = self.fd(path, os.O_PATH) if hasattr(os, "O_PATH") else None
        for supplied in (wrong, path_only):
            if supplied is None:
                continue
            with self.subTest(supplied=supplied):
                refused = release_executable(plan, input_fd=supplied, authorize=lambda p: p == plan)
                if refused.worker is not None:
                    self.adopt(refused.worker)
                self.assertIsNone(refused.worker)
                self.assertEqual((refused.delivery, refused.effect),
                                 (DeliveryStatus.NOT_ATTEMPTED, EffectStatus.NOT_ATTEMPTED))
                self.assertFalse((control / "held").exists())
                os.fstat(supplied)
        released = release_executable(plan, input_fd=original, authorize=lambda p: p == plan)
        self.assertIsNotNone(released.worker, released.error)
        worker = self.adopt(released.worker)
        self.assertEqual((released.delivery, released.effect),
                         (DeliveryStatus.DISPATCHED, EffectStatus.NOT_ATTEMPTED))
        binding = self.binding(identity, payload)
        slot = int(self.note(control / "held"))
        ref = original if path_only is None else path_only
        provider = self.observer(binding, worker, slot, ref, path)
        held, reported = self.point(binding, provider, 1, "readable-slot")
        self.assertEqual((held.process, held.slot_match), (ProcessState.LIVE, Match.ORIGINAL))
        self.assertEqual(held.flags & (getattr(os, "O_PATH", 0) | os.O_ACCMODE), os.O_RDONLY)
        if path_only is not None:
            self.assertTrue(held.reference_flags & os.O_PATH)
        required = (("reader", "validated-read"),)
        with self.assertRaises(ValueError):
            validate_run_evidence(binding, (reported,), require_observed=required)
        later_window = replace(binding, started_ns=held.finished_ns + 1)
        with self.assertRaises(ValueError):
            validate_run_evidence(later_window, (reported,))

        before = monotonic_ns()
        (control / "read").touch()
        self.assertEqual(self.note(control / "validated"), payload.hex())
        accepted = RunEvent(binding, "reader", 2, before, monotonic_ns(), observations=(
            EvidenceObservation("validated-read", EvidenceState.OBSERVED),
        ))
        terminal = self.reap(binding, worker, control, 3)
        validate_run_evidence(
            binding, (reported, accepted, terminal),
            require_observed=required, require_terminal_from="supervisor",
        )
        with self.assertRaises(ValueError):
            validate_run_evidence(
                binding, (reported, replace(terminal, sequence=2)),
                require_observed=required, require_terminal_from="supervisor",
            )
        self.assertEqual(observe(original).identity, identity)

    def test_current_recipient_receipt_gates_write_and_uncertainty_blocks_retry(self):
        payload = b"abcdef"
        path, marker = self.tmp / "receipt-input", self.tmp / "unexpected-launch"
        path.write_bytes(payload)
        peer = Worker("recipient", "read", os.getpid(), os.geteuid())
        artifact = sha256(payload).hexdigest()
        required = (("recipient", "receipt"),)
        unresolved = False
        real_pwrite = os.pwrite

        def write_then_lose_result(fd, data, offset):
            self.assertEqual(real_pwrite(fd, data[:1], offset), 1)
            raise OSError("synthetic unknown write result")

        with path.open("rb") as held, path.open("r+b") as writer:
            identity = observe(held.fileno()).identity
            plan = ReleasePlan(
                "receipt-worker", "read",
                (sys.executable, "-I", "-c",
                 "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'launched')", str(marker)),
                identity, self.due, write=PositionalWrite(2, b"YZ"),
            )

            def receipt(binding):
                token = binding.run_id.encode("ascii")
                tx, rx = socket.socketpair()
                started = monotonic_ns()
                with tx, rx:
                    send_original(tx, held.fileno(), peer=peer, identity=identity,
                                  token=token, due_ns=self.due)
                    with receive_original(rx, peer=peer, identity=identity,
                                          token=token, due_ns=self.due) as received:
                        self.assertEqual(os.pread(received.fileno(), len(payload), 0), payload)
                return (RunEvent(binding, "recipient", 1, started, monotonic_ns(), observations=(
                    EvidenceObservation("receipt", EvidenceState.OBSERVED),
                )),)

            previous = RunBinding("previous", artifact, "local", monotonic_ns(), self.due)
            historical = receipt(previous)
            started = monotonic_ns()
            current = RunBinding("current", artifact, "local", started, self.due)
            foreign = RunBinding("other", artifact, "local", started, self.due)
            wrong, accepted = receipt(foreign), receipt(current)
            for binding, reports in ((previous, historical), (foreign, wrong), (current, accepted)):
                validate_run_evidence(binding, reports, require_observed=required)

            def attempt(binding, reports):
                nonlocal unresolved

                def authorize(_):
                    if unresolved:
                        return False
                    try:
                        validate_run_evidence(binding, reports, require_observed=required)
                    except ValueError:
                        return False
                    return True

                result = release_executable(
                    plan, input_fd=held.fileno(), writer_fd=writer.fileno(), authorize=authorize,
                )
                unresolved = unresolved or result.effect is EffectStatus.UNKNOWN
                return result

            with (patch("worker_handoff.managed.os.pwrite", side_effect=write_then_lose_result) as write,
                  patch("worker_handoff.workers.subprocess.Popen", wraps=subprocess.Popen) as launch):
                for case, reports in (("missing", ()), ("wrong attempt", wrong), ("historical", historical)):
                    with self.subTest(case=case):
                        refused = attempt(current, reports)
                        self.assertIs(refused.effect, EffectStatus.NOT_ATTEMPTED)
                        self.assertIs(refused.delivery, DeliveryStatus.NOT_ATTEMPTED)
                        self.assertEqual(path.read_bytes(), payload)
                write.assert_not_called()
                uncertain = attempt(current, accepted)
                self.assertIs(uncertain.effect, EffectStatus.UNKNOWN)
                self.assertIs(uncertain.delivery, DeliveryStatus.NOT_ATTEMPTED)
                self.assertIsNone(uncertain.worker)
                self.assertEqual(path.read_bytes(), b"abYdef")
                retry = attempt(current, accepted)
                self.assertIs(retry.effect, EffectStatus.NOT_ATTEMPTED)
                self.assertIs(retry.delivery, DeliveryStatus.NOT_ATTEMPTED)
                self.assertEqual(path.read_bytes(), b"abYdef")
                write.assert_called_once()
                launch.assert_not_called()
                self.assertFalse(marker.exists())

    def test_completed_write_precedes_read_and_cleanup_stays_with_each_child(self):
        self._completed_write_and_read(hold_writer_during_delivery=False)

    def test_writer_and_reader_hold_the_original_before_writer_closure(self):
        self._completed_write_and_read(hold_writer_during_delivery=True)

    def _completed_write_and_read(self, *, hold_writer_during_delivery):
        payload = b"completed write"
        path = self.tmp / "ordinary-input"
        path.write_bytes(b"old")
        ref = self.fd(path, os.O_RDONLY)
        alias = self.fd(path, os.O_WRONLY)
        identity = observe(ref).identity
        writer_run = self.binding(identity, payload)
        reader_run = self.binding(identity, payload)
        self.assertNotEqual(writer_run.run_id, reader_run.run_id)
        writer_gate, reader_gate = self.tmp / "write-gates", self.tmp / "read-gates"
        writer_gate.mkdir()
        reader_gate.mkdir()

        writer_code = _CHILD_COMMON + """
from worker_handoff import Writer
fd = int(os.environ["WORKER_HANDOFF_FD_OUTPUT"])
os.set_inheritable(fd, False)
with Writer(fd, identity) as writer:
    report("ready", "writer")
    wait_for("write")
    count = writer.write(bytes.fromhex(sys.argv[5]))
    writer.flush(sync=True)
    report("written", str(count))
    wait_for("close")
require_closed(fd)
report("closed", "writer")
wait_for("exit")
"""
        reader_code = _CHILD_COMMON + """
from io import BytesIO
import json
from socket import AF_UNIX, socket
from worker_handoff import Original, Worker, receive_original
with socket(AF_UNIX) as channel:
    channel.connect(sys.argv[5])
    report("ready", "reader")
    peer = Worker("launcher", "send", int(sys.argv[6]), os.getuid())
    with receive_original(channel, peer=peer, identity=identity,
                          token=sys.argv[7].encode(), due_ns=due) as received:
        fd = received.detach()
if fd != 42:
    try:
        os.dup2(fd, 42, inheritable=False)
    finally:
        os.close(fd)
with Original(42, identity) as original:
    report("held", "reader")
    wait_for("read")
    sink = BytesIO()
    result = original.read_and_close(sink, due_ns=due, expected_size=int(sys.argv[8]))
    require_closed(42)
    report("receipt", json.dumps([sink.getvalue().hex(), result.bytes_read,
           result.original.device, result.original.inode, result.eof_observed_ns, result.closed_ns]))
wait_for("exit")
"""
        endpoint = self.stack.enter_context(socket.socket(socket.AF_UNIX))
        socket_path = self.tmp / "handoff.sock"
        endpoint.bind(str(socket_path))
        endpoint.listen(1)
        endpoint.settimeout(5)
        common = tuple(map(str, (self.due, identity.device, identity.inode)))
        writer = self.start("writer", self.command(
            writer_code, str(writer_gate), *common, payload.hex(),
        ), fds={"OUTPUT": alias})
        reader = self.start("reader", self.command(
            reader_code, str(reader_gate), *common, str(socket_path),
            str(os.getpid()), reader_run.run_id, str(len(payload)),
        ))
        channel = self.stack.enter_context(endpoint.accept()[0])
        self.assertEqual(self.note(writer_gate / "ready"), "writer")
        self.assertEqual(self.note(reader_gate / "ready"), "reader")
        writer_view = self.observer(writer_run, writer, alias, ref, path)
        reader_view = self.observer(reader_run, reader, 42, ref, path)
        writing, writer_held = self.point(writer_run, writer_view, 1, "writer-slot-held")
        before, before_grant = self.point(reader_run, reader_view, 1, "reader-slot-before-grant")
        self.assertEqual((writing.process, writing.slot_match), (ProcessState.LIVE, Match.ORIGINAL))
        self.assertEqual(writing.flags & (getattr(os, "O_PATH", 0) | os.O_ACCMODE), os.O_WRONLY)
        self.assertEqual((before.process, before.slot_match), (ProcessState.LIVE, Match.ABSENT))

        started = monotonic_ns()
        (writer_gate / "write").touch()
        self.assertEqual(int(self.note(writer_gate / "written")), len(payload))
        self.assertEqual(os.pread(ref, len(payload) + 1, 0), payload)
        os.fsync(self.fd(path.parent, os.O_DIRECTORY | os.O_RDONLY))
        write_complete = RunEvent(writer_run, "writer", 2, started, monotonic_ns(), observations=(
            EvidenceObservation("write-complete", EvidenceState.OBSERVED),
        ))
        writer_events = [writer_held, write_complete]

        def close_writer():
            (writer_gate / "close").touch()
            self.assertEqual(self.note(writer_gate / "closed"), "writer")
            sample, event = self.point(
                writer_run, writer_view, len(writer_events) + 1, "writer-slot-closed",
            )
            self.assertEqual((sample.process, sample.slot_match), (ProcessState.LIVE, Match.ABSENT))
            writer_events.append(event)
            return sample

        if not hold_writer_during_delivery:
            closed = close_writer()

        started = monotonic_ns()
        send_original(channel, ref, peer=reader, identity=identity,
                      token=reader_run.run_id.encode(), due_ns=self.due)
        dispatched = RunEvent(reader_run, "sender", 2, started, monotonic_ns(), observations=(
            EvidenceObservation("descriptor-sent", EvidenceState.OBSERVED),
        ))
        self.assertEqual(self.note(reader_gate / "held"), "reader")
        holding, reader_held = self.point(reader_run, reader_view, 3, "reader-slot-held")
        self.assertEqual((holding.process, holding.slot_match), (ProcessState.LIVE, Match.ORIGINAL))
        self.assertEqual(holding.flags & (getattr(os, "O_PATH", 0) | os.O_ACCMODE), os.O_RDONLY)
        if hold_writer_during_delivery:
            # Both children are gated before closure and before the read.
            overlapping, writer_at_delivery = self.point(
                writer_run, writer_view, 3, "writer-slot-after-delivery",
            )
            self.assertEqual((overlapping.process, overlapping.slot_match),
                             (ProcessState.LIVE, Match.ORIGINAL))
            self.assertEqual(overlapping.flags & (getattr(os, "O_PATH", 0) | os.O_ACCMODE),
                             os.O_WRONLY)
            self.assertEqual(overlapping.original, holding.original)
            self.assertLessEqual(holding.finished_ns, overlapping.started_ns)
            writer_events.append(writer_at_delivery)
            lookup_unknown = self._check_unavailable_observations(reader_run, reader_view, reader, path)
            closed = close_writer()
            self.assertLessEqual(overlapping.finished_ns, closed.started_ns)
        else:
            self.assertLessEqual(closed.finished_ns, dispatched.started_ns)
            # Inject one missing lookup while the real worker holds its named slot.
            error = OSError(errno.EIO, "fixture lookup")
            with patch.object(reader_view, "_slot_sample", side_effect=error):
                unavailable, lookup_unknown = self.point(
                    reader_run, reader_view, 4, "reader-slot-unavailable",
                )
            self.assertEqual((unavailable.process, unavailable.slot_match, unavailable.flags),
                             (ProcessState.LIVE, Match.UNKNOWN, None))
        started = monotonic_ns()
        self.assertLessEqual(closed.finished_ns, started)
        (reader_gate / "read").touch()
        data, count, dev, ino, eof, closed_at = json.loads(self.note(reader_gate / "receipt"))
        self.assertEqual((bytes.fromhex(data), count, dev, ino),
                         (payload, len(payload), identity.device, identity.inode))
        self.assertLessEqual(eof, closed_at)
        validated = RunEvent(reader_run, "recipient", 5, started, monotonic_ns(), observations=(
            EvidenceObservation("read-to-eof", EvidenceState.OBSERVED),
        ))
        retired, reader_closed = self.point(reader_run, reader_view, 6, "reader-slot-closed")
        self.assertEqual((retired.process, retired.slot_match), (ProcessState.LIVE, Match.ABSENT))
        reader_reap = self.reap(reader_run, reader, reader_gate, 7)
        exited, after_exit = self.point(reader_run, reader_view, 8, "reader-slot-after-exit")
        self.assertEqual((exited.process, exited.slot_match), (ProcessState.EXITED, Match.UNKNOWN))
        self.assertEqual((before.session, before.scope), (exited.session, exited.scope))
        self.assertIs(reader_reap.cleanup, CleanupStatus.REAPED)
        still_live, other_child = self.point(
            writer_run, writer_view, len(writer_events) + 1, "writer-after-reader-reap",
        )
        self.assertEqual((still_live.process, still_live.slot_match), (ProcessState.LIVE, Match.ABSENT))
        self.assertEqual(observe(alias).identity, identity)
        self.assertEqual(observe(alias).flags & os.O_ACCMODE, os.O_WRONLY)
        writer_events.append(other_child)
        writer_events.append(self.reap(writer_run, writer, writer_gate, len(writer_events) + 1))
        validate_run_evidence(
            writer_run, tuple(writer_events),
            require_observed=(("writer", "write-complete"),), require_terminal_from="supervisor",
        )
        reader_events = (before_grant, dispatched, reader_held, lookup_unknown,
                         validated, reader_closed, reader_reap, after_exit)
        handoff = (("sender", "descriptor-sent"), ("observer", "reader-slot-held"),
                   ("recipient", "read-to-eof"))
        validate_run_evidence(reader_run, reader_events, require_observed=handoff,
                              require_terminal_from="supervisor")
        if hold_writer_during_delivery:
            self._check_qualification_limits(reader_run, writer_run, reader_events, handoff)

    def _check_qualification_limits(self, binding, other_run, events, handoff):
        # The added qualification reports are synthetic validator inputs.
        # Keep the real slot absence and reap in every evidence history.
        for source, subjects in (
            ("custody-observer", ("independent-custody",)),
            ("scope-meter", ("scope-begin", "scope-end")),
        ):
            required = handoff + tuple((source, subject) for subject in subjects)
            now = monotonic_ns()
            unavailable = RunEvent(binding, source, len(events) + 1, now, now, observations=tuple(
                EvidenceObservation(subject, EvidenceState.UNAVAILABLE) for subject in subjects
            ))
            reports = events + (unavailable,)
            validate_run_evidence(binding, reports, require_observed=handoff,
                                  require_terminal_from="supervisor")
            observed = replace(unavailable, observations=tuple(
                EvidenceObservation(subject, EvidenceState.OBSERVED) for subject in subjects
            ))
            cases = [
                ("missing", events, "missing required observations"),
                ("unavailable", reports, "missing required observations"),
                ("wrong run", events + (replace(observed, binding=other_run),), "event run"),
            ]
            if source == "scope-meter":
                for point in observed.observations:
                    partial = replace(observed, observations=(point,))
                    cases.append((f"{point.subject} only", events + (partial,), "missing required observations"))
            for status, history, reason in cases:
                with self.subTest(source=source, status=status), self.assertRaisesRegex(ValueError, reason):
                    validate_run_evidence(binding, history, require_observed=required,
                                          require_terminal_from="supervisor")

    def _check_unavailable_observations(self, binding, provider, worker, path):
        # Vary only the one observer input. Both real slots stay open.
        stat = os.stat
        fields = lifecycle._fields
        slot_info = f"/proc/{worker.pid}/fdinfo/{provider._slot}"

        def unavailable_name(name, *args, **kwargs):
            if (name == path.name and kwargs.get("dir_fd") == provider._directory
                    and kwargs.get("follow_symlinks") is False):
                raise OSError(errno.EIO, "fixture named-entry lookup")
            return stat(name, *args, **kwargs)

        def mismatched_mount(name):
            row = fields(name)
            if name == slot_info:
                row[b"mnt_id"] = str(int(row[b"mnt_id"]) + 1).encode()
            return row

        with patch.object(lifecycle.os, "stat", side_effect=unavailable_name):
            sample = provider.sample()
        self.assertEqual((sample.process, sample.slot_match, sample.name_match, sample.reasons),
                         (ProcessState.LIVE, Match.ORIGINAL, Match.UNKNOWN, (f"name_errno:{errno.EIO}",)))
        self.assertEqual(sample.flags & (getattr(os, "O_PATH", 0) | os.O_ACCMODE), os.O_RDONLY)
        with patch.object(lifecycle, "_fields", side_effect=mismatched_mount):
            sample, event = self.point(binding, provider, 4, "reader-slot-mount-unconfirmed")
        self.assertEqual((sample.process, sample.slot_match, sample.name_match, sample.flags, sample.reasons),
                         (ProcessState.LIVE, Match.UNKNOWN, Match.ORIGINAL, None, ("mount_mismatch",)))
        return event
