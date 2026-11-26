"""Read-only cgroup v2 meter qualification on an ordinary owned child."""

from contextlib import ExitStack
from dataclasses import asdict, replace
import errno
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
import unittest
from unittest.mock import patch
from uuid import uuid4

from worker_handoff import CleanupStatus, DirectChildSupervisor, LifecycleStatus, observe
from worker_handoff.evidence import (
    EvidenceScope, EvidenceState, RunBinding, ScopePhase, validate_scope_evidence,
)
from worker_handoff.lifecycle import Match, ProcessState, RegularFileObserver
from worker_handoff.scope_meter import (
    CgroupIdentity, CgroupSample, CgroupScopeMeter, ScopeMeterUnavailable, cpu_delta_usec,
    monotonic_clock_id,
)


_PAYLOAD = b"scope input"
_MEMORY_GAUGES = {
    "memory.current": ("memory_current_bytes", "memory_current_state"),
    "memory.peak": ("memory_peak_bytes", "memory_peak_state"),
}
_CHILD = """
import os, select, sys, time
from pathlib import Path

def own_group_matches():
    rows = Path('/proc/self/cgroup').read_text(errors='surrogateescape').splitlines()
    return [row[3:] for row in rows if row.startswith('0::')] == [sys.argv[1]]

if not own_group_matches():
    os.write(1, b'm')
    raise SystemExit(65)
fd = int(sys.argv[3])
os.set_inheritable(fd, False)
assert os.pread(fd, 32, 0) == b'scope input'
os.write(1, b'r')
due = int(sys.argv[2])
if not select.select([0], [], [], max(0, due - time.monotonic_ns()) / 1e9)[0]:
    raise SystemExit(66)
if os.read(0, 1) != b'g':
    raise SystemExit(67)
cpu_due = time.process_time_ns() + 30_000_000
while time.process_time_ns() < cpu_due:
    if time.monotonic_ns() >= due:
        raise SystemExit(68)
raise SystemExit(0 if own_group_matches() else 65)
"""


def _mount_path(field):
    # mountinfo escapes these four path characters using octal text.
    return PurePosixPath(re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), field))


@unittest.skipUnless(sys.platform == "linux", "Linux cgroup v2 required")
class CgroupScopeMeterTest(unittest.TestCase):
    def scope(self, clock_id):
        start = monotonic_ns()
        due = start + 15_000_000_000
        # A declared identifier cannot turn unknown kernel context into a report.
        run = RunBinding(uuid4().hex, sha256(_PAYLOAD).hexdigest(),
                         clock_id or "fixture-unbound-clock", start, due)
        return EvidenceScope(run, sha256(uuid4().bytes).hexdigest(), start, due)

    def open_self_cgroup(self, stack):
        try:
            groups = Path("/proc/self/cgroup").read_text(errors="surrogateescape").splitlines()
            mounts = Path("/proc/self/mountinfo").read_text(errors="surrogateescape").splitlines()
        except OSError as exc:
            self.skipTest(f"own cgroup or mount metadata unavailable (errno {exc.errno})")
        unified = [row[3:] for row in groups if row.startswith("0::")]
        if len(unified) != 1:
            self.skipTest("a single unified cgroup v2 membership is unavailable")
        group = PurePosixPath(unified[0])
        if not group.is_absolute() or ".." in group.parts:
            self.skipTest("own cgroup path is outside its visible namespace")

        candidates = []
        for row in mounts:
            left, _, right = row.partition(" - ")
            if not right.startswith("cgroup2 "):
                continue
            fields = left.split()
            if len(fields) < 5:
                continue
            mount_id, root, mountpoint = fields[0], _mount_path(fields[3]), _mount_path(fields[4])
            if (not root.is_absolute() or not mountpoint.is_absolute()
                    or ".." in root.parts or ".." in mountpoint.parts):
                continue
            try:
                relative = group.relative_to(root)
            except ValueError:
                continue
            candidates.append((mount_id, mountpoint / relative))
        if len(candidates) != 1:
            self.skipTest("own cgroup v2 path has no unique matching mount context")
        mount_id, directory = candidates[0]
        try:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            stack.callback(os.close, fd)
            fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
        except OSError as exc:
            self.skipTest(f"own cgroup directory or mount ID unavailable (errno {exc.errno})")
        seen_ids = [row.partition(":")[2].strip() for row in fdinfo if row.startswith("mnt_id:")]
        if seen_ids != [mount_id]:
            self.skipTest("opened cgroup directory does not match the recorded mount ID")
        return fd, unified[0]

    def kernel_usage(self, directory_fd):
        try:
            fd = os.open("cpu.stat", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            with os.fdopen(fd, encoding="ascii") as source:
                rows = [line.split()[1:] for line in source if line.startswith("usage_usec ")]
        except OSError as exc:
            self.skipTest(f"own cgroup v2 CPU counter unavailable (errno {exc.errno})")
        if len(rows) != 1 or len(rows[0]) != 1 or not rows[0][0].isdecimal():
            self.skipTest("own cgroup v2 cpu.stat has no usable usage_usec counter")
        return int(rows[0][0])

    @staticmethod
    def kernel_memory_states(directory_fd):
        states = {}
        for leaf in _MEMORY_GAUGES:
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as source:
                    data = source.read(128).strip()
            except OSError:
                states[leaf] = EvidenceState.UNAVAILABLE
                continue
            states[leaf] = (EvidenceState.OBSERVED
                            if 0 < len(data) <= 20 and data.isdigit() and int(data) < 1 << 64
                            else EvidenceState.INDETERMINATE)
        return states

    def assert_memory_fields(self, fields, expected, *, serialized=False):
        for leaf, (value_key, state_key) in _MEMORY_GAUGES.items():
            state = expected[leaf]
            if serialized:
                self.assertEqual(fields[state_key], state.value, leaf)
            else:
                self.assertIs(fields[state_key], state, leaf)
            value = fields[value_key]
            if state is EvidenceState.OBSERVED:
                self.assertIs(type(value), int, leaf)
                self.assertTrue(0 <= value < 1 << 64, leaf)
            else:
                self.assertIsNone(value, leaf)

    def observed_sample(self, meter, phase, clock_id):
        sample = meter.sample(phase)
        if sample.cpu_state is EvidenceState.UNAVAILABLE:
            self.skipTest(f"own cgroup v2 CPU counter unavailable at {phase.value}")
        self.assertIs(sample.cpu_state, EvidenceState.OBSERVED)
        self.assertIs(type(sample.usage_usec), int)
        self.assertEqual(sample.clock_id, clock_id)
        if clock_id is None:
            self.assertIsNone(sample.report)
        else:
            self.assertIsNotNone(sample.report, "sample ran outside the declared window")
            self.assertIs(sample.report.observation.state, EvidenceState.OBSERVED)
        if sample.populated is not None:
            self.assertIs(sample.populated, True)  # The test parent is still in this cgroup.
        return sample

    def held_slot_report(self, stack, scope, worker, original_fd, clock_id):
        pin = os.pidfd_open(worker.pid)
        stack.callback(os.close, pin)
        identity = observe(original_fd).identity
        observer = stack.enter_context(RegularFileObserver(
            scope=scope.scope_id, due_ns=scope.finished_ns, original_fd=original_fd,
            identity=identity, pidfd=pin, worker=worker, slot=original_fd,
        ))
        if clock_id is None:
            sample, report = observer.sample(), None
            with self.assertRaisesRegex(ValueError, "clock"):
                observer.sample_for_scope(scope, provider_id="observer")
        else:
            sample, report = observer.sample_for_scope(scope, provider_id="observer")
            self.assertIs(report.observation.state, EvidenceState.OBSERVED)
        self.assertEqual((sample.process, sample.slot_match), (ProcessState.LIVE, Match.ORIGINAL))
        self.assertEqual((sample.worker_pid, sample.original, sample.slot),
                         (worker.pid, identity, original_fd))
        self.assertEqual(sample.flags & (os.O_PATH | os.O_ACCMODE), os.O_RDONLY)
        return report

    def test_real_aggregate_scope_brackets_owned_cpu_child_and_reap(self):
        clock_id = monotonic_clock_id()
        scope = self.scope(clock_id)
        supervisor = DirectChildSupervisor()
        try:
            supervisor.check_available("cpu-child", "fixture")
        except (OSError, RuntimeError) as exc:
            self.skipTest(f"Linux pidfd supervision unavailable ({exc})")
        with ExitStack() as stack:
            fd, group = self.open_self_cgroup(stack)
            tmp = Path(stack.enter_context(TemporaryDirectory()))
            path = tmp / "input"
            path.write_bytes(_PAYLOAD)
            original_fd = stack.enter_context(path.open("rb")).fileno()
            try:
                meter = stack.enter_context(CgroupScopeMeter(scope=scope, provider_id="meter", directory_fd=fd))
            except ScopeMeterUnavailable as exc:
                self.skipTest(f"cgroup v2 meter unavailable: {exc}")
            lower = self.kernel_usage(fd)
            memory_states = self.kernel_memory_states(fd)
            begin = self.observed_sample(meter, ScopePhase.METER_BEGIN, clock_id)
            self.assertLessEqual(lower, begin.usage_usec)
            self.assertLessEqual(begin.usage_usec, self.kernel_usage(fd))
            self.assert_memory_fields(asdict(begin), memory_states)

            launched = monotonic_ns()
            child = subprocess.Popen(
                [sys.executable, "-I", "-c", _CHILD, group, str(scope.finished_ns), str(original_fd)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
                pass_fds=(original_fd,),
            )
            stack.callback(child.stdin.close)
            stack.callback(child.stdout.close)
            try:
                worker = supervisor.adopt("cpu-child", "fixture", child, uid=os.getuid())
            except BaseException:
                child.kill()  # Only this caller-owned child; adoption did not take ownership.
                child.wait(timeout=5)
                raise
            stack.callback(lambda: supervisor.cleanup(worker.name, due_ns=monotonic_ns() + 5_000_000_000))
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "CPU child did not report ready")
            ready = os.read(child.stdout.fileno(), 1)
            if ready == b"m":
                self.skipTest("owned child did not inherit the measured cgroup membership")
            self.assertEqual(ready, b"r")
            point = self.held_slot_report(stack, scope, worker, original_fd, clock_id)
            child.stdin.write(b"g")
            waited = supervisor.wait(worker.name, due_ns=scope.finished_ns)
            if waited.returncode == 65:
                self.skipTest("owned child cgroup membership changed while gated")
            self.assertEqual((waited.lifecycle, waited.returncode), (LifecycleStatus.EXITED, 0))
            cleanup = supervisor.cleanup(worker.name, due_ns=scope.finished_ns)
            self.assertEqual((cleanup.status, cleanup.returncode), (CleanupStatus.REAPED, 0))
            reaped = monotonic_ns()

            lower = self.kernel_usage(fd)
            memory_states = self.kernel_memory_states(fd)
            end = self.observed_sample(meter, ScopePhase.METER_END, clock_id)
            self.assertLessEqual(lower, end.usage_usec)
            self.assertLessEqual(end.usage_usec, self.kernel_usage(fd))
            self.assert_memory_fields(asdict(end), memory_states)
            # These are shared cgroup gauges. Attribute neither value to the child.
            for leaf, state in memory_states.items():
                print(f"SCOPE-METER {leaf}: {state.name}")

            real_open = os.open

            def missing_fields(path, *args, **kwargs):
                if path in ("cgroup.events", "memory.current") and kwargs.get("dir_fd") == meter._directory:
                    raise FileNotFoundError(errno.ENOENT, "fixture metric file absent")
                return real_open(path, *args, **kwargs)

            with patch("worker_handoff.scope_meter.os.open", side_effect=missing_fields):
                cpu_only = self.observed_sample(meter, ScopePhase.METER_END, clock_id)
            self.assertIs(cpu_only.population_state, EvidenceState.UNAVAILABLE)
            self.assertIsNone(cpu_only.populated)
            self.assertIn(f"cgroup.events_errno:{errno.ENOENT}", cpu_only.reasons)
            self.assertIn(f"memory.current_errno:{errno.ENOENT}", cpu_only.reasons)
            self.assert_memory_fields(asdict(cpu_only), memory_states | {"memory.current": EvidenceState.UNAVAILABLE})
            self.assertLessEqual(end.usage_usec, cpu_only.usage_usec)

            self.assertIsNotNone(begin.identity)
            self.assertEqual(begin.identity, end.identity)
            pinned = os.fstat(fd)
            self.assertEqual((begin.identity.device, begin.identity.inode), (pinned.st_dev, pinned.st_ino))
            # This is an aggregate cgroup counter, shared with the test parent.
            self.assertGreater(end.usage_usec, begin.usage_usec)
            interval = (launched, reaped)
            if clock_id is None:
                self.assertIsNone(point)
                with self.assertRaises(ValueError):
                    cpu_delta_usec(begin, end, require_meter_for=interval)
                print("SCOPE-METER clock-bound composition: UNAVAILABLE (Linux clock context absent)")
            else:
                reports = (begin.report, point, end.report)
                self.assertIs(validate_scope_evidence(
                    scope, reports, observer_id="observer", meter_id="meter", require_meter_for=interval,
                ), reports)
                self.assertEqual(cpu_delta_usec(begin, end, require_meter_for=interval),
                                 end.usage_usec - begin.usage_usec)
                print("SCOPE-METER clock-bound composition: OBSERVED (cgroup, held slot, direct-child reap)")
            os.fstat(fd)  # The meter borrowed the caller's directory descriptor.

    def test_two_phase_cli_reports_the_pinned_directory_and_scope(self):
        clock_id = monotonic_clock_id()
        scope = self.scope(clock_id)
        with ExitStack() as stack:
            fd, _ = self.open_self_cgroup(stack)
            lower = self.kernel_usage(fd)
            memory_states = self.kernel_memory_states(fd)
            plan = {"scope": asdict(scope), "directory_fd": fd, "provider_id": "meter"}
            phases = (ScopePhase.METER_BEGIN, ScopePhase.METER_END)
            requests = "".join(json.dumps(item) + "\n" for item in (plan, *(p.value for p in phases)))
            python = [sys.executable, "-I"] if sys.flags.isolated else [sys.executable]
            result = subprocess.run(
                [*python, "-m", "worker_handoff.scope_meter"], input=requests, text=True,
                capture_output=True, pass_fds=(fd,), timeout=5, check=True,
            )
            upper = self.kernel_usage(fd)
            pinned = os.fstat(fd)
            lines = result.stdout.splitlines()
            self.assertEqual(len(lines), 2)
            samples = []
            for phase, line in zip(phases, lines):
                envelope = json.loads(line)
                sample, report = envelope["sample"], envelope["scope_report"]
                self.assertEqual((sample["scope"], sample["provider_id"], sample["phase"]),
                                 (plan["scope"], "meter", phase.value))
                self.assertEqual(sample["cpu_state"], EvidenceState.OBSERVED.value)
                self.assert_memory_fields(sample, memory_states, serialized=True)
                self.assertEqual(sample["clock_id"], clock_id)
                if clock_id is None:
                    self.assertIsNone(report)
                else:
                    self.assertEqual((report["scope"], report["provider_id"], report["phase"]),
                                     (plan["scope"], "meter", phase.value))
                    self.assertEqual(report["observation"]["state"], EvidenceState.OBSERVED.value)
                self.assertNotEqual(sample["meter_pid"], os.getpid())
                self.assertEqual(sample["meter_uid"], os.geteuid())
                self.assertEqual((sample["identity"]["device"], sample["identity"]["inode"]),
                                 (pinned.st_dev, pinned.st_ino))
                self.assertLessEqual(lower, sample["usage_usec"])
                self.assertLessEqual(sample["usage_usec"], upper)
                samples.append(sample)
            begin, end = samples
            self.assertEqual((begin["session"], begin["identity"]), (end["session"], end["identity"]))
            if clock_id is not None:
                self.assertLessEqual(begin["finished_ns"], end["started_ns"])
            self.assertFalse(os.get_inheritable(fd))

    def test_synthetic_delta_rejects_unpaired_and_regressed_samples(self):
        # These in-memory values check rejection independently of host clock support.
        run = RunBinding("fixture-run", "fixture-artifact", "fixture-clock", 0, 10)
        scope = EvidenceScope(run, "fixture-scope", 0, 10)
        begin = CgroupSample(
            scope=scope, provider_id="meter", phase=ScopePhase.METER_BEGIN,
            identity=CgroupIdentity(1, 2, 3), session="fixture-session", meter_pid=4, meter_uid=5,
            clock_id=run.clock_id, started_ns=1, finished_ns=2, usage_usec=60,
            cpu_state=EvidenceState.OBSERVED, populated=None,
            population_state=EvidenceState.UNAVAILABLE, reasons=(),
        )
        end = replace(begin, phase=ScopePhase.METER_END, started_ns=7, finished_ns=8, usage_usec=75)
        interval = (3, 6)
        self.assertEqual(cpu_delta_usec(begin, end, require_meter_for=interval), 15)
        for altered, message in (
            (replace(end, session="different-session"), "session does not match"),
            (replace(end, meter_uid=None), "invalid cgroup meter provenance"),
            (replace(end, identity=None), "invalid cgroup meter provenance"),
            (replace(end, usage_usec=59), "counter regressed"),
            (replace(end, usage_usec=1 << 64), "invalid CPU counters"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                cpu_delta_usec(begin, altered, require_meter_for=interval)

    def test_plain_directory_cannot_supply_cgroup_kernel_evidence(self):
        scope = self.scope(monotonic_clock_id())
        with TemporaryDirectory() as directory:
            Path(directory, "cpu.stat").write_text("usage_usec 41\n")
            Path(directory, "cgroup.events").write_text("populated 1\n")
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with self.assertRaises(ScopeMeterUnavailable):
                    with CgroupScopeMeter(scope=scope, provider_id="meter", directory_fd=fd):
                        self.fail("a plain directory accepted as cgroup v2")
                os.fstat(fd)
            finally:
                os.close(fd)
