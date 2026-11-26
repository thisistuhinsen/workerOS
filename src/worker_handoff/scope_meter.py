"""Read aggregate measurements from one caller-supplied Linux cgroup v2."""

from contextlib import ExitStack
from dataclasses import asdict, dataclass
import json
import os
import stat
import sys
from time import monotonic_ns
from uuid import uuid4

from .evidence import (
    EvidenceObservation, EvidenceScope, EvidenceState, RunBinding, ScopePhase,
    ScopeReport, validate_scope_evidence,
)
from .lifecycle import _clock_context, _duplicate, _fields, monotonic_clock_id as _clock_id


_MAX_COUNTER = (1 << 64) - 1


class ScopeMeterUnavailable(RuntimeError):
    """The requested read-only cgroup kernel interface cannot be established."""


def monotonic_clock_id() -> str | None:
    """Return this thread's Linux monotonic clock context, if available."""
    return _clock_id(*_clock_context())


@dataclass(frozen=True, slots=True)
class CgroupIdentity:
    """Identity of the pinned directory on the meter's visible mount."""

    device: int
    inode: int
    mount_id: int


@dataclass(frozen=True, slots=True)
class CgroupSample:
    """CPU microseconds, memory bytes and a population point, with provenance."""

    scope: EvidenceScope
    provider_id: str
    phase: ScopePhase
    identity: CgroupIdentity
    session: str
    meter_pid: int
    meter_uid: int
    clock_id: str | None
    started_ns: int
    finished_ns: int
    usage_usec: int | None
    cpu_state: EvidenceState
    populated: bool | None
    population_state: EvidenceState
    reasons: tuple[str, ...]
    memory_current_bytes: int | None = None
    memory_current_state: EvidenceState = EvidenceState.UNAVAILABLE
    memory_peak_bytes: int | None = None
    memory_peak_state: EvidenceState = EvidenceState.UNAVAILABLE

    @property
    def report(self) -> ScopeReport | None:
        """Project the CPU reading into the declared scope when its time is attributable."""
        if (self.clock_id != self.scope.run.clock_id or not
                self.scope.started_ns <= self.started_ns <= self.finished_ns <= self.scope.finished_ns):
            return None
        return ScopeReport(
            self.scope, self.provider_id, self.phase, self.started_ns, self.finished_ns,
            EvidenceObservation("cgroup-v2-cpu-usage", self.cpu_state),
        )


def _provenance(sample):
    identity = sample.identity
    if (type(identity) is not CgroupIdentity or type(identity.device) is not int or identity.device < 0
            or type(identity.inode) is not int or identity.inode <= 0
            or type(identity.mount_id) is not int or identity.mount_id <= 0
            or type(sample.session) is not str or not sample.session.strip()
            or type(sample.meter_pid) is not int or sample.meter_pid <= 0
            or type(sample.meter_uid) is not int or sample.meter_uid < 0
            or type(sample.scope) is not EvidenceScope):
        raise ValueError("invalid cgroup meter provenance")
    return sample.scope, sample.provider_id, identity, sample.session, sample.meter_pid, sample.meter_uid


def cpu_delta_usec(begin: CgroupSample, end: CgroupSample, *, require_meter_for: tuple[int, int]) -> int:
    """Return the bracketed aggregate delta for one pinned meter session.

    The caller supplies the actual interval through observed cleanup and
    establishes which activity the cgroup contained. Preserve the raw samples
    for CPU and population provenance.
    """
    if (type(begin) is not CgroupSample or type(end) is not CgroupSample
            or begin.phase is not ScopePhase.METER_BEGIN or end.phase is not ScopePhase.METER_END):
        raise ValueError("expected cgroup begin and end samples")
    if _provenance(begin) != _provenance(end):
        raise ValueError("cgroup scope or meter session does not match")
    if require_meter_for is None:
        raise ValueError("expected an interval to bracket")
    reports = begin.report, end.report
    if None in reports or begin.clock_id != end.clock_id:
        raise ValueError("meter samples lack a common bound clock or scope window")
    validate_scope_evidence(begin.scope, reports, observer_id=begin.provider_id,
                            meter_id=begin.provider_id, require_meter_for=require_meter_for)
    if any(type(value) is not int or not 0 <= value <= _MAX_COUNTER
           for value in (begin.usage_usec, end.usage_usec)):
        raise ValueError("missing or invalid CPU counters")
    if end.usage_usec < begin.usage_usec:
        raise ValueError("CPU counter regressed")
    return end.usage_usec - begin.usage_usec


def _mount_id(fd):
    return int(_fields(f"/proc/self/fdinfo/{fd}")[b"mnt_id"])


def _cgroup_mount(mount_id):
    with open("/proc/self/mountinfo", "rb") as mounts:
        for row in mounts:
            fields, separator, filesystem = row.partition(b" - ")
            if separator and fields.split()[0] == str(mount_id).encode("ascii"):
                return filesystem.split()[0] == b"cgroup2"
    return False


def _unsigned(value, maximum):
    if not 0 < len(value) <= 20 or not value.isdigit() or int(value) > maximum:
        raise ValueError("invalid unsigned kernel value")
    return int(value)


def _counter(data, key, maximum):
    if key is None:
        return _unsigned(data.strip(), maximum)
    rows = [row.split() for row in data.splitlines()]
    matches = [row for row in rows if row and row[0] == key]
    if len(matches) == 1 and len(matches[0]) == 2:
        return _unsigned(matches[0][1], maximum)
    raise ValueError("counter missing, duplicated, or invalid")


class CgroupScopeMeter:
    """Borrow a directory FD and read fixed CPU, memory and population files.

    Use one serial meter instance for both readings. The caller provisions and
    verifies workload membership and who controls the scope. CPU usage is
    aggregate. Memory and population are separate readings, possibly unavailable
    at the hierarchy root. The meter only reads the historic memory peak. None
    of these results supplies a cleanup receipt.
    """

    def __init__(self, *, scope, provider_id, directory_fd):
        if type(scope) is not EvidenceScope or type(provider_id) is not str or not provider_id.strip():
            raise ValueError("expected a declared EvidenceScope and provider ID")
        if type(directory_fd) is not int or directory_fd < 0 or os.get_inheritable(directory_fd):
            raise ValueError("expected a non-inheritable cgroup directory descriptor")
        clock = monotonic_clock_id()
        if clock is not None and scope.run.clock_id != clock:
            raise ValueError("declared scope uses a different clock context")
        with ExitStack() as owned:
            fd = _duplicate(owned, directory_fd)
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("expected a directory descriptor")
            try:
                mount = _mount_id(fd)
                if not _cgroup_mount(mount):
                    raise ScopeMeterUnavailable("directory is not on a visible cgroup v2 mount")
            except (OSError, KeyError, ValueError) as exc:
                raise ScopeMeterUnavailable("cgroup v2 mount context is unavailable") from exc
            self._identity = CgroupIdentity(info.st_dev, info.st_ino, mount)
            self._directory = fd
            self._owned = owned.pop_all()
        self._scope, self._provider_id, self._clock = scope, provider_id, clock
        self._session, self._pid, self._uids = uuid4().hex, os.getpid(), os.getresuid()
        self._closed = False

    def close(self):
        self._closed = True
        self._owned.close()

    def __enter__(self):
        if self._closed:
            raise ValueError("closed scope meter")
        return self

    def __exit__(self, *_):
        self.close()

    def _read(self, leaf, key=None, maximum=_MAX_COUNTER):
        try:
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(leaf, flags, dir_fd=self._directory)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(fd).st_mode) or _mount_id(fd) != self._identity.mount_id:
                    raise ValueError("unexpected cgroup metric handle")
                data = stream.read(65537)
            if len(data) > 65536:
                raise ValueError("cgroup metric exceeded read limit")
            return _counter(data, key, maximum), EvidenceState.OBSERVED, ()
        except OSError as exc:
            return None, EvidenceState.UNAVAILABLE, (f"{leaf}_errno:{exc.errno}",)
        except (KeyError, ValueError):
            return None, EvidenceState.INDETERMINATE, (f"{leaf}_invalid",)

    def sample(self, phase: ScopePhase) -> CgroupSample:
        if self._closed or os.getpid() != self._pid or os.getresuid() != self._uids:
            raise ValueError("scope meter closed or process credentials changed")
        if type(phase) is not ScopePhase or phase is ScopePhase.OBSERVATION:
            raise ValueError("expected a begin or end meter phase")
        clock = monotonic_clock_id()
        start = monotonic_ns()
        usage = population = memory_current = memory_peak = None
        cpu_state = population_state = current_state = peak_state = EvidenceState.INDETERMINATE
        reasons = ()
        if clock == self._clock and self._scope.started_ns <= start <= self._scope.finished_ns:
            usage, cpu_state, cpu_reasons = self._read("cpu.stat", b"usage_usec")
            population, population_state, population_reasons = self._read("cgroup.events", b"populated", 1)
            memory_current, current_state, current_reasons = self._read("memory.current")
            memory_peak, peak_state, peak_reasons = self._read("memory.peak")
            reasons = cpu_reasons + population_reasons + current_reasons + peak_reasons
        clock_changed = clock != self._clock or monotonic_clock_id() != self._clock
        finish = monotonic_ns()
        if clock_changed:
            clock = None
            reasons += ("clock_context_changed",)
        elif clock is None:
            reasons += ("clock_context_unavailable",)
        bounded = self._scope.started_ns <= start <= finish <= self._scope.finished_ns
        if not bounded:
            reasons += ("sample_outside_scope_window",)
        if clock_changed or not bounded:
            usage = population = memory_current = memory_peak = None
            cpu_state = population_state = current_state = peak_state = EvidenceState.INDETERMINATE
        return CgroupSample(
            self._scope, self._provider_id, phase, self._identity, self._session,
            self._pid, self._uids[1], clock, start, finish, usage, cpu_state,
            None if population is None else bool(population), population_state, reasons,
            memory_current_bytes=memory_current, memory_current_state=current_state,
            memory_peak_bytes=memory_peak, memory_peak_state=peak_state,
        )


def main():
    """Serve two explicit phases over stdin on a separately launched worker."""
    plan = json.loads(sys.stdin.readline())
    scope_data = plan["scope"]
    scope = EvidenceScope(**{**scope_data, "run": RunBinding(**scope_data["run"])})
    fd = plan["directory_fd"]
    if type(fd) is not int or fd < 3:
        raise ValueError("expected an explicitly inherited non-standard directory FD")
    os.set_inheritable(fd, False)
    with CgroupScopeMeter(scope=scope, provider_id=plan["provider_id"], directory_fd=fd) as meter:
        for phase in (ScopePhase.METER_BEGIN, ScopePhase.METER_END):
            request = sys.stdin.readline()
            if not request:
                raise ValueError(f"missing {phase.value} request")
            if json.loads(request) != phase.value:
                raise ValueError(f"expected {phase.value}")
            reading = meter.sample(phase)
            report = reading.report
            print(json.dumps({"sample": asdict(reading), "scope_report": asdict(report) if report else None}),
                  flush=True)


if __name__ == "__main__":
    main()
