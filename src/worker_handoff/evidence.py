"""Optional structural validation of reported evidence for one execution.

The caller supplies the run, artifact, sources, and comparable clock domain.
Use separate observation subjects for transport exposure, effects, receipt,
and any other measured facts. Validation checks the shape and consistency of
the reports. Source trust and any decision to act remain with the caller.
"""

from dataclasses import dataclass
from enum import Enum

from .supervisor import CleanupResult, CleanupStatus, LifecycleStatus, SupervisionResult


class EvidenceState(str, Enum):
    """State of one reported observation, including intentional omission."""

    OBSERVED = "observed"
    CONFIRMED_ABSENT = "confirmed_absent"
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"
    NOT_REQUESTED = "not_requested"


class ScopePhase(str, Enum):
    """Role of a provider report in a declared execution scope."""

    OBSERVATION = "observation"
    METER_BEGIN = "meter_begin"
    METER_END = "meter_end"


def _identifier(value, field):
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")


def _interval(started_ns, finished_ns):
    if (type(started_ns) is not int or type(finished_ns) is not int
            or not 0 <= started_ns <= finished_ns < 1 << 63):
        raise ValueError("expected a bounded nanosecond interval")


def _returncode(value):
    if value is not None and type(value) is not int:
        raise ValueError("returncode must be an integer or None")


@dataclass(frozen=True, slots=True)
class RunBinding:
    """Opaque identities and caller-supplied clock window for one bound child.

    Use a separate binding for each child execution.
    Assign a clock ID only when timestamps in that domain are comparable.
    """

    run_id: str
    artifact_id: str
    clock_id: str
    started_ns: int
    finished_ns: int

    def __post_init__(self):
        _identifier(self.run_id, "run_id")
        _identifier(self.artifact_id, "artifact_id")
        _identifier(self.clock_id, "clock_id")
        _interval(self.started_ns, self.finished_ns)


@dataclass(frozen=True, slots=True)
class EvidenceObservation:
    """One named point observation as reported by the event's source."""

    subject: str
    state: EvidenceState
    detail: str | None = None

    def __post_init__(self):
        _identifier(self.subject, "subject")
        if type(self.state) is not EvidenceState:
            raise ValueError("expected an EvidenceState")
        if self.detail is not None and type(self.detail) is not str:
            raise ValueError("observation detail must be a string or None")


@dataclass(frozen=True, slots=True)
class EvidenceScope:
    """Caller-declared report window in the bound run's clock domain.

    The report window can extend before and after the child's run window.
    The caller assigns a fresh scope identity and declares what it covers.
    """

    run: RunBinding
    scope_id: str
    started_ns: int
    finished_ns: int

    def __post_init__(self):
        if type(self.run) is not RunBinding:
            raise ValueError("expected a RunBinding")
        _identifier(self.scope_id, "scope_id")
        _interval(self.started_ns, self.finished_ns)


@dataclass(frozen=True, slots=True)
class ScopeReport:
    """One point or meter endpoint supplied by a caller-selected provider."""

    scope: EvidenceScope
    provider_id: str
    phase: ScopePhase
    started_ns: int
    finished_ns: int
    observation: EvidenceObservation

    def __post_init__(self):
        if type(self.scope) is not EvidenceScope:
            raise ValueError("expected an EvidenceScope")
        _identifier(self.provider_id, "provider_id")
        if type(self.phase) is not ScopePhase:
            raise ValueError("expected a ScopePhase")
        _interval(self.started_ns, self.finished_ns)
        if not self.scope.started_ns <= self.started_ns <= self.finished_ns <= self.scope.finished_ns:
            raise ValueError("report interval is outside the scope window")
        if type(self.observation) is not EvidenceObservation:
            raise ValueError("expected an EvidenceObservation")


def validate_scope_evidence(
    scope: EvidenceScope,
    reports: tuple[ScopeReport, ...],
    *,
    observer_id: str,
    meter_id: str,
    require_meter_for: tuple[int, int] | None = None,
) -> tuple[ScopeReport, ...]:
    """Check provider bindings and optionally require a bracketing meter pair.

    The original tuple is returned, including unavailable or indeterminate
    reports. An omitted report stays missing. Tuple order is immaterial and
    point observations can overlap meter samples. Each meter phase can appear
    once, and the begin sample must finish by the start of the end sample.

    ``require_meter_for`` is the exact interval to bracket, including cleanup
    if required by the caller. Both endpoints must be OBSERVED, with the begin
    sample finished by the interval start and the end sample started at or
    after its finish. This checks reported timing and coverage only. Caller
    authentication, provider qualification, meter semantics, and decisions
    about cleanup or custody remain external.
    """
    if type(scope) is not EvidenceScope or type(reports) is not tuple:
        raise ValueError("expected an EvidenceScope and tuple of scope reports")
    _identifier(observer_id, "observer_id")
    _identifier(meter_id, "meter_id")
    endpoints = {}
    for report in reports:
        if type(report) is not ScopeReport or report.scope != scope:
            raise ValueError("report scope or run does not match")
        is_point = report.phase is ScopePhase.OBSERVATION
        if report.provider_id != (observer_id if is_point else meter_id):
            raise ValueError("report provider does not match its phase")
        if not is_point:
            if report.phase in endpoints:
                raise ValueError("duplicate meter phase")
            endpoints[report.phase] = report

    begin = endpoints.get(ScopePhase.METER_BEGIN)
    end = endpoints.get(ScopePhase.METER_END)
    if begin is not None and end is not None and begin.finished_ns > end.started_ns:
        raise ValueError("meter samples overlap or are out of order")
    if require_meter_for is not None:
        if type(require_meter_for) is not tuple or len(require_meter_for) != 2:
            raise ValueError("expected a required meter interval")
        started, finished = require_meter_for
        _interval(started, finished)
        if not scope.started_ns <= started <= finished <= scope.finished_ns:
            raise ValueError("required meter interval is outside the scope window")
        if (begin is None or end is None or begin.observation.state is not EvidenceState.OBSERVED
                or end.observation.state is not EvidenceState.OBSERVED):
            raise ValueError("meter coverage requires observed begin and end reports")
        if not begin.finished_ns <= started <= finished <= end.started_ns:
            raise ValueError("meter reports do not bracket the required interval")
    return reports


@dataclass(frozen=True, slots=True)
class RunEvent:
    """One source's report from a bounded interval, with independent facets.

    Multiple observations from one sample can share this interval. A
    lifecycle value describes the observed wait or process state, while a
    returncode and cleanup status capture separate facts.
    """

    binding: RunBinding
    source_id: str
    sequence: int
    started_ns: int
    finished_ns: int
    observations: tuple[EvidenceObservation, ...] = ()
    lifecycle: LifecycleStatus | None = None
    returncode: int | None = None
    cleanup: CleanupStatus | None = None

    def __post_init__(self):
        if type(self.binding) is not RunBinding:
            raise ValueError("expected a RunBinding")
        _identifier(self.source_id, "source_id")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        _interval(self.started_ns, self.finished_ns)
        if type(self.observations) is not tuple or any(
            type(point) is not EvidenceObservation for point in self.observations
        ):
            raise ValueError("expected a tuple of EvidenceObservation values")
        if len({point.subject for point in self.observations}) != len(self.observations):
            raise ValueError("an event can report a subject only once")
        if self.lifecycle is not None and type(self.lifecycle) is not LifecycleStatus:
            raise ValueError("expected a LifecycleStatus or None")
        _returncode(self.returncode)
        if self.cleanup is not None and type(self.cleanup) is not CleanupStatus:
            raise ValueError("expected a CleanupStatus or None")
        if self.lifecycle is LifecycleStatus.OBSERVED and (
            self.returncode is not None or self.cleanup is CleanupStatus.REAPED
        ):
            raise ValueError("an external observation cannot report an exit code or reap")
        if (not self.observations and self.lifecycle is None
                and self.returncode is None and self.cleanup is None):
            raise ValueError("an event must contain a reported fact")

    @classmethod
    def from_result(cls, binding, source_id, sequence, started_ns, finished_ns, result):
        """Copy status and returncode from a supervisor wait or cleanup result."""
        lifecycle, code = None, None
        cleanup = result
        if type(result) is SupervisionResult:
            lifecycle, code, cleanup = result.lifecycle, result.returncode, result.cleanup
            if type(lifecycle) is not LifecycleStatus:
                raise ValueError("expected a LifecycleStatus")
        if type(cleanup) is not CleanupResult or type(cleanup.status) is not CleanupStatus:
            raise ValueError("expected a SupervisionResult or CleanupResult")
        _returncode(code)
        _returncode(cleanup.returncode)
        if cleanup.returncode is not None:
            if cleanup.status is not CleanupStatus.REAPED:
                raise ValueError("a cleanup returncode requires a reported reap")
            if code is not None and code != cleanup.returncode:
                raise ValueError("conflicting supervisor returncodes")
            code = cleanup.returncode
        return cls(
            binding, source_id, sequence, started_ns, finished_ns,
            lifecycle=lifecycle, returncode=code, cleanup=cleanup.status,
        )


def validate_run_evidence(
    binding: RunBinding,
    events: tuple[RunEvent, ...],
    *,
    require_observed: tuple[tuple[str, str], ...] = (),
    require_terminal_from: str | None = None,
) -> tuple[RunEvent, ...]:
    """Return the original valid event tuple or raise ValueError.

    Sequence numbers start at one. Intervals must be ordered and may touch.
    Each required pair needs an OBSERVED report from that source for that
    subject. This is historical coverage. Set `require_terminal_from` to a
    source ID to require one event from that source reporting both an exit
    code and REAPED for this execution. A nonzero exit can satisfy that
    coverage. The application decides how to act on the process outcome.
    Keep raw receipts for source-specific details beyond this projection.
    """
    if type(binding) is not RunBinding or type(events) is not tuple:
        raise ValueError("expected a RunBinding and tuple of run events")
    if type(require_observed) is not tuple:
        raise ValueError("expected a tuple of required pairs")
    if require_terminal_from is not None:
        _identifier(require_terminal_from, "required terminal source_id")
    missing = set()
    for pair in require_observed:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("expected a (source_id, subject) pair")
        _identifier(pair[0], "required source_id")
        _identifier(pair[1], "required subject")
        missing.add(pair)

    previous_finish = binding.started_ns
    code, reaped, terminal_report = None, False, False
    for sequence, event in enumerate(events, 1):
        if type(event) is not RunEvent or event.binding != binding:
            raise ValueError("event run, artifact, clock, or window does not match")
        if event.sequence != sequence:
            raise ValueError("event sequence must be contiguous from one")
        if event.started_ns < previous_finish or event.finished_ns > binding.finished_ns:
            raise ValueError("event intervals overlap, are out of order, or exceed the run window")
        previous_finish = event.finished_ns
        if event.returncode is not None:
            if code is not None and code != event.returncode:
                raise ValueError("conflicting execution returncodes")
            code = event.returncode
        if reaped and event.cleanup is CleanupStatus.PENDING:
            raise ValueError("cleanup pending after a reported reap")
        if event.cleanup is CleanupStatus.REAPED:
            reaped = True
            if event.source_id == require_terminal_from and event.returncode is not None:
                terminal_report = True
        for point in event.observations:
            if point.state is EvidenceState.OBSERVED:
                missing.discard((event.source_id, point.subject))
    if missing:
        raise ValueError(f"missing required observations: {sorted(missing)!r}")
    if require_terminal_from is not None and not terminal_report:
        raise ValueError("terminal coverage requires one report with both an exit code and REAPED")
    return events
