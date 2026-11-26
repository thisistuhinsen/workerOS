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
    """Opaque identities and caller-supplied clock window for one execution.

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
    require_terminal: bool = False,
) -> tuple[RunEvent, ...]:
    """Return the original valid event tuple or raise ValueError.

    Sequence numbers start at one. Intervals must be ordered and may touch.
    Each required pair needs an OBSERVED report from that source for that
    subject. This is historical coverage. Terminal coverage requires a
    consistent exit code and an explicit REAPED report for this execution.
    A nonzero exit can satisfy that coverage. The caller keeps the raw
    receipts for any source-specific details beyond this projection.
    """
    if type(binding) is not RunBinding or type(events) is not tuple:
        raise ValueError("expected a RunBinding and tuple of run events")
    if type(require_observed) is not tuple or type(require_terminal) is not bool:
        raise ValueError("expected a tuple of required pairs and a bool terminal flag")
    missing = set()
    for pair in require_observed:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("expected a (source_id, subject) pair")
        _identifier(pair[0], "required source_id")
        _identifier(pair[1], "required subject")
        missing.add(pair)

    previous_finish = binding.started_ns
    code, reaped = None, False
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
        reaped = reaped or event.cleanup is CleanupStatus.REAPED
        for point in event.observations:
            if point.state is EvidenceState.OBSERVED:
                missing.discard((event.source_id, point.subject))
    if missing:
        raise ValueError(f"missing required observations: {sorted(missing)!r}")
    if require_terminal and (code is None or not reaped):
        raise ValueError("terminal coverage requires an exit code and explicit reap")
    return events
