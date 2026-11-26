"""Read-only Linux observations of one previously designated process, file and slot.

This is an observer-side library, NOT an authorization service. Neither a
sample nor a sequence of samples can be supplied as a CustodyReceipt.
"""

from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum
import os
import re
import select
import stat
from time import monotonic_ns
from uuid import uuid4

from .evidence import EvidenceObservation, EvidenceScope, EvidenceState, ScopePhase, ScopeReport
from .original import Identity, observe
from .workers import Worker


class ProcessState(str, Enum):
    LIVE = "live"
    EXITED = "exit_observed"  # not wait/reap or whole-group exit
    UNKNOWN = "unknown"


class Match(str, Enum):
    ORIGINAL = "original"
    OTHER = "other"
    ABSENT = "absent"
    UNKNOWN = "unknown"
    NOT_REQUESTED = "not_requested"


@dataclass(frozen=True, slots=True)
class Sample:
    scope: str
    session: str
    observer_pid: int
    observer_uid: int
    boot_id: str | None
    time_namespace: str | None
    original: Identity
    reference_flags: int
    worker_pid: int
    expected_worker_uid: int
    sampled_worker_uids: tuple[int, ...] | None
    slot: int
    started_ns: int
    finished_ns: int
    process: ProcessState
    slot_match: Match
    flags: int | None
    name_match: Match
    reasons: tuple[str, ...]


def _fields(path):
    with open(path, "rb") as source:
        return dict(line.split(b":", 1) for line in source if b":" in line)


def _ident(st):
    return Identity(st.st_dev, st.st_ino)


def _context(read):
    try:
        return read()
    except OSError:
        return None  # never use an invented boot or time namespace


def _boot():
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as source:
        return source.read().strip()


def _clock_context():
    return _context(_boot), _context(lambda: os.readlink("/proc/thread-self/ns/time"))


def monotonic_clock_id(boot_id: str | None, time_namespace: str | None) -> str | None:
    """Describe the Linux monotonic clock when both kernel identifiers are known."""
    if any(type(value) is not str or not value.strip() for value in (boot_id, time_namespace)):
        return None
    return f"linux-monotonic:{boot_id}:{time_namespace}"


def _scope_observation(sample, subject):
    expired = "expired" in sample.reasons
    if subject == "process":
        process = sample.process
        if expired:
            state = EvidenceState.UNAVAILABLE
        elif process is ProcessState.UNKNOWN:
            state = EvidenceState.INDETERMINATE
        else:
            state = EvidenceState.OBSERVED
        return EvidenceObservation(subject, state, process.value)

    if subject == "slot":
        match = sample.slot_match
        unavailable = any(reason.startswith("slot_errno:") or reason in (
            "kernel_metadata_unavailable", "leader_file_table_unavailable",
        ) for reason in sample.reasons)
    else:
        match = sample.name_match
        unavailable = any(reason.startswith("name_errno:") for reason in sample.reasons)
    state = {
        Match.ORIGINAL: EvidenceState.OBSERVED,
        Match.OTHER: EvidenceState.INDETERMINATE,
        Match.ABSENT: EvidenceState.CONFIRMED_ABSENT,
        Match.UNKNOWN: EvidenceState.UNAVAILABLE if expired or unavailable else EvidenceState.INDETERMINATE,
        Match.NOT_REQUESTED: EvidenceState.NOT_REQUESTED,
    }[match]
    return EvidenceObservation(subject, state, match.value)


def _duplicate(stack, fd):
    if type(fd) is not int or fd < 0:
        raise ValueError("expected a borrowed descriptor")
    held = os.dup(fd)  # CLOEXEC; no change to caller's handle
    stack.callback(os.close, held)
    return held


class RegularFileObserver:
    """One serially driven observation session. No scan, signal, reopen or content read.

    All scope inputs must come from the observer's trusted controller, not
    the worker being measured. pidfd and non-inheritable, preheld O_PATH or read-only original
    are borrowed at bind and privately duplicated. Optional directory and leaf are bound together.
    The deadline applies to observation only and grants no release authority.
    Same-UID diagnostics are allowed but do not establish independence.
    """

    def __init__(self, *, scope, due_ns, original_fd, identity, pidfd, worker,
                 slot, directory_fd=None, leaf=None, evidence_scope: EvidenceScope | None = None):
        if type(scope) is not str or not re.fullmatch("[0-9a-f]{64}", scope):
            raise ValueError("expected the trusted plan's SHA-256 scope")
        if evidence_scope is not None and (
            type(evidence_scope) is not EvidenceScope or evidence_scope.scope_id != scope
        ):
            raise ValueError("evidence scope must match the trusted plan's scope")
        if type(due_ns) is not int or not monotonic_ns() < due_ns < 1 << 63:
            raise ValueError("expected a future absolute monotonic deadline")
        if type(identity) is not Identity or type(worker) is not Worker or worker.uid is None:
            raise ValueError("expected an exact identity and a PID/UID-pinned worker")
        if type(slot) is not int or slot < 0:
            raise ValueError("expected a prebound descriptor number")
        if (directory_fd is None) != (leaf is None) or (leaf is not None and
                (type(leaf) is not str or not leaf or leaf in (".", "..")
                 or "/" in leaf or "\x00" in leaf)):
            raise ValueError("bind directory and one relative leaf together")
        with ExitStack() as owned:
            if type(original_fd) is not int or original_fd < 0 or os.get_inheritable(original_fd):
                raise ValueError("expected a non-inheritable held reference")
            original = _duplicate(owned, original_fd)
            file = observe(original)
            if (file.identity != identity or not stat.S_ISREG(file.mode)
                    or (not file.flags & os.O_PATH and file.flags & os.O_ACCMODE != os.O_RDONLY)):
                raise ValueError("expected an exact O_PATH or read-only regular file")
            self._reference_flags = file.flags
            self._mount = int(_fields(f"/proc/self/fdinfo/{original}")[b"mnt_id"])
            self._pin = _duplicate(owned, pidfd)
            self._poll = select.poll()
            self._poll.register(self._pin, select.POLLIN)
            if (os.readlink(f"/proc/self/fd/{self._pin}") != "anon_inode:[pidfd]"
                    or int(_fields(f"/proc/self/fdinfo/{self._pin}")[b"Pid"]) != worker.pid
                    or self._poll.poll(0)):
                raise ValueError("expected a live, preheld pidfd for this process")
            self._directory = None if directory_fd is None else _duplicate(owned, directory_fd)
            if self._directory is not None and not stat.S_ISDIR(os.fstat(self._directory).st_mode):
                raise ValueError("expected a directory descriptor")
            self._scope, self._due, self._identity = scope, due_ns, identity
            self._evidence_scope = evidence_scope
            self._pid, self._uid, self._slot = worker.pid, worker.uid, slot
            self._leaf = leaf
            self._owner = os.getpid()
            self._observer_uids = os.getresuid()
            self._session = uuid4().hex
            self._boot, self._time_ns = _clock_context()
            self._owned = owned.pop_all()
        self._closed = False

    def close(self):
        self._closed = True
        self._owned.close()

    def __enter__(self):
        if self._closed:
            raise ValueError("closed observer")
        return self

    def __exit__(self, *_):
        self.close()

    def _uids(self):
        return tuple(map(int, _fields(f"/proc/{self._pid}/status")[b"Uid"].split()))

    def _leader_available(self):
        with open(f"/proc/{self._pid}/stat", "rb") as source:
            _, sep, fields = source.read().rpartition(b") ")
        if not sep or len(fields.split()) < 1:
            raise ValueError("missing task state")
        # A dead leader can leave a multithreaded group running with a proc
        # fd directory that *looks empty*. It is not a witnessed empty slot.
        return fields.split()[0] in (b"R", b"S", b"D", b"T", b"t", b"I", b"W", b"P")

    def _slot_sample(self):
        # Establish directory visibility separately. ENOENT opening the process's
        # fd directory is not the same as ENOENT for one known slot within it.
        base = f"/proc/{self._pid}"
        fd_dir = os.open(base + "/fd", os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
        try:
            leaf = str(self._slot)
            try:
                first = os.stat(leaf, dir_fd=fd_dir)
            except FileNotFoundError:
                # fdinfo must independently agree, in an accessible directory.
                info_dir = os.open(base + "/fdinfo", os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC)
                try:
                    try:
                        os.stat(leaf, dir_fd=info_dir, follow_symlinks=False)
                    except FileNotFoundError:
                        return Match.ABSENT, None, ()
                    return Match.UNKNOWN, None, ("slot_changed",)
                finally:
                    os.close(info_dir)
            info = _fields(base + "/fdinfo/" + leaf)
            last = os.stat(leaf, dir_fd=fd_dir)
        finally:
            os.close(fd_dir)
        first_id, last_id = _ident(first), _ident(last)
        if first_id != last_id or int(info[b"ino"]) != first_id.inode:
            return Match.UNKNOWN, None, ("slot_changed",)
        if first_id != self._identity or not stat.S_ISREG(first.st_mode):
            return Match.OTHER, None, ()
        if int(info[b"mnt_id"]) != self._mount:
            return Match.UNKNOWN, None, ("mount_mismatch",)
        # flags, mnt_id and ino come from one fdinfo record; this is not an
        # open-file-description ID or proof the slot stayed unchanged.
        return Match.ORIGINAL, int(info[b"flags"], 8), ()

    def _name_sample(self):
        if self._directory is None:
            return Match.NOT_REQUESTED, ()
        try:
            st = os.stat(self._leaf, dir_fd=self._directory, follow_symlinks=False)
        except FileNotFoundError:
            return Match.ABSENT, ()
        except OSError as exc:
            return Match.UNKNOWN, (f"name_errno:{exc.errno}",)
        return (Match.ORIGINAL if _ident(st) == self._identity else Match.OTHER), ()

    def _process(self):
        events = self._poll.poll(0)
        if not events:
            return ProcessState.LIVE
        flags = events[0][1]
        if flags & (select.POLLERR | select.POLLNVAL):
            return ProcessState.UNKNOWN
        return ProcessState.EXITED if flags & (select.POLLIN | select.POLLHUP) else ProcessState.UNKNOWN

    def sample_for_scope(
        self, scope: EvidenceScope, *, provider_id: str, subject: str = "slot",
    ) -> tuple[Sample, ScopeReport]:
        """Return the raw sample and a bound report about slot, name, or process.

        The complete EvidenceScope must have been supplied at construction.
        Refuse a different scope, an unavailable or mismatched clock, or an
        interval outside the declared window. Slot and name reports describe
        the prebound original, with a different object reported as
        indeterminate. Process reports describe pidfd liveness.
        """
        if type(scope) is not EvidenceScope or scope != self._evidence_scope:
            raise ValueError("expected the observer's predeclared evidence scope")
        if type(provider_id) is not str or not provider_id.strip():
            raise ValueError("provider_id must be a nonempty string")
        if type(subject) is not str or subject not in ("slot", "name", "process"):
            raise ValueError("expected an observation subject of slot, name, or process")
        clock = scope.run.clock_id
        if (monotonic_clock_id(self._boot, self._time_ns) != clock
                or monotonic_clock_id(*_clock_context()) != clock):
            raise ValueError("observer monotonic clock is unavailable or does not match scope")
        if not scope.started_ns <= monotonic_ns() <= scope.finished_ns:
            raise ValueError("observation is outside the scope window")
        raw = self.sample()
        if monotonic_clock_id(*_clock_context()) != clock:
            raise ValueError("observer monotonic clock became unavailable or changed during sampling")
        return raw, ScopeReport(
            scope, provider_id, ScopePhase.OBSERVATION, raw.started_ns, raw.finished_ns,
            _scope_observation(raw, subject),
        )

    def sample(self):
        if self._closed or os.getpid() != self._owner or os.getresuid() != self._observer_uids:
            raise ValueError("observer closed or process credentials changed")
        start = monotonic_ns()
        process, slot, flags, name, reasons = ProcessState.UNKNOWN, Match.UNKNOWN, None, Match.UNKNOWN, ()
        uids = None
        if start < self._due:
            try:
                process = self._process()
                if process == ProcessState.LIVE:
                    first_uids = self._uids()
                    if first_uids != (self._uid,) * 4:
                        uids = first_uids  # diagnostic mismatch, not an identity confirmation
                        reasons += ("worker_uid_mismatch",)
                        process = ProcessState.UNKNOWN
                    elif not self._leader_available():
                        reasons += ("leader_file_table_unavailable",)
                    else:
                        slot, flags, reasons = self._slot_sample()
                        if not self._leader_available():
                            slot, flags = Match.UNKNOWN, None
                            reasons += ("leader_file_table_unavailable",)
                        if self._uids() != first_uids:
                            slot, flags, process = Match.UNKNOWN, None, ProcessState.UNKNOWN
                            reasons += ("worker_uid_changed",)
                        else:
                            uids = first_uids
            except OSError as exc:
                slot, flags, reasons = Match.UNKNOWN, None, (f"slot_errno:{exc.errno}",)
            except (KeyError, ValueError):
                slot, flags, reasons = Match.UNKNOWN, None, ("kernel_metadata_unavailable",)
            after = self._process()
            if after != ProcessState.LIVE:
                process = after
                slot, flags = Match.UNKNOWN, None  # a dead target is not a known empty slot
                reasons += ("worker_not_live",)
            name, why = self._name_sample()
            reasons += why
        end = monotonic_ns()
        if end >= self._due:
            uids = None
            process, slot, flags, name, reasons = ProcessState.UNKNOWN, Match.UNKNOWN, None, Match.UNKNOWN, ("expired",)
        return Sample(self._scope, self._session, self._owner, self._observer_uids[0], self._boot,
                      self._time_ns, self._identity, self._reference_flags, self._pid, self._uid, uids, self._slot,
                      start, end, process, slot, flags, name, reasons)
