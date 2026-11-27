"""An authorized, one-shot inherited FD release with optional supervision and custody."""

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum
import fcntl
from hashlib import sha256
import json
import os
from threading import Event

from .custody import CustodyReceipt, IndependentCustody, require_custody
from .original import HandoffError, Identity, _before, _check, _require
from .supervisor import (
    CleanupResult, CleanupStatus, DirectChildSupervisor, LifecycleStatus,
    SupervisionResult, SupervisionStartError,
)
from .workers import Worker, WorkerRoster, _exec_context


class DeliveryStatus(str, Enum):
    NOT_ATTEMPTED = "not-attempted"
    DISPATCHED = "dispatched"
    UNKNOWN = "unknown"


class EffectStatus(str, Enum):
    NOT_ATTEMPTED = "not-attempted"
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PositionalWrite:
    offset: int
    data: bytes

    def __post_init__(self):
        if (type(self.data) is not bytes or not self.data
                or type(self.offset) is not int
                or not 0 <= self.offset <= (1 << 63) - 1 - len(self.data)):
            raise ValueError("expected nonempty bytes within a signed 64-bit positional range")


@dataclass(frozen=True, slots=True)
class ReleasePlan:
    name: str
    role: str
    argv: tuple[str, ...]
    identity: Identity
    due_ns: int
    write: PositionalWrite | None = None
    exclusive_writer: bool = False

    def __post_init__(self):
        if any(type(value) is not str or not value.strip() or "\x00" in value
               for value in (self.name, self.role)):
            raise ValueError("expected a worker name and role")
        if (type(self.argv) is not tuple or not self.argv
                or any(type(arg) is not str or "\x00" in arg for arg in self.argv)
                or not os.path.isabs(self.argv[0])):
            raise ValueError("expected argv with an absolute executable path")
        if type(self.identity) is not Identity:
            raise TypeError("expected the authorized original identity")
        if type(self.due_ns) is not int or not 0 < self.due_ns < 1 << 63:
            raise ValueError("expected an absolute monotonic deadline")
        if self.write is not None and type(self.write) is not PositionalWrite:
            raise TypeError("expected a PositionalWrite")
        if type(self.exclusive_writer) is not bool or (self.exclusive_writer and self.write is None):
            raise ValueError("writer exclusion requires a positional write")

    @property
    def custody_scope(self) -> str:
        """Digest of the immutable plan, including the content hash of any write."""
        write = self.write
        canonical = json.dumps([
            "worker-handoff/executable-input/v1", self.name, self.role, self.argv,
            self.identity.device, self.identity.inode, self.due_ns,
            None if write is None else [write.offset, len(write.data), sha256(write.data).hexdigest()],
            self.exclusive_writer,
        ], separators=(",", ":"), ensure_ascii=True)
        return sha256(canonical.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    delivery: DeliveryStatus
    effect: EffectStatus
    bytes_written: int | None
    custody: CustodyReceipt | None
    worker: Worker | None
    lifecycle: SupervisionResult | None
    cleanup: tuple[str, ...]
    error: str | None


_WRITE_MODES = (os.O_WRONLY, os.O_RDWR)


def _check_writer(fd, identity):
    sample = _check(fd, identity, _WRITE_MODES)
    _require(sample.owner_uid == os.getuid() == os.geteuid(),
             "writer must own the original under its actual Linux UID")
    _require(not (sample.flags & os.O_APPEND), "positional writes refuse O_APPEND")


def _owned_fd(stack, cleanup, fd):
    def close():
        try:
            os.close(fd)
        except OSError as exc:
            cleanup.append(f"close staged descriptor {fd}: {exc}")

    stack.callback(close)
    return fd


def _require_active(plan, cancel):
    _before(plan.due_ns)
    _require(cancel is None or not cancel.is_set(), "release cancelled before dispatch")


def release_executable(
    plan: ReleasePlan, *,
    input_fd: int,
    authorize: Callable[[ReleasePlan], bool],
    writer_fd: int | None = None,
    supervisor: DirectChildSupervisor | None = None,
    strict_custody: bool = False,
    custody: IndependentCustody | None = None,
    cancel: Event | None = None,
    cleanup_due_ns: int | None = None,
) -> ReleaseResult:
    """Stage and release the exact read-only INPUT to one authorized executable.

    The policy callback must explicitly approve the immutable plan. The caller
    retains its source descriptors and must keep them stable throughout this call.
    The child receives a fixed environment consisting of the inherited FD ABI.
    Supervisors are driven by one supervising caller. Authorizers must avoid
    re-entering this release or driving that supervisor.

    Supplying custody or setting strict_custody requires independent evidence.
    A short or uncertain write ends the operation before dispatch. An uncertain
    dispatch is never repeated. Callers must reconcile either outcome themselves.
    """
    if type(plan) is not ReleasePlan or not callable(authorize):
        raise TypeError("expected a release plan and an authorization policy")
    if supervisor is not None and type(supervisor) is not DirectChildSupervisor:
        raise TypeError("expected a DirectChildSupervisor")
    if type(strict_custody) is not bool or (cancel is not None and not isinstance(cancel, Event)):
        raise TypeError("expected a strict custody flag and optional threading.Event")
    if cleanup_due_ns is not None and (
        supervisor is None or type(cleanup_due_ns) is not int or not 0 < cleanup_due_ns < 1 << 63
    ):
        raise ValueError("a cleanup deadline requires supervision and a monotonic timestamp")

    delivery = DeliveryStatus.NOT_ATTEMPTED
    effect = EffectStatus.NOT_ATTEMPTED
    count = receipt = worker = lifecycle = error = None
    cleanup = []
    launcher = WorkerRoster() if supervisor is None else supervisor

    try:
        _require_active(plan, cancel)
        try:
            authorized = authorize(plan)
        except Exception as exc:
            raise HandoffError("release authorization could not be evaluated") from exc
        _require(authorized is True, "release authorization refused")
        _require((plan.write is None) == (writer_fd is None),
                 "a writer descriptor and a positional write must be supplied together")
        if supervisor is not None:
            supervisor.check_available(plan.name, plan.role)

        with ExitStack() as stack:
            _check(input_fd, plan.identity, (os.O_RDONLY,))
            reader = _owned_fd(stack, cleanup, fcntl.fcntl(input_fd, fcntl.F_DUPFD_CLOEXEC, 3))
            _check(reader, plan.identity, (os.O_RDONLY,))
            bindings = {"INPUT": reader}
            _exec_context(plan.name, plan.role, plan.argv, bindings, plan.due_ns, {})

            if plan.write is not None:
                _check_writer(writer_fd, plan.identity)
                writer = _owned_fd(stack, cleanup, fcntl.fcntl(writer_fd, fcntl.F_DUPFD_CLOEXEC, 3))
                _check_writer(writer, plan.identity)

            _require_active(plan, cancel)
            if strict_custody or custody is not None:
                receipt = require_custody(
                    custody, identity=plan.identity,
                    operation="write-and-inherit-input" if plan.write is not None else "inherit-input",
                    scope=plan.custody_scope, due_ns=plan.due_ns,
                )

            if plan.write is not None:
                if plan.exclusive_writer:
                    # A fresh open description prevents taking or releasing a caller's
                    # existing flock. The pinned FD selects the actual original.
                    _check_writer(writer, plan.identity)
                    locked = _owned_fd(stack, cleanup, os.open(
                        f"/proc/self/fd/{writer}", os.O_WRONLY | os.O_CLOEXEC,
                    ))
                    _check_writer(locked, plan.identity)
                    fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    writer = locked
                _check_writer(writer, plan.identity)
                _require_active(plan, cancel)
                effect = EffectStatus.UNKNOWN
                count = os.pwrite(writer, plan.write.data, plan.write.offset)
                effect = EffectStatus.COMPLETE if count == len(plan.write.data) else EffectStatus.PARTIAL
                _require(effect is EffectStatus.COMPLETE, "short positional write; release stopped")

            _check(reader, plan.identity, (os.O_RDONLY,))
            _require_active(plan, cancel)
            delivery = DeliveryStatus.UNKNOWN
            worker = launcher.start_executable(
                plan.name, plan.role, plan.argv, due_ns=plan.due_ns, fds=bindings, env={},
            )
            delivery = DeliveryStatus.DISPATCHED
    except SupervisionStartError as exc:
        # Popen returned, so the child already inherited the descriptor. Its
        # owner gets the real handle back for reconciliation, without a relaunch.
        delivery = DeliveryStatus.DISPATCHED
        worker = Worker(plan.name, plan.role, exc.process.pid, process=exc.process)
        lifecycle = SupervisionResult(
            LifecycleStatus.UNKNOWN, CleanupResult(CleanupStatus.UNKNOWN), error=exc.__cause__,
        )
        error = str(exc)
    except (ValueError, OSError, RuntimeError) as exc:
        error = str(exc)

    if worker is not None and supervisor is not None and lifecycle is None:
        try:
            lifecycle = supervisor.wait(
                plan.name, due_ns=plan.due_ns, cancel=cancel, cleanup_due_ns=cleanup_due_ns,
            )
        except OSError as exc:
            lifecycle = SupervisionResult(
                LifecycleStatus.UNKNOWN, CleanupResult(CleanupStatus.UNKNOWN), error=exc,
            )
            error = str(exc)
        except (ValueError, RuntimeError) as exc:
            lifecycle = SupervisionResult(LifecycleStatus.UNKNOWN, CleanupResult(CleanupStatus.UNKNOWN))
            error = str(exc)

    return ReleaseResult(delivery, effect, count, receipt, worker, lifecycle, tuple(cleanup), error)
