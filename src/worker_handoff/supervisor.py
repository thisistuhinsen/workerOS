"""Opt-in supervision of direct Linux children through pinned process handles."""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from io import FileIO
import os
import signal
import subprocess
from threading import Event, Lock
from time import monotonic_ns, sleep

from .workers import Worker, _exec_context


class LifecycleStatus(str, Enum):
    EXITED = "exited"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OBSERVED = "observed"
    UNKNOWN = "unknown"


class CleanupStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    OUTSIDE_SCOPE = "outside_scope"
    REAPED = "reaped"
    PENDING = "pending"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CleanupResult:
    status: CleanupStatus
    returncode: int | None = None
    terminate_sent: bool = False
    kill_sent: bool = False
    error: OSError | None = None


@dataclass(frozen=True, slots=True)
class SupervisionResult:
    lifecycle: LifecycleStatus
    cleanup: CleanupResult
    returncode: int | None = None
    error: OSError | None = None


class SupervisionStartError(RuntimeError):
    """A child was started but could not be pinned. Its owner must reconcile it."""

    def __init__(self, process: subprocess.Popen):
        super().__init__("started child could not be pinned for supervision")
        self.process = process


@dataclass(slots=True)
class _Child:
    process: subprocess.Popen
    pin: FileIO | None
    returncode: int | None = None
    error: OSError | None = None

    def reap_if_exited(self):
        if self.pin is None:
            return
        try:
            event = os.waitid(os.P_PIDFD, self.pin.fileno(), os.WEXITED | os.WNOHANG)
        except OSError as exc:
            self.error = exc
        else:
            if event is None:
                return
            self.returncode = event.si_status if event.si_code == os.CLD_EXITED else -event.si_status
            self.process.returncode = self.returncode
        self.pin.close()
        self.pin = None


_POLL_INTERVAL_NS = 10_000_000
_TERM_GRACE_NS = 100_000_000


def _deadline(due_ns):
    if type(due_ns) is not int or not 0 < due_ns < 1 << 63:
        raise ValueError("expected an absolute monotonic deadline")


def _check_name(name, role):
    if any(type(value) is not str or not value.strip() or "\x00" in value for value in (name, role)):
        raise ValueError("name and role must be nonempty strings without NUL")


def _open_pin(pid):
    return os.fdopen(os.pidfd_open(pid), "rb", buffering=0)


def _check_host():
    if not (hasattr(os, "pidfd_open") and hasattr(os, "P_PIDFD")
            and hasattr(signal, "pidfd_send_signal")):
        raise RuntimeError("direct-child supervision requires Linux pidfd support")
    if signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN:
        raise RuntimeError("direct-child supervision requires waitable children")
    with _open_pin(os.getpid()) as pin:
        try:
            os.waitid(os.P_PIDFD, pin.fileno(), os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            pass  # P_PIDFD is supported and the caller is not its own child.


def _pin_child(process):
    pin = _open_pin(process.pid)
    try:
        os.waitid(os.P_PIDFD, pin.fileno(), os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except BaseException:
        pin.close()
        raise
    return _Child(process, pin)


def _wait(child, due_ns, cancel=None):
    while True:
        child.reap_if_exited()
        if child.pin is None:
            return LifecycleStatus.EXITED if child.error is None else LifecycleStatus.UNKNOWN
        if cancel is not None and cancel.is_set():
            return LifecycleStatus.CANCELLED
        remaining = due_ns - monotonic_ns()
        if remaining <= 0:
            return LifecycleStatus.TIMED_OUT
        interval = min(_POLL_INTERVAL_NS, remaining) / 1_000_000_000
        if cancel is None:
            sleep(interval)
        else:
            cancel.wait(interval)


def _send_signal(child, number):
    try:
        signal.pidfd_send_signal(child.pin.fileno(), number)
    except ProcessLookupError:
        return False  # The process can exit between the observation and signal.
    return True


def _cleanup(child, due_ns):
    child.reap_if_exited()
    terminate_sent = kill_sent = False
    error = None
    remaining = due_ns - monotonic_ns()
    try:
        if child.pin is not None and remaining > 0:
            terminate_sent = _send_signal(child, signal.SIGTERM)
            grace = monotonic_ns() + min(_TERM_GRACE_NS, remaining // 2)
            _wait(child, min(grace, due_ns))
            if child.pin is not None and monotonic_ns() < due_ns:
                kill_sent = _send_signal(child, signal.SIGKILL)
                _wait(child, due_ns)
    except OSError as exc:
        error = exc
        child.reap_if_exited()
    if child.returncode is not None:
        status = CleanupStatus.REAPED
    elif child.error is not None:
        status = CleanupStatus.UNKNOWN
    else:
        status = CleanupStatus.PENDING
    return CleanupResult(status, child.returncode, terminate_sent, kill_sent, child.error or error)


class DirectChildSupervisor:
    """Wait and stop explicitly owned direct children with Linux pidfds.

    One supervising caller drives an instance. Another thread may signal an
    Event supplied to wait(). A started or adopted child transfers wait and
    signal ownership to this supervisor and must have no competing waiters.
    Cleanup covers only the exact pinned child. Descendants and process groups
    require independent management by the application.
    """

    def __init__(self):
        self._owner = os.getpid()
        self._lock = Lock()
        self._workers = {}
        self._children = {}
        self._attempted = set()

    @contextmanager
    def _scope(self):
        if self._owner != os.getpid():
            raise RuntimeError("the supervisor belongs to its creating process")
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("the supervisor is already in use")
        try:
            yield
        finally:
            self._lock.release()

    def _check_available(self, name, role):
        _check_name(name, role)
        if name in self._workers or name in self._attempted:
            raise ValueError("duplicate worker name")

    def check_available(self, name, role):
        """Check launch naming and pidfd support without reserving a name."""
        with self._scope():
            self._check_available(name, role)
            _check_host()

    def external(self, name, role, *, pid, uid=None):
        """Record an endpoint from the caller's observation only."""
        with self._scope():
            self._check_available(name, role)
            worker = Worker(name, role, pid, uid)
            self._workers[name] = worker
            return worker

    def adopt(self, name, role, process, *, uid=None):
        """Accept explicit wait and signal authority over a live Popen handle.

        The caller must own the process handle and relinquish its wait/signal
        operations on success. An already observed worker must match all fields.
        """
        with self._scope():
            _check_name(name, role)
            if type(process) is not subprocess.Popen or process.returncode is not None:
                raise ValueError("expected a caller-owned, unreaped direct Popen child")
            worker = Worker(name, role, process.pid, uid)
            current = self._workers.get(name)
            if name in self._attempted or name in self._children or (current is not None and current != worker):
                raise ValueError("worker name is in use by a different registration")
            if any(child.process is process for child in self._children.values()):
                raise ValueError("process handle is already supervised")
            _check_host()
            self._children[name] = _pin_child(process)
            self._workers[name] = worker
            return worker

    def start_executable(self, name, role, argv, *, due_ns, fds=None, env=None, uid=None):
        """Launch a trusted argv with the existing inherited-FD ABI and pin it."""
        with self._scope():
            self._check_available(name, role)
            if uid is not None and (type(uid) is not int or uid < 0):
                raise ValueError("expected worker UID must be nonnegative")
            _check_host()
            handles, context = _exec_context(name, role, argv, fds, due_ns, env)
            self._attempted.add(name)
            process = subprocess.Popen(tuple(argv), shell=False, close_fds=True,
                                       pass_fds=handles, env=context)
            try:
                child = _pin_child(process)
            except OSError as exc:
                raise SupervisionStartError(process) from exc
            worker = Worker(name, role, process.pid, uid)
            self._children[name] = child
            self._workers[name] = worker
            return worker

    def wait(self, name, *, due_ns, cancel=None, cleanup_due_ns=None):
        """Wait until exit, the absolute deadline or a threading.Event cancellation.

        Explicit cleanup has its own deadline and runs only on timeout/cancel.
        Each status reports the corresponding observation or action separately.
        """
        _deadline(due_ns)
        if cancel is not None and not isinstance(cancel, Event):
            raise TypeError("cancel must be a threading.Event")
        if cleanup_due_ns is not None:
            _deadline(cleanup_due_ns)
        with self._scope():
            self._workers[name]
            child = self._children.get(name)
            cleanup = CleanupResult(CleanupStatus.NOT_REQUESTED)
            if child is None:
                if cleanup_due_ns is not None:
                    cleanup = CleanupResult(CleanupStatus.OUTSIDE_SCOPE)
                return SupervisionResult(LifecycleStatus.OBSERVED, cleanup)
            lifecycle = _wait(child, due_ns, cancel)
            returncode, error = child.returncode, child.error
            if cleanup_due_ns is not None and lifecycle in (LifecycleStatus.TIMED_OUT, LifecycleStatus.CANCELLED):
                cleanup = _cleanup(child, cleanup_due_ns)
            return SupervisionResult(lifecycle, cleanup, returncode, error)

    def cleanup(self, name, *, due_ns):
        """Request SIGTERM, then SIGKILL if needed, and bounded direct-child reap."""
        _deadline(due_ns)
        with self._scope():
            self._workers[name]
            child = self._children.get(name)
            if child is None:
                return CleanupResult(CleanupStatus.OUTSIDE_SCOPE)
            return _cleanup(child, due_ns)
