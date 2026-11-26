"""Names and optional process creation. A role is not an isolation boundary."""

from dataclasses import dataclass, field
from functools import partial, partialmethod
import inspect
from multiprocessing import get_context
import os
import re
import stat
import subprocess
from time import monotonic_ns
from types import AsyncGeneratorType, FunctionType, GeneratorType, MethodType
from typing import Any

_ABI_PREFIX = "WORKER_HANDOFF_"
_BINDING_NAME = re.compile(r"[A-Z][A-Z0-9_]*", re.ASCII)


def _is_async_or_generator_target(target):
    while (issubclass(type(target), partial)
           and inspect.getattr_static(type(target), "__call__") is partial.__call__):
        target = partial.func.__get__(target)
    if type(target) not in (FunctionType, MethodType):
        target = inspect.getattr_static(type(target), "__call__", None)
        if type(target) is partialmethod:
            target = target.func
        if type(target) in (staticmethod, classmethod):
            target = target.__func__
    if type(target) is MethodType:
        target = target.__func__
    # Decorators can copy coroutine markers onto a synchronous bridge.
    return type(target) is FunctionType and bool(
        target.__code__.co_flags
        & (inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR | inspect.CO_GENERATOR)
    )


def _has_await_method(kind):
    # Special methods come from the actual type hierarchy. Do not invoke
    # attribute hooks on the result or its metaclass.
    for base in type.__dict__["__mro__"].__get__(kind):
        members = type.__dict__["__dict__"].__get__(base)
        if "__await__" in members:
            return members["__await__"] is not None
    return False


def _run_sync_target(target, args):
    result = target(*args)
    kind = type(result)
    if (kind is AsyncGeneratorType
            or (kind is GeneratorType and result.gi_code.co_flags & inspect.CO_ITERABLE_COROUTINE)
            or _has_await_method(kind)):
        raise TypeError("WorkerRoster synchronous target returned an awaitable or async generator")


def _exec_context(name, role, argv, fds, due_ns, env):
    # Observe the actual files. These per-launch facts are not credentials.
    from .original import observe

    if (type(argv) not in (list, tuple) or not argv or not argv[0]
            or any(type(arg) is not str or "\x00" in arg for arg in argv)
            or "\x00" in name or "\x00" in role):
        raise ValueError("expected valid executable argv without a shell")
    if type(due_ns) is not int or not 0 < due_ns < 1 << 63:
        raise ValueError("expected a Linux monotonic deadline")
    if monotonic_ns() >= due_ns:
        raise TimeoutError("worker start deadline expired")
    if fds is not None and type(fds) is not dict:
        raise TypeError("fds is a mapping of ABI names to explicitly owned original descriptors")
    if env is not None and type(env) is not dict:
        raise TypeError("env is a string-to-string mapping")
    context = {
        k:v for k,v in os.environ.items() if not k.startswith(_ABI_PREFIX)
    } if env is None else dict(env)
    if any(type(k) is not str or type(v) is not str or not k or "=" in k or "\x00" in k+v
           or k.startswith(_ABI_PREFIX) for k,v in context.items()):
        raise ValueError("invalid or reserved environment key/value")
    context.update({
        _ABI_PREFIX+"ABI": "1",
        _ABI_PREFIX+"NAME": name,
        _ABI_PREFIX+"ROLE": role,
        _ABI_PREFIX+"DEADLINE_NS": str(due_ns),
    })
    handles = set()
    for binding,fd in ({} if fds is None else fds).items():
        if type(binding) is not str or _BINDING_NAME.fullmatch(binding) is None:
            raise ValueError("descriptor bindings use uppercase ASCII environment names")
        if type(fd) is not int or fd < 3:
            raise ValueError("only explicit original descriptors, not standard streams")
        seen = observe(fd)
        mode = seen.flags & os.O_ACCMODE
        if (not stat.S_ISREG(seen.mode) or seen.inheritable or seen.flags & os.O_PATH
                or mode not in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR)
                or (mode != os.O_RDONLY and seen.owner_uid != os.getuid())
                or (mode != os.O_RDONLY and os.getuid() != os.geteuid())):
            raise ValueError("only a stable readable or caller-owned writable regular descriptor")
        handles.add(fd)
        # Separate field prefixes make long names and suffix names unambiguous.
        context[_ABI_PREFIX+"FD_"+binding] = str(fd)
        context[_ABI_PREFIX+"DEV_"+binding] = str(seen.identity.device)
        context[_ABI_PREFIX+"INO_"+binding] = str(seen.identity.inode)
        context[_ABI_PREFIX+"ACCESS_"+binding] = {os.O_RDONLY:"read",os.O_WRONLY:"write",
                                                   os.O_RDWR:"read-write"}[mode]
    if monotonic_ns() >= due_ns:
        raise TimeoutError("worker start deadline expired")
    return tuple(sorted(handles)),context


@dataclass(frozen=True, slots=True)
class Worker:
    name: str
    role: str
    pid: int
    uid: int | None = None
    process: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if any(type(x) is not str or not x.strip() for x in (self.name, self.role)):
            raise ValueError("name and role must be nonempty strings")
        if type(self.pid) is not int or self.pid <= 0:
            raise ValueError("expected a live or observed worker PID")
        if self.uid is not None and (type(self.uid) is not int or self.uid < 0):
            raise ValueError("expected a nonnegative Linux UID")


class WorkerRoster:
    """A supervisor-local roster; no topology, privilege, daemon or global cap."""

    def __init__(self):
        self._workers = {}
        self._owned = {}

    def _free(self, name, role):
        if any(type(x) is not str or not x.strip() for x in (name, role)):
            raise ValueError("name and role must be nonempty strings")
        if name in self._workers or name in self._owned:
            raise ValueError("duplicate worker name")

    def external(self, name, role, *, pid, uid=None):
        """Register an existing endpoint; nothing is spawned, stopped or joined."""
        self._free(name, role)
        worker = Worker(name, role, pid, uid)
        self._workers[name] = worker
        return worker

    def start(self, name, role, target, *, args=(), context=None, uid=None):
        """Start the caller's synchronous Python handler with positional arguments.

        Async and generator functions are refused. Returning an awaitable or
        async generator fails in the child after the handler runs. Other return
        values are ignored.
        On a start exception, retain the process in `owned()` for reconciliation;
        a partly started child is never automatically replaced. This class is
        driven by one supervising caller, not a concurrent scheduler.
        """
        self._free(name, role)
        if not callable(target) or type(args) is not tuple:
            raise TypeError("a callable handler and an argument tuple are required")
        if _is_async_or_generator_target(target):
            raise TypeError("WorkerRoster requires a synchronous, non-generator target")
        if uid is not None and (type(uid) is not int or uid < 0):
            raise ValueError("expected worker UID must be nonnegative")
        process = (context if context is not None else get_context("spawn")).Process(
            name=name, target=_run_sync_target, args=(target, args))
        self._owned[name] = process
        process.start()
        worker = Worker(name, role, process.pid, uid, process)
        self._workers[name] = worker
        return worker

    def start_executable(self, name, role, argv, *, due_ns, fds=None, env=None, uid=None):
        """Start an application-supplied executable with the Linux FD ABI v1.

        The caller retains its own descriptors. Child inherits only named
        original descriptors in addition to standard streams (no shell).
        Do not rebind or close those descriptors during this call. No timeout
        kills a child; the actual supervisor retains that decision.
        """
        self._free(name, role)
        if uid is not None and (type(uid) is not int or uid < 0):
            raise ValueError("expected worker UID must be nonnegative")
        handles, context = _exec_context(name, role, argv, fds, due_ns, env)
        # If process creation raises, do not recycle this name or claim absence
        # of a child based on a missing local return.
        self._owned[name] = None
        process = subprocess.Popen(tuple(argv), shell=False, close_fds=True,
                                   pass_fds=handles, env=context)
        self._owned[name] = process
        worker = Worker(name, role, process.pid, uid, process)
        self._workers[name] = worker
        return worker

    def __iter__(self):
        return iter(self._workers.values())

    def owned(self, name):
        """The actual optional owned process; external workers keep their owner."""
        return self._owned[name]

    def join(self, name, *, due_ns):
        """Join one owned worker and report its exit status or None (still running)."""
        if type(due_ns) is not int or not 0 < due_ns < 1 << 63:
            raise ValueError("expected an absolute monotonic deadline")
        p = self.owned(name)
        if p is None or p.pid is None:
            return None  # no actual process outcome established
        timeout = max(0, due_ns-monotonic_ns())/1_000_000_000
        if isinstance(p, subprocess.Popen):
            try:
                return p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return None
        p.join(timeout)
        return p.exitcode
