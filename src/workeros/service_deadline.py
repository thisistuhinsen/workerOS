"""Linux absolute timers for the already-authorized service manager."""
from contextlib import ExitStack
from ctypes import CDLL, POINTER, Structure, byref, c_int, c_long, get_errno, sizeof
import os
import select
from time import CLOCK_MONOTONIC, monotonic_ns

from .managed_launch import ServiceWindow


_TIMER_ABSOLUTE = 1


class _Timespec(Structure):
    _fields_ = [('seconds', c_long), ('nanoseconds', c_long)]


class _Interval(Structure):
    _fields_ = [('interval', _Timespec), ('expires', _Timespec)]


def _check(result):
    if result < 0:
        number = get_errno()
        raise OSError(number, os.strerror(number))
    return result


def _arm(deadline_ns, owned):
    if sizeof(c_long) != 8:
        raise ValueError('service timers require the supported Linux 64-bit timespec ABI')
    libc = CDLL(None, use_errno=True)
    create = libc.timerfd_create
    create.argtypes = (c_int, c_int)
    create.restype = c_int
    settime = libc.timerfd_settime
    settime.argtypes = (c_int, c_int, POINTER(_Interval), POINTER(_Interval))
    settime.restype = c_int
    fd = _check(create(CLOCK_MONOTONIC, os.O_CLOEXEC | os.O_NONBLOCK))
    owned.callback(os.close, fd)
    expires = _Timespec(*divmod(deadline_ns, 1_000_000_000))
    _check(settime(fd, _TIMER_ABSOLUTE, byref(_Interval(_Timespec(0, 0), expires)), None))
    return fd


class ArmedServiceWindow:
    """One-shot kernel notifications for a fixed active and cleanup window.

    The owning manager must service these notifications. Expiry alone does
    not terminate a process, release a scope, or establish a cleanup receipt.
    """

    def __init__(self, window):
        if type(window) is not ServiceWindow or monotonic_ns() >= window.active_until_ns:
            raise ValueError('service_window_not_active')
        self._window = window
        with ExitStack() as owned:
            self._active = _arm(window.active_until_ns, owned)
            self._cleanup = _arm(window.cleanup_until_ns, owned)
            if monotonic_ns() >= window.active_until_ns:
                raise ValueError('service_window_not_active')
            self._owned = owned.pop_all()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self._active = self._cleanup = None
        self._owned.close()

    def wait_for_child(self, pidfd=None, *, cleanup=False):
        """Return whether a waitable fd became readable before the fixed cutoff."""
        timer, deadline = ((self._cleanup, self._window.cleanup_until_ns) if cleanup else
                           (self._active, self._window.active_until_ns))
        if timer is None:
            raise ValueError('service_window_closed')
        poll = select.poll()
        poll.register(timer, select.POLLIN)
        if pidfd is not None:
            poll.register(pidfd, select.POLLIN)
        if monotonic_ns() >= deadline:
            return False
        ready = dict(poll.poll())
        flags = ready.get(timer, 0)
        if flags & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
            raise OSError('service timer readiness unavailable')
        if monotonic_ns() >= deadline:
            return False
        if flags:
            raise OSError('service timer ready before its absolute cutoff')
        flags = ready.get(pidfd, 0)
        if not flags & (select.POLLIN | select.POLLHUP) or flags & (select.POLLERR | select.POLLNVAL):
            raise OSError('service child readiness unavailable')
        return True
