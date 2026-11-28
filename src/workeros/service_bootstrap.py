"""Hold a resource-free bootstrap in the already-authorized manager process.

The passive gate cannot start a worker. The active gate receives its fixed
sandbox inputs only after the manager verifies pre-effect placement.
"""
from array import array
from contextlib import contextmanager
from dataclasses import dataclass, field
import os
import signal
import socket
import subprocess
import sys
from time import monotonic_ns

from .lifecycle import _fields


# Only /dev/null streams, the private socket, and the already-armed active
# timer reach this interpreter. It never reads or reprograms the timer.
_GATE = """import os
import select
import sys
fd = int(sys.argv[1])
timer = int(sys.argv[2])
poll = select.poll()
poll.register(fd, select.POLLIN)
poll.register(timer, select.POLLIN)
os.write(fd, b'B')
ready = dict(poll.poll())
if timer in ready:
    os._exit(0 if ready[timer] == select.POLLIN else 1)
os._exit(0 if os.read(fd, 1) == b'' else 1)
"""

# Until the exact rights packet arrives, this gate owns only the control
# socket, active timer, and inert standard streams. It can run one fixed
# bubblewrap command; neither an executable name nor arguments come over IPC.
_RELEASE_GATE = """import array
import ctypes
import fcntl
import os
import select
import socket
import stat
import sys
from time import monotonic_ns

gate, timer, due, uid, gid = map(int, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
prctl = libc.prctl
prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
if prctl(4, 0, 0, 0, 0) != 0 or prctl(38, 1, 0, 0, 0) != 0:  # DUMPABLE, NO_NEW_PRIVS
    os._exit(125)
with socket.socket(fileno=gate) as channel:
    poll = select.poll()
    poll.register(gate, select.POLLIN)
    poll.register(timer, select.POLLIN)
    channel.sendall(b'B')
    ready = dict(poll.poll())
    if timer in ready or ready.get(gate, 0) & ~select.POLLIN or monotonic_ns() >= due:
        os._exit(125)
    fds = array.array('i')
    payload, control, flags, _ = channel.recvmsg(2, socket.CMSG_SPACE(5 * fds.itemsize),
                                                socket.MSG_CMSG_CLOEXEC)
    if (len(payload) != 2 or payload[:1] != b'R' or not 0 < payload[1] < 8
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(control) != 1
            or control[0][:2] != (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            or len(control[0][2]) != (2 + payload[1].bit_count()) * fds.itemsize):
        os._exit(125)
    fds.frombytes(control[0][2])
os.close(timer)
sandbox, executable, *streams = fds
if any(fd < 3 for fd in fds):
    os._exit(125)
for fd in streams:
    if (not stat.S_ISREG(os.fstat(fd).st_mode)
            or fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_PATH | os.O_APPEND)):
        os._exit(125)
if os.getresgid() != (gid,) * 3 or set(os.getgroups()) - {gid}:
    os.setgroups([])
    os.setresgid(gid, gid, gid)
if os.getresuid() != (uid,) * 3:
    os.setresuid(uid, uid, uid)
if (os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3 or set(os.getgroups()) - {gid}
        or prctl(4, 0, 0, 0, 0) != 0):
    os._exit(125)
# Clear the effective, permitted and inheritable Linux capability sets before
# exec. Clearing inheritable/permitted also clears any corresponding ambient
# capabilities.
class CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
capset = libc.capset
capset.argtypes = [ctypes.POINTER(CapHeader), ctypes.POINTER(ctypes.c_uint32)]
if capset(ctypes.byref(CapHeader(0x20080522, 0)), (ctypes.c_uint32 * 6)()) != 0:
    os._exit(125)
selected = iter(streams)
for slot in range(3):
    if payload[1] & (1 << slot):
        fd = next(selected)
        os.dup2(fd, slot)
        os.close(fd)
os.set_inheritable(executable, True)
if monotonic_ns() >= due:
    os._exit(125)
os.execve(sandbox, ['bwrap', '--unshare-user', '--unshare-pid', '--unshare-net', '--unshare-ipc',
    '--unshare-uts', '--disable-userns', '--new-session', '--die-with-parent', '--cap-drop', 'ALL',
    '--clearenv', '--chdir', '/', '--perms', '0500', '--ro-bind-data', str(executable), '/worker',
    '--remount-ro', '/', '--', '/worker'], {})
"""


class BootstrapCleanupUnconfirmed(ValueError):
    """The bootstrap was closed locally, but timely reap is unverified."""


@dataclass(frozen=True, slots=True)
class HeldBootstrap:
    """A local borrowed pidfd, valid only within the staging context."""

    pid: int
    pidfd: int = field(repr=False)
    _held: '_HeldRelease | None' = field(default=None, repr=False, compare=False)
    attempted: bool = field(default=False, init=False)

    @property
    def reaped_ns(self):
        return self._held.reaped_ns if self._held is not None else None


@dataclass(slots=True)
class _HeldRelease:
    process: subprocess.Popen = field(repr=False)
    pidfd: int = field(repr=False)
    channel: socket.socket = field(repr=False)
    attempted: bool = field(default=False, init=False)
    reaped_ns: int | None = field(default=None, init=False)

    @property
    def pid(self):
        return self.process.pid

    def release(self, descriptors, deadline_ns):
        if self.attempted:
            raise ValueError('service_bootstrap_release_already_attempted')
        if type(descriptors) is not tuple or len(descriptors) != 5:
            raise ValueError('service_bootstrap_release_handles_invalid')
        sandbox, executable, *streams = descriptors
        given = (sandbox, executable, *(fd for fd in streams if fd is not None))
        if len(given) == 2 or any(type(fd) is not int or fd < 3 for fd in given) or len(set(given)) != len(given):
            raise ValueError('service_bootstrap_release_handles_invalid')
        mask = sum(1 << slot for slot, fd in enumerate(streams) if fd is not None)
        self.attempted = True
        self.channel.settimeout(_remaining(deadline_ns))
        rights = array('i', given)
        if self.channel.sendmsg([b'R' + bytes((mask,))], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != 2:
            raise OSError('service_bootstrap_release_unconfirmed')

    def observe_reap(self, event):
        # The leaf owns waitid after placement. Keep Popen's cleanup from
        # treating the same terminated child as unreaped.
        if event.si_pid != self.pid or self.reaped_ns is not None:
            raise ValueError('service_bootstrap_reap_mismatch')
        self.process.returncode = event.si_status if event.si_code == os.CLD_EXITED else -event.si_status
        self.reaped_ns = monotonic_ns()


def _remaining(deadline):
    left = deadline - monotonic_ns()
    if left <= 0:
        raise TimeoutError('service_bootstrap_deadline_elapsed')
    return left / 1_000_000_000


def _reap(process, pidfd, timers, cleanup_until_ns, *, failed):
    try:
        if pidfd is None:
            # The socket already reached EOF. Popen can reap its own child
            # even if obtaining the pidfd failed, without signalling a PID.
            process.wait(timeout=_remaining(cleanup_until_ns))
        else:
            observation_error = None
            if failed and monotonic_ns() < cleanup_until_ns:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    observation_error = exc
            try:
                timers.wait_for_child(pidfd, cleanup=True)
            except (OSError, ValueError) as exc:
                observation_error = exc
            # Reap an already-exited child even if readiness arrived late,
            # while keeping the bounded cleanup outcome unconfirmed.
            event = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            if event is None:
                raise BootstrapCleanupUnconfirmed('service_bootstrap_reap_unconfirmed') from observation_error
            process.returncode = event.si_status if event.si_code == os.CLD_EXITED else -event.si_status
        reaped = monotonic_ns()
        if reaped >= cleanup_until_ns:
            raise BootstrapCleanupUnconfirmed('service_bootstrap_reap_late')
        return reaped
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise BootstrapCleanupUnconfirmed('service_bootstrap_reap_unconfirmed') from exc


def _check_bootstrap(timers, window):
    # Execute the running trusted CPython image, pinned by the kernel, not a
    # path selected by the request. -I -S -B excludes user startup code.
    if (sys.implementation.name != 'cpython' or not os.path.isabs(sys.executable)
            or not os.path.samefile(sys.executable, '/proc/self/exe')):
        raise ValueError('trusted_bootstrap_interpreter_unavailable')
    _remaining(window.active_until_ns)
    if timers._window != window or timers._active is None:
        raise ValueError('service_bootstrap_timer_unverified')


@contextmanager
def _hold_gate(timers, window, script, *arguments):
    _check_bootstrap(timers, window)
    timer = timers._active
    local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with local, remote:
        process = subprocess.Popen(
            [sys.executable, '-I', '-S', '-B', '-c', script, str(remote.fileno()), str(timer), *arguments],
            executable='/proc/self/exe', close_fds=True, pass_fds=(remote.fileno(), timer),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd='/', env={},
        )
        pidfd = None
        held = None
        failed = True
        try:
            remote.close()
            pidfd = os.pidfd_open(process.pid)
            local.settimeout(_remaining(window.active_until_ns))
            if local.recv(2) != b'B' or os.waitid(
                    os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                raise ValueError('service_bootstrap_gate_unverified')
            _remaining(window.active_until_ns)
            held = _HeldRelease(process, pidfd, local)
            yield held
            failed = False
        finally:
            try:
                local.close()
            finally:
                try:
                    if process.returncode is None:
                        reaped = _reap(process, pidfd, timers, window.cleanup_until_ns, failed=failed)
                        if held is not None:
                            held.reaped_ns = reaped
                finally:
                    if pidfd is not None:
                        os.close(pidfd)


@contextmanager
def _hold_bootstrap(timers, window):
    with _hold_gate(timers, window, _GATE) as held:
        yield HeldBootstrap(held.pid, held.pidfd, held)


@contextmanager
def _hold_release(timers, window, uid, gid, deadline_ns):
    _check_worker_identity(uid, gid)
    # The held gate runs under the already-authorized manager until release.
    # Linux must permit the child to move to the exact ordinary appointment;
    # the gate then clears capability sets before entering the fixed sandbox.
    with _hold_gate(timers, window, _RELEASE_GATE, str(deadline_ns), str(uid), str(gid)) as held:
        yield held


def _check_worker_identity(uid, gid):
    if type(uid) is not int or type(gid) is not int or not 0 < min(uid, gid) <= max(uid, gid) < 2**32 - 1:
        raise ValueError('service_bootstrap_ordinary_principal_required')
    required = 0
    if os.getresuid() != (uid,) * 3:
        required |= 1 << 7  # CAP_SETUID
    if os.getresgid() != (gid,) * 3 or set(os.getgroups()) - {gid}:
        required |= 1 << 6  # CAP_SETGID
    if required and int(_fields('/proc/thread-self/status')[b'CapEff'], 16) & required != required:
        raise PermissionError('service_bootstrap_credential_authority_unavailable')
