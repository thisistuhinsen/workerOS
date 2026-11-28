"""Check and retain a trusted host's preheld incumbent resources in-process.

The caller must already control the resource handoff. This module authorizes
no transfer, sends no frames, and produces no independent closure evidence.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from fcntl import F_GETFL, fcntl
import os
import select
import socket
import stat
from time import monotonic_ns

from .evidence import EvidenceScope
from .lifecycle import _duplicate, _fields
from .managed_launch import _digest, _service_cgroup, _uid, _unsigned
from .original import Identity, _CREDENTIALS
from .scope_meter import CgroupIdentity, _cgroup_mount, _mount_id, monotonic_clock_id


class IncumbentRefusal(ValueError):
    """A preheld resource, its scope, or the outer handoff is unverified."""


@dataclass(frozen=True, slots=True)
class DirectoryPin:
    identity: Identity
    mount_id: int

    def __post_init__(self):
        if type(self.identity) is not Identity:
            raise IncumbentRefusal('incumbent_directory_pin_invalid')
        _unsigned(self.mount_id, positive=True)


@dataclass(frozen=True, slots=True)
class ProcessPin:
    pid: int
    uid: int
    start_ticks: int

    def __post_init__(self):
        _unsigned(self.pid, positive=True, maximum=(1 << 31) - 1)
        _uid(self.uid)
        _unsigned(self.start_ticks)


@dataclass(frozen=True, slots=True)
class PhasePin:
    identity: Identity
    peer_pid: int
    peer_uid: int
    socket_type: int

    def __post_init__(self):
        if (type(self.identity) is not Identity or type(self.socket_type) not in (int, socket.SocketKind)
                or self.socket_type not in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET)):
            raise IncumbentRefusal('incumbent_phase_pin_invalid')
        _unsigned(self.peer_pid, positive=True, maximum=(1 << 31) - 1)
        _uid(self.peer_uid)


@dataclass(frozen=True, slots=True)
class IncumbentPins:
    """The exact protected profile and invocation supplied by the incumbent owner."""

    profile_identity: str
    scope: EvidenceScope
    original: DirectoryPin
    writer: ProcessPin
    reader: ProcessPin
    phase: PhasePin
    meter: CgroupIdentity

    def __post_init__(self):
        _digest(self.profile_identity)
        if (type(self.scope) is not EvidenceScope or type(self.original) is not DirectoryPin
                or type(self.writer) is not ProcessPin or type(self.reader) is not ProcessPin
                or type(self.phase) is not PhasePin or type(self.meter) is not CgroupIdentity):
            raise IncumbentRefusal('incumbent_pin_invalid')
        _service_cgroup(self.meter)
        if len({self.writer.pid, self.reader.pid, self.phase.peer_pid}) != 3:
            raise IncumbentRefusal('incumbent_roles_overlap')
        if (self.original.identity.device, self.original.identity.inode) == (self.meter.device, self.meter.inode):
            raise IncumbentRefusal('incumbent_resource_alias')
        run = self.scope.run
        if not self.scope.started_ns <= run.started_ns < run.finished_ns <= self.scope.finished_ns:
            raise IncumbentRefusal('incumbent_window_invalid')

    def _check_window(self):
        if (monotonic_clock_id() != self.scope.run.clock_id
                or not self.scope.run.started_ns <= monotonic_ns() < self.scope.run.finished_ns):
            raise IncumbentRefusal('incumbent_scope_not_active')


@dataclass(frozen=True, slots=True, repr=False)
class IncumbentHandles:
    """Borrowed local descriptors. Do not close, mutate or serialize them."""

    original: int
    writer: int
    reader: int
    phase: int
    meter: int

    def _fds(self):
        return self.original, self.writer, self.reader, self.phase, self.meter


class RetainedIncumbent:
    """Pinned resources for a single local use, until the owner leaves the context."""

    __slots__ = ('_pins', '_handles', '_owned')

    def __init__(self, pins, handles, owned):
        self._pins = pins
        self._handles = handles
        self._owned = owned

    @property
    def pins(self):
        return self._pins

    @property
    def handles(self):
        if self._handles is None:
            raise IncumbentRefusal('incumbent_handles_closed')
        return self._handles

    def close(self):
        """Release local copies before checking peer EOF or final closure."""
        self._handles = None
        self._owned.close()


def _directory(fd, identity, mount_id):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or Identity(info.st_dev, info.st_ino) != identity
            or _mount_id(fd) != mount_id):
        raise IncumbentRefusal('incumbent_directory_mismatch')


def _process(fd, pin):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    if (os.readlink(f'/proc/self/fd/{fd}') != 'anon_inode:[pidfd]'
            or int(_fields(f'/proc/self/fdinfo/{fd}')[b'Pid']) != pin.pid or poll.poll(0)):
        raise IncumbentRefusal('incumbent_process_mismatch')
    with open(f'/proc/{pin.pid}/stat', 'rb') as source:
        _, separator, fields = source.read().rpartition(b') ')
    fields = fields.split()
    uids = tuple(map(int, _fields(f'/proc/{pin.pid}/status')[b'Uid'].split()))
    if not separator or len(fields) <= 19 or int(fields[19]) != pin.start_ticks or uids != (pin.uid,) * 4:
        raise IncumbentRefusal('incumbent_process_mismatch')
    if poll.poll(0):
        raise IncumbentRefusal('incumbent_process_mismatch')


def _phase(fd, pin):
    info = os.fstat(fd)
    if not stat.S_ISSOCK(info.st_mode) or Identity(info.st_dev, info.st_ino) != pin.identity:
        raise IncumbentRefusal('incumbent_phase_mismatch')
    # Borrow the already owned socket FD. Do not consume a frame or change
    # flags (a dup shares the original stream's open-file description).
    channel = socket.socket(fileno=fd)
    try:
        kind = channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        channel.getpeername()
        pid, uid, _ = _CREDENTIALS.unpack(channel.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size))
        if channel.family != socket.AF_UNIX or (kind, pid, uid) != (
                pin.socket_type, pin.peer_pid, pin.peer_uid):
            raise IncumbentRefusal('incumbent_phase_mismatch')
    finally:
        channel.detach()


@contextmanager
def retain_incumbent(pins: IncumbentPins, handles: IncumbentHandles):
    """Retain the five exact resources through a trusted consumer's outer close.

    Yields local duplicates only to the in-process owner. Release closes
    those duplicates, never signals, restarts, or settles the incumbent.
    """
    if type(pins) is not IncumbentPins or type(handles) is not IncumbentHandles:
        raise IncumbentRefusal('incumbent_binding_invalid')
    pins._check_window()
    fds = handles._fds()
    if any(type(fd) is not int or fd < 3 for fd in fds) or len(set(fds)) != len(fds):
        raise IncumbentRefusal('incumbent_handle_invalid')
    with ExitStack() as held:
        try:
            if any(os.get_inheritable(fd) for fd in fds):
                raise IncumbentRefusal('incumbent_handle_inheritable')
            bound = IncumbentHandles(*(_duplicate(held, fd) for fd in fds))
            _directory(bound.original, pins.original.identity, pins.original.mount_id)
            flags = fcntl(bound.original, F_GETFL)
            if flags & os.O_PATH or flags & os.O_ACCMODE != os.O_RDONLY:
                raise IncumbentRefusal('incumbent_original_not_readable')
            _process(bound.writer, pins.writer)
            _process(bound.reader, pins.reader)
            _phase(bound.phase, pins.phase)
            _directory(bound.meter, Identity(pins.meter.device, pins.meter.inode), pins.meter.mount_id)
            if not _cgroup_mount(pins.meter.mount_id):
                raise IncumbentRefusal('incumbent_meter_not_cgroup')
            pins._check_window()
        except (OSError, KeyError) as exc:
            raise IncumbentRefusal('incumbent_kernel_identity_unavailable') from exc
        retained = RetainedIncumbent(pins, bound, held)
        try:
            yield retained
        finally:
            retained.close()
