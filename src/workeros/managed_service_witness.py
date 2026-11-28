"""Finite, same-invocation observation using already entitled read-only handles."""

from contextlib import ExitStack
from dataclasses import asdict, dataclass
from fcntl import F_GETFL, fcntl
from hashlib import sha256
import os
import re
from select import poll, POLLIN
from socket import AF_UNIX
import stat
from time import monotonic_ns, sleep

from .delegated_service_leaf import service_process_identity
from .managed_executor import authority_pin
from .managed_launch import LaunchInvocation, _digest
from .managed_service_observer import EffectCleanupObservation
from .managed_service_parent import _identity
from .managed_service_scope import ServiceBundle
from .original import Identity, _check
from .roles_cli import _canonical, _fields
from .scope_meter import _counter, _mount_id


@dataclass(frozen=True, slots=True)
class _WitnessedService:
    invocation: LaunchInvocation
    cleanup: EffectCleanupObservation
    effect_sha256: str
    source: str
    socket: str
    uid: int


def _read_only_counter(fd, path, leaf):
    flags = fcntl(fd, F_GETFL)
    if (not stat.S_ISREG(os.fstat(fd).st_mode) or _mount_id(fd) != leaf.mount_id
            or flags & (os.O_PATH | os.O_ACCMODE)
            or os.readlink(f'/proc/self/fd/{fd}') != path):
        raise ValueError('service_witness_counter_unbound')


def _effect(fd, original, deadline_ns):
    digest = sha256()
    before = _check(fd, Identity(original.device, original.inode), (os.O_RDONLY,))
    if before.owner_uid != original.owner_uid:
        raise ValueError('service_witness_original_owner_changed')
    info = os.fstat(fd)
    position = 0
    while position < info.st_size:
        if monotonic_ns() >= deadline_ns:
            raise TimeoutError('service_witness_deadline_elapsed')
        block = os.pread(fd, min(65_536, info.st_size - position), position)
        if not block:
            raise ValueError('service_witness_original_changed')
        digest.update(block)
        position += len(block)
    updated = os.fstat(fd)
    if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            updated.st_size, updated.st_mtime_ns, updated.st_ctime_ns):
        raise ValueError('service_witness_original_changed')
    return digest.hexdigest()


def observe_effect_cleanup(invocation, scope, manager_run_id, *, pid, pidfd, leaf_fd, procs_fd, events_fd,
                           output_fd, source, endpoint, expected_effect_sha256, ready=None, empty_ready=None,
                           expected_process=None, expected_leaf=None):
    """Hold the exact live sandbox, leaf, and approved output through retirement.

    Transfer the witness's five preheld read-only descriptors to this call;
    it closes them before returning. An appointed holder supplies exclusive
    output custody. A separate legitimate reaper owns wait status. The
    callbacks notify the already authorized owner that the witness acquired
    the pins or observed emptiness, respectively. They supply no evidence.
    Peer and principal separation are checked when serving the result.
    """
    from .managed_bootstrap import setup_clock_id

    handles = (pidfd, leaf_fd, procs_fd, events_fd, output_fd)
    if any(type(fd) is not int or fd < 3 for fd in handles) or len(set(handles)) != len(handles):
        raise ValueError('service_witness_handles_invalid')
    with ExitStack() as held:
        for fd in handles:
            held.callback(os.close, fd)
        if (type(invocation) is not LaunchInvocation or invocation.service_window is None
                or type(scope) is not ServiceBundle or scope.parent is None
                or invocation.clock_id != setup_clock_id() or os.geteuid() == 0):
            raise ValueError('service_witness_scope_unverified')
        _digest(expected_effect_sha256)
        authority_pin(source, endpoint, os.geteuid())
        output = next((descriptor for descriptor in scope.descriptors if descriptor.slot == 'stdout'), None)
        if output is None or output.mode not in ('write', 'read-write'):
            raise ValueError('service_witness_output_unavailable')
        unit = f'workeros-{invocation.plan.invocation_key}.service'
        path = '/sys/fs/cgroup' + scope.parent.control_group + '/' + unit
        deadline = invocation.service_window.cleanup_until_ns
        leaf = _identity(leaf_fd)
        with scope.parent.directory() as parent:
            native = os.stat(unit, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(native.st_mode) or (native.st_dev, native.st_ino) != (leaf.device, leaf.inode)
                    or leaf.mount_id != scope.parent.mount_id):
                raise ValueError('service_witness_leaf_unbound')
        _read_only_counter(procs_fd, path + '/cgroup.procs', leaf)
        _read_only_counter(events_fd, path + '/cgroup.events', leaf)
        if os.pread(procs_fd, 8193, 0).split() != [str(pid).encode('ascii')]:
            raise ValueError('service_witness_process_outside_leaf')
        process = service_process_identity(pid, pidfd)
        if ((expected_process is not None and process != expected_process)
                or (expected_leaf is not None and leaf != expected_leaf)):
            raise ValueError('service_witness_attempt_unbound')
        waiter = poll()
        waiter.register(pidfd, POLLIN)
        if _effect(output_fd, output, deadline) == expected_effect_sha256 or waiter.poll(0):
            raise ValueError('service_witness_initial_state_unverified')
        live = monotonic_ns()
        if live >= invocation.service_window.active_until_ns:
            raise TimeoutError('service_witness_deadline_elapsed')
        if ready is not None:
            ready()
        while True:
            remaining = deadline - monotonic_ns()
            if remaining <= 0:
                raise TimeoutError('service_witness_deadline_elapsed')
            events = waiter.poll(min(1 + remaining // 1_000_000, 60_000))
            if events:
                if not events[0][1] & POLLIN:
                    raise ValueError('service_witness_exit_unverified')
                break
        exited = monotonic_ns()
        while _counter(os.pread(events_fd, 8193, 0), b'populated', 1):
            remaining = deadline - monotonic_ns()
            if remaining <= 0:
                raise TimeoutError('service_witness_deadline_elapsed')
            sleep(min(remaining, 5_000_000) / 1_000_000_000)
        empty = monotonic_ns()
        effect = _effect(output_fd, output, deadline)
        if effect != expected_effect_sha256:
            raise ValueError('service_witness_effect_mismatch')
        observed = monotonic_ns()
        if empty_ready is not None:
            empty_ready()
        while not scope.parent.retired_child_absent(unit):
            remaining = deadline - monotonic_ns()
            if remaining <= 0:
                raise TimeoutError('service_witness_deadline_elapsed')
            sleep(min(remaining, 5_000_000) / 1_000_000_000)
        retired = monotonic_ns()
    closed = monotonic_ns()
    if closed >= deadline:
        raise TimeoutError('service_witness_deadline_elapsed')
    observation = EffectCleanupObservation(scope.digest, manager_run_id, leaf, process, live, exited, empty,
                                           retired, observed, closed)
    return _WitnessedService(invocation, observation, effect, source, endpoint, os.geteuid())


def serve_witness_result(connection, record, *, deadline_ns, expires_ns):
    """Serve one exact read-only request from the already-appointed launcher."""
    from .managed_cli import _TRUSTED_UID
    from .managed_service_client import _frame_read, _frame_write, _peer

    if (type(record) is not _WitnessedService or record.uid != os.geteuid() or record.uid == _TRUSTED_UID
            or record.uid == record.invocation.plan.principal_uid
            or record.source == record.invocation.plan.authority
            or connection.family != AF_UNIX or _peer(connection) != _TRUSTED_UID):
        raise PermissionError('service_witness_peer_untrusted')
    deadline = min(deadline_ns, expires_ns)
    request = _frame_read(connection, deadline / 1_000_000_000)
    _fields(request, ('version', 'operation', 'nonce', 'invocation'))
    allowed = asdict(record.invocation)
    if (type(request['version']) is not int or request['version'] != 1 or request['operation'] != 'read_result'
            or type(request['nonce']) is not str or re.fullmatch(r'[0-9a-f]{32}', request['nonce']) is None
            or request['invocation'] != allowed):
        raise ValueError('service_witness_request_unbound')
    proof = {'invocation': allowed, 'source': record.source,
             'source_sha256': authority_pin(record.source, record.socket, record.uid),
             'cleanup': asdict(record.cleanup)}
    proof['receipt_sha256'] = sha256(_canonical({**proof, 'effect_sha256': record.effect_sha256})).hexdigest()
    verified = monotonic_ns()
    if not record.cleanup.handles_closed_ns <= verified < deadline:
        raise TimeoutError('service_witness_deadline_elapsed')
    _frame_write(connection, {'version': 1, 'operation': 'read_result', 'nonce': request['nonce'],
                              'result': {'observation': proof, 'effect_sha256': record.effect_sha256,
                                         'verified_ns': verified, 'expires_ns': expires_ns}},
                 deadline / 1_000_000_000)
