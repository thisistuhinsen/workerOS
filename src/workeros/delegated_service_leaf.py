"""Native manager-side controls for a pre-existing, exclusive cgroup leaf.

The appointed manager must already control the leaf. This module supplies
local placement and reaping observations for the independent authority.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
import os
import pwd
import re
import stat
import subprocess
from time import monotonic_ns, sleep

from .lifecycle import _duplicate, _fields
from .managed_launch import (LaunchInvocation, ServiceLimits, ServiceMeterReading, ServiceProcessIdentity,
                             _digest, _service_cgroup)
from .managed_service_parent import PlacementRefusal, ServiceParent, _DIR, _identity, check_unit
from .scope_meter import CgroupIdentity, _mount_id, _read_metric
from .service_bootstrap import (
    BootstrapCleanupUnconfirmed, _check_worker_identity, _hold_bootstrap, _hold_release, _remaining,
)
from .service_deadline import ArmedServiceWindow
from .supervisor import _check_host


def service_process_identity(pid, pidfd):
    """Read the live incarnation through a pidfd pinned to the same PID."""
    def pin_matches():
        return (os.readlink(f'/proc/self/fd/{pidfd}') == 'anon_inode:[pidfd]'
                and int(_fields(f'/proc/self/fdinfo/{pidfd}')[b'Pid']) == pid)

    if not pin_matches():
        raise PlacementRefusal('delegated_service_child_mismatch')
    with open(f'/proc/{pid}/stat', 'rb') as source:
        raw = source.read(8193)
    _, separator, fields = raw.rpartition(b') ')
    values = fields.split()
    if not separator or len(raw) > 8192 or len(values) <= 19 or not pin_matches():
        raise PlacementRefusal('delegated_service_incarnation_unavailable')
    return ServiceProcessIdentity(pid, int(values[19]), os.stat('/proc/self/ns/pid').st_ino)


@dataclass(frozen=True, slots=True)
class LeafObservation:
    """The manager's local reap and empty-leaf observations for one invocation."""

    invocation_key: str
    clock_id: str
    cgroup: CgroupIdentity
    adopted_ns: int
    reaped_ns: int
    disposition: str
    exit_status: int
    empty_ns: int
    meter_begin: ServiceMeterReading | None
    meter_end: ServiceMeterReading | None
    active_cutoff_observation: str
    retired_ns: int | None = None
    reaped_process: ServiceProcessIdentity | None = None


@dataclass(frozen=True, slots=True)
class UnreleasedBootstrap:
    """A placed trusted gate reaped before any worker release attempt."""

    cgroup: CgroupIdentity
    placed_ns: int
    reaped_ns: int
    empty_ns: int
    retired_ns: int | None = None


class DelegatedServiceLeaf:
    """One invocation managed outside the client connection.

    Call only as its already-appointed exclusive owner. Use a single serial
    manager and the same process for the waitable child. The supervisor must
    withhold worker effects until its native admission contract is satisfied.
    """

    def __init__(self, invocation, parent, leaf, limits, *, scope_sha256=None):
        from .managed_bootstrap import setup_clock_id

        if (type(invocation) is not LaunchInvocation or invocation.service_window is None
                or type(parent) is not ServiceParent or type(limits) is not ServiceLimits):
            raise PlacementRefusal('delegated_service_registration_invalid')
        self._leaf = _service_cgroup(leaf)
        self._window = invocation.service_window
        self._clock = invocation.clock_id
        if (self._clock != setup_clock_id()
                or self._window.cleanup_until_ns - self._window.active_until_ns > limits.cleanup_ms * 1_000_000
                or self._window.active_until_ns - monotonic_ns() > limits.active_ms * 1_000_000
                or self._leaf.mount_id != parent.mount_id or self._leaf.device != parent.device
                or self._leaf == parent.identity):
            raise PlacementRefusal('delegated_service_binding_mismatch')
        _check_host()
        self._parent = parent
        self._owner = (os.getpid(), os.getresuid())
        if scope_sha256 is not None:
            _digest(scope_sha256)
        self._scope_sha256, self._invocation, self._limits = scope_sha256, invocation, limits
        self._key = invocation.plan.invocation_key
        self._unit = f'workeros-{invocation.plan.invocation_key}.service'
        check_unit(self._unit)
        self._metered = limits.metered
        self._child = self._adopted = self._final = None
        self._child_identity = None
        self._finished = self._retirement_attempted = self._closed = False
        self._bootstrap_attempted = False
        self._unreleased = None
        self.stop_sent_ns = None
        with ExitStack() as owned, parent.directory() as directory:
            self._directory = os.open(self._unit, _DIR, dir_fd=directory)
            owned.callback(os.close, self._directory)
            if (_identity(self._directory) != self._leaf
                    or os.fstat(self._directory).st_uid != os.geteuid() or self._populated()):
                raise PlacementRefusal('delegated_service_leaf_unavailable')
            flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            self._kill = os.open('cgroup.kill', flags, dir_fd=self._directory)
            owned.callback(os.close, self._kill)
            if (not stat.S_ISREG(os.fstat(self._kill).st_mode)
                    or _mount_id(self._kill) != self._leaf.mount_id):
                raise PlacementRefusal('delegated_service_kill_unavailable')
            self._begin = self._sample_empty() if self._metered else None
            self._timers = owned.enter_context(ArmedServiceWindow(self._window))
            self.armed_ns = monotonic_ns()
            if self.armed_ns >= self._window.active_until_ns:
                raise TimeoutError('delegated_service_arm_expired')
            self._owned = owned.pop_all()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        """Close this manager's local handles; this is not a retirement receipt."""
        self._closed = True
        self._owned.close()

    def _metric(self, leaf, key=None):
        return _read_metric(self._directory, self._leaf.mount_id, leaf, key,
                            1 if leaf == 'cgroup.events' else (1 << 64) - 1)

    def _populated(self):
        return self._metric('cgroup.events', b'populated') != 0

    def _check_clock(self):
        from .managed_bootstrap import setup_clock_id

        if self._closed or self._owner != (os.getpid(), os.getresuid()) or setup_clock_id() != self._clock:
            raise PlacementRefusal('delegated_service_clock_or_owner_changed')

    def _check_leaf(self):
        self._check_clock()
        if self._parent.child_identity(self._unit) != self._leaf:
            raise PlacementRefusal('delegated_service_leaf_changed')
        member = self._member('self')
        leaf = self._leaf_membership()
        if member == leaf or member.startswith(leaf + b'/'):
            raise PlacementRefusal('delegated_service_manager_inside_leaf')

    def _leaf_membership(self):
        return f'0::{self._parent.control_group}/{self._unit}'.encode('ascii')

    @staticmethod
    def _member(pid):
        with open(f'/proc/{pid}/cgroup', 'rb') as source:
            raw = source.read(8193)
        lines = raw.splitlines()
        if len(raw) > 8192 or len(lines) != 1 or not lines[0].startswith(b'0::/'):
            raise PlacementRefusal('delegated_service_membership_unverified')
        return lines[0]

    def _sample_empty(self):
        if self._populated():
            raise PlacementRefusal('delegated_service_not_empty')
        usage = self._metric('cpu.stat', b'usage_usec')
        current = self._metric('memory.current')
        peak = self._metric('memory.peak')
        if self._populated():
            raise PlacementRefusal('delegated_service_not_empty')
        self._check_clock()
        observed = monotonic_ns()
        if observed >= self._window.cleanup_until_ns:
            raise TimeoutError('delegated_service_final_accounting_late')
        return ServiceMeterReading(observed, self._leaf, usage, current, peak, False)

    def adopt_gated_child(self, *, pid, pidfd):
        """Bind one already-confined, still-gated direct child before effects."""
        if self._bootstrap_attempted:
            # The staging context owns its bootstrap and always reaps it.
            # A waitable pidfd is not an authenticated worker release.
            raise PlacementRefusal('delegated_service_bootstrap_release_unavailable')
        if self._child is not None or self._finished:
            raise PlacementRefusal('delegated_service_child_already_bound')
        if type(pid) is not int or pid <= 0 or type(pidfd) is not int or pidfd < 3 or os.get_inheritable(pidfd):
            raise PlacementRefusal('delegated_service_child_mismatch')
        with ExitStack() as borrowed:
            pin = _duplicate(borrowed, pidfd)
            adopted = self._verify_gated_child(pid, pin, self._leaf_membership())
            self._owned.enter_context(borrowed.pop_all())
            self._child, self._adopted = pin, adopted

    def _verify_gated_child(self, pid, pin, membership):
        self._check_leaf()
        if (os.readlink(f'/proc/self/fd/{pin}') != 'anon_inode:[pidfd]'
                or int(_fields(f'/proc/self/fdinfo/{pin}')[b'Pid']) != pid):
            raise PlacementRefusal('delegated_service_child_mismatch')
        if self._member(pid) != membership:
            raise PlacementRefusal('delegated_service_child_outside_leaf')
        if os.waitid(os.P_PIDFD, pin, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            raise PlacementRefusal('delegated_service_child_unwaitable')
        observed = monotonic_ns()
        if observed >= self._window.active_until_ns:
            raise TimeoutError('delegated_service_admission_expired')
        return observed

    @contextmanager
    def stage_trusted_bootstrap(self):
        """Stage a fixed, blocked bootstrap in a venue-approved delegated leaf.

        Use this only when the appointed manager's policy authorizes
        bootstrap migration from inside the same parent. This context has
        no worker release operation and does not adopt a workload.
        """
        with self._place_bootstrap(lambda: _hold_bootstrap(self._timers, self._window)) as child:
            yield child

    @contextmanager
    def _place_bootstrap(self, hold):
        if self._bootstrap_attempted or self._child is not None or self._finished:
            raise PlacementRefusal('delegated_service_bootstrap_already_requested')
        self._check_leaf()
        source = self._member('self')
        parent = f'0::{self._parent.control_group}/'.encode('ascii')
        if not source.startswith(parent) or self._populated():
            raise PlacementRefusal('delegated_service_bootstrap_source_unapproved')
        if monotonic_ns() >= self._window.active_until_ns:
            raise TimeoutError('delegated_service_admission_expired')
        flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        control = os.open('cgroup.procs', flags, dir_fd=self._directory)
        placement_attempted = False
        placed_ns = child = None
        self._bootstrap_attempted = True
        try:
            if not stat.S_ISREG(os.fstat(control).st_mode) or _mount_id(control) != self._leaf.mount_id:
                raise PlacementRefusal('delegated_service_bootstrap_control_unverified')
            with hold() as child:
                self._verify_gated_child(child.pid, child.pidfd, source)
                if self._member('self') != source or self._populated():
                    raise PlacementRefusal('delegated_service_bootstrap_source_unapproved')
                if monotonic_ns() >= self._window.active_until_ns:
                    raise TimeoutError('delegated_service_admission_expired')
                data = f'{child.pid}\n'.encode('ascii')
                placement_attempted = True
                if os.write(control, data) != len(data):
                    raise PlacementRefusal('delegated_service_bootstrap_placement_unconfirmed')
                if self._metric('cgroup.procs') != child.pid:
                    raise PlacementRefusal('delegated_service_bootstrap_placement_unconfirmed')
                placed_ns = self._verify_gated_child(child.pid, child.pidfd, self._leaf_membership())
                yield child
        finally:
            try:
                os.close(control)
            finally:
                if placement_attempted:
                    try:
                        self._check_leaf()
                        populated = self._populated()
                        empty_ns = monotonic_ns()
                        if populated or empty_ns >= self._window.cleanup_until_ns:
                            raise PlacementRefusal('delegated_service_bootstrap_empty_unconfirmed')
                        reaped_ns = getattr(child, 'reaped_ns', None)
                        if (placed_ns is not None and type(reaped_ns) is int
                                and placed_ns <= reaped_ns <= empty_ns
                                and child.attempted is False):
                            self._unreleased = UnreleasedBootstrap(self._leaf, placed_ns, reaped_ns, empty_ns)
                    except (OSError, ValueError) as exc:
                        raise BootstrapCleanupUnconfirmed('delegated_service_bootstrap_cleanup_unconfirmed') from exc

    def _release_inputs(self, scope, deadline_ns, held):
        from .managed_cli import _TRUSTED_UID
        from .managed_executor import _BWRAP, _open_bwrap, _snapshot
        from .managed_service import ServiceScope, limits
        from .managed_service_scope import ServiceBundle
        from .original import Identity, _check

        if (type(scope) not in (ServiceScope, ServiceBundle) or self._scope_sha256 is None
                or scope.digest != self._scope_sha256 or scope.parent != self._parent
                or limits(scope) != self._limits or not scope.operations <= {'read', 'write'}
                or os.execve not in os.supports_fd):
            raise PlacementRefusal('delegated_service_release_scope_unsupported')

        plan = self._invocation.plan
        account = pwd.getpwnam(plan.principal)
        if (not plan.principal_uid or (account.pw_uid, account.pw_gid) != (plan.principal_uid, scope.principal_gid)):
            raise PlacementRefusal('delegated_service_release_principal_changed')
        _check_worker_identity(account.pw_uid, account.pw_gid)
        root = os.open(scope.root_directory, _DIR)
        held.callback(os.close, root)
        info = os.fstat(root)
        if ((info.st_dev, info.st_ino, info.st_uid) != (scope.root_device, scope.root_inode, _TRUSTED_UID)
                or info.st_mode & 0o022):
            raise PlacementRefusal('delegated_service_release_root_changed')
        if type(scope) is ServiceBundle:
            # Retain and recheck every descriptor against the protected scope's
            # exact inode, declared owner, and mode before it can be sent.
            streams = scope.retain(held).streams
        else:
            # The legacy single-file scope has no separate owner pin. Keep its
            # existing administrator-owned original boundary.
            original = os.dup(scope.original_fd)
            held.callback(os.close, original)
            replace(scope, original_fd=original).check_original()
            expected_mode = os.O_RDONLY if scope.mode == 'read' else os.O_RDWR
            device, inode = scope.original
            sample = _check(original, Identity(int(device), int(inode)), (expected_mode,))
            if sample.owner_uid != _TRUSTED_UID or sample.mode & 0o133:
                raise PlacementRefusal('delegated_service_release_original_untrusted')
            streams = {'stdin': original}

        executable = _snapshot(scope.root_directory + scope.executable, plan.executable_sha256, held)
        current_root = os.stat(scope.root_directory, follow_symlinks=False)
        if (current_root.st_dev, current_root.st_ino) != (info.st_dev, info.st_ino):
            raise PlacementRefusal('delegated_service_release_root_changed')
        sandbox = _open_bwrap(held)
        version = subprocess.run(
            [_BWRAP, '--version'], executable=f'/proc/self/fd/{sandbox}', pass_fds=(sandbox,),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={}, cwd='/', timeout=_remaining(deadline_ns), check=True,
        )
        parsed = re.fullmatch(rb'bubblewrap ([0-9]+)\.([0-9]+)\.([0-9]+)\n?', version.stdout)
        if parsed is None or tuple(map(int, parsed.groups())) < (0, 12, 0):
            raise PlacementRefusal('delegated_service_release_requires_bubblewrap_0_12')
        return account, (sandbox, executable, *(streams.get(slot) for slot in ('stdin', 'stdout', 'stderr')))

    def release_approved_child(self, scope, *, deadline_ns, approval, witness=None, on_released=None):
        """Release one verified worker with the approved descriptors and reap it.

        The appointed caller has already consumed the exact armed ticket.
        The bound scope supplies the executable and resource registrations.
        """
        if self._bootstrap_attempted or self._child is not None or self._finished or self._retirement_attempted:
            raise PlacementRefusal('delegated_service_bootstrap_already_requested')
        self._check_leaf()
        deadline = min(deadline_ns, self._window.active_until_ns)
        _remaining(deadline)
        with ExitStack() as held:
            account, descriptors = self._release_inputs(scope, deadline, held)
            gate = lambda: _hold_release(self._timers, self._window, account.pw_uid, account.pw_gid, deadline)
            with self._place_bootstrap(gate) as child:
                # Just before admitting effects, the selected account and the
                # live waitable child must still match the exact active cut.
                current = pwd.getpwnam(self._invocation.plan.principal)
                if (current.pw_uid, current.pw_gid) != (account.pw_uid, account.pw_gid):
                    raise PlacementRefusal('delegated_service_release_principal_changed')
                scope.check_original()
                self._adopted = self._verify_gated_child(child.pid, child.pidfd, self._leaf_membership())
                self._child_identity = service_process_identity(child.pid, child.pidfd)
                self._child = child.pidfd
                try:
                    with approval():
                        if witness is not None:
                            with ExitStack() as opened:
                                handles = [child.pidfd, self._directory]
                                for name in ('cgroup.procs', 'cgroup.events'):
                                    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                                 dir_fd=self._directory)
                                    opened.callback(os.close, fd)
                                    handles.append(fd)
                                witness(self._child_identity, self._leaf, handles, deadline)
                            self._verify_gated_child(child.pid, child.pidfd, self._leaf_membership())
                        child.release(descriptors, deadline)
                        if on_released is not None:
                            on_released(monotonic_ns())
                    return self._finish(child)
                except BaseException:
                    if child.attempted and self._populated() and self.stop_sent_ns is None:
                        self._stop()
                    raise
                finally:
                    self._child = None

    def _stop(self):
        self._check_leaf()
        if monotonic_ns() >= self._window.cleanup_until_ns:
            raise TimeoutError('delegated_service_stop_late')
        # This fd is the scoped kernel control, not a PID or parent-wide kill.
        if os.write(self._kill, b'1') != 1:
            raise OSError('delegated service stop was incomplete')
        self.stop_sent_ns = monotonic_ns()
        if self.stop_sent_ns >= self._window.cleanup_until_ns:
            raise TimeoutError('delegated_service_stop_late')

    def finish(self):
        """Wait, stop at cutoff when needed, and sample the retained empty leaf.

        Raises on an unverified outcome. A caller must continue its approved
        reconciliation if the manager times out or loses a required handle.
        """
        return self._finish()

    def _finish(self, gate=None):
        if self._child is None or self._finished:
            raise PlacementRefusal('delegated_service_child_not_waitable')
        self._finished = True
        self._check_leaf()
        if not self._timers.wait_for_child(self._child):
            self._stop()
            if not self._timers.wait_for_child(self._child, cleanup=True):
                raise TimeoutError('delegated_service_reap_unconfirmed')
        event = os.waitid(os.P_PIDFD, self._child, os.WEXITED | os.WNOHANG)
        terminal = monotonic_ns()
        if event is not None and gate is not None:
            gate.observe_reap(event)
        if event is None or terminal >= self._window.cleanup_until_ns:
            raise TimeoutError('delegated_service_reap_unconfirmed')
        identity = getattr(self, '_child_identity', None)
        if identity is not None and event.si_pid != identity.pid:
            raise PlacementRefusal('delegated_service_reaped_process_mismatch')
        dispositions = {os.CLD_EXITED: 'exited', os.CLD_KILLED: 'signaled', os.CLD_DUMPED: 'signaled'}
        disposition = dispositions.get(event.si_code)
        if disposition is None:
            raise PlacementRefusal('delegated_service_terminal_unverified')
        if self._populated() and self.stop_sent_ns is None:
            self._timers.wait_for_child()
            if self._populated():
                self._stop()
        while self._populated():
            left = self._window.cleanup_until_ns - monotonic_ns()
            if left <= 0:
                raise TimeoutError('delegated_service_empty_unconfirmed')
            sleep(min(left, 10_000_000) / 1_000_000_000)
        self._check_leaf()
        empty = monotonic_ns()
        if empty >= self._window.cleanup_until_ns:
            raise TimeoutError('delegated_service_empty_unconfirmed')
        end = self._sample_empty() if self._metered else None
        if end is not None and (end.usage_usec < self._begin.usage_usec
                                or end.memory_peak_bytes < self._begin.memory_peak_bytes):
            raise PlacementRefusal('delegated_service_accounting_regressed')
        active = 'empty_observed_before_cutoff' if empty < self._window.active_until_ns else 'unconfirmed'
        self._final = LeafObservation(self._key, self._clock, self._leaf, self._adopted, terminal,
                                      disposition, event.si_status, empty, self._begin, end, active,
                                      reaped_process=identity)
        return self._final

    def retire(self):
        """Remove the same verified empty leaf after its required final sample."""
        if self._final is None or self._retirement_attempted:
            raise PlacementRefusal('delegated_service_retirement_not_ready')
        return replace(self._final, retired_ns=self._remove_empty())

    def cancel_unstarted(self):
        """Retire an armed but still-unstarted empty leaf without admission."""
        if self._bootstrap_attempted or self._child is not None or self._finished or self._retirement_attempted:
            raise PlacementRefusal('delegated_service_cancellation_unverified')
        return self._remove_empty()

    def retire_unreleased(self):
        """Retire the exact empty leaf after its unreleased gate was reaped."""
        if (self._unreleased is None or self._child is not None or self._finished
                or self._retirement_attempted):
            raise PlacementRefusal('delegated_service_unreleased_unverified')
        return replace(self._unreleased, retired_ns=self._remove_empty())

    def _remove_empty(self):
        self._retirement_attempted = True
        self._check_leaf()
        with self._parent.directory() as parent:
            info = os.stat(self._unit, dir_fd=parent, follow_symlinks=False)
            if ((info.st_dev, info.st_ino) != (self._leaf.device, self._leaf.inode)
                    or self._populated() or monotonic_ns() >= self._window.cleanup_until_ns):
                raise PlacementRefusal('delegated_service_retirement_unverified')
            os.rmdir(self._unit, dir_fd=parent)
            try:
                os.stat(self._unit, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                self._check_clock()
                retired = monotonic_ns()
                if retired < self._window.cleanup_until_ns:
                    return retired
        raise PlacementRefusal('delegated_service_retirement_unverified')
