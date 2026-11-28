"""Dispatch one protected, descriptor-scoped job to the existing system manager."""
from dataclasses import asdict, dataclass
import fcntl
from hashlib import sha256
import os
import stat
from time import monotonic_ns

from . import managed_system_bus
from .managed_launch import (GUARDED_SERVICE, LaunchRegistration, ManagedServiceEvidence, ServiceLimits,
                             UnreleasedServiceEvidence, _uid, launch_result)
from .managed_service_guard import GuardedServiceAuthority
from .managed_service_parent import PlacementRefusal, ServiceParent, check_unit, decode_parent
from .managed_service_scope import ServiceBundle, ServiceRefusal, _identity, _path
from .roles_cli import _canonical

_MANAGER_SOCKET = '/run/systemd/private'
_SYSTEM_BUS = '/run/dbus/system_bus_socket'


@dataclass(frozen=True, slots=True)
class ServiceScope:
    root_directory: str
    root_device: int
    root_inode: int
    executable: str
    principal_gid: int
    mode: str
    original_device: int
    original_inode: int
    original_fd: int
    limits: ServiceLimits | None = None
    parent: ServiceParent | None = None

    def __post_init__(self):
        _path(self.root_directory)
        _path(self.executable)
        for item in (self.root_device, self.root_inode, self.original_device, self.original_inode):
            _identity(item)
        _uid(self.principal_gid)
        if self.principal_gid == 0 or self.mode not in ('read', 'read-write'):
            raise ServiceRefusal('unsupported_service_access')
        if type(self.original_fd) is not int or self.original_fd < 3:
            raise ServiceRefusal('invalid_service_original')
        if type(self.limits) is dict:
            object.__setattr__(self, 'limits', ServiceLimits(**self.limits))
        if self.limits is not None and type(self.limits) is not ServiceLimits:
            raise ServiceRefusal('invalid_service_budget')
        object.__setattr__(self, 'parent', decode_parent(self.parent))

    @property
    def operations(self):
        return frozenset(('read', 'write') if self.mode == 'read-write' else ('read',))

    @property
    def original(self):
        return str(self.original_device), str(self.original_inode)

    @property
    def digest(self):
        record = {
            'version': 1, 'backend': 'systemd-fd', 'root_directory': self.root_directory,
            'root_device': self.root_device, 'root_inode': self.root_inode,
            'executable': self.executable, 'principal_gid': self.principal_gid, 'mode': self.mode,
            'original_device': self.original_device, 'original_inode': self.original_inode,
        }
        if self.limits is not None:
            record['limits'] = {'active_ms': self.limits.active_ms, 'cleanup_ms': self.limits.cleanup_ms,
                                'metered': self.limits.metered}
        if self.parent is not None:
            record['parent'] = asdict(self.parent)
        return sha256(_canonical(record)).hexdigest()

    def check_original(self):
        info = os.fstat(self.original_fd)
        flags = fcntl.fcntl(self.original_fd, fcntl.F_GETFL)
        required = os.O_RDWR if self.mode == 'read-write' else os.O_RDONLY
        if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (
                self.original_device, self.original_inode)
                or flags & (os.O_PATH | os.O_APPEND) or flags & os.O_ACCMODE != required):
            raise ServiceRefusal('service_original_mismatch')


def _system_manager():
    try:
        endpoints = [os.stat(path, follow_symlinks=False) for path in (_MANAGER_SOCKET, _SYSTEM_BUS)]
        namespaces = [
            (os.stat('/proc/1/ns/' + name), os.stat('/proc/self/ns/' + name))
            for name in ('mnt', 'time')
        ]
    except OSError as exc:
        raise ServiceRefusal('system_service_manager_unavailable') from exc
    if (any(not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 for endpoint in endpoints)
            or any((manager.st_dev, manager.st_ino) != (own.st_dev, own.st_ino)
                   for manager, own in namespaces)):
        raise ServiceRefusal('system_service_manager_unavailable')


def limits(scope):
    if type(scope) is ServiceBundle:
        return ServiceLimits(scope.active_ms, scope.cleanup_ms, scope.metered)
    return scope.limits


def _properties(scope, plan, streams, *, remaining_us, cleanup_us):
    if scope.parent is None:
        raise ServiceRefusal('service_parent_registration_required')
    if scope.parent.delegated_service:
        raise ServiceRefusal('service_slice_observation_required')
    properties = (
        ('Slice', b's', scope.parent.unit),
        ('Type', b's', 'exec'), ('RootDirectory', b's', scope.root_directory),
        ('WorkingDirectory', b's', '/'), ('User', b's', str(plan.principal_uid)), ('Group', b's', str(scope.principal_gid)),
        ('MountAPIVFS', b'b', False), ('ProtectSystem', b's', 'strict'),
        ('PrivateNetwork', b'b', True), ('PrivateDevices', b'b', True),
        ('NoNewPrivileges', b'b', True), ('RestrictNamespaces', b't', 0),
        ('CapabilityBoundingSet', b't', 0), ('AmbientCapabilities', b't', 0),
        ('KillMode', b's', 'control-group'), ('Restart', b's', 'no'),
        ('JobTimeoutUSec', b't', remaining_us), ('TimeoutStartUSec', b't', remaining_us),
        ('RuntimeMaxUSec', b't', remaining_us), ('TimeoutStopUSec', b't', cleanup_us),
        ('TimeoutStartFailureMode', b's', 'kill'), ('TimeoutStopFailureMode', b's', 'kill'),
        ('RemainAfterExit', b'b', True), ('CollectMode', b's', 'inactive'),
    )
    for slot, prop in (('stdin', 'StandardInput'), ('stdout', 'StandardOutput'), ('stderr', 'StandardError')):
        properties += ((prop + 'FileDescriptor', b'h', streams[slot]) if slot in streams
                       else (prop, b's', 'null'),)
    return properties


def prepare(scope, policy, authority, _resources, *, deadline_ns):
    """Verify placement before creating the locally reserved launch adapter."""
    bounds = limits(scope)
    if bounds is None:
        raise ServiceRefusal('service_limit_registration_required')
    if scope.parent is None:
        raise ServiceRefusal('service_parent_registration_required')
    guarded = type(authority) is GuardedServiceAuthority
    if guarded and not scope.parent.delegated_service:
        raise ServiceRefusal('service_guard_delegated_parent_required')
    if scope.parent.delegated_service and not guarded:
        raise ServiceRefusal('service_deadline_guard_provider_unavailable')
    _system_manager()
    try:
        if guarded:
            managed_system_bus.verify_parent(scope.parent, deadline_ns, guard_uid=authority.guard_uid,
                                             metered=bounds.metered)
        else:
            managed_system_bus.verify_parent(scope.parent, deadline_ns)
    except PlacementRefusal as exc:
        raise ServiceRefusal(str(exc)) from exc
    except TimeoutError as exc:
        raise ServiceRefusal('service_parent_verification_timed_out') from exc
    except OSError as exc:
        raise ServiceRefusal('service_parent_unavailable') from exc

    if not guarded:
        raise ServiceRefusal('service_deadline_guard_provider_unavailable')
    scope.check_original()
    return LaunchRegistration(policy, authority.authorize, authority.submit, authority.readback,
                              bounded=True, service_scope_sha256=scope.digest, service_limits=bounds,
                              service_enforcement=GUARDED_SERVICE, require_ticket_claim=True)


def _retired_leaf_absent(parent, unit, deadline_ns):
    check_unit(unit)
    if parent.delegated_service:
        _system_manager()
        return parent.retired_child_absent(unit) and monotonic_ns() < deadline_ns
    managed_system_bus.verify_parent(parent, deadline_ns)
    with parent.directory() as directory:
        try:
            os.stat(unit, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return monotonic_ns() < deadline_ns
    return False


def verify_native_readback(parent, result, deadline_ns, *, guarded=False):
    """Corroborate historical effects without inferring verified retirement."""
    observer_result = result.get('observer_result')
    if observer_result is not None:
        result = {key: value for key, value in result.items() if key != 'observer_result'}
    if result.get('code') == 'service_bootstrap_unreleased':
        try:
            from .managed_bootstrap import setup_clock_id

            proof = UnreleasedServiceEvidence(**result['unreleased'])
            if (guarded and parent is not None and proof.clock_id == setup_clock_id()
                    and (proof.cgroup.mount_id, proof.cgroup.device) == (parent.mount_id, parent.device)
                    and _retired_leaf_absent(parent, proof.unit, deadline_ns)):
                return result
        except (OSError, ValueError, TypeError, KeyError):
            pass
        return launch_result('unknown', 'unknown', 'service_unreleased_readback_unconfirmed',
                             request_id=result['request_id'], invocation_key=result['invocation_key'])
    if parent is None or result.get('effect') != 'dispatched':
        return result
    try:
        from .managed_bootstrap import setup_clock_id

        report = ManagedServiceEvidence(**result['service'])
        if report.lifecycle is None or report.lifecycle.clock_id != setup_clock_id():
            raise PlacementRefusal('service_native_clock_unconfirmed')
        if report.manager_run_id is not None:
            if (guarded and result['status'] == 'terminal' and report.lifecycle.retired_ns is not None
                    and (report.lifecycle.cgroup.mount_id, report.lifecycle.cgroup.device) ==
                    (parent.mount_id, parent.device)
                    and _retired_leaf_absent(parent, report.unit, deadline_ns)):
                # The reaped guard child can have exited before worker exec.
                # On failure preserve its local terminal evidence separately
                # from any matching output a witness might have observed.
                if (observer_result is not None and monotonic_ns() < observer_result['expires_ns']
                        and (report.lifecycle.terminal_disposition, report.lifecycle.terminal_status) == ('exited', 0)):
                    independent = dict(observer_result)
                    if 'cleanup_observation' in independent:
                        terminal_source = independent.pop('terminal_source')
                        return {**result, 'code': 'independent_service_result_verified',
                                'terminal_source': terminal_source, 'observer_result': independent}
                    observed_service = independent.pop('service')
                    return {**result, 'code': 'independent_service_result_verified', 'service': observed_service,
                            'receipt_sha256': independent['receipt_sha256'], 'observer_result': independent}
                return launch_result(
                    'unknown', 'unknown', 'service_terminal_reported', request_id=result['request_id'],
                    invocation_key=result['invocation_key'],
                    provider_report={'receipt_sha256': result['receipt_sha256'], 'service': result['service']})
            raise PlacementRefusal('service_manager_report_unconfirmed')
        _system_manager()
        terminal = result['status'] == 'terminal'
        try:
            observed = managed_system_bus.observe(parent, report.unit, deadline_ns)
        except OSError:
            if (guarded and terminal and report.lifecycle.retired_ns is not None
                    and _retired_leaf_absent(parent, report.unit, deadline_ns)):
                # Retain the authorized provider's distinct terminal, meter
                # and removal observations. Local absence corroborates only
                # removal now, not the earlier terminal or final sampling.
                return launch_result(
                    'unknown', 'unknown', 'service_terminal_reported', request_id=result['request_id'],
                    invocation_key=result['invocation_key'],
                    provider_report={'receipt_sha256': result['receipt_sha256'], 'service': result['service']})
            raise
        if not observed.matches(parent, report, terminal=terminal):
            raise PlacementRefusal('service_native_readback_mismatch')
    except (OSError, ValueError, TypeError, KeyError):
        return launch_result('unknown', 'unknown', 'service_native_readback_unconfirmed',
                             request_id=result['request_id'], invocation_key=result['invocation_key'])
    if terminal:
        # Native terminal while the group is present corroborates the effect,
        # but cannot establish later retirement. Do not release from a receipt
        # if the exact cgroup has disappeared before this native observation.
        return {**result, 'cleanup': 'unconfirmed', 'code': 'service_retirement_unconfirmed'}
    return result
