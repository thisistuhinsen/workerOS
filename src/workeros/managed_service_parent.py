"""Protected systemd parent and native cgroup identity checks."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import os
import re
import stat

from .scope_meter import CgroupIdentity, _cgroup_mount, _mount_id

_SLICE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,232}\.slice\Z')
_SERVICE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,232}\.service\Z')
_SUBGROUP = re.compile(rb'[A-Za-z0-9][A-Za-z0-9_.-]{0,232}\Z')
_UNIT = re.compile(r'workeros-[0-9a-f]{64}\.service\Z')
_NATIVE_ID = re.compile(r'[0-9a-f]{32}\Z')
_DEFAULTS = frozenset(('system.slice', 'user.slice', 'machine.slice'))
_CGROUP_ROOT = '/sys/fs/cgroup'
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class PlacementRefusal(ValueError):
    pass


def _identity(fd):
    info = os.fstat(fd)
    mount = _mount_id(fd)
    if not _cgroup_mount(mount):
        raise PlacementRefusal('service_cgroup_mount_unverified')
    return CgroupIdentity(info.st_dev, info.st_ino, mount)


@contextmanager
def _directory_for(parts):
    fd = os.open(_CGROUP_ROOT, _DIR)
    try:
        for part in parts:
            child = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@dataclass(frozen=True, slots=True)
class ServiceParent:
    unit: str
    control_group: str
    device: int
    inode: int
    mount_id: int

    def __post_init__(self):
        if (type(self.unit) is not str or not (_SLICE.fullmatch(self.unit) or self.delegated_service)
                or self.unit in _DEFAULTS or type(self.control_group) is not str
                or not self.control_group.startswith('/')):
            raise PlacementRefusal('unsupported_service_parent')
        components = self.control_group[1:].split('/')
        if components[-1] != self.unit or any(
                not (_SLICE.fullmatch(part) or self.delegated_service and _SERVICE.fullmatch(part))
                for part in components[:-1]):
            raise PlacementRefusal('unsupported_service_parent')
        if (type(self.device) is not int or self.device < 0
                or any(type(value) is not int or value <= 0 for value in (self.inode, self.mount_id))):
            raise PlacementRefusal('invalid_service_parent_identity')

    @property
    def delegated_service(self):
        return _SERVICE.fullmatch(self.unit) is not None

    @property
    def identity(self):
        return CgroupIdentity(self.device, self.inode, self.mount_id)

    @contextmanager
    def directory(self):
        with _directory_for(self.control_group[1:].split('/')) as fd:
            if _identity(fd) != self.identity:
                raise PlacementRefusal('service_parent_identity_changed')
            yield fd

    def retired_child_absent(self, unit):
        """Corroborate present absence on the pinned cgroup mount."""
        check_unit(unit)
        with _directory_for(()) as root, ExitStack() as opened:
            fd = root
            for part in self.control_group[1:].split('/'):
                identity = _identity(fd)
                if (identity.device, identity.mount_id) != (self.device, self.mount_id):
                    return False
                try:
                    fd = os.open(part, _DIR, dir_fd=fd)
                except FileNotFoundError:
                    return True
                opened.callback(os.close, fd)
            if _identity(fd) != self.identity:
                return False
            try:
                os.stat(unit, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
        return False

    def _control(self, directory, name, *, owner=None):
        fd = os.open(name, _READ, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or _mount_id(fd) != self.mount_id
                    or owner is not None and (info.st_uid != owner or not info.st_mode & stat.S_IWUSR)):
                raise PlacementRefusal('service_parent_control_unverified')
            payload = os.read(fd, 8193)
            if len(payload) > 8192:
                raise PlacementRefusal('service_parent_control_unverified')
            return payload
        finally:
            os.close(fd)

    def check_delegated_root(self, directory, guard_uid, *, metered):
        if not self.delegated_service or type(guard_uid) is not int or guard_uid <= 0:
            raise PlacementRefusal('service_guard_delegated_parent_required')
        try:
            delegated = os.getxattr(directory, 'user.delegate') == b'1'
        except OSError as exc:
            raise PlacementRefusal('service_parent_delegation_unverified') from exc
        info = os.fstat(directory)
        owner_rights = stat.S_IWUSR | stat.S_IXUSR
        if (_identity(directory) != self.identity or info.st_uid != guard_uid
                or info.st_mode & owner_rights != owner_rights or not delegated
                or self._control(directory, 'cgroup.type').strip() != b'domain'
                or self._control(directory, 'cgroup.procs', owner=guard_uid).strip()):
            raise PlacementRefusal('service_parent_delegation_unverified')
        if metered and b'memory' not in self._control(directory, 'cgroup.subtree_control').split():
            raise PlacementRefusal('service_parent_memory_controller_unavailable')

    def check_guard_subgroup(self, directory, membership, pid, guard_uid):
        prefix = self.control_group.encode('ascii') + b'/'
        subgroup = membership.removeprefix(prefix)
        if (not membership.startswith(prefix) or not _SUBGROUP.fullmatch(subgroup)
                or _UNIT.fullmatch(subgroup.decode('ascii'))):
            raise PlacementRefusal('guard_manager_outside_approved_parent')
        fd = os.open(subgroup, _DIR, dir_fd=directory)
        try:
            group = _identity(fd)
            if ((group.device, group.mount_id) != (self.device, self.mount_id)
                    or os.fstat(fd).st_uid != guard_uid
                    or str(pid).encode('ascii') not in self._control(fd, 'cgroup.procs').splitlines()):
                raise PlacementRefusal('guard_manager_outside_approved_parent')
        finally:
            os.close(fd)

    def child_identity(self, unit):
        check_unit(unit)
        with self.directory() as parent, ExitStack() as resources:
            child = os.open(unit, _DIR, dir_fd=parent)
            resources.callback(os.close, child)
            identity = _identity(child)
            if identity.mount_id != self.mount_id:
                raise PlacementRefusal('service_child_mount_changed')
            return identity

def decode_parent(value):
    if type(value) is dict:
        try:
            return ServiceParent(**value)
        except TypeError as exc:
            raise PlacementRefusal('invalid_service_parent_identity') from exc
    if value is not None and type(value) is not ServiceParent:
        raise PlacementRefusal('invalid_service_parent_identity')
    return value


def check_unit(unit):
    if type(unit) is not str or not _UNIT.fullmatch(unit):
        raise PlacementRefusal('invalid_service_unit')


def pin_delegated_service(unit, group):
    # Validate the manager's path before any relative open.
    stub = ServiceParent(unit, group, 0, 1, 1)
    if not stub.delegated_service:
        raise PlacementRefusal('service_guard_delegated_parent_required')
    with _directory_for(group[1:].split('/')) as fd:
        pin = _identity(fd)
    return ServiceParent(unit, group, pin.device, pin.inode, pin.mount_id)


@dataclass(frozen=True, slots=True)
class ManagerObservation:
    """One direct read of a retained service at its exact kernel placement."""

    unit: str
    invocation_id: str
    control_group: str
    cgroup: CgroupIdentity
    exit_code: int
    exit_status: int
    exit_ns: int
    active_state: bytes
    sub_state: bytes
    main_pid: int

    def __post_init__(self):
        check_unit(self.unit)
        if (type(self.invocation_id) is not str or not _NATIVE_ID.fullmatch(self.invocation_id)
                or self.invocation_id == '0'*32 or type(self.cgroup) is not CgroupIdentity):
            raise PlacementRefusal('service_manager_identity_unverified')
        if any(type(value) is not int or value < 0 for value in (self.exit_code, self.exit_status, self.exit_ns)):
            raise PlacementRefusal('service_manager_terminal_unverified')
        if (type(self.active_state) is not bytes or type(self.sub_state) is not bytes
                or type(self.main_pid) is not int or self.main_pid < 0):
            raise PlacementRefusal('service_manager_state_unverified')

    def matches(self, parent, report, *, terminal):
        lifecycle = report.lifecycle
        if (self.unit != report.unit or self.invocation_id != report.invocation_id
                or self.control_group != parent.control_group + '/' + self.unit
                or lifecycle is None or self.cgroup != lifecycle.cgroup):
            return False
        if not terminal:
            return (lifecycle.terminal_ns is None and self.active_state == b'active' and self.sub_state == b'running'
                    and self.main_pid > 0 and self.exit_code == self.exit_status == self.exit_ns == 0)
        disposition = {1: 'exited', 2: 'signaled', 3: 'signaled'}.get(self.exit_code)
        return (lifecycle.terminal_ns is not None and disposition is not None
                and disposition == lifecycle.terminal_disposition and self.exit_status == lifecycle.terminal_status
                and lifecycle.start_ns <= self.exit_ns <= lifecycle.terminal_ns and self.exit_ns > 0)
