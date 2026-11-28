"""Protected descriptor contracts for a named systemd service."""

from contextlib import ExitStack
from dataclasses import asdict, dataclass, replace
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import re
import stat

from .configuration import ConfigurationError
from .enrollment import _budget
from .managed_launch import _uid
from .managed_service_parent import ServiceParent, decode_parent
from .recording import _name
from .roles_cli import _canonical, _operation_aliases


_PATH = re.compile(r'/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+')
_ACCESS = {
    'read': (os.O_RDONLY, ('read',)),
    'write': (os.O_WRONLY, ('write',)),
    'read-write': (os.O_RDWR, ('read', 'write')),
}
_SLOTS = ('stdin', 'stdout', 'stderr')


class ServiceRefusal(ValueError):
    pass


def _path(value):
    if (type(value) is not str or _PATH.fullmatch(value) is None
            or any(part in ('.', '..') for part in value.split('/'))):
        raise ServiceRefusal('invalid_service_path')
    return value


def _identity(value):
    if type(value) is not int or value < 0:
        raise ServiceRefusal('invalid_service_identity')
    return value


def _overflow_uid():
    try:
        value = int(Path('/proc/sys/kernel/overflowuid').read_text(encoding='ascii'))
        _uid(value)
    except (OSError, ValueError) as exc:
        raise ServiceRefusal('service_owner_identity_unavailable') from exc
    return value


@dataclass(frozen=True, slots=True)
class ServiceDescriptor:
    """One approved standard stream backed by an exact preheld regular file."""

    slot: str
    scope: str
    owner_uid: int
    mode: str
    device: int
    inode: int
    fd: int

    def __post_init__(self):
        if (type(self.slot) is not str or self.slot not in _SLOTS
                or type(self.mode) is not str or self.mode not in _ACCESS):
            raise ServiceRefusal('unsupported_service_access')
        _name(self.scope)
        _uid(self.owner_uid)
        _identity(self.device)
        _identity(self.inode)
        if type(self.fd) is not int or self.fd < 3:
            raise ServiceRefusal('invalid_service_original')

    @property
    def original(self):
        return str(self.device), str(self.inode)

    @property
    def operations(self):
        return frozenset(_ACCESS[self.mode][1])

    def check_original(self):
        try:
            info = os.fstat(self.fd)
            flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        except OSError as exc:
            raise ServiceRefusal('service_descriptor_mismatch') from exc
        if (not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino, info.st_uid) != (self.device, self.inode, self.owner_uid)
                or flags & (os.O_PATH | os.O_APPEND)
                or flags & os.O_ACCMODE != _ACCESS[self.mode][0]):
            raise ServiceRefusal('service_descriptor_mismatch')
        if self.owner_uid == _overflow_uid():
            raise ServiceRefusal('service_descriptor_owner_unmapped')


@dataclass(frozen=True, slots=True)
class ServiceCapability:
    """An approved role operation backed by one exact descriptor access mode."""

    name: str
    scope: str
    operation: str

    def __post_init__(self):
        _name(self.name)
        _name(self.scope)
        if self.operation not in ('read', 'write'):
            raise ServiceRefusal('unsupported_service_capability')


@dataclass(frozen=True, slots=True)
class ServiceBundle:
    """Protected manifest of distinct resource grants for one service invocation."""

    root_directory: str
    root_device: int
    root_inode: int
    executable: str
    principal_gid: int
    descriptors: tuple[ServiceDescriptor, ...]
    active_ms: int
    cleanup_ms: int
    metered: bool
    observation_scope: str | None = None
    parent: ServiceParent | None = None
    elevated_capabilities: tuple[ServiceCapability, ...] = ()

    def __post_init__(self):
        _path(self.root_directory)
        _path(self.executable)
        _identity(self.root_device)
        _identity(self.root_inode)
        _uid(self.principal_gid)
        if not self.principal_gid:
            raise ServiceRefusal('unsupported_service_principal')
        try:
            _budget(self.active_ms, 86_400_000)
            _budget(self.cleanup_ms, 60_000)
        except ConfigurationError as exc:
            raise ServiceRefusal('invalid_service_budget') from exc
        if type(self.metered) is not bool:
            raise ServiceRefusal('invalid_service_meter')
        entries = self.descriptors
        if type(entries) not in (list, tuple) or not 1 <= len(entries) <= len(_SLOTS):
            raise ServiceRefusal('invalid_service_descriptors')
        if type(entries) is list:
            if not all(type(entry) is dict for entry in entries):
                raise ServiceRefusal('invalid_service_descriptors')
            try:
                entries = tuple(ServiceDescriptor(**entry) for entry in entries)
            except TypeError as exc:
                raise ServiceRefusal('invalid_service_descriptors') from exc
        if not all(type(entry) is ServiceDescriptor for entry in entries):
            raise ServiceRefusal('invalid_service_descriptors')
        for field in ('slot', 'scope', 'owner_uid', 'fd', 'original'):
            if len({getattr(entry, field) for entry in entries}) != len(entries):
                raise ServiceRefusal('duplicate_service_descriptor')
        if self.observation_scope is not None:
            _name(self.observation_scope)
            if self.observation_scope not in {entry.scope for entry in entries}:
                raise ServiceRefusal('service_observation_scope_mismatch')
        object.__setattr__(self, 'descriptors', tuple(sorted(entries, key=lambda entry: _SLOTS.index(entry.slot))))
        object.__setattr__(self, 'parent', decode_parent(self.parent))
        capabilities = self.elevated_capabilities
        if type(capabilities) not in (list, tuple) or len(capabilities) > 64:
            raise ServiceRefusal('invalid_service_capabilities')
        if type(capabilities) is list:
            if not all(type(capability) is dict for capability in capabilities):
                raise ServiceRefusal('invalid_service_capabilities')
            try:
                capabilities = tuple(ServiceCapability(**capability) for capability in capabilities)
            except TypeError as exc:
                raise ServiceRefusal('invalid_service_capabilities') from exc
        allowed = {entry.scope: entry.operations for entry in entries}
        if (any(type(capability) is not ServiceCapability
                or capability.operation not in allowed.get(capability.scope, ()) for capability in capabilities)
                or len({capability.name for capability in capabilities}) != len(capabilities)):
            raise ServiceRefusal('service_capability_scope_mismatch')
        object.__setattr__(self, 'elevated_capabilities', tuple(sorted(capabilities, key=lambda value: value.name)))

    @property
    def digest(self):
        record = {
            'version': 1, 'backend': 'systemd-fd-bundle', 'root_directory': self.root_directory,
            'root_device': self.root_device, 'root_inode': self.root_inode, 'executable': self.executable,
            'principal_gid': self.principal_gid, 'descriptors': [
                {'slot': entry.slot, 'scope': entry.scope, 'owner_uid': entry.owner_uid,
                 'mode': entry.mode, 'device': entry.device, 'inode': entry.inode}
                for entry in self.descriptors
            ], 'observation_scope': self.observation_scope, 'active_ms': self.active_ms,
            'cleanup_ms': self.cleanup_ms, 'metered': self.metered,
        }
        if self.parent is not None:
            record['parent'] = asdict(self.parent)
        if self.elevated_capabilities:
            record['elevated_capabilities'] = [asdict(value) for value in self.elevated_capabilities]
        return sha256(_canonical(record)).hexdigest()

    @property
    def operations(self):
        return frozenset(operation for entry in self.descriptors for operation in entry.operations)

    @property
    def streams(self):
        return {entry.slot: entry.fd for entry in self.descriptors}

    @property
    def observation_original(self):
        if self.observation_scope is not None:
            return next(entry.original for entry in self.descriptors if entry.scope == self.observation_scope)
        return None

    def check_original(self):
        for entry in self.descriptors:
            entry.check_original()

    def match_role(self, role):
        """Check the protected role's grants without resolving caller-supplied paths."""
        if type(role) is not dict:
            return False
        scopes = role.get('scopes', ())
        operations = role.get('operations', ())
        resources = role.get('resources', {})
        if (type(scopes) is not list or type(operations) is not list or type(resources) is not dict
                or any(type(operation) is not str for operation in operations)):
            return False
        try:
            aliases = _operation_aliases(role)
        except ValueError:
            return False
        targeted = {entry.scope: entry.operations for entry in self.descriptors}
        alias_rights = {}
        requested = {(value['capability'], value['scope']) for value in role.get('privileged', ())
                     if value.get('approved') is True}
        if (len(requested) != len(role.get('privileged', ()))
                or requested != {(value.name, value.scope) for value in self.elevated_capabilities}):
            return False
        if aliases:
            pin = self.digest
            for binding in aliases.values():
                scope, capability = binding['scope'], binding['capability']
                if binding['provider_sha256'] != pin or capability not in targeted.get(scope, ()):
                    return False
                alias_rights.setdefault(scope, set()).add(capability)
        for value in self.elevated_capabilities:
            binding = aliases.get(value.name)
            if binding is None or (binding['scope'], binding['capability']) != (value.scope, value.operation):
                return False
        native = set(operations)
        for entry in self.descriptors:
            resource = resources.get(entry.scope)
            if (entry.scope not in scopes or type(resource) is not dict
                    or (resource.get('device'), resource.get('inode')) != entry.original
                    or not entry.operations <= native | alias_rights.get(entry.scope, set())):
                return False
            if 'owner_uid' in resource and (type(resource['owner_uid']) is not int
                                           or resource['owner_uid'] != entry.owner_uid):
                return False
        return True

    def retain(self, resources):
        """Acquire an all-or-nothing descriptor set in the caller's cleanup stack."""
        with ExitStack() as held:
            retained = []
            for entry in self.descriptors:
                try:
                    fd = fcntl.fcntl(entry.fd, fcntl.F_DUPFD_CLOEXEC, 3)
                except OSError as exc:
                    raise ServiceRefusal('service_descriptor_mismatch') from exc
                held.callback(os.close, fd)
                retained.append(replace(entry, fd=fd))
            bundle = replace(self, descriptors=tuple(retained))
            bundle.check_original()
            resources.enter_context(held.pop_all())
            return bundle
