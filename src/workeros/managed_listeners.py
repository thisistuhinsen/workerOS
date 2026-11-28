"""Finite Unix listeners for commissioned local service endpoints."""

from contextlib import ExitStack, contextmanager
from dataclasses import replace
import errno
import os
from pathlib import PurePosixPath
import socket
import stat


class HolderEndpointRefusal(PermissionError):
    pass


def _require_no_acl(fd, name):
    try:
        os.getxattr(fd, name)
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            return
    raise HolderEndpointRefusal('holder_endpoint_directory_acl_unverified')


def _require_guard_traversal(fd):
    from .delegated_acl import _XATTR

    if not os.fstat(fd).st_mode & 0o001:
        raise HolderEndpointRefusal('holder_endpoint_guard_traversal_unverified')
    _require_no_acl(fd, _XATTR)


def _require_holder_directory(fd, guard_uid):
    from .delegated_acl import _XATTR, _acl

    try:
        exact = os.getxattr(fd, _XATTR) == _acl(guard_uid, 1, owner_access=7)
    except OSError as exc:
        raise HolderEndpointRefusal('holder_endpoint_directory_acl_unverified') from exc
    if not exact or stat.S_IMODE(os.fstat(fd).st_mode) != 0o710:
        raise HolderEndpointRefusal('holder_endpoint_directory_acl_unverified')
    _require_no_acl(fd, 'system.posix_acl_default')


def _grant_guard_connect(directory, name, guard_uid, bound):
    from .delegated_acl import _XATTR, _acl

    # The named inode is in the pinned directory. The sole extra principal
    # can search the directory but cannot replace or create an entry there.
    path = f'/proc/self/fd/{directory}/{name}'
    acl = _acl(guard_uid, 2)
    try:
        os.setxattr(path, _XATTR, acl, os.XATTR_CREATE, follow_symlinks=False)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if ((current.st_dev, current.st_ino, current.st_uid) != (bound.st_dev, bound.st_ino, bound.st_uid)
                or stat.S_IMODE(current.st_mode) != 0o620
                or os.getxattr(path, _XATTR, follow_symlinks=False) != acl):
            raise ValueError('socket permission mismatch')
    except (OSError, ValueError) as exc:
        raise HolderEndpointRefusal('holder_endpoint_socket_acl_unverified') from exc


def activation_descriptors(required, optional):
    """Take a finite set of named manager FDs; individual consumers verify their provenance."""
    pid, count, labels, pidfd_id = (os.environ.pop(key, '') for key in (
        'LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES', 'LISTEN_PIDFDID'))
    if not any((pid, count, labels, pidfd_id)) and not required:
        return {}
    names = labels.split(':')
    if (pid != str(os.getpid()) or count != str(len(names)) or len(set(names)) != len(names)
            or not required <= set(names) <= required | optional):
        raise ValueError('service_activation_descriptors_invalid')
    if pidfd_id:
        fd = os.pidfd_open(os.getpid())
        try:
            if pidfd_id != str(os.fstat(fd).st_ino):
                raise ValueError('service_activation_descriptors_invalid')
        finally:
            os.close(fd)
    descriptors = {name: fd for fd, name in enumerate(names, 3)}
    for fd in descriptors.values():
        os.set_inheritable(fd, False)
    return descriptors


_SLOT_PREFIX = 'workeros-original-'
ORIGINALS = frozenset(_SLOT_PREFIX + name for name in ('stdin', 'stdout', 'stderr'))


def bind_originals(scope, originals):
    """Bind names to process-local numbers without changing the registered resource digest."""
    from .managed_service_scope import ServiceBundle

    slots = scope.streams if type(scope) is ServiceBundle else {'stdin': scope.original_fd}
    if set(originals) != {_SLOT_PREFIX + slot for slot in slots}:
        raise ValueError('service_original_activation_mismatch')
    if type(scope) is ServiceBundle:
        entries = tuple(replace(item, fd=originals[_SLOT_PREFIX + item.slot]) for item in scope.descriptors)
        bound = replace(scope, descriptors=entries)
    else:
        bound = replace(scope, original_fd=originals[_SLOT_PREFIX + 'stdin'])
    if bound.digest != scope.digest:
        raise ValueError('service_original_activation_mismatch')
    bound.check_original()
    return bound


def open_registered_original(path, entry, held, *, observe=False):
    """Retain an appointed original using the endpoint's existing OS permissions."""
    from .managed_service_scope import _ACCESS

    target = PurePosixPath(path)
    if target.root != '/' or str(target) != path or len(target.parts) < 2 or '..' in target.parts:
        raise ValueError('service_original_path_invalid')
    expected = (entry.device, entry.inode, entry.owner_uid)
    entry = replace(entry, mode='read') if observe else entry
    directory = os.O_PATH | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as lookup:
        parent = os.open('/', directory)
        lookup.callback(os.close, parent)
        for part in target.parts[1:-1]:
            parent = os.open(part, directory, dir_fd=parent)
            lookup.callback(os.close, parent)
        pin = os.open(target.name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        lookup.callback(os.close, pin)
        info = os.fstat(pin)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_uid) != expected:
            raise ValueError('service_original_activation_mismatch')
        # Open the checked inode under the current principal without revisiting the name.
        flags = _ACCESS[entry.mode][0] | os.O_CLOEXEC | os.O_NONBLOCK
        fd = os.open(f'/proc/self/fd/{pin}', flags)
        held.callback(os.close, fd)
        replace(entry, fd=fd).check_original()
    return fd


@contextmanager
def registered_listener(path, owner, *, public=False, guard_uid=None):
    """Bind once in an existing protected directory and remove only our socket."""
    if type(path) is not str or not 0 < len(os.fsencode(path)) <= 107 or '\0' in path:
        raise ValueError('service_listener_path_invalid')
    target = PurePosixPath(path)
    if (str(target) != path or target.anchor != '/' or len(target.parts) < 3
            or '..' in target.parts or (public and owner != 0)):
        raise ValueError('service_listener_path_invalid')
    if guard_uid is not None and (type(guard_uid) is not int or not 0 < guard_uid < 2**32 - 1
                                  or guard_uid == owner or public):
        raise HolderEndpointRefusal('holder_endpoint_guard_untrusted')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as resources:
        directory = os.open('/', flags)
        resources.callback(os.close, directory)
        if guard_uid is not None:
            _require_guard_traversal(directory)
        ancestors = target.parts[1:-1]
        for index, part in enumerate(ancestors):
            directory = os.open(part, flags, dir_fd=directory)
            resources.callback(os.close, directory)
            info = os.fstat(directory)
            # A root-owned sticky transit directory cannot let a third UID
            # replace the next component, which is itself ownership-checked.
            sticky_transit = info.st_uid == 0 and info.st_mode & stat.S_ISVTX and index + 1 < len(ancestors)
            if info.st_uid not in (0, owner) or (info.st_mode & 0o022 and not sticky_transit):
                raise PermissionError('service_listener_directory_untrusted')
            if guard_uid is not None and index + 1 < len(ancestors):
                _require_guard_traversal(directory)
        if (info.st_uid != owner or os.getresuid() != (owner,) * 3
                or (not public and guard_uid is None and info.st_mode & 0o077)):
            raise PermissionError('service_listener_owner_mismatch')
        if guard_uid is not None:
            _require_holder_directory(directory, guard_uid)
        listener = resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        listener.bind(path)
        bound = None
        try:
            observed = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISSOCK(observed.st_mode) or observed.st_uid != owner:
                raise PermissionError('service_listener_owner_mismatch')
            bound = observed
            os.chmod(target.name, 0o666 if public else 0o600, dir_fd=directory, follow_symlinks=False)
            if guard_uid is not None:
                _grant_guard_connect(directory, target.name, guard_uid, bound)
            listener.listen()
            yield listener
        finally:
            if bound is not None:
                try:
                    current = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (bound.st_dev, bound.st_ino):
                        os.unlink(target.name, dir_fd=directory)
                except FileNotFoundError:
                    pass
