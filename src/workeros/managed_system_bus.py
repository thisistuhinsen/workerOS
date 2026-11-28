"""Bounded readback from the local systemd manager."""
from contextlib import ExitStack, contextmanager
from ctypes import (CDLL, POINTER, byref, c_char, c_char_p, c_int, c_size_t, c_uint32, c_uint64,
                    c_void_p, string_at)
import os
from select import poll
from time import monotonic_ns

from .managed_service_parent import ManagerObservation, PlacementRefusal, check_unit, pin_delegated_service

_SOCKET = b'unix:path=/run/dbus/system_bus_socket'
_SERVICE = b'org.freedesktop.systemd1'
_MANAGER_PATH = b'/org/freedesktop/systemd1'
_MANAGER = b'org.freedesktop.systemd1.Manager'
_DRIVER = b'org.freedesktop.DBus'
_DRIVER_PATH = b'/org/freedesktop/DBus'
_PROPERTIES = b'org.freedesktop.DBus.Properties'
_UNIT = b'org.freedesktop.systemd1.Unit'
_SLICE = b'org.freedesktop.systemd1.Slice'
_WORKER = b'org.freedesktop.systemd1.Service'
_UNIT_PATH = b'/org/freedesktop/systemd1/unit/'


def _check(result):
    if result < 0:
        raise OSError(-result, 'system manager call failed')


def _library():
    library = CDLL('libsystemd.so.0')
    pointer = POINTER(c_void_p)
    signatures = {
        'sd_bus_new': (c_int, (pointer,)),
        'sd_bus_set_address': (c_int, (c_void_p, c_char_p)),
        'sd_bus_set_bus_client': (c_int, (c_void_p, c_int)),
        'sd_bus_start': (c_int, (c_void_p,)),
        'sd_bus_unref': (c_void_p, (c_void_p,)),
        'sd_bus_message_new_method_call': (c_int, (c_void_p, pointer, c_char_p, c_char_p, c_char_p, c_char_p)),
        'sd_bus_message_append_basic': (c_int, (c_void_p, c_char, c_void_p)),
        'sd_bus_message_enter_container': (c_int, (c_void_p, c_char, c_char_p)),
        'sd_bus_message_exit_container': (c_int, (c_void_p,)),
        'sd_bus_message_read_array': (c_int, (c_void_p, c_char, pointer, POINTER(c_size_t))),
        'sd_bus_message_read_basic': (c_int, (c_void_p, c_char, c_void_p)),
        'sd_bus_message_unref': (c_void_p, (c_void_p,)),
        'sd_bus_call': (c_int, (c_void_p, c_void_p, c_uint64, c_void_p, pointer)),
    }
    for name, (result, args) in signatures.items():
        function = getattr(library, name)
        function.restype = result
        function.argtypes = args
    return library


class _Bus:
    def __init__(self, library, handle):
        self.lib = library
        self.handle = handle

    @contextmanager
    def message(self, member, *, destination=_DRIVER, path=_DRIVER_PATH, interface=_DRIVER):
        message = c_void_p()
        _check(self.lib.sd_bus_message_new_method_call(
            self.handle, byref(message), destination, path, interface, member))
        try:
            yield message
        finally:
            self.lib.sd_bus_message_unref(message)

    def append(self, message, value):
        _check(self.lib.sd_bus_message_append_basic(message, b's', c_char_p(os.fsencode(value))))

    def _read(self, reply, kind):
        if kind == b'ay':
            data, size = c_void_p(), c_size_t()
            count = self.lib.sd_bus_message_read_array(reply, b'y', byref(data), byref(size))
            if count != 1 or size.value != 16 or not data.value:
                raise OSError('system bus invocation ID was incomplete')
            return string_at(data, size.value).hex()
        fields = {b's': c_char_p, b'o': c_char_p, b'u': c_uint32, b'i': c_int, b'b': c_int, b't': c_uint64}
        field = fields[kind]()
        count = self.lib.sd_bus_message_read_basic(reply, kind, byref(field))
        if count != 1 or field.value is None:
            raise OSError('system bus reply was incomplete')
        return field.value

    def call(self, message, deadline_ns, *, response, variant=False):
        remaining = (deadline_ns - monotonic_ns()) // 1000
        if remaining <= 0:
            raise TimeoutError()
        reply = c_void_p()
        _check(self.lib.sd_bus_call(self.handle, message, remaining, None, byref(reply)))
        try:
            if variant and self.lib.sd_bus_message_enter_container(reply, b'v', response) != 1:
                raise OSError('system bus reply has the wrong property type')
            value = self._read(reply, response)
            if variant:
                _check(self.lib.sd_bus_message_exit_container(reply))
            return value
        finally:
            self.lib.sd_bus_message_unref(reply)

    def manager(self, deadline_ns):
        with self.message(b'GetNameOwner') as message:
            self.append(message, _SERVICE)
            owner = self.call(message, deadline_ns, response=b's')
        if not owner.startswith(b':'):
            raise OSError('system service manager identity unavailable')
        for member, expected in ((b'GetConnectionUnixProcessID', 1), (b'GetConnectionUnixUser', 0)):
            with self.message(member) as message:
                self.append(message, owner)
                if self.call(message, deadline_ns, response=b'u') != expected:
                    raise PermissionError('system service manager identity mismatch')
        return owner

    def unit(self, owner, name, deadline_ns):
        with self.message(b'GetUnit', destination=owner, path=_MANAGER_PATH, interface=_MANAGER) as message:
            self.append(message, name)
            path = self.call(message, deadline_ns, response=b'o')
        if not path.startswith(_UNIT_PATH):
            raise OSError('system manager unit path mismatch')
        return path

    def property(self, owner, path, interface, name, kind, deadline_ns):
        with self.message(b'Get', destination=owner, path=path, interface=_PROPERTIES) as message:
            self.append(message, interface)
            self.append(message, name)
            return self.call(message, deadline_ns, response=kind, variant=True)

    def check_parent(self, owner, parent, deadline_ns):
        if parent.delegated_service:
            raise PlacementRefusal('service_slice_observation_required')
        path = self.unit(owner, parent.unit, deadline_ns)
        get = self.property
        unit = get(owner, path, _UNIT, b'Id', b's', deadline_ns)
        state = get(owner, path, _UNIT, b'ActiveState', b's', deadline_ns)
        group = get(owner, path, _SLICE, b'ControlGroup', b's', deadline_ns)
        if (unit, state, group) != (parent.unit.encode(), b'active', parent.control_group.encode()):
            raise PlacementRefusal('service_parent_manager_mismatch')
        with parent.directory():
            pass

    def check_delegation(self, owner, parent, deadline_ns, *, guard_uid, metered, guard_pid):
        path = self.unit(owner, parent.unit, deadline_ns)

        def get(interface, name, kind):
            return self.property(owner, path, interface, name, kind, deadline_ns)

        def state():
            return (get(_UNIT, b'Id', b's'), get(_UNIT, b'ActiveState', b's'),
                    get(_UNIT, b'SubState', b's'), get(_WORKER, b'ControlGroup', b's'),
                    get(_WORKER, b'Delegate', b'b'), get(_WORKER, b'DelegateSubgroup', b's'),
                    get(_WORKER, b'MainPID', b'u'),
                    get(_UNIT, b'InvocationID', b'ay'))

        initial = state()
        subgroup, pid, invocation = initial[-3:]
        if (initial[:5] != (parent.unit.encode(), b'active', b'running', parent.control_group.encode(), 1)
                or pid <= 0 or guard_pid is not None and pid != guard_pid or invocation == '0' * 32):
            raise PlacementRefusal('service_parent_manager_mismatch')
        with ExitStack() as resources:
            pidfd = os.pidfd_open(pid)
            resources.callback(os.close, pidfd)
            live = poll()
            live.register(pidfd)
            if live.poll(0):
                raise PlacementRefusal('guard_manager_process_unverified')
            membership = _guard_process(pid, guard_uid)
            if membership != parent.control_group.encode('ascii') + b'/' + subgroup:
                raise PlacementRefusal('guard_manager_outside_approved_parent')
            with parent.directory() as directory:
                parent.check_delegated_root(directory, guard_uid, metered=metered)
                parent.check_guard_subgroup(directory, membership, pid, guard_uid)
            if state() != initial or _guard_process(pid, guard_uid) != membership or live.poll(0):
                raise PlacementRefusal('service_parent_changed_during_readback')
        if monotonic_ns() >= deadline_ns:
            raise TimeoutError()
        return invocation


def _guard_process(pid, guard_uid):
    def read(name):
        with open(f'/proc/{pid}/{name}', 'rb') as source:
            raw = source.read(16385)
        if len(raw) > 16384:
            raise PlacementRefusal('guard_manager_process_unverified')
        return raw.splitlines()

    uids = [line.split()[1:] for line in read('status') if line.startswith(b'Uid:')]
    membership = read('cgroup')
    if (uids != [[str(guard_uid).encode()] * 4] or len(membership) != 1
            or not membership[0].startswith(b'0::/')):
        raise PlacementRefusal('guard_manager_process_unverified')
    return membership[0][3:]


@contextmanager
def _system_bus():
    lib = _library()
    handle = c_void_p()
    _check(lib.sd_bus_new(byref(handle)))
    with ExitStack() as resources:
        resources.callback(lib.sd_bus_unref, handle)
        _check(lib.sd_bus_set_address(handle, _SOCKET))
        _check(lib.sd_bus_set_bus_client(handle, 1))
        _check(lib.sd_bus_start(handle))
        yield _Bus(lib, handle)


def verify_parent(parent, deadline_ns, *, guard_uid=None, metered=False, guard_pid=None):
    with _system_bus() as bus:
        owner = bus.manager(deadline_ns)
        if parent.delegated_service:
            return bus.check_delegation(owner, parent, deadline_ns, guard_uid=guard_uid, metered=metered,
                                        guard_pid=guard_pid)
        else:
            bus.check_parent(owner, parent, deadline_ns)


def discover_guard_parent(unit, deadline_ns, *, guard_uid, guard_pid):
    with _system_bus() as bus:
        owner = bus.manager(deadline_ns)
        path = bus.unit(owner, unit, deadline_ns)
        group = bus.property(owner, path, _WORKER, b'ControlGroup', b's', deadline_ns).decode('ascii')
        parent = pin_delegated_service(unit, group)
        invocation = bus.check_delegation(owner, parent, deadline_ns, guard_uid=guard_uid,
                                          metered=False, guard_pid=guard_pid)
        return parent, invocation

def observe(parent, unit, deadline_ns):
    check_unit(unit)
    with _system_bus() as bus:
        owner = bus.manager(deadline_ns)
        bus.check_parent(owner, parent, deadline_ns)
        path = bus.unit(owner, unit, deadline_ns)

        def get(interface, name, kind):
            return bus.property(owner, path, interface, name, kind, deadline_ns)

        identity = get(_UNIT, b'InvocationID', b'ay')
        group = parent.control_group + '/' + unit
        if (get(_UNIT, b'Id', b's') != unit.encode()
                or get(_WORKER, b'Slice', b's') != parent.unit.encode()
                or get(_WORKER, b'ControlGroup', b's') != group.encode()):
            raise PlacementRefusal('service_child_manager_mismatch')
        cgroup = parent.child_identity(unit)
        def process_state():
            return (
                get(_WORKER, b'ExecMainCode', b'i'),
                get(_WORKER, b'ExecMainStatus', b'i'),
                get(_WORKER, b'ExecMainExitTimestampMonotonic', b't') * 1_000,
                get(_UNIT, b'ActiveState', b's'),
                get(_UNIT, b'SubState', b's'),
                get(_WORKER, b'MainPID', b'u'),
            )

        state = process_state()
        if (get(_UNIT, b'InvocationID', b'ay') != identity
                or get(_WORKER, b'ControlGroup', b's') != group.encode()
                or parent.child_identity(unit) != cgroup
                or process_state() != state):
            raise PlacementRefusal('service_child_changed_during_readback')
        if monotonic_ns() >= deadline_ns:
            raise TimeoutError()
        return ManagerObservation(unit, identity, group, cgroup, *state)
