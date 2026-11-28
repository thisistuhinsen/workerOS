"""Activate one commissioned result witness for a guarded invocation."""

import argparse
from array import array
from contextlib import ExitStack
from dataclasses import asdict
import os
import re
import socket
from time import monotonic_ns
from uuid import uuid4

from . import managed_cli
from .managed_executor import _remaining
from .managed_launch import LaunchInvocation, LaunchPlan, ServiceProcessIdentity
from .managed_listeners import activation_descriptors, open_registered_original, registered_listener
from .managed_provider import _read_registration
from .managed_service_client import _frame_read, _frame_write, _peer
from .managed_service_scope import ServiceBundle
from .managed_service_witness import observe_effect_cleanup, serve_witness_result
from .roles_cli import _fields
from .scope_meter import CgroupIdentity
from .verify_install import verify_install


def validate_scope(config, scope):
    if config.get('handoff') is not True:
        return
    if (type(scope) is not ServiceBundle or scope.parent is None or not scope.parent.delegated_service
            or not any(item.slot == 'stdout' and 'write' in item.operations for item in scope.descriptors)):
        raise ValueError('service_witness_scope_unverified')


class WitnessHandoff:
    """One attempt connection from the enrolled guard to the appointed witness."""

    def __init__(self, config, invocation, service, run_id, held):
        self.config, self.invocation, self.service, self.run_id = config, invocation, service, run_id
        self.held = held
        self.connection = None
        self.nonce = uuid4().hex

    def activate(self, process, leaf, handles, deadline_ns):
        deadline = deadline_ns / 1_000_000_000
        connection = self.held.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        connection.settimeout(_remaining(deadline))
        connection.connect(self.config['socket'])
        if _peer(connection) != self.config['uid']:
            raise PermissionError('service_witness_peer_untrusted')
        self.connection = connection
        _frame_write(connection, {
            'version': 1, 'operation': 'observe_attempt', 'nonce': self.nonce,
            'invocation': asdict(self.invocation), 'service': self.service, 'manager_run_id': self.run_id,
            'process': asdict(process), 'leaf': asdict(leaf),
        }, deadline)
        connection.settimeout(_remaining(deadline))
        rights = array('i', handles)
        if connection.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != 1:
            raise OSError('service_witness_delivery_unconfirmed')
        self._confirm('ready', deadline_ns)

    def _confirm(self, phase, deadline_ns):
        frame = _frame_read(self.connection, deadline_ns / 1_000_000_000)
        if frame != {'nonce': self.nonce, 'phase': phase}:
            raise ValueError('service_witness_confirmation_unbound')

    def captured(self):
        end = self.invocation.service_window.cleanup_until_ns
        now = monotonic_ns()
        # Two serial steps remain: witness capture and native retirement.
        # Allocate them within the time actually left on the original clock.
        self._confirm('captured', now + (end - now) // 2)

    def closed(self):
        self._confirm('closed', self.invocation.service_window.cleanup_until_ns)


def _receive_handles(peer, deadline, held):
    fds = array('i')
    peer.settimeout(_remaining(deadline))
    data, control, flags, _ = peer.recvmsg(1, socket.CMSG_SPACE(4 * fds.itemsize), socket.MSG_CMSG_CLOEXEC)
    for level, kind, raw in control:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            fds.frombytes(raw[:len(raw) - len(raw) % fds.itemsize])
    for fd in fds:
        held.callback(os.close, fd)
    if (data != b'F' or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(control) != 1 or len(fds) != 4):
        raise ValueError('service_witness_delivery_invalid')
    return fds


def serve_attempt(peer, enrollment, config, output_fd, output_owner, activation_ns, expires_ns):
    if _peer(peer) != enrollment.caller_uid:
        raise PermissionError('service_witness_peer_untrusted')
    admission = activation_ns / 1_000_000_000
    request = _frame_read(peer, admission)
    _fields(request, ('version', 'operation', 'nonce', 'invocation', 'service', 'manager_run_id', 'process', 'leaf'))
    nonce = request['nonce']
    if (type(request['version']) is not int or request['version'] != 1 or request['operation'] != 'observe_attempt'
            or type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None
            or type(request['manager_run_id']) is not str
            or re.fullmatch('[0-9a-f]{32}', request['manager_run_id']) is None
            or request['manager_run_id'] == '0' * 32):
        raise ValueError('service_witness_attempt_invalid')
    wire = request['invocation']
    _fields(wire, ('profile_identity', 'clock_id', 'plan', 'service_window'))
    invocation = LaunchInvocation(wire['profile_identity'], wire['clock_id'], LaunchPlan(**wire['plan']),
                                  wire['service_window'])
    if (not enrollment.matches(invocation, request['service'])
            or invocation.service_window.active_until_ns >= expires_ns):
        raise ValueError('service_witness_attempt_unbound')
    process = ServiceProcessIdentity(**request['process'])
    leaf = CgroupIdentity(**request['leaf'])
    window = invocation.service_window

    def respond(phase, deadline_ns):
        _frame_write(peer, {'nonce': nonce, 'phase': phase}, deadline_ns / 1_000_000_000)

    with ExitStack() as received:
        pidfd, leaf_fd, procs_fd, events_fd = _receive_handles(
            peer, min(admission, window.active_until_ns / 1_000_000_000), received)
        # Transfer the original and the four received handles to the witness.
        # It closes all five before sealing the result.
        output_owner.pop_all()
        received.pop_all()
        result = observe_effect_cleanup(
            invocation, enrollment.scope, request['manager_run_id'], pid=process.pid, pidfd=pidfd,
            leaf_fd=leaf_fd, procs_fd=procs_fd, events_fd=events_fd, output_fd=output_fd,
            source=config['source'], endpoint=config['socket'], expected_effect_sha256=config['expected_effect_sha256'],
            ready=lambda: respond('ready', window.active_until_ns),
            empty_ready=lambda: respond('captured', window.cleanup_until_ns), expected_process=process,
            expected_leaf=leaf)
    try:
        respond('closed', window.cleanup_until_ns)
    except OSError:
        # A lost acknowledgement does not erase independently held evidence.
        pass
    return result


def main(argv):
    from .managed_guard_server import GuardEnrollment, _approved_identity
    from .managed_registration import _service_registration
    from .recording import _name

    parser = argparse.ArgumentParser(prog='workeros managed serve-witness',
                                     description='Observe one approved guarded run and serve its retained result.')
    parser.add_argument('--commissioned', required=True, metavar='WORKFLOW')
    parser.add_argument('--observed-output', metavar='ABSOLUTE_PATH')
    args = parser.parse_args(argv)
    try:
        workflow = _name(args.commissioned)
        with ExitStack() as held:
            required = {'workeros-setup', 'workeros-executor'}
            if args.observed_output is None:
                required.add('workeros-observed-output')
            descriptors = activation_descriptors(required, frozenset())
            output_fd = descriptors.pop('workeros-observed-output', None)
            output_owner = held.enter_context(ExitStack())
            if output_fd is not None:
                output_owner.callback(os.close, output_fd)
            for fd in descriptors.values():
                held.callback(os.close, fd)
            setup = _read_registration(descriptors['workeros-setup'])
            executor = _read_registration(descriptors['workeros-executor'])
            if type(executor['version']) is not int or executor['version'] != 2:
                raise ValueError('service_witness_registration_invalid')
            entry = executor['workflows'][workflow]
            config, guard = entry['result_observer'], entry['authority']
            policy, scope = _service_registration(entry, workflow, local_observer=True)
            if config.get('handoff') is not True or os.getresuid() != (config['uid'],) * 3:
                raise PermissionError('service_witness_identity_untrusted')
            verify_install(executor['wheel_path'], executor['wheel_sha256'])
            definition, clock, identity = _approved_identity(setup, executor, policy)
            if output_fd is None:
                output = next(item for item in scope.descriptors if item.slot == 'stdout')
                output_fd = open_registered_original(args.observed_output, output, output_owner, observe=True)
            enrollment = GuardEnrollment(policy, scope, identity, clock, guard['uid'])
            activation = min(definition.expires_ns, monotonic_ns() + int(managed_cli._TIMEOUT * 1_000_000_000))
            with registered_listener(config['socket'], config['uid'], guard_uid=guard['uid']) as listener:
                result = None
                while result is None:
                    listener.settimeout(_remaining(activation / 1_000_000_000))
                    peer, _ = listener.accept()
                    with peer:
                        if _peer(peer) == guard['uid']:
                            result = serve_attempt(peer, enrollment, config, output_fd, output_owner, activation,
                                                   definition.expires_ns)
                while monotonic_ns() < definition.expires_ns:
                    try:
                        listener.settimeout(_remaining(definition.expires_ns / 1_000_000_000))
                        peer, _ = listener.accept()
                    except TimeoutError:
                        break
                    with peer:
                        try:
                            serve_witness_result(
                                peer, result, expires_ns=definition.expires_ns,
                                deadline_ns=monotonic_ns() + int(managed_cli._TIMEOUT * 1_000_000_000))
                        except (EOFError, OSError, ValueError, TypeError, KeyError):
                            continue
        return 0
    except (EOFError, OSError, ValueError, TypeError, KeyError):
        print('{"status":"unverified","code":"service_witness_unavailable"}')
        return 1
