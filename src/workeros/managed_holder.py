"""Transfer only the live originals of one approved workflow to its two consumers."""

import argparse
from array import array
from contextlib import ExitStack
import os
import re
import socket
from time import monotonic
from uuid import uuid4

from . import managed_cli
from .managed_executor import _remaining
from .managed_launch import GUARDED_SERVICE, LaunchRolePolicy, _uid
from .managed_listeners import (ORIGINALS, HolderEndpointRefusal, activation_descriptors, bind_originals,
                                open_registered_original, registered_listener)
from .managed_provider import _read_registration
from .managed_service_scope import ServiceBundle, _overflow_uid, _path
from .recording import _name
from .roles_cli import _canonical, _fields
from .verify_install import verify_install


class HolderDeliveryUnconfirmed(OSError):
    pass


def validate_holder(config, policy, scope, guard):
    _fields(config, ('uid', 'socket'))
    uid, endpoint = config['uid'], _path(config['socket'])
    _uid(uid)
    if (type(scope) is not ServiceBundle or scope.parent is None or guard.get('enforcement') != GUARDED_SERVICE
            or uid in (managed_cli._TRUSTED_UID, policy.principal_uid, guard['uid'], _overflow_uid())
            or endpoint == guard['socket'] or len(os.fsencode(endpoint)) > 107):
        raise ValueError('service_holder_registration_invalid')


def _pin(profile, revision, workflow, scope):
    return {'version': 1, 'profile': _name(profile), 'revision': _name(revision),
            'workflow': _name(workflow), 'scope_sha256': scope.digest}


def receive_originals(config, profile, revision, workflow, scope, resources, deadline):
    """Take bounded close-on-exec copies from the commissioned holder."""
    from .managed_service_client import _peer

    request = {**_pin(profile, revision, workflow, scope), 'nonce': uuid4().hex}
    names = sorted(scope.streams)
    fds = array('i')
    with ExitStack() as received, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(_remaining(deadline))
        peer.connect(config['socket'])
        if _peer(peer) != config['uid']:
            raise PermissionError('service_holder_peer_untrusted')
        from .managed_service_client import _frame_write

        _frame_write(peer, request, deadline)
        peer.settimeout(_remaining(deadline))
        data, control, flags, _ = peer.recvmsg(2, socket.CMSG_SPACE(len(names) * fds.itemsize),
                                               socket.MSG_CMSG_CLOEXEC)
        for level, kind, raw in control:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                delivered = array('i')
                delivered.frombytes(raw[:len(raw) - len(raw) % fds.itemsize])
                fds.extend(delivered)
                for fd in delivered:
                    received.callback(os.close, fd)
        if (data != b'F' or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(control) != 1 or len(fds) != len(names)):
            raise ValueError('service_holder_reply_invalid')
        originals = dict(zip(('workeros-original-' + name for name in names), fds, strict=True))
        bound = bind_originals(scope, originals)
        resources.enter_context(received.pop_all())
        return bound


def serve_originals(listener, scope, pin, allowed, *, deadline):
    """Supply one copy per entitled consumer. The holder retains every original."""
    from .managed_service_client import _frame_read, _peer

    served = set()
    unconfirmed = False
    while served != allowed:
        try:
            listener.settimeout(_remaining(deadline))
            connection, _ = listener.accept()
        except TimeoutError as exc:
            if served:
                raise HolderDeliveryUnconfirmed('service_holder_transfer_unconfirmed') from exc
            raise
        with connection:
            try:
                uid = _peer(connection)
                if uid not in allowed or uid in served:
                    continue
                request = _frame_read(connection, deadline)
                nonce = request.pop('nonce', None)
                if request != pin or type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
                    continue
                scope.check_original()
                rights = array('i', [scope.streams[name] for name in sorted(scope.streams)])
                connection.settimeout(_remaining(deadline))
            except (EOFError, OSError, ValueError, KeyError, TypeError):
                continue
            # A lost receiver acknowledgement never causes another transfer.
            served.add(uid)
            try:
                unconfirmed |= connection.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != 1
            except OSError:
                unconfirmed = True
    if unconfirmed:
        raise HolderDeliveryUnconfirmed('service_holder_transfer_unconfirmed')


def main(argv):
    parser = argparse.ArgumentParser(prog='workeros managed serve-holder',
                                     description='Supply live originals for one commissioned workflow.')
    parser.add_argument('--commissioned', required=True, metavar='WORKFLOW')
    for slot in ('stdin', 'stdout', 'stderr'):
        parser.add_argument(f'--original-{slot}', metavar='ABSOLUTE_PATH')
    args = parser.parse_args(argv)
    try:
        workflow = _name(args.commissioned)
        paths = {slot: path for slot in ('stdin', 'stdout', 'stderr')
                 if (path := getattr(args, f'original_{slot}')) is not None}
        with ExitStack() as held:
            descriptors = activation_descriptors({'workeros-executor'}, frozenset() if paths else ORIGINALS)
            for fd in descriptors.values():
                held.callback(os.close, fd)
            executor = _read_registration(descriptors.pop('workeros-executor'))
            if type(executor['version']) is not int or executor['version'] != 2:
                raise ValueError('service_holder_registration_invalid')
            entry = executor['workflows'][workflow]
            policy = LaunchRolePolicy(**entry['policy'])
            scope = ServiceBundle(**entry['service'])
            guard, holder = entry['authority'], entry['holder']
            validate_holder(holder, policy, scope, guard)
            if policy.workflow != workflow or os.getresuid() != (holder['uid'],) * 3:
                raise PermissionError('service_holder_identity_untrusted')
            verify_install(executor['wheel_path'], executor['wheel_sha256'])
            if paths:
                if paths.keys() != scope.streams.keys():
                    raise ValueError('service_original_activation_mismatch')
                descriptors = {
                    f'workeros-original-{item.slot}': open_registered_original(paths[item.slot], item, held)
                    for item in scope.descriptors
                }
            scope = bind_originals(scope, descriptors)
            pin = _pin(executor['profile'], executor['revision'], workflow, scope)
            with registered_listener(holder['socket'], holder['uid'], guard_uid=guard['uid']) as listener:
                serve_originals(listener, scope, pin, {managed_cli._TRUSTED_UID, guard['uid']},
                                deadline=monotonic() + managed_cli._TIMEOUT)
    except HolderDeliveryUnconfirmed:
        print('{"status":"unknown","effect":"unknown","code":"service_holder_transfer_unconfirmed"}')
        return 1
    except HolderEndpointRefusal:
        print('{"status":"refused","effect":"not_attempted","code":"service_holder_access_unverified"}')
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print('{"status":"refused","effect":"not_attempted","code":"service_holder_unavailable"}')
        return 1
    return 0
