"""No-start client for an administrator-commissioned local host integration."""
import argparse
from contextlib import ExitStack
from contextvars import ContextVar
import json
import os
import re
import socket
import stat
import struct
import sys
from time import monotonic, monotonic_ns

from .enrollment import decode_policy
from .recording import _name

_CONFIG_PARENT = '/etc'
_CONFIG_DIRECTORY = 'workeros'
_CONFIG_FILE = 'managed-host.json'
_TRUSTED_UID = 0
_LIMIT = 65536
_TIMEOUT = 5.0
_CHECK_WORK_DEADLINE = ContextVar("managed_binding_check_work_deadline", default=None)
_CHECK_BINDINGS = 'check-bindings'
_OPERATIONS = frozenset(('setup', 'readback', 'reconcile', _CHECK_BINDINGS))
_LOCAL_OPERATIONS = frozenset(('commission', 'commission-status', 'commission-apply',
                               'apply-profile', 'profile-status', 'revoke-profile'))
_REGISTRY_OPERATIONS = frozenset(('appointment-register', 'appointment-status'))
_STATES = frozenset(('accepted', 'refused', 'unknown', 'conflict', 'not_committed', 'recorded', 'absent'))
_EFFECTS = frozenset(('not_attempted', 'committed', 'not_committed', 'unknown'))
_CODES = frozenset(('manager_readback_verified', 'binding_generation_changed', 'commissioned_mapping_mismatch',
    'independent_evidence_invalid', 'profile_revoked', 'manager_selection_denied',
    'host_bindings_unavailable', 'manager_create_unconfirmed', 'reconciliation_required',
    'manager_readback_unavailable', 'role_appointment_unverified', 'role_appointment_mismatch',
    'scope_commit_verified', 'scope_commit_unconfirmed', 'scope_commit_unattributed',
    'scope_mapping_conflict', 'binding_check_only', 'file_acl_readback_unverified', 'other'))
_CHECK_BOUNDARY = {'effect': 'not_attempted', 'readiness': 'not_checked',
                   'independence': 'unverified', 'runtime_evidence': 'not_requested'}
_CHECK_REFUSALS = frozenset(('installed_package_unverified', 'profile_revoked', 'manager_selection_denied',
                            'commissioned_mapping_mismatch', 'host_bindings_unavailable',
                            'binding_generation_changed', 'role_appointment_unverified', 'role_appointment_mismatch',
                            'file_acl_readback_unverified'))
_CHECK_SCOPE_CODES = frozenset(('bindings_verified', 'manager_selection_unavailable',
                               'manager_selection_stale', 'manager_selection_denied',
                               'commissioned_mapping_mismatch', 'host_bindings_unavailable',
                               'binding_generation_changed', 'independent_evidence_invalid',
                               'independent_evidence_missing', 'other'))
_HASH = re.compile(r'[0-9a-f]{64}')


class Refusal(ValueError):
    pass


def _binding_check_time_available():
    deadline = _CHECK_WORK_DEADLINE.get()
    return deadline is None or monotonic() < deadline


def _safe_directory(fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != _TRUSTED_UID or info.st_mode & 0o022:
        raise Refusal('untrusted_configuration')


def _read_admin_json(filename, *, public=False):
    """Open only the fixed administrator-controlled configuration, no symlinks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as resources:
        parent = os.open(_CONFIG_PARENT, flags)
        resources.callback(os.close, parent)
        _safe_directory(parent)
        directory = parent
        if not public:
            directory = os.open(_CONFIG_DIRECTORY, flags, dir_fd=parent)
            resources.callback(os.close, directory)
            _safe_directory(directory)
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        resources.callback(os.close, fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _TRUSTED_UID
                or info.st_mode & 0o022 or info.st_nlink != 1
                or (public and info.st_mode & 0o444 != 0o444)):
            raise Refusal('untrusted_configuration')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(_LIMIT + 1)
    if len(data) > _LIMIT:
        raise Refusal('configuration_invalid')
    try:
        return decode_policy(data)
    except ValueError as exc:
        raise Refusal('configuration_invalid') from exc


def _configuration():
    config = _read_admin_json(_CONFIG_FILE)
    try:
        required = {'version','socket','peer_uid','profile','scopes','identity','operation_key'}
        if type(config) is not dict or not required <= config.keys() <= required | {'binding_check'}:
            raise ValueError()
        if type(config['version']) is not int or config['version'] != 1:
            raise ValueError()
        path = config['socket']
        if type(path) is not str or not path.startswith('/') or '\0' in path or len(os.fsencode(path)) > 107:
            raise ValueError()
        if type(config['peer_uid']) is not int or not 0 <= config['peer_uid'] < 2**32:
            raise ValueError()
        _name(config['profile'])
        for field in ('identity','operation_key'):
            if type(config[field]) is not str or not _HASH.fullmatch(config[field]): raise ValueError()
        scopes = config['scopes']
        if type(scopes) is not list or not scopes or len(scopes) > 64:
            raise ValueError()
        for scope in scopes: _name(scope)
        if len(set(scopes)) != len(scopes): raise ValueError()
        if 'binding_check' in config:
            pins = config['binding_check']
            if type(pins) is not dict or pins.keys() != {'revision', 'clock_id', 'scope_digests'}:
                raise ValueError()
            _name(pins['revision'])
            _name(pins['clock_id'])
            digests = pins['scope_digests']
            if (type(digests) is not dict or digests.keys() != set(scopes)
                    or any(type(value) is not str or not _HASH.fullmatch(value) for value in digests.values())):
                raise ValueError()
        return config
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise Refusal('configuration_invalid') from None


def _read_exact(sock, count, deadline):
    out = bytearray()
    while len(out) < count:
        remaining = deadline - monotonic()
        if remaining <= 0: raise TimeoutError()
        sock.settimeout(remaining)
        data = sock.recv(count - len(out))
        if not data: raise EOFError()
        out.extend(data)
    return bytes(out)


def _observation_times(observation):
    if type(observation) is not dict or observation.keys() != {'clock_id','start_ns','end_ns','valid_until_ns'}:
        raise ValueError()
    _name(observation['clock_id'])
    values = []
    for field in ('start_ns','end_ns','valid_until_ns'):
        value = observation[field]
        if type(value) is not str or not re.fullmatch(r'(?:0|[1-9][0-9]{0,18})', value):
            raise ValueError()
        values.append(int(value))
    start, end, until = values
    if not 0 <= start <= end < 2**63 or not 0 < until < 2**63:
        raise ValueError()
    return end, until


def _response(data, config):
    """Accept only bounded, fixed fields; never print arbitrary server text."""
    try:
        result = decode_policy(data)
        if type(result) is not dict or set(result) != {'version','profile','identity','operation_key','status','effect','scopes','observation'}:
            raise ValueError()
        if type(result['version']) is not int or result['version'] != 1 or result['profile'] != config['profile']:
            raise ValueError()
        if result['identity'] != config['identity'] or result['operation_key'] != config['operation_key']:
            raise ValueError()
        if result['status'] not in ('ready','incomplete','refused','unknown') or result['effect'] not in _EFFECTS:
            raise ValueError()
        scopes = result['scopes']
        if type(scopes) is not list or len(scopes) != len(config['scopes']): raise ValueError()
        found = set()
        for item in scopes:
            if type(item) is not dict or set(item) != {'name','setup','final','effect','code'}: raise ValueError()
            if item['name'] not in config['scopes'] or item['name'] in found: raise ValueError()
            if (item['setup'] not in _STATES or item['final'] not in _STATES | {'not_checked'}
                    or item['effect'] not in _EFFECTS or item['code'] not in _CODES): raise ValueError()
            found.add(item['name'])
        if result['status'] == 'ready' and any(x['setup'] != 'accepted' or x['final'] != 'accepted' for x in scopes):
            raise ValueError()
        observation = result['observation']
        if observation is not None:
            end, until = _observation_times(observation)
            if result['status'] == 'ready' and end >= until: raise ValueError()
        elif result['status'] == 'ready': raise ValueError()
        return result
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise Refusal('response_invalid') from None


def _binding_response(data, config):
    try:
        pins = config['binding_check']
        expected = {'version': 1, 'operation': _CHECK_BINDINGS, 'profile': config['profile'],
                    'identity': config['identity'], 'operation_key': config['operation_key'],
                    'revision': pins['revision'], **_CHECK_BOUNDARY}
        result = decode_policy(data)
        if (type(result) is not dict or result.keys() != expected.keys() | {'status','code','scopes','observation'}
                or type(result['version']) is not int
                or any(result[key] != value for key, value in expected.items())):
            raise ValueError()
        status, code, scopes, observation = (result[key] for key in ('status','code','scopes','observation'))
        if type(scopes) is not list:
            raise ValueError()
        if status == 'refused':
            if code not in _CHECK_REFUSALS or scopes or observation is not None:
                raise ValueError()
            return result
        if status not in ('bindings_verified','incomplete'):
            raise ValueError()
        digests = pins['scope_digests']
        seen = set()
        for scope in scopes:
            if type(scope) is not dict or scope.keys() != {'name','status','code','definition_sha256'}:
                raise ValueError()
            name, state, reason = scope['name'], scope['status'], scope['code']
            if (name in seen or scope['definition_sha256'] != digests[name]
                    or state not in ('bindings_verified','refused','unknown') or reason not in _CHECK_SCOPE_CODES
                    or (state == 'bindings_verified') != (reason == 'bindings_verified')):
                raise ValueError()
            seen.add(name)
        if seen != digests.keys():
            raise ValueError()
        if all(scope['status'] == 'bindings_verified' for scope in scopes):
            end, until = _observation_times(observation)
            if observation['clock_id'] != pins['clock_id'] or int(observation['start_ns']) >= until:
                raise ValueError()
            if status == 'bindings_verified' and (code is not None or end >= until):
                raise ValueError()
            if status == 'incomplete' and code != 'binding_evidence_expired':
                raise ValueError()
        elif (status, code, observation) != ('incomplete', None, None):
            raise ValueError()
        return result
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise Refusal('response_invalid') from None


def run(operation):
    """One authenticated request; a lost effectful reply requires reconciliation."""
    if operation not in _OPERATIONS: raise ValueError('unsupported operation')
    checking = operation == _CHECK_BINDINGS
    refusal_boundary = _CHECK_BOUNDARY if checking else {'effect':'not_attempted'}
    try:
        config = _configuration()
    except Refusal as exc:
        return {'status':'refused','code':str(exc),**refusal_boundary}
    except OSError:
        return {'status':'refused','code':'configuration_unavailable',**refusal_boundary}
    if checking and 'binding_check' not in config:
        return {'status':'refused', 'code':'binding_check_pins_required', **_CHECK_BOUNDARY}
    sent = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            deadline = monotonic() + _TIMEOUT
            client.settimeout(_TIMEOUT)
            client.connect(config['socket'])
            creds = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _, uid, _ = struct.unpack('3i', creds)
            if uid != config['peer_uid']:
                return {'status':'refused','code':'peer_untrusted',**refusal_boundary}
            payload = json.dumps({'version':1,'operation':operation,'profile':config['profile'],
                                  'identity':config['identity'],'operation_key':config['operation_key']}, separators=(',', ':')).encode()
            sent = True
            client.settimeout(max(0.001, deadline-monotonic()))
            client.sendall(struct.pack('!I',len(payload)) + payload)
            length = struct.unpack('!I', _read_exact(client,4,deadline))[0]
            if not 0 < length <= _LIMIT: raise Refusal('response_invalid')
            validate = _binding_response if checking else _response
            return validate(_read_exact(client,length,deadline), config)
    except (OSError, EOFError, TimeoutError, Refusal, AttributeError, struct.error):
        result = {'status':'unknown' if sent else 'refused', 'effect':'unknown' if sent else 'not_attempted',
                  'code':'response_unconfirmed' if sent else 'endpoint_unavailable'}
        if sent:
            result.update(identity=config['identity'], operation_key=config['operation_key'])
        if checking:
            result.update(_CHECK_BOUNDARY)
        return result


def serve_connection(connection, *, authorized_uids, adapter, check_only=False):
    """Serve one already-accepted socket in an existing trusted host.

    The host supplies the fixed commissioned adapter; the request never selects
    code or resources. The host owns persistence, authorization, time bounds
    for host operations and reconciliation. No listener or privilege is created.
    """
    from .managed_host import ManagedHostAdapter
    if (type(authorized_uids) is not frozenset or not authorized_uids or
            any(type(uid) is not int or uid < 0 for uid in authorized_uids) or type(adapter) is not ManagedHostAdapter
            or type(check_only) is not bool):
        raise ValueError('invalid host registration')
    creds = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _, uid, _ = struct.unpack('3i', creds)
    if uid not in authorized_uids:
        raise PermissionError('caller not authorized')
    deadline = monotonic() + _TIMEOUT
    length = struct.unpack('!I', _read_exact(connection, 4, deadline))[0]
    if not 0 < length <= _LIMIT: raise Refusal('request_invalid')
    request = decode_policy(_read_exact(connection, length, deadline))
    if (type(request) is not dict or set(request) != {'version','operation','profile','identity','operation_key'}
            or type(request['version']) is not int or request['version'] != 1
            or request['profile'] != adapter.profile or request['identity'] != adapter.identity
            or request['operation_key'] != adapter.operation_key or request['operation'] not in _OPERATIONS):
        raise Refusal('request_invalid')
    config = {'profile': adapter.profile, 'identity':adapter.identity, 'operation_key':adapter.operation_key,
              'scopes': [scope.name for scope in adapter.scopes]}
    operation = request['operation']
    checking = operation == _CHECK_BINDINGS
    if checking:
        config['binding_check'] = adapter.binding_check_pins()
        # Scope the existing reply deadline to this read-only request without
        # changing adapter or provider protocols.
        work_deadline = deadline
        enclosing_deadline = _CHECK_WORK_DEADLINE.get()
        if enclosing_deadline is not None:
            work_deadline = min(work_deadline, enclosing_deadline)
        token = _CHECK_WORK_DEADLINE.set(work_deadline)
        try:
            checked = adapter.check_bindings()
        finally:
            _CHECK_WORK_DEADLINE.reset(token)
        result = {'code': None, 'scopes': [], 'observation': None, **checked,
                  'version': 1, 'operation': operation, 'operation_key': adapter.operation_key}
        result.pop('next_action', None)  # The client supplies its own guidance.
        validate = _binding_response
    elif check_only:
        result = adapter._approval_refusal('binding_check_only')
        validate = _response
    else:
        # If this callback raises, setup may already have had an effect.
        result = {'setup':adapter.setup,'readback':adapter.readback,'reconcile':adapter.reconcile}[operation]()
        validate = _response
    encoded = json.dumps(result, separators=(',', ':'), ensure_ascii=True).encode()
    if len(encoded) > _LIMIT: raise Refusal('response_invalid')
    validate(encoded, config)
    # Scope evidence can expire during serialization. Check again immediately
    # before dispatch; this is an observation, not a promise through delivery.
    if result['status'] in ('ready', 'bindings_verified') and monotonic_ns() >= int(result['observation']['valid_until_ns']):
        result['status'] = 'incomplete'
        if checking:
            result['code'] = 'binding_evidence_expired'
        encoded = json.dumps(result, separators=(',', ':'), ensure_ascii=True).encode()
        validate(encoded, config)
    remaining = deadline - monotonic()
    if remaining <= 0: raise TimeoutError()
    connection.settimeout(remaining)
    connection.sendall(struct.pack('!I', len(encoded)) + encoded)


def serve_listener_once(listener, *, authorized_uids, adapter, accept_timeout=5.0, check_only=False):
    """Serve one request on a host-owned listening Unix socket, then return.

    The trusted host supplies the already commissioned adapter and listener.
    This function creates no socket path, service, provider or authority. The
    caller owns listener lifecycle and may invoke it again for another request.
    """
    from .managed_host import ManagedHostAdapter
    if (not isinstance(listener, socket.socket) or listener.family != socket.AF_UNIX
            or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            or type(authorized_uids) is not frozenset or not authorized_uids
            or any(type(uid) is not int or uid < 0 for uid in authorized_uids)
            or type(adapter) is not ManagedHostAdapter
            or type(accept_timeout) not in (int, float) or not 0 < accept_timeout <= _TIMEOUT
            or type(check_only) is not bool):
        raise ValueError('invalid host registration')
    original_timeout = listener.gettimeout()
    try:
        listener.settimeout(accept_timeout)
        connection, _ = listener.accept()
        with connection:
            serve_connection(connection, authorized_uids=authorized_uids, adapter=adapter, check_only=check_only)
    finally:
        listener.settimeout(original_timeout)


def _commission_document(argv, *, acl_registrations):
    from hashlib import sha256

    from . import roles_cli
    from .cli import InputError, _yaml_to_json
    from .recording import RecordError

    parser = argparse.ArgumentParser(prog='workeros managed apply-profile',
                                     description='Apply and read back an approved profile and its registered grants.')
    parser.add_argument('--format', choices=('json', 'yaml'), default='json')
    parser.add_argument('--preview', action='store_true', help='validate and show digests without writing')
    registered = parser.add_mutually_exclusive_group()
    registered.add_argument('--registered-file-acl', action='store_true',
                            help='require the administrator-owned file-acl-registrations.json approval')
    registered.add_argument('--registered-managed', action='store_true',
                            help='match protected managed-setup and launch-executor pins without starting work')
    registered.add_argument('--provision-managed', action='store_true',
                            help='provision absent protected registrations from one approved administrator bundle')
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(_LIMIT + 1)
        if len(raw) > _LIMIT:
            raise roles_cli.Refusal('document_too_large')
        data = _yaml_to_json(raw) if args.format == 'yaml' else raw
    except (roles_cli.Refusal, InputError) as exc:
        result = roles_cli._commission_result('refused', 'not_attempted', code=str(exc))
    except OSError:
        result = roles_cli._commission_result('refused', 'not_attempted', code='input_unavailable')
    else:
        try:
            if args.registered_managed or args.provision_managed:
                from . import managed_registration
                if acl_registrations is not None:
                    raise roles_cli.Refusal('managed_registration_requires_appointments_without_file_acls')
                result = managed_registration.apply(data, input_sha256=sha256(raw).hexdigest(),
                                                    preview=args.preview, provision=args.provision_managed)
            else:
                if args.registered_file_acl:
                    acl_registrations = _admin_acl_registrations(acl_registrations)
                result = roles_cli.commission_apply(data, input_sha256=sha256(raw).hexdigest(),
                                                    preview=args.preview, acl_registrations=acl_registrations)
        except roles_cli.Refusal as exc:
            result = roles_cli._commission_result('unknown' if exc.uncertain else 'refused',
                                                  'unknown' if exc.uncertain else 'not_attempted', code=str(exc))
        except (OSError, RecordError):
            result = roles_cli._commission_result('unknown', 'not_attempted' if args.preview else 'unknown',
                                                  code='commission_state_unconfirmed')
        except ValueError:
            result = roles_cli._commission_result('refused', 'not_attempted', code='invalid_profile')
    if result['status'] == 'file_acl_verified':
        result['next_action'] = ('Use managed profile-status to check this revision or '
                                 'managed revoke-profile to remove its ACLs before expiry or uninstall.')
    elif result['status'] == 'configured':
        result['next_action'] = (
            'Use the managed host to verify live bindings and independent provider evidence.'
            if result.get('appointment_status') == 'registered' else
            'Ask the host administrator to register and verify any providers required by the workflow.'
        )
    elif result['status'] in ('incomplete', 'unknown'):
        result['next_action'] = (
            'Check profile-status (alias commission-status) for this profile and revision before running another apply.'
        )
    elif result.get('code') == 'automatic_acl_expiry_unsupported':
        result['next_action'] = ('Use a host backend that enforces expiry, or choose manual cleanup '
                                 'and schedule managed revoke-profile before expiry.')
    elif result.get('code') == 'process_scoped_enforcement_unavailable':
        result['next_action'] = ('Use an authorized supervisor with executable-bound enforcement. '
                                 'The named-file ACL applies to the approved UID across its processes.')
    elif result.get('code') == 'yaml_dependency_missing':
        result['next_action'] = 'Install optional PyYAML in the trusted WorkerOS environment or use JSON.'
    print(json.dumps(result, separators=(',', ':'), sort_keys=True))
    return 0 if result['status'] in ('configured', 'preview', 'file_acl_verified') else 1


def _admin_acl_registrations(existing):
    from . import delegated_acl, roles_cli

    if existing is not None:
        raise roles_cli.Refusal('conflicting_native_acl_registration_sources')
    if os.geteuid() != _TRUSTED_UID:
        raise roles_cli.Refusal('administrator_required')
    try:
        value = _read_admin_json('file-acl-registrations.json')
    except FileNotFoundError:
        raise roles_cli.Refusal('native_acl_registration_unavailable') from None
    except (OSError, Refusal):
        raise roles_cli.Refusal('native_acl_registration_untrusted') from None
    try:
        return delegated_acl.load_registrations(value)
    except (KeyError, TypeError, ValueError):
        raise roles_cli.Refusal('invalid_native_acl_registration') from None


def _local_commission(argv):
    from . import roles_cli
    from .recording import RecordError

    operation = argv[0]
    writing = operation == 'commission'
    revoking = operation == 'revoke-profile'
    parser = argparse.ArgumentParser(
        prog=f'workeros managed {operation if writing or revoking else "profile-status"}',
        description=('Revoke this exact profile revision and verify removal of its managed file ACLs.'
                     if revoking else 'Record or inspect local administrator intent.'))
    parser.add_argument('profile')
    parser.add_argument('revision')
    if writing:
        parser.add_argument('--declaration-sha256', required=True)
        parser.add_argument('--intent-sha256', required=True)
    elif not revoking:
        parser.add_argument('--registered-managed', action='store_true',
                            help='read back protected managed registration pins without starting work')
    args = parser.parse_args(argv[1:])
    try:
        _name(args.profile)
        _name(args.revision)
    except ValueError:
        result = roles_cli._commission_result('refused', 'not_attempted', code='invalid_profile_revision')
    else:
        try:
            if writing:
                result = roles_cli.commission(args.profile, args.revision, args.declaration_sha256,
                                              args.intent_sha256)
            elif revoking:
                result = roles_cli.revoke_profile(args.profile, args.revision)
            elif args.registered_managed:
                from . import managed_registration
                result = managed_registration.readback(args.profile, args.revision)
            else:
                result = roles_cli.commission_status(args.profile, args.revision)
        except roles_cli.Refusal as exc:
            code = str(exc)
            unavailable = exc.uncertain or code in ('untrusted_store', 'profile_store_busy')
            status = ('unknown' if unavailable else 'unconfigured'
                      if not writing and code == 'profile_store_missing' else 'refused')
            effect = 'unknown' if (writing or revoking) and exc.uncertain else 'not_attempted'
            result = roles_cli._commission_result(status, effect, code=code)
        except (OSError, ValueError, RecordError):
            result = roles_cli._commission_result('unknown', 'unknown' if writing or revoking else 'not_attempted',
                                                  code='commission_state_unconfirmed')
    if revoking and result['status'] in ('unknown', 'incomplete'):
        result['next_action'] = ('Inspect managed profile-status and each file_access row. '
                                 'Reconcile unknown cleanup before submitting another change.')
    elif revoking and result.get('code') == 'file_acl_manifest_missing':
        result['next_action'] = 'Use roles grant-check and grant-revoke with the exact earlier grant plan.'
    print(json.dumps(result, separators=(',', ':'), sort_keys=True))
    successful = ('revoked',) if revoking else ('configured', 'file_acl_verified')
    return 0 if result['status'] in successful else 1


def main(argv=None, *, acl_registrations=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'serve-launch':
        from .managed_service_client import serve_main
        return serve_main(argv[1:])
    if argv and argv[0] == 'serve-guard':
        from .managed_guard_server import main as serve_guard
        return serve_guard(argv[1:])
    if argv and argv[0] == 'serve-holder':
        from .managed_holder import main as serve_holder
        return serve_holder(argv[1:])
    if argv and argv[0] == 'serve-witness':
        from .managed_witness_activation import main as serve_witness
        return serve_witness(argv[1:])
    if argv and argv[0] in ('run-approved', 'launch-status'):
        from . import managed_executor
        return managed_executor.main(argv[0], argv[1:])
    if argv and argv[0] == 'serve-setup':
        from . import managed_bootstrap
        return managed_bootstrap.main(argv[1:])
    if argv and argv[0] == 'serve-provider':
        from . import managed_provider
        return managed_provider.main(argv[1:])
    if argv and argv[0] in _REGISTRY_OPERATIONS:
        from . import appointment_registry
        return appointment_registry.main(argv[0], argv[1:])
    if argv and argv[0] in ('apply-profile', 'commission-apply'):
        return _commission_document(argv[1:], acl_registrations=acl_registrations)
    if argv and argv[0] in _LOCAL_OPERATIONS:
        return _local_commission(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=sorted(_OPERATIONS | _LOCAL_OPERATIONS | _REGISTRY_OPERATIONS
                                                    | {'preview','serve-setup','serve-provider'}))
    args = parser.parse_args(argv)
    if args.operation == 'preview':
        try:
            config = _configuration()
            result = {'status':'configured','effect':'not_attempted','profile':config['profile'],
                      'identity':config['identity'],'operation_key':config['operation_key'],
                      'scopes':config['scopes'],
                      'next_action':'Ask the host administrator to verify the appointed providers and endpoint.'}
        except (OSError, Refusal):
            result = {'status':'refused','effect':'not_attempted','code':'configuration_unavailable',
                      'next_action':'Ask the host administrator to commission the managed profile.'}
        print(json.dumps(result, separators=(',', ':'), sort_keys=True))
        return 0 if result['status'] == 'configured' else 1
    result = run(args.operation)
    if result.get('code') in ('configuration_unavailable','configuration_invalid','untrusted_configuration'):
        result['next_action'] = 'Ask the host administrator to commission the managed profile.'
    elif result.get('code') in ('endpoint_unavailable','peer_untrusted'):
        result['next_action'] = 'Ask the host administrator to verify the configured endpoint and identity.'
    elif result.get('code') == 'binding_check_pins_required':
        result['next_action'] = 'Ask the host administrator to pin the approved revision and scope definitions.'
    elif result.get('code') == 'response_unconfirmed':
        result['next_action'] = ('Ask the host administrator to confirm check-bindings support and the exact pins.'
                                 if args.operation == _CHECK_BINDINGS else
                                 'Use readback or reconcile for this exact operation; do not repeat setup.')
    elif args.operation == _CHECK_BINDINGS and result['status'] == 'incomplete':
        result['next_action'] = 'Check current provider bindings for each unverified scope before setup.'
    print(json.dumps(result, separators=(',', ':'), sort_keys=True))
    success = 'bindings_verified' if args.operation == _CHECK_BINDINGS else 'ready'
    return 0 if result['status'] == success else 1


if __name__ == '__main__':
    sys.exit(main())
