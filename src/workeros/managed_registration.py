"""Join protected launch registrations to exact approved records without starting work."""

from contextlib import contextmanager, nullcontext
import fcntl
from hashlib import sha256
import os
from pathlib import PurePosixPath
import stat
from uuid import uuid4

from . import managed_bootstrap, managed_cli, managed_executor, managed_service, roles_cli
from .appointment_registry import definition_sha256, launch_policy_sha256, read_registry
from .enrollment import _operations
from .managed_launch import GUARDED_SERVICE, LaunchRolePolicy, _digest, _uid
from .managed_service_scope import ServiceBundle
from .recording import EvidenceType, RecordError
from .verify_install import VerificationError, verify_install


_FILES = (managed_bootstrap._CONFIG_FILE, managed_executor._REGISTRATION)
_PIN_KEYS = ('managed_setup_sha256', 'launch_executor_sha256')
_ROTATION_KEYS = (*_PIN_KEYS, 'launch_client_sha256')
_ROTATION_KIND = EvidenceType('managed-registration-rotation', 'application/json')


def _fingerprint(value):
    return sha256(roles_cli._canonical(value)).hexdigest()


def _pin_pair(host, executor):
    return dict(zip(_PIN_KEYS, (_fingerprint(host), _fingerprint(executor)), strict=True))


def _require_administrator():
    if os.getresuid() != (managed_cli._TRUSTED_UID,) * 3:
        raise roles_cli.Refusal('administrator_required')


def _read_pair():
    try:
        return managed_cli._read_admin_json(_FILES[0]), managed_executor._read_registration()
    except (FileNotFoundError, managed_executor.ExecutorRefusal) as exc:
        raise roles_cli.Refusal('managed_registration_unavailable') from exc
    except (managed_cli.Refusal, OSError) as exc:
        raise roles_cli.Refusal('managed_registration_untrusted') from exc


def _durable_match(pins, expected):
    if pins is None:
        raise roles_cli.Refusal('managed_registration_unpinned')
    if any(pins[key] != digest for key, digest in expected.items()):
        raise roles_cli.Refusal('managed_registration_drift')


def require_pinned_pair(executor, *, required=False, readback=False):
    """Return the verified launch setup snapshot, without opening live resources."""
    try:
        _require_administrator()
        profile, revision = executor['profile'], executor['revision']
        with roles_cli._store(create=False) as store:
            receipt = roles_cli._commission_status_store(store, profile, revision)
            pins = receipt.get('managed_registration_pins')
            if pins is None and not required:
                return None
            _durable_match(pins, {'launch_executor_sha256': _fingerprint(executor)})
            if readback:
                # Historical state access must use the pinned executor rights,
                # even after revocation or removal of the live setup file.
                return None
            if receipt['status'] != 'configured':
                raise roles_cli.Refusal('managed_registration_inactive')
            declaration = roles_cli._inspect_store(store, profile, revision)
            if read_registry(store, profile, revision, receipt, declaration) is None:
                raise roles_cli.Refusal('managed_registration_unavailable')
            rotation = _readback_rotation(store, receipt)
            if rotation is not None and rotation['status'] != 'verified':
                raise roles_cli.Refusal('managed_rotation_incomplete')
            host = managed_cli._read_admin_json(_FILES[0])
            _durable_match(pins, {'managed_setup_sha256': _fingerprint(host)})
            return host
    except roles_cli.Refusal as exc:
        if str(exc) == 'profile_store_missing' and not required:
            return None
        code = 'managed_registration_unpinned' if str(exc) == 'profile_store_missing' else str(exc)
        raise managed_executor.ExecutorRefusal(code) from exc
    except (OSError, ValueError, TypeError, KeyError, RecordError) as exc:
        raise managed_executor.ExecutorRefusal('managed_registration_unavailable') from exc


def _existing_registration(filename, *, public=False):
    try:
        if public:
            return managed_cli._read_admin_json(filename, public=True)
        return managed_cli._read_admin_json(filename)
    except FileNotFoundError:
        return None
    except (OSError, managed_cli.Refusal) as exc:
        raise roles_cli.Refusal('managed_registration_untrusted') from exc


def _check_provision_pair(pair, client=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent = os.open(managed_cli._CONFIG_PARENT, flags)
        try:
            managed_cli._safe_directory(parent)
        finally:
            os.close(parent)
    except (OSError, managed_cli.Refusal) as exc:
        raise roles_cli.Refusal('managed_registration_untrusted') from exc
    for filename, value in zip(_FILES, pair, strict=True):
        current = _existing_registration(filename)
        if current is not None and _fingerprint(current) != _fingerprint(value):
            raise roles_cli.Refusal('managed_registration_file_conflict')
        if len(roles_cli._canonical(value)) > managed_cli._LIMIT:
            raise roles_cli.Refusal('managed_registration_too_large')
    if client is not None:
        from .managed_service_client import _PUBLIC_CLIENT_CONFIG

        current = _existing_registration(_PUBLIC_CLIENT_CONFIG, public=True)
        if current is not None and current != client:
            raise roles_cli.Refusal('managed_registration_file_conflict')


@contextmanager
def _configuration_directory(*, create=True):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(managed_cli._CONFIG_PARENT, flags)
    try:
        managed_cli._safe_directory(parent)
        try:
            directory = os.open(managed_cli._CONFIG_DIRECTORY, flags, dir_fd=parent)
        except FileNotFoundError:
            if not create:
                raise roles_cli.Refusal('managed_rotation_registration_missing') from None
            try:
                os.mkdir(managed_cli._CONFIG_DIRECTORY, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            os.fsync(parent)
            directory = os.open(managed_cli._CONFIG_DIRECTORY, flags, dir_fd=parent)
        try:
            managed_cli._safe_directory(directory)
            yield directory
        finally:
            os.close(directory)
    finally:
        os.close(parent)


def _write_registration(directory, filename, value, *, public=False, replace_digest=None):
    current = _existing_registration(filename, public=public)
    replacing = replace_digest is not None
    if current is not None:
        digest = _fingerprint(current)
        if digest == _fingerprint(value):
            if replacing:
                _sync_registration(directory, filename)
            return False
        if digest != replace_digest:
            raise roles_cli.Refusal('managed_registration_file_conflict')
    elif replacing:
        raise roles_cli.Refusal('managed_rotation_registration_missing')
    temporary = '.managed-registration-' + uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(roles_cli._canonical(value))
            output.flush()
            if public:
                os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
        if replacing:
            current = _existing_registration(filename, public=public)
            if current is None or _fingerprint(current) != replace_digest:
                raise roles_cli.Refusal('managed_registration_file_conflict')
            os.replace(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
        else:
            os.link(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                if not replacing:
                    raise
    os.fsync(directory)
    return True


def _sync_registration(directory, filename):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = os.open(filename, flags, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != managed_cli._TRUSTED_UID
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise roles_cli.Refusal('managed_registration_untrusted')
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _provision_pair(pair, client=None):
    """Install only absent fixed files; never replace an administrator file."""
    created = False
    with _configuration_directory() as directory:
        for filename, value in zip(_FILES, pair, strict=True):
            created |= _write_registration(directory, filename, value)
    if client is not None:
        from .managed_service_client import _PUBLIC_CLIENT_CONFIG

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open(managed_cli._CONFIG_PARENT, flags)
        try:
            managed_cli._safe_directory(parent)
            created |= _write_registration(parent, _PUBLIC_CLIENT_CONFIG, client, public=True)
        finally:
            os.close(parent)
    return 'recorded' if created else 'unchanged'


def _rotation_plan(source, declaration, pair, client):
    roles_cli._fields(source, ('revision', *_ROTATION_KEYS))
    try:
        roles_cli._name(source['revision'])
        for field in _ROTATION_KEYS:
            _digest(source[field])
    except ValueError as exc:
        raise roles_cli.Refusal('invalid_managed_rotation_source') from exc
    if client is None or source['revision'] == declaration['revision']:
        raise roles_cli.Refusal('invalid_managed_rotation_source')
    return {'version': 1, 'profile': declaration['profile'], 'revision': declaration['revision'],
            'rotate_from': source, 'next': {**_pin_pair(*pair), 'launch_client_sha256': _fingerprint(client)}}


def _rotation_key(plan):
    return roles_cli._key(plan['profile'], plan['revision'], 'registration-rotation')


def _rotation_completion(plan):
    return (roles_cli._key(plan['profile'], plan['revision'], 'registration-rotation-completed'),
            roles_cli._canonical({'version': 1, 'rotation_sha256': _fingerprint(plan)}))


def _rotation_completed(store, plan):
    key, expected = _rotation_completion(plan)
    stored = roles_cli._read(store, key)
    if stored is None:
        return False
    if stored != expected:
        raise roles_cli.Refusal('managed_rotation_completion_unconfirmed', uncertain=True)
    return True


def _check_rotation_source(store, plan):
    prior = roles_cli._commission_status_store(store, plan['profile'], plan['rotate_from']['revision'])
    pins = {key: plan['rotate_from'][key] for key in _PIN_KEYS}
    if prior['status'] != 'revoked' or prior.get('managed_registration_pins') != pins:
        raise roles_cli.Refusal('managed_rotation_source_not_verified_revoked')


def _rotation_files():
    from .managed_service_client import _PUBLIC_CLIENT_CONFIG

    return tuple((filename, False) for filename in _FILES) + ((_PUBLIC_CLIENT_CONFIG, True),)


def _rotation_progress(plan, *, reserved):
    current = [_existing_registration(filename, public=public) for filename, public in _rotation_files()]
    if any(value is None for value in current):
        raise roles_cli.Refusal('managed_rotation_registration_missing')
    if any(type(value) is not dict for value in current):
        raise roles_cli.Refusal('managed_rotation_registration_drift')
    actual = tuple(_fingerprint(value) for value in current)
    old = tuple(plan['rotate_from'][key] for key in _ROTATION_KEYS)
    new = tuple(plan['next'][key] for key in _ROTATION_KEYS)
    updated = sum(left == right for left, right in zip(actual, new, strict=True))
    if ((updated and not reserved) or actual != new[:updated] + old[updated:]):
        raise roles_cli.Refusal('managed_rotation_registration_drift')
    if not reserved:
        if any((document.get('profile'), document.get('revision')) != (
                plan['profile'], plan['rotate_from']['revision']) for document in current):
            raise roles_cli.Refusal('managed_rotation_registration_drift')
        _check_client(current[-1], current[1])
    return updated


def _check_rotation(plan):
    with roles_cli._store(create=False) as store:
        _check_rotation_source(store, plan)
        prior = roles_cli._read(store, _rotation_key(plan))
        if prior is not None and prior != roles_cli._canonical(plan):
            raise roles_cli.Refusal('managed_rotation_intent_conflict')
        completed = _rotation_completed(store, plan)
    progress = _rotation_progress(plan, reserved=prior is not None)
    if completed and progress != len(_ROTATION_KEYS):
        raise roles_cli.Refusal('managed_rotation_registration_drift')
    return progress


def _reserve_rotation(store, plan):
    _check_rotation_source(store, plan)
    approved = roles_cli._commission_status_store(store, plan['profile'], plan['revision'])
    if (approved['status'] != 'configured'
            or approved.get('managed_registration_pins') != {key: plan['next'][key] for key in _PIN_KEYS}):
        raise roles_cli.Refusal('managed_rotation_successor_unconfirmed')
    key, data = _rotation_key(plan), roles_cli._canonical(plan)
    roles_cli._commit(store, key, data, kind=_ROTATION_KIND, admin_revision=plan['revision'])
    if roles_cli._read(store, key) != data:
        raise roles_cli.Refusal('managed_rotation_intent_unconfirmed', uncertain=True)


@contextmanager
def _rotation_directory():
    with _configuration_directory(create=False) as directory:
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise roles_cli.Refusal('managed_rotation_busy') from exc
        yield directory


@contextmanager
def _rotation_locations(directory):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(managed_cli._CONFIG_PARENT, flags)
    try:
        managed_cli._safe_directory(parent)
        yield tuple((parent if public else directory, filename, public)
                    for filename, public in _rotation_files())
    finally:
        os.close(parent)


def _activate_rotation(directory, plan, pair, client):
    with roles_cli._store(create=False) as store:
        _reserve_rotation(store, plan)
        progress = _rotation_progress(plan, reserved=True)
        if _rotation_completed(store, plan):
            if progress != len(_ROTATION_KEYS):
                raise roles_cli.Refusal('managed_rotation_registration_drift')
            return 'unchanged'
        with _rotation_locations(directory) as locations:
            for (parent, filename, public), key, value in zip(locations, _ROTATION_KEYS, (*pair, client), strict=True):
                _write_registration(parent, filename, value, public=public,
                                    replace_digest=plan['rotate_from'][key])
        if _rotation_progress(plan, reserved=True) != len(_ROTATION_KEYS):
            raise roles_cli.Refusal('managed_rotation_readback_unconfirmed', uncertain=True)
        key, payload = _rotation_completion(plan)
        roles_cli._commit(store, key, payload, kind=_ROTATION_KIND, admin_revision=plan['revision'])
        if not _rotation_completed(store, plan):
            raise roles_cli.Refusal('managed_rotation_completion_unconfirmed', uncertain=True)
    return 'recorded'


def _check_client(client, executor):
    from .managed_service_client import _validate_client_registration

    try:
        _validate_client_registration(client)
        backend, registered = _executors(executor)
        expected = {name: launch_policy_sha256(item[0]) for name, item in registered.items()}
        endpoints = {item[field]['socket'] for item in executor.get('workflows', {}).values()
                     for field in ('authority', 'result_observer', 'holder') if field in item}
        if (backend != 'systemd-fd' or (client['profile'], client['revision']) != (
                executor['profile'], executor['revision']) or client['workflows'] != expected
                or client['socket'] in endpoints):
            raise ValueError('crossed client registration')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise roles_cli.Refusal('managed_client_registration_mismatch') from exc


def _service_registration(raw, workflow, *, local_observer=False):
    roles_cli._fields(raw, ('policy', 'service', 'authority', 'run_uids', 'result_uids'), ('result_observer', 'holder'))
    policy = LaunchRolePolicy(**raw['policy'])
    if policy.workflow != workflow:
        raise ValueError('crossed workflow')
    descriptor = raw['service']
    service = ServiceBundle(**descriptor) if 'descriptors' in descriptor else managed_service.ServiceScope(**descriptor)
    endpoint = raw['authority']
    roles_cli._fields(endpoint, ('socket', 'uid'), ('enforcement',))
    managed_executor._Authority(endpoint['socket'], endpoint['uid'], policy)
    if 'enforcement' in endpoint and (endpoint['enforcement'] != GUARDED_SERVICE
            or managed_service.limits(service) is None or service.parent is None):
        raise ValueError('unsupported service enforcement')
    if (service.parent is not None and service.parent.delegated_service
            and endpoint.get('enforcement') != GUARDED_SERVICE):
        raise ValueError('delegated_service_requires_guarded_enforcement')
    if (type(service) is ServiceBundle and service.elevated_capabilities
            and endpoint.get('enforcement') != GUARDED_SERVICE):
        raise ValueError('elevated_service_requires_guarded_enforcement')
    for field in ('run_uids', 'result_uids'):
        if type(raw[field]) is not list or len(raw[field]) > 64:
            raise ValueError('invalid workflow callers')
        for uid in raw[field]:
            _uid(uid)
    if 'result_observer' in raw:
        from .managed_service_observer import ResultObserver, validate_observer
        from .managed_witness_activation import validate_scope

        config = raw['result_observer']
        if local_observer:
            validate_observer(config, policy, endpoint, managed_service.limits(service))
        else:
            ResultObserver(config, policy, endpoint, managed_service.limits(service))
        validate_scope(config, service)
        if config['uid'] in raw['run_uids']:
            raise ValueError('service_result_observer_not_independent')
    if 'holder' in raw:
        from .managed_holder import validate_holder

        validate_holder(raw['holder'], policy, service, endpoint)
        if 'result_observer' in raw and raw['holder']['socket'] == raw['result_observer']['socket']:
            raise ValueError('service_holder_registration_invalid')
    return policy, service


def _executors(executor):
    if type(executor.get('version')) is not int:
        raise ValueError('invalid executor version')
    if executor['version'] == 1:
        _, policy, _ = managed_executor._registration(executor)
        path = PurePosixPath(executor['executable'])
        if not path.is_absolute() or len(path.parts) < 2 or '..' in path.parts or str(path) != executor['executable']:
            raise ValueError('invalid executor path')
        return 'bubblewrap', {policy.workflow: (policy, None)}
    if executor['version'] != 2:
        raise ValueError('unsupported executor version')
    roles_cli._fields(executor, ('version', 'profile', 'revision', 'wheel_path', 'wheel_sha256', 'workflows'))
    workflows = executor['workflows']
    if type(workflows) is not dict or not 1 <= len(workflows) <= 8:
        raise ValueError('invalid workflows')
    return 'systemd-fd', {name: _service_registration(entry, name) for name, entry in workflows.items()}


def _service_grants(declaration, executor):
    role_doc = {key: value for key, value in declaration.items() if key != 'appointments'}
    validated = roles_cli._validate(roles_cli._canonical(role_doc))
    roles = {role['name']: role for role in validated['roles']}
    _, registrations = _executors(executor)
    grants = set()
    for policy, service in registrations.values():
        if type(service) is not ServiceBundle or not service.elevated_capabilities:
            continue
        role = roles.get(policy.role)
        if role is None or not service.match_role(role):
            raise roles_cli.Refusal('unsupported_privileged_enforcement')
        grants.update((policy.role, value.scope, value.name) for value in service.elevated_capabilities)
    return frozenset(grants)


def _check_approval(scope, entry, role, wheel_sha256):
    roles_cli._fields(scope, managed_bootstrap._SCOPE_BASE_FIELDS,
                     managed_bootstrap._SCOPE_OPTIONAL_FIELDS + ('interval_provider',))
    definition = managed_bootstrap._definition(scope['definition'])
    document = scope['policy']
    roles_cli._fields(document, ('version', 'roles', 'workflows'))
    workflow = document['workflows'][definition.name]
    operations = _operations(workflow['operations'])
    if ((entry['workflow'], entry['workflow_revision'], entry['scope'], entry['definition_sha256'],
         entry['role'], entry['principal'], entry['generation'], set(entry['operations'])) !=
            (definition.name, definition.revision, definition.scope, definition_sha256(definition),
             scope['role'], role['principal'], scope['binding_generation'], operations)
            or role['name'] != scope['role'] or workflow['role'] != scope['role']
            or set(document['workflows']) != {definition.name}
            or definition.package_sha256 != wheel_sha256 or definition.policy_sha256 != _fingerprint(document)):
        raise ValueError('crossed workflow approval')
    return definition, workflow, operations


def _check_scope(scope, entry, role, policy, service, wheel_sha256):
    definition, workflow, operations = _check_approval(scope, entry, role, wheel_sha256)
    selected = ({'observe'} if 'observer' in scope else set()) | ({'meter'} if 'meter' in scope else set())
    if ((policy.definition_sha256, policy.role, policy.principal, policy.generation) !=
            (entry['definition_sha256'], entry['role'], entry['principal'], entry['generation'])
            or entry.get('launch') != {'policy_sha256': launch_policy_sha256(policy),
                                       'scope_sha256': policy.scope_sha256}
            or operations != {'launch', *selected}):
        raise ValueError('crossed launch approval')
    account = roles_cli._principal(role['principal'])
    if account.pw_uid != policy.principal_uid:
        raise ValueError('crossed workflow principal')
    managed_bootstrap._preflight_scopes((scope,), check_intervals=True, launch_plan=policy, launch_service=service)
    refs = workflow['bindings']
    bindings = {binding.kind: binding for binding in definition.providers}
    if (len(bindings) != len(definition.providers) or refs.keys() != bindings.keys()
            or any(binding.scope != definition.scope for binding in bindings.values())
            or bindings['executable'].capability != 'executable'
            or bindings['executable'].reference != policy.executable_sha256
            or bindings['supervisor'].capability != 'scoped-launch'
            or bindings['supervisor'].principal != policy.launcher
            or bindings['supervisor'].reference != policy.scope_sha256):
        raise ValueError('crossed backend bindings')
    for kind in ('executable', 'supervisor'):
        if refs[kind] != bindings[kind].name:
            raise ValueError('crossed backend reference')
    for kind in ('observers', 'meters'):
        if kind in bindings and list(refs[kind].values()) != [bindings[kind].name]:
            raise ValueError('crossed evidence reference')
    if not policy.principal_uid or service is not None and account.pw_gid != service.principal_gid:
        raise ValueError('unsupported workflow principal')
    observer = scope.get('observer')
    if role.get('privileged') and type(service) is not ServiceBundle:
        raise ValueError('unsupported privileged workflow backend')
    if service is None:
        if operations != {'launch', 'observe'} or observer is None or 'provider' not in scope:
            raise ValueError('unsupported bubblewrap scope')
        original = (str(observer['device']), str(observer['inode']))
    else:
        stream = bindings['streams']
        slots = ({slot: f'{stream.name}.{slot}' for slot in service.streams} if type(service) is ServiceBundle
                 else {'stdin': stream.name})
        if ((stream.capability, stream.reference, stream.principal) != ('systemd-fd', service.digest, policy.launcher)
                or refs['streams'] != slots):
            raise ValueError('crossed service stream')
        if type(service) is ServiceBundle:
            if not service.match_role(role):
                raise ValueError('crossed service role')
            original = service.observation_original
        else:
            if not service.operations <= set(role['operations']):
                raise ValueError('crossed service role')
            original = service.original
    if observer is not None and original != (str(observer['device']), str(observer['inode'])):
        raise ValueError('crossed original observation')
    if type(service) is not ServiceBundle:
        resource = role.get('resources', {}).get(definition.scope)
        if type(resource) is not dict or (resource.get('device'), resource.get('inode')) != original:
            raise ValueError('crossed approved original')


def check(receipt, declaration, appointments, *, pair=None):
    """Compare approved pins, without opening scope FDs, sockets, or a backend."""
    _require_administrator()
    if not appointments or 'file_acl_plans_sha256' in receipt:
        raise roles_cli.Refusal('managed_registration_requires_appointments_without_file_acls')
    host, executor = _read_pair() if pair is None else pair
    try:
        profile, revision = receipt['profile'], receipt['revision']
        if (type(host['version']) is not int or host['version'] != 2
                or (host['profile'], host['revision']) != (profile, revision)
                or (executor['profile'], executor['revision']) != (profile, revision)
                or executor['wheel_path'] != host['wheel_path']
                or type(executor['wheel_path']) is not str or not os.path.isabs(executor['wheel_path'])
                or host['local_approval'] != {key: receipt[key] for key in ('declaration_sha256', 'intent_sha256')}):
            raise ValueError('crossed profile receipt')
        _digest(executor['wheel_sha256'])
        backend, registered = _executors(executor)
        approved = {entry['workflow']: entry for entry in appointments}
        approved_launches = {name for name, entry in approved.items() if 'launch' in entry}
        roles = {role['name']: role for role in declaration['roles']}
        entries = managed_bootstrap._scope_entries(host, check_only=True)
        scopes = {entry['definition']['name']: entry for entry in entries}
        if (len(scopes) != len(entries) or approved_launches != registered.keys()
                or approved.keys() != scopes.keys() or len(approved) != len(appointments)):
            raise ValueError('crossed approved workflows')
        for name, scope in scopes.items():
            entry = approved[name]
            role = roles[entry['role']]
            if name in registered:
                policy, service = registered[name]
                _check_scope(scope, entry, role, policy, service, executor['wheel_sha256'])
            else:
                _check_approval(scope, entry, role, executor['wheel_sha256'])
                managed_bootstrap._preflight_scopes((scope,), check_intervals=True)
        service_grants = []
        for name, (policy, service) in sorted(registered.items()):
            if type(service) is ServiceBundle:
                for grant in service.elevated_capabilities:
                    resource = roles[policy.role]['resources'][grant.scope]
                    service_grants.append({'workflow': name, 'role': policy.role, 'principal': policy.principal,
                                           'capability': grant.name, 'scope': grant.scope,
                                           'operation': grant.operation, 'resource': resource})
        installed = verify_install(executor['wheel_path'], executor['wheel_sha256'])
        if any(scope['definition']['package_version'] != installed['version'] for scope in scopes.values()):
            raise ValueError('crossed installed package version')
    except VerificationError as exc:
        raise roles_cli.Refusal('installed_package_unverified') from exc
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise roles_cli.Refusal('managed_registration_mismatch') from exc
    result = {'status': 'pins_matched', 'backend': backend, 'workflows': sorted(registered),
              'wheel_sha256': executor['wheel_sha256'], **_pin_pair(host, executor), 'enforcement': 'not_checked'}
    if service_grants:
        result['elevated_capabilities'] = service_grants
    if backend == 'systemd-fd':
        observers = [{'workflow': name, 'source': entry['result_observer']['source']}
                     for name, entry in sorted(executor['workflows'].items()) if 'result_observer' in entry]
        if observers:
            result['result_observers'] = observers
        holders = [{'workflow': name, 'uid': entry['holder']['uid']}
                   for name, entry in sorted(executor['workflows'].items()) if 'holder' in entry]
        if holders:
            result['holders'] = holders
    return result


def readback(profile, revision):
    """Read the exact current role, appointments and protected registration pins."""
    with roles_cli._store(create=False) as store:
        receipt = roles_cli._commission_status_store(store, profile, revision)
        if receipt['status'] != 'configured':
            return receipt
        declaration = roles_cli._inspect_store(store, profile, revision)
        registry = read_registry(store, profile, revision, receipt, declaration)
        if registry is None:
            raise roles_cli.Refusal('managed_registration_requires_appointments_without_file_acls')
        rotation = _readback_rotation(store, receipt)
        if rotation is not None and rotation['status'] == 'incomplete':
            return {**receipt, 'status': 'incomplete', 'code': 'managed_rotation_incomplete',
                    'managed_rotation': rotation}
        pair = _read_pair()
        _durable_match(receipt.get('managed_registration_pins'), _pin_pair(*pair))
        return {**receipt, 'appointment_status': 'registered',
                'managed_registration': check(receipt, declaration, registry['appointments'], pair=pair),
                **({} if rotation is None else {'managed_rotation': rotation})}


def _readback_rotation(store, receipt):
    data = roles_cli._read(store, _rotation_key(receipt))
    if data is None:
        return None
    try:
        plan = managed_cli.decode_policy(data)
        roles_cli._fields(plan, ('version', 'profile', 'revision', 'rotate_from', 'next'))
        roles_cli._fields(plan['rotate_from'], ('revision', *_ROTATION_KEYS))
        roles_cli._fields(plan['next'], _ROTATION_KEYS)
        roles_cli._name(plan['rotate_from']['revision'])
        for field in _ROTATION_KEYS:
            _digest(plan['rotate_from'][field])
            _digest(plan['next'][field])
        if (type(plan['version']) is not int or plan['version'] != 1
                or any(plan[key] != receipt[key] for key in ('profile', 'revision'))
                or plan['rotate_from']['revision'] == plan['revision']
                or {key: plan['next'][key] for key in _PIN_KEYS} != receipt.get('managed_registration_pins')
                or roles_cli._canonical(plan) != data):
            raise ValueError('crossed rotation record')
    except (ValueError, TypeError, KeyError) as exc:
        raise roles_cli.Refusal('managed_rotation_intent_unconfirmed', uncertain=True) from exc
    _check_rotation_source(store, plan)
    updated = _rotation_progress(plan, reserved=True)
    completed = _rotation_completed(store, plan)
    if completed and updated != len(_ROTATION_KEYS):
        raise roles_cli.Refusal('managed_rotation_registration_drift')
    return _rotation_result(plan, 'verified' if completed else 'incomplete', updated)


def _rotation_result(plan, status, updated):
    return {'status': status, 'source_revision': plan['rotate_from']['revision'],
            'revision': plan['revision'], 'matched_files': updated}


def apply(data, *, input_sha256, preview=False, provision=False):
    """Apply only the approved role/appointment receipt for a matched pair."""
    _require_administrator()
    try:
        declaration = managed_cli.decode_policy(data)
    except ValueError as exc:
        raise roles_cli.Refusal('invalid_document') from exc
    client = None
    bundle = None
    if provision:
        roles_cli._fields(declaration, ('version', 'profile', 'managed_setup', 'launch_executor'),
                          ('launch_client', 'rotate_from'))
        bundle = declaration
        if type(declaration['version']) is not int or declaration['version'] != 1:
            raise roles_cli.Refusal('invalid_managed_provision_version')
        pair = (declaration['managed_setup'], declaration['launch_executor'])
        if 'launch_client' in declaration:
            client = declaration['launch_client']
            _check_client(client, pair[1])
        declaration = declaration['profile']
        data = roles_cli._canonical(declaration)
        input_sha256 = sha256(data).hexdigest()
    if type(declaration) is not dict or declaration.keys() & {'grant', 'grants'}:
        raise roles_cli.Refusal('managed_registration_requires_appointments_without_file_acls')
    if not provision:
        pair = _read_pair()
    try:
        service_grants = _service_grants(declaration, pair[1])
        pins = _pin_pair(*pair)
    except roles_cli.Refusal:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise roles_cli.Refusal('managed_registration_mismatch') from exc
    proposed = roles_cli.commission_apply(data, input_sha256=input_sha256, preview=True,
                                          managed_registration_pins=pins if service_grants else None,
                                          _service_grants=service_grants)
    verified = check(proposed, declaration, proposed.get('appointments', ()), pair=pair)
    plan = (_rotation_plan(bundle['rotate_from'], declaration, pair, client)
            if bundle is not None and 'rotate_from' in bundle else None)
    if plan is not None and any(len(roles_cli._canonical(item)) > managed_cli._LIMIT for item in (*pair, client)):
        raise roles_cli.Refusal('managed_registration_too_large')
    with (_rotation_directory() if plan is not None else nullcontext()) as directory:
        routing = {} if client is None else {'local_client_routing': 'preview'}
        if plan is not None:
            progress = _check_rotation(plan)
            routing['managed_rotation'] = _rotation_result(plan, 'preview', progress)
        elif provision:
            _check_provision_pair(pair, client)
        if preview:
            return {**proposed, **routing, 'managed_registration': verified}
        outcome = roles_cli.commission_apply(data, input_sha256=input_sha256, managed_registration_pins=pins,
                                             _service_grants=service_grants)
        if outcome['status'] != 'configured':
            return outcome
        configuration = {}
        try:
            if provision:
                configuration['managed_configuration_effect'] = 'unknown'
                if plan is not None:
                    configuration['managed_configuration_effect'] = _activate_rotation(directory, plan, pair, client)
                else:
                    configuration['managed_configuration_effect'] = _provision_pair(pair, client)
            if client is not None:
                from .managed_service_client import _client_registration

                if _client_registration() != client:
                    raise ValueError('managed_client_registration_readback_unconfirmed')
                configuration['local_client_routing'] = 'verified'
            observed = readback(outcome['profile'], outcome['revision'])
            if observed.get('managed_registration') == verified:
                if plan is not None:
                    configuration['managed_rotation'] = observed['managed_rotation']
                return {**outcome, **configuration, 'managed_registration': verified}
        except (OSError, ValueError, RecordError):
            pass
        # Existing role writes may be durable even if later readback cannot be confirmed.
        code = 'managed_rotation_incomplete' if plan is not None else 'managed_registration_readback_unconfirmed'
        return {**outcome, **configuration, 'status': 'incomplete', 'code': code}
