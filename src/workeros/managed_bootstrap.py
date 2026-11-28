"""Check approved no-start bindings or serve one commissioned request."""
import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, replace
from hashlib import sha256
import fcntl
import json
import os
import socket
import struct
from pathlib import Path
from time import monotonic, monotonic_ns
from uuid import uuid4

from . import managed_cli
from .aggregate_setup import ScopeEvidence, ScopeSetup
from .appointment_registry import definition_sha256
from .configuration import ConfigurationError
from .enrollment import HostBindings, _operations
from .lifecycle import RegularFileObserver
from .managed_host import LocalProfileApproval, ManagedHostAdapter, _commissioned_identity, _recover_pending
from .managed_journal import ManagedJournal, _POLICY
from .managed_launch import GUARDED_SERVICE, LaunchRegistration
from .managed_service_scope import ServiceBundle
from .original import Identity
from .profile_setup import ManagerReadback, ManagerSelection, ProfileDefinition, ProfileRequirements, ProviderBinding, ProviderRequirement
from .recording import Persistence, RecordError, _name
from .roles_cli import _canonical, _fields
from .scope_meter import CgroupScopeMeter, ScopeMeterUnavailable, _mount_id, _scope_from_dict, monotonic_clock_id
from .verify_install import verify_install
from .workers import Worker


_CONFIG_FILE = 'managed-setup.json'
_HOST_REFUSALS = frozenset((
    'administrator_required', 'monotonic_clock_unavailable', 'setup_clock_mismatch',
    'provider_requires_distinct_uid', 'invalid_provider_endpoint', 'provider_source_conflict',
    'invalid_listener_descriptor', 'invalid_inherited_observer_handles', 'observer_plan_mismatch',
    'unsupported_setup_binding', 'unsupported_setup_policy', 'unsupported_setup_version',
    'setup_policy_mismatch', 'invalid_authorized_uids',
    'invalid_setup_scopes', 'scope_meter_unavailable', 'meter_plan_mismatch',
    'meter_provider_requires_separate_principal', 'point_observer_requires_readable_original',
    'directory_plan_mismatch', 'duplicate_inherited_setup_handles',
    'interval_custody_unsupported', 'independent_attester_unavailable',
    'interval_check_only', 'interval_registration_mismatch', 'interval_meter_scope_mismatch',
))


def setup_clock_id():
    """Return an identifier for this boot and Linux monotonic clock namespace."""
    clock = monotonic_clock_id()
    if clock is None:
        raise ValueError('monotonic_clock_unavailable')
    return sha256(clock.encode('ascii')).hexdigest()


def _provider_is_independent(uid):
    return uid != os.geteuid()


class _EvidenceProvider:
    """Read one attestation from a pinned local provider. Never derives evidence from a record."""

    def __init__(self, socket_path, uid, source, *, window_end_ns=None, interval=False):
        if (type(socket_path) is not str or not socket_path.startswith('/')
                or '\0' in socket_path or len(os.fsencode(socket_path)) > 107
                or type(uid) is not int or not 0 <= uid < 2**32 - 1):
            raise ValueError('invalid_provider_endpoint')
        if not _provider_is_independent(uid):
            raise ValueError('provider_requires_distinct_uid')
        self.path, self.uid, self.source = socket_path, uid, _name(source)
        self.window_end_ns = window_end_ns
        self.interval = interval

    def _invalid_attestation(self, code):
        if self.interval:
            return ConfigurationError('independent_evidence_invalid')
        return ValueError(code)

    def attest(self, selection, role, generation):
        definition = selection.definition
        request = {'version': 1, 'request_id': uuid4().hex, 'definition_sha256': definition_sha256(definition),
                   'role': role, 'clock_id': definition.clock_id, 'generation': generation}
        if self.interval:
            request.update(version=2, capability='interval')
        data = _canonical(request)
        work_deadline = managed_cli._CHECK_WORK_DEADLINE.get()
        if work_deadline is not None and monotonic() >= work_deadline:
            raise TimeoutError()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            now = monotonic()
            deadline = now + managed_cli._TIMEOUT
            if work_deadline is not None:
                deadline = min(deadline, work_deadline)
            remaining = deadline - now
            if remaining <= 0:
                raise TimeoutError()
            connection.settimeout(remaining)
            connection.connect(self.path)
            pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.uid or pid <= 0 or pid == os.getpid():
                raise PermissionError('provider_peer_untrusted')
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError()
            connection.settimeout(remaining)
            connection.sendall(struct.pack('!I', len(data)) + data)
            size, = struct.unpack('!I', managed_cli._read_exact(connection, 4, deadline))
            if not 0 < size <= managed_cli._LIMIT:
                raise self._invalid_attestation('invalid_provider_frame')
            reply = managed_cli.decode_policy(managed_cli._read_exact(connection, size, deadline))
        expected = {'request_id':request['request_id'], 'definition_sha256':request['definition_sha256'],
                    'role':role, 'clock_id':definition.clock_id, 'generation':generation,
                    'source':self.source, 'status':'verified'}
        if self.interval:
            expected.update(version=2, capability='interval')
        if (type(reply) is not dict or set(reply) != set(expected) | {'evidence_sha256', 'valid_until_ns'}
                or (self.interval and type(reply['version']) is not int)
                or any(reply[key] != value for key, value in expected.items())):
            raise self._invalid_attestation('provider_attestation_mismatch')
        until = reply['valid_until_ns']
        limit = selection.expires_ns
        if self.window_end_ns is not None:
            limit = min(limit, self.window_end_ns)
        if (type(until) is not str or not until.isascii() or not until.isdecimal()
                or len(until) > 19 or str(int(until)) != until
                or not monotonic_ns() < int(until) <= limit):
            raise self._invalid_attestation('provider_attestation_expired')
        return ScopeEvidence(definition, role, self.source, reply['evidence_sha256'],
                             definition.clock_id, int(until), True, generation)


class _BootstrapProfileManager:
    """Own the durable mapping and consult the external source for each current check."""

    def __init__(self, selection, requirements, bindings, generation, providers, journal, *, observed_original=None,
                 require_launch_resource=False, launch_service=None, guarded_launch=False):
        self.selection, self.requirements = selection, requirements
        self.bindings, self.generation, self.providers = bindings, generation, providers
        self.journal = journal
        self.observed_original = observed_original
        self.require_launch_resource = require_launch_resource
        self.launch_service = launch_service
        self.guarded_launch = guarded_launch

    def verify_launch_scope(self, principal_uid, resource):
        if any(provider.uid == principal_uid for provider in self.providers):
            return False
        if type(self.launch_service) is ServiceBundle:
            return True  # Every exact resource is checked by verify_launch_role.
        if resource is None:
            return not self.require_launch_resource
        return self.observed_original == (resource['device'], resource['inode'])

    def verify_launch_role(self, role):
        if role.get('operation_aliases') and type(self.launch_service) is not ServiceBundle:
            return False
        if self.launch_service is None:
            return not role.get('privileged')
        if type(self.launch_service) is ServiceBundle:
            return (self.launch_service.match_role(role) and (self.guarded_launch or not role.get('privileged'))
                    and ('independent_of' not in role or bool(self.bindings.observers))
                    and (not self.launch_service.metered or 'meter' in role['operations']))
        return (self.launch_service.operations <= set(role['operations'])
                and not role.get('privileged')
                and ('independent_of' not in role or bool(self.bindings.observers)))

    def select(self, name, revision):
        if ((name, revision) != (self.selection.definition.name, self.selection.definition.revision)
                or monotonic_ns() >= self.selection.expires_ns):
            raise PermissionError('profile_not_current')
        return self.selection

    def verify_bindings(self, selected, compiled, host):
        workflow = compiled[selected.definition.name]
        if (selected != self.selection or host is not self.bindings
                or len(workflow.observers) != len(host.observers or {})
                or any(a is not b for a, b in zip(workflow.observers.values(), (host.observers or {}).values()))
                or len(workflow.meters) != len(host.meters or {})
                or any(a is not b for a, b in zip(workflow.meters.values(), (host.meters or {}).values()))):
            raise PermissionError('setup_binding_mismatch')
        return self.generation

    def attest(self, selected, requirements, generation):
        if (selected, requirements, generation) != (self.selection, self.requirements, self.generation):
            raise PermissionError('provider_selection_mismatch')
        reports = []
        deadline = managed_cli._CHECK_WORK_DEADLINE.get()
        for provider in self.providers:
            if deadline is None or not reports:
                reports.append(provider.attest(selected, requirements.role, generation))
                continue
            expires_ns = min(report.expires_ns for report in reports)
            if monotonic_ns() >= expires_ns:
                raise ConfigurationError('independent_evidence_invalid')
            # A later attestation cannot make an expired earlier one current.
            # Limit this read by that expiry as well as the transport deadline.
            token = managed_cli._CHECK_WORK_DEADLINE.set(min(deadline, expires_ns / 1_000_000_000))
            try:
                reports.append(provider.attest(selected, requirements.role, generation))
            except TimeoutError:
                if monotonic_ns() >= expires_ns:
                    raise ConfigurationError('independent_evidence_invalid') from None
                raise
            finally:
                managed_cli._CHECK_WORK_DEADLINE.reset(token)
        if len(reports) == 1:
            return reports[0]
        digest = sha256(_canonical([
            {'source': report.source, 'evidence_sha256': report.evidence_sha256} for report in reports
        ])).hexdigest()
        return ScopeEvidence(selected.definition, requirements.role, reports[0].source, digest,
                             selected.clock_id, min(report.expires_ns for report in reports), True, generation)

    def readback(self, name, revision):
        if (name, revision) != (self.selection.definition.name, self.selection.definition.revision):
            return ManagerReadback('unavailable')
        return self.journal.current_mapping(self.selection.definition)

    def create(self, selected):
        # The adapter holds the local approval lock. Revalidate the separately
        # operated provider immediately before making the immutable mapping.
        evidence = self.attest(selected, self.requirements, self.generation)
        if monotonic_ns() >= evidence.expires_ns:
            raise PermissionError('provider_attestation_expired')
        if self.journal.commit_mapping(selected.definition) not in (Persistence.COMMITTED, Persistence.EXISTING):
            raise OSError('mapping_unconfirmed')


_HOST_FIELDS = ('version', 'profile', 'revision', 'operation_key', 'authorized_uids',
                'wheel_path', 'journal_directory', 'local_approval')
_SCOPE_BASE_FIELDS = ('definition', 'policy', 'role', 'binding_generation')
_SCOPE_FIELDS = _SCOPE_BASE_FIELDS + ('observer', 'provider')
_SCOPE_OPTIONAL_FIELDS = ('observer', 'provider', 'meter', 'meter_provider')


def _provider(config, binding, definition, *, window_end_ns=None, interval=False):
    _fields(config, ('socket', 'peer_uid'))
    if (binding.principal == definition.manager
            or any(binding.principal == item.independent_of for item in definition.providers)):
        raise ValueError('provider_source_conflict')
    return _EvidenceProvider(config['socket'], config['peer_uid'], binding.principal,
                             window_end_ns=window_end_ns, interval=interval)


def _meter_peer_is_distinct(observer, meter):
    return observer.uid != meter.uid


def _inherit(fds, used):
    if any(type(fd) is not int or fd < 3 for fd in fds):
        raise ValueError('invalid_inherited_observer_handles')
    if len(set(fds)) != len(fds) or used.intersection(fds):
        raise ValueError('duplicate_inherited_setup_handles')
    for fd in fds:
        os.set_inheritable(fd, False)
    used.update(fds)


def _observer(config, binding, definition, resources, used, *, interval_provider=None):
    _fields(config, ('original_fd', 'pidfd', 'device', 'inode', 'pid', 'uid', 'slot', 'scope_sha256'),
            ('require_readable', 'directory'))
    plan = {key:value for key,value in config.items() if key not in ('original_fd','pidfd')}
    directory = config.get('directory')
    directory_fd, leaf = None, None
    if 'directory' in config:
        _fields(directory, ('directory_fd', 'device', 'inode', 'leaf'))
        plan['directory'] = {key:value for key,value in directory.items() if key != 'directory_fd'}
        directory_fd, leaf = directory['directory_fd'], directory['leaf']
    if interval_provider is not None:
        if config.get('require_readable') is not True:
            raise ValueError('interval_registration_mismatch')
        plan = {'observer': plan, 'interval_provider': interval_provider}
    if binding.reference != sha256(_canonical(plan)).hexdigest():
        raise ValueError('observer_plan_mismatch')
    original_fd, pidfd = config['original_fd'], config['pidfd']
    _inherit((original_fd, pidfd) if directory is None else (original_fd, pidfd, directory_fd), used)
    if directory is not None:
        info = os.fstat(directory_fd)
        if (type(directory['device']) is not int or type(directory['inode']) is not int
                or (info.st_dev, info.st_ino) != (directory['device'], directory['inode'])):
            raise ValueError('directory_plan_mismatch')
    readable = config.get('require_readable', False)
    if type(readable) is not bool:
        raise ValueError('invalid_inherited_observer_handles')
    if readable and fcntl.fcntl(original_fd, fcntl.F_GETFL) & os.O_PATH:
        raise ValueError('point_observer_requires_readable_original')
    return resources.enter_context(RegularFileObserver(
        scope=config['scope_sha256'], due_ns=definition.expires_ns, original_fd=original_fd, pidfd=pidfd,
        identity=Identity(config['device'], config['inode']),
        worker=Worker('target', 'observed', config['pid'], config['uid']), slot=config['slot'],
        directory_fd=directory_fd, leaf=leaf,
    ))


def _meter(config, binding, definition, resources, used, *, paired_endpoint=None):
    _fields(config, ('directory_fd', 'device', 'inode', 'mount_id', 'scope'))
    plan = {key:value for key,value in config.items() if key != 'directory_fd'}
    if paired_endpoint is not None:
        plan = {'meter': plan, 'meter_provider': paired_endpoint}
    if binding.reference != sha256(_canonical(plan)).hexdigest():
        raise ValueError('meter_plan_mismatch')
    scope = _scope_from_dict(config['scope'])
    if (scope.run.clock_id != monotonic_clock_id() or scope.scope_id != binding.scope
            or not monotonic_ns() < scope.finished_ns <= definition.expires_ns):
        raise ValueError('meter_plan_mismatch')
    fd = config['directory_fd']
    _inherit((fd,), used)
    identities = config['device'], config['inode'], config['mount_id']
    try:
        info = os.fstat(fd)
        if (any(type(pin) is not int for pin in identities)
                or identities != (info.st_dev, info.st_ino, _mount_id(fd))):
            raise ValueError('meter_plan_mismatch')
        return resources.enter_context(CgroupScopeMeter(scope=scope, provider_id=binding.name, directory_fd=fd)), scope
    except (OSError, ScopeMeterUnavailable) as exc:
        raise ValueError('scope_meter_unavailable') from exc


def _bound_scope(config, *, clock_id, resources, used, launch_plan=None, executable_argv=None,
                 launch_service=None):
    _fields(config, _SCOPE_BASE_FIELDS, _SCOPE_OPTIONAL_FIELDS + ('interval_provider',))
    # The caller has already screened the shape and mode of every scope.
    interval = 'interval_provider' in config
    has_observer = 'observer' in config
    has_meter = 'meter' in config
    definition = _definition(config['definition'])
    providers = definition.providers
    if definition.clock_id != clock_id:
        raise ValueError('setup_clock_mismatch')
    by_kind = {binding.kind:binding for binding in providers}

    policy = config['policy']
    _fields(policy, ('version', 'roles', 'workflows'))
    workflow = policy['workflows'][definition.name]
    operations = ({'observe'} if has_observer else set()) | ({'meter'} if has_meter else set())
    executables = supervisors = streams = None
    bundle = type(launch_service) is ServiceBundle
    if launch_plan is not None and launch_plan.workflow == definition.name:
        if (definition_sha256(definition) != launch_plan.definition_sha256
                or config['binding_generation'] != launch_plan.generation or config['role'] != launch_plan.role):
            raise ValueError('launch_scope_unverified')
        tool, supervisor = by_kind['executable'], by_kind['supervisor']
        if (tool.reference != launch_plan.executable_sha256 or tool.scope != definition.scope
                or (supervisor.capability, supervisor.reference, supervisor.principal, supervisor.scope) != (
                    'scoped-launch', launch_plan.scope_sha256, launch_plan.launcher, definition.scope)):
            raise ValueError('launch_scope_unverified')
        operations.add('launch')
        executables = {tool.name: executable_argv}
        supervisors = frozenset((supervisor.name,))
        if launch_service is not None:
            stream = by_kind['streams']
            stream_slots = ({slot: f'{stream.name}.{slot}' for slot in launch_service.streams} if bundle
                            else {'stdin': stream.name})
            if ((stream.capability, stream.reference, stream.principal, stream.scope) != (
                    'systemd-fd', launch_service.digest, launch_plan.launcher, definition.scope)
                    or workflow['bindings'].get('streams') != stream_slots):
                raise ValueError('launch_service_scope_unverified')
            launch_service.check_original()
            original = launch_service.observation_original if bundle else launch_service.original
            if (bundle and not has_observer and original is not None
                    or has_observer and original != tuple(str(config['observer'][field]) for field in ('device', 'inode'))):
                raise ValueError('launch_service_original_mismatch')
            selected_fds = launch_service.streams if bundle else {'stdin': launch_service.original_fd}
            streams = {stream_slots[slot]: fd for slot, fd in selected_fds.items()}
    refs = workflow['bindings']
    if (set(policy['workflows']) != {definition.name}
            or _operations(workflow['operations']) != operations
            or set(refs) != set(by_kind) or len(by_kind) != len(providers)
            or any((refs[kind] != binding.name if kind in ('executable', 'supervisor') else
                    list(refs[kind].values()) != [binding.name]) for kind,binding in by_kind.items()
                   if not (bundle and kind == 'streams'))
            or workflow['role'] != config['role']):
        raise ValueError('unsupported_setup_policy')
    policy_bytes = _canonical(policy)
    if sha256(policy_bytes).hexdigest() != definition.policy_sha256:
        raise ValueError('setup_policy_mismatch')

    selection = ManagerSelection(definition, policy_bytes, definition.clock_id, definition.expires_ns)
    requirements = _requirements(config['role'], definition)
    attesters, observers = [], {}
    if has_observer:
        observation = by_kind['observers']
        endpoint = config['interval_provider' if interval else 'provider']
        attesters.append(_provider(endpoint, observation, definition, interval=interval))
        observer = _observer(config['observer'], observation, definition, resources, used,
                             interval_provider=endpoint if interval else None)
        observers[observation.name] = (observer, None, observation.name)
    meters = None
    if has_meter:
        binding = by_kind['meters']
        endpoint = config['meter_provider']
        meter, scope = _meter(config['meter'], binding, definition, resources, used,
                              paired_endpoint=endpoint if interval else None)
        if interval and config['observer']['scope_sha256'] != sha256(_canonical(asdict(scope))).hexdigest():
            raise ValueError('interval_meter_scope_mismatch')
        attester = _provider(endpoint, binding, definition, window_end_ns=scope.finished_ns)
        if attesters and (not _meter_peer_is_distinct(attesters[0], attester)
                or (attester.path == attesters[0].path or attester.source == attesters[0].source)):
            raise ValueError('meter_provider_requires_separate_principal')
        meters = {binding.name:meter}
        attesters.append(attester)

    # The listener never authorizes a workflow operation or produces run evidence.
    bindings = HostBindings(authorize=lambda *_: False, observers=observers, meters=meters,
                            executables=executables, supervisors=supervisors, streams=streams)
    return selection, requirements, bindings, _name(config['binding_generation']), tuple(attesters)


def _scope_entries(config, *, check_only=False):
    if type(config) is not dict or type(config.get('version')) is not int:
        raise ValueError('unsupported_setup_version')
    host_fields = tuple(name for name in _HOST_FIELDS if not check_only or name != 'journal_directory')
    optional = ('journal_directory',) if check_only else ()
    if config['version'] == 1:
        _fields(config, host_fields + _SCOPE_FIELDS, optional)
        entries = [{key:config[key] for key in _SCOPE_FIELDS}]
    elif config['version'] == 2:
        _fields(config, host_fields + ('scopes',), optional)
        entries = config['scopes']
        if type(entries) is not list or not 1 <= len(entries) <= 8:
            raise ValueError('invalid_setup_scopes')
    else:
        raise ValueError('unsupported_setup_version')
    return entries


def _requirements(role, definition):
    return ProfileRequirements(role, definition.scope, tuple(
        ProviderRequirement(binding.kind, binding.name, binding.capability, binding.scope, binding.independent_of)
        for binding in definition.providers
    ))


def _definition(raw):
    return ProfileDefinition(**{**raw, 'providers': tuple(ProviderBinding(**p) for p in raw['providers'])})


def _reconcile_local(config):
    """Read an exact interrupted attempt without asking live providers."""
    entries = _scope_entries(config)
    definitions, requirements, generations = [], [], []
    for entry in entries:
        if 'interval_provider' in entry:
            raise ValueError('interval_check_only')
        _fields(entry, _SCOPE_BASE_FIELDS, _SCOPE_OPTIONAL_FIELDS)
        definition = _definition(entry['definition'])
        if sha256(_canonical(entry['policy'])).hexdigest() != definition.policy_sha256:
            raise ValueError('setup_policy_mismatch')
        definitions.append(definition)
        requirements.append(_requirements(entry['role'], definition))
        generations.append(_name(entry['binding_generation']))
    definitions = tuple(definitions)
    wheel_hash = definitions[0].package_sha256
    if any((d.package_sha256, d.clock_id) != (wheel_hash, definitions[0].clock_id) for d in definitions):
        raise ValueError('invalid_setup_scopes')
    verify_install(config['wheel_path'], wheel_hash)
    profile, revision = _name(config['profile']), _name(config['revision'])
    approval = LocalProfileApproval(**config['local_approval'])
    identity = _commissioned_identity(profile, revision, wheel_hash, definitions, requirements,
                                      generations, approval, True)
    key = config['operation_key']
    journal = ManagedJournal(Path(config['journal_directory']), definitions=definitions, scope_pins=(
        profile, revision, tuple((req.role, generation) for req, generation in zip(requirements, generations))))
    record = journal.read(identity, key)
    if record.state != 'pending':
        return {'status': 'unknown' if record.state == 'unavailable' else 'not_pending',
                'identity': identity, 'operation_key': key, 'readiness': 'not_checked',
                'scopes': [], 'effect': 'unknown'}
    results = _recover_pending(journal, identity, key, definitions)
    return {'status': 'incomplete' if any(r.status != 'unknown' for _, r in results) else 'unknown',
            'identity': identity, 'operation_key': key, 'readiness': 'not_checked', 'effect': 'unknown',
            'scopes': [{'name': name, 'status': r.status, 'effect': r.effect, 'code': r.code}
                       for name, r in results]}


class _UnsupportedScopes(ValueError):
    def __init__(self, scopes):
        self.scopes = scopes
        super().__init__(next(item['code'] for item in scopes if item['status'] == 'unavailable'))


def _paired_interval_meter(definition):
    providers = definition.providers
    return (len(providers) == 2
            and {(p.kind, p.capability) for p in providers}
                == {('observers', 'interval'), ('meters', 'cgroup-v2')}
            and len({p.principal for p in providers}) == 2
            and all(p.scope == definition.scope and p.independent_of is not None for p in providers))


def _preflight_scopes(entries, *, check_intervals=False, launch_plan=None, launch_service=None):
    """Report unsupported requested scopes before binding any resources or writing state."""
    results = []
    for entry in entries:
        definition = _definition(entry['definition'])
        name = _name(definition.name)
        descriptor_scope = launch_service is not None and launch_plan.workflow == name
        if launch_plan is not None and launch_plan.workflow == name:
            # Only the trusted launch entry can add these two bindings. The
            # normal no-start source rules still apply to the original scopes.
            excluded = {'executable', 'supervisor'} | ({'streams'} if descriptor_scope else set())
            definition = replace(definition, providers=tuple(
                provider for provider in definition.providers if provider.kind not in excluded))
        providers = definition.providers
        workflow = entry['policy']['workflows'][name]
        interval = (any(binding.kind == 'custody' or
                        (binding.kind == 'observers' and binding.capability in
                         ('interval', 'custody', 'interval-custody')) for binding in providers)
                    or workflow.get('require_custody') is True or 'custody' in workflow['bindings'])
        has_observer = 'observer' in entry
        has_meter = 'meter' in entry
        registered = 'interval_provider' in entry
        allowed = {**({'observers': 'point'} if has_observer else {}),
                   **({'meters': 'cgroup-v2'} if has_meter else {})}
        by_kind = {binding.kind: binding.capability for binding in providers}
        unsupported = (has_observer != ('provider' in entry) or
                       has_meter != ('meter_provider' in entry) or
                       len(providers) != len(allowed) or by_kind != allowed)
        if registered:
            fields = set(_SCOPE_BASE_FIELDS) | {'observer', 'interval_provider'}
            if has_meter:
                fields |= {'meter', 'meter_provider'}
            single_interval = (len(providers) == 1 and by_kind == {'observers': 'interval'}
                               and providers[0].scope == definition.scope
                               and providers[0].independent_of is not None)
            matched = _paired_interval_meter(definition) if has_meter else single_interval
            if not check_intervals:
                code = 'interval_check_only'
            elif (not matched or set(entry) != fields
                    or workflow.get('require_custody') is True or 'custody' in workflow['bindings']):
                code = 'interval_registration_mismatch'
            else:
                code = None
        else:
            code = ('interval_custody_unsupported' if interval else
                    'unsupported_setup_binding' if unsupported else
                    'independent_attester_unavailable' if not allowed and not descriptor_scope else None)
        result = {'name': name, 'status': 'unavailable' if code else 'not_checked'}
        if code:
            result['code'] = code
        results.append(result)
    if len({item['name'] for item in results}) != len(results):
        raise ValueError('invalid_setup_scopes')
    if any(item['status'] == 'unavailable' for item in results):
        raise _UnsupportedScopes(results)


class _CheckOnlyStore:
    """Supply the adapter interface without opening a journal."""

    def read(self, *_):
        raise PermissionError('binding_check_only')

    claim = finish = read


def _build(config, resources, *, check_only=False, launch_registration=None, executable_argv=None,
           require_launch_resource=False, launch_service=None):
    entries = _scope_entries(config, check_only=check_only)
    launch_plan = launch_registration.plan if launch_registration is not None else None
    guarded_launch = (type(launch_service) is ServiceBundle and launch_registration is not None
                      and launch_registration.service_enforcement == GUARDED_SERVICE
                      and launch_registration.service_scope_sha256 == launch_service.digest)
    _preflight_scopes(entries, check_intervals=check_only, launch_plan=launch_plan, launch_service=launch_service)

    clock_id = setup_clock_id()
    used = set()
    registrations = tuple(_bound_scope(entry, clock_id=clock_id, resources=resources, used=used,
                                       launch_plan=launch_plan, executable_argv=executable_argv,
                                       launch_service=launch_service)
                          for entry in entries)
    definitions = tuple(selection.definition for selection,*_ in registrations)
    if launch_plan is not None and launch_plan.workflow not in {definition.name for definition in definitions}:
        raise ValueError('launch_scope_unverified')
    wheel_hash = definitions[0].package_sha256
    if any(definition.package_sha256 != wheel_hash for definition in definitions):
        raise ValueError('invalid_setup_scopes')
    verify_install(config['wheel_path'], wheel_hash)
    if check_only:
        journal = _CheckOnlyStore()
    else:
        journal = ManagedJournal(Path(config['journal_directory']), definitions=definitions, scope_pins=(
            config['profile'], config['revision'],
            tuple((requirements.role, generation) for _, requirements, _, generation, _ in registrations)))
        journal.store.check_policy(_POLICY)
    scopes = tuple(
        ScopeSetup(selection.definition.name, selection.definition.revision, requirements,
            _BootstrapProfileManager(selection, requirements, bindings, generation, attesters, journal,
                observed_original=(launch_service.observation_original if type(launch_service) is ServiceBundle
                    else launch_service.original if launch_service is not None else (
                        tuple(str(entry['observer'][key]) for key in ('device', 'inode'))
                        if 'observer' in entry else None)),
                require_launch_resource=require_launch_resource, launch_service=launch_service,
                guarded_launch=guarded_launch),
            bindings)
        for (selection, requirements, bindings, generation, attesters), entry in zip(registrations, entries, strict=True)
    )
    adapter = ManagedHostAdapter(profile=config['profile'], revision=config['revision'],
        operation_key=config['operation_key'], scopes=scopes, definitions=definitions,
        generations=tuple(item[3] for item in registrations), wheel=config['wheel_path'], wheel_sha256=wheel_hash,
        clock_id=clock_id, store=journal, local_approval=LocalProfileApproval(**config['local_approval']),
        local_appointments=True, launch_registration=launch_registration)
    uids = config['authorized_uids']
    if (type(uids) is not list or not 1 <= len(uids) <= 64
            or any(type(uid) is not int or not 0 <= uid < 2**32 - 1 for uid in uids)):
        raise ValueError('invalid_authorized_uids')
    return adapter, frozenset(uids), used


@contextmanager
def open_approved_launch(registration, *, executable_argv, config=None, require_launch_resource=False):
    """Compose a trusted bounded backend with the installed administrator registry.

    The argv is host enrollment metadata for checking the compiled policy; the
    stock adapter never executes it. The external backend enforces the plan.
    The entitled host may supply the same protected configuration explicitly.
    """
    if os.geteuid() != managed_cli._TRUSTED_UID:
        raise PermissionError('administrator_required')
    if (type(registration) is not LaunchRegistration or not registration.bounded
            or type(executable_argv) is not tuple or not executable_argv
            or any(type(value) is not str or '\0' in value for value in executable_argv)
            or not executable_argv[0]):
        raise ValueError('trusted_launch_backend_unavailable')
    if config is None:
        config = managed_cli._read_admin_json(_CONFIG_FILE)
    with _open_approved_launch(config, registration, executable_argv=executable_argv,
                               require_launch_resource=require_launch_resource) as adapter:
        yield adapter


@contextmanager
def _open_approved_launch(config, registration, *, executable_argv, require_launch_resource=False,
                          launch_service=None):
    with ExitStack() as resources:
        adapter, _, _ = _build(config, resources, check_only=True, launch_registration=registration,
                               executable_argv=executable_argv, require_launch_resource=require_launch_resource,
                               launch_service=launch_service)
        with adapter._approval(launch_plan=registration.plan) as (code, _, _):
            if code is not None:
                raise PermissionError(code)
        yield adapter


def main(argv=None):
    parser = argparse.ArgumentParser(prog='workeros managed serve-setup', description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--listen-fd', metavar='FD', type=int, help='preopened listening Unix stream socket')
    mode.add_argument('--describe', action='store_true', help='show pinned client identity without serving')
    mode.add_argument('--recover-interrupted', action='store_true',
                      help='read exact interrupted scope commits locally without live providers')
    parser.add_argument('--check-bindings', action='store_true',
                        help='verify bindings locally or restrict --describe or --listen-fd to binding checks')
    args = parser.parse_args(argv)
    if not (args.check_bindings or args.describe or args.listen_fd is not None or args.recover_interrupted):
        parser.error('choose --check-bindings, --describe, --listen-fd or --recover-interrupted')
    if args.check_bindings and args.recover_interrupted:
        parser.error('--check-bindings cannot be combined with --recover-interrupted')
    try:
        if os.geteuid() != managed_cli._TRUSTED_UID:
            raise PermissionError('administrator_required')
        config = managed_cli._read_admin_json(_CONFIG_FILE)
        if args.recover_interrupted:
            recovered = _reconcile_local(config)
            print(json.dumps(recovered, sort_keys=True))
            return 1  # This is historical scope evidence, never setup completion.
        with ExitStack() as resources:
            adapter, uids, handles = _build(config, resources, check_only=args.check_bindings)
            if args.describe:
                print(json.dumps({'status':'configured','identity':adapter.identity,'profile':adapter.profile,
                                  'scopes':[scope.name for scope in adapter.scopes],
                                  'binding_check':adapter.binding_check_pins()}, sort_keys=True))
                return 0
            if args.listen_fd is None:
                checked = adapter.check_bindings()
                print(json.dumps(checked, sort_keys=True))
                return 0 if checked['status'] == 'bindings_verified' else 1
            if args.listen_fd < 3 or args.listen_fd in handles:
                raise ValueError('invalid_listener_descriptor')
            listener = resources.enter_context(socket.socket(fileno=os.dup(args.listen_fd)))
            managed_cli.serve_listener_once(listener, authorized_uids=uids, adapter=adapter,
                                            check_only=args.check_bindings)
            return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, EOFError, RecordError) as exc:
        code = str(exc)
        result = {'status': 'unavailable',
                  'code': code if code in _HOST_REFUSALS else 'managed_setup_host_unavailable'}
        if args.check_bindings:
            result.update(effect='not_attempted', readiness='not_checked',
                          independence='unverified', runtime_evidence='not_requested')
        if isinstance(exc, _UnsupportedScopes):
            result.update(scopes=exc.scopes, effect='not_attempted', readiness='not_checked')
        if code == 'interval_custody_unsupported':
            result.update(effect='not_attempted',
                          next_action='Use a separately authorized custody workflow with evidence through cleanup.')
        print(json.dumps(result))
        return 1
