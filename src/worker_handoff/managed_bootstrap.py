"""Serve one no-start setup request for approved point observers and scope meters."""
import argparse
from contextlib import ExitStack
from dataclasses import asdict
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
    'interval_custody_unsupported',
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

    def __init__(self, socket_path, uid, source, *, window_end_ns=None):
        if (type(socket_path) is not str or not socket_path.startswith('/')
                or '\0' in socket_path or len(os.fsencode(socket_path)) > 107
                or type(uid) is not int or not 0 <= uid < 2**32 - 1):
            raise ValueError('invalid_provider_endpoint')
        if not _provider_is_independent(uid):
            raise ValueError('provider_requires_distinct_uid')
        self.path, self.uid, self.source = socket_path, uid, _name(source)
        self.window_end_ns = window_end_ns

    def attest(self, selection, role, generation):
        definition = selection.definition
        request = {'version': 1, 'request_id': uuid4().hex, 'definition_sha256': definition_sha256(definition),
                   'role': role, 'clock_id': definition.clock_id, 'generation': generation}
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
                raise ValueError('invalid_provider_frame')
            reply = managed_cli.decode_policy(managed_cli._read_exact(connection, size, deadline))
        expected = {'request_id':request['request_id'], 'definition_sha256':request['definition_sha256'],
                    'role':role, 'clock_id':definition.clock_id, 'generation':generation,
                    'source':self.source, 'status':'verified'}
        if (type(reply) is not dict or set(reply) != set(expected) | {'evidence_sha256', 'valid_until_ns'}
                or any(reply[key] != value for key, value in expected.items())):
            raise ValueError('provider_attestation_mismatch')
        until = reply['valid_until_ns']
        limit = selection.expires_ns
        if self.window_end_ns is not None:
            limit = min(limit, self.window_end_ns)
        if (type(until) is not str or not until.isascii() or not until.isdecimal()
                or len(until) > 19 or str(int(until)) != until
                or not monotonic_ns() < int(until) <= limit):
            raise ValueError('provider_attestation_expired')
        return ScopeEvidence(definition, role, self.source, reply['evidence_sha256'],
                             definition.clock_id, int(until), True, generation)


class _BootstrapProfileManager:
    """Own the durable mapping and consult the external source for each current check."""

    def __init__(self, selection, requirements, bindings, generation, providers, journal):
        self.selection, self.requirements = selection, requirements
        self.bindings, self.generation, self.providers = bindings, generation, providers
        self.journal = journal

    def select(self, name, revision):
        if ((name, revision) != (self.selection.definition.name, self.selection.definition.revision)
                or monotonic_ns() >= self.selection.expires_ns):
            raise PermissionError('profile_not_current')
        return self.selection

    def verify_bindings(self, selected, compiled, host):
        workflow = compiled[selected.definition.name]
        if (selected != self.selection or host is not self.bindings
                or len(workflow.observers) != 1
                or next(iter(workflow.observers.values())) is not next(iter(host.observers.values()))
                or len(workflow.meters) != len(host.meters or {})
                or host.meters is not None
                and next(iter(workflow.meters.values())) is not next(iter(host.meters.values()))):
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
_SCOPE_FIELDS = ('definition', 'policy', 'role', 'binding_generation', 'observer', 'provider')


def _provider(config, binding, definition, *, window_end_ns=None):
    _fields(config, ('socket', 'peer_uid'))
    if (binding.principal == definition.manager
            or any(binding.principal == item.independent_of for item in definition.providers)):
        raise ValueError('provider_source_conflict')
    return _EvidenceProvider(config['socket'], config['peer_uid'], binding.principal,
                             window_end_ns=window_end_ns)


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


def _observer(config, binding, definition, resources, used):
    _fields(config, ('original_fd', 'pidfd', 'device', 'inode', 'pid', 'uid', 'slot', 'scope_sha256'),
            ('require_readable', 'directory'))
    plan = {key:value for key,value in config.items() if key not in ('original_fd','pidfd')}
    directory = config.get('directory')
    directory_fd, leaf = None, None
    if 'directory' in config:
        _fields(directory, ('directory_fd', 'device', 'inode', 'leaf'))
        plan['directory'] = {key:value for key,value in directory.items() if key != 'directory_fd'}
        directory_fd, leaf = directory['directory_fd'], directory['leaf']
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


def _meter(config, binding, definition, resources, used):
    _fields(config, ('directory_fd', 'device', 'inode', 'mount_id', 'scope'))
    plan = {key:value for key,value in config.items() if key != 'directory_fd'}
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


def _bound_scope(config, *, clock_id, resources, used):
    _fields(config, _SCOPE_FIELDS, ('meter', 'meter_provider'))
    has_meter = 'meter' in config
    if has_meter != ('meter_provider' in config):
        raise ValueError('unsupported_setup_binding')
    definition = _definition(config['definition'])
    providers = definition.providers
    if definition.clock_id != clock_id:
        raise ValueError('setup_clock_mismatch')
    if any(binding.kind == 'custody' or
           (binding.kind == 'observers' and binding.capability in ('interval', 'custody', 'interval-custody'))
           for binding in providers):
        raise ValueError('interval_custody_unsupported')
    by_kind = {binding.kind:binding for binding in providers}
    allowed = {'observers':'point', 'meters':'cgroup-v2'} if has_meter else {'observers':'point'}
    if len(providers) != len(allowed) or {kind:binding.capability for kind,binding in by_kind.items()} != allowed:
        raise ValueError('unsupported_setup_binding')

    policy = config['policy']
    _fields(policy, ('version', 'roles', 'workflows'))
    workflow = policy['workflows'][definition.name]
    if workflow.get('require_custody') is True or 'custody' in workflow['bindings']:
        raise ValueError('interval_custody_unsupported')
    operations = {'observe', 'meter'} if has_meter else {'observe'}
    if (set(policy['workflows']) != {definition.name}
            or _operations(workflow['operations']) != operations
            or set(workflow['bindings']) != set(allowed)
            or any(list(workflow['bindings'][kind].values()) != [binding.name] for kind,binding in by_kind.items())
            or workflow['role'] != config['role']):
        raise ValueError('unsupported_setup_policy')
    policy_bytes = _canonical(policy)
    if sha256(policy_bytes).hexdigest() != definition.policy_sha256:
        raise ValueError('setup_policy_mismatch')

    selection = ManagerSelection(definition, policy_bytes, definition.clock_id, definition.expires_ns)
    requirements = _requirements(config['role'], definition)
    observation = by_kind['observers']
    attesters = [_provider(config['provider'], observation, definition)]
    observer = _observer(config['observer'], observation, definition, resources, used)
    meters = None
    if has_meter:
        binding = by_kind['meters']
        meter, scope = _meter(config['meter'], binding, definition, resources, used)
        attester = _provider(config['meter_provider'], binding, definition, window_end_ns=scope.finished_ns)
        if (not _meter_peer_is_distinct(attesters[0], attester)
                or (attester.path == attesters[0].path or attester.source == attesters[0].source)):
            raise ValueError('meter_provider_requires_separate_principal')
        meters = {binding.name:meter}
        attesters.append(attester)

    # The listener never authorizes a workflow operation or produces run evidence.
    bindings = HostBindings(authorize=lambda *_: False,
                            observers={observation.name:(observer,None,observation.name)}, meters=meters)
    return selection, requirements, bindings, _name(config['binding_generation']), tuple(attesters)


def _scope_entries(config):
    if type(config) is not dict or type(config.get('version')) is not int:
        raise ValueError('unsupported_setup_version')
    if config['version'] == 1:
        _fields(config, _HOST_FIELDS + _SCOPE_FIELDS)
        entries = [{key:config[key] for key in _SCOPE_FIELDS}]
    elif config['version'] == 2:
        _fields(config, _HOST_FIELDS + ('scopes',))
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
        _fields(entry, _SCOPE_FIELDS, ('meter', 'meter_provider'))
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


def _build(config, resources):
    entries = _scope_entries(config)

    clock_id = setup_clock_id()
    used = set()
    registrations = tuple(_bound_scope(entry, clock_id=clock_id, resources=resources, used=used)
                          for entry in entries)
    definitions = tuple(selection.definition for selection,*_ in registrations)
    wheel_hash = definitions[0].package_sha256
    if any(definition.package_sha256 != wheel_hash for definition in definitions):
        raise ValueError('invalid_setup_scopes')
    verify_install(config['wheel_path'], wheel_hash)
    journal = ManagedJournal(Path(config['journal_directory']), definitions=definitions, scope_pins=(
        config['profile'], config['revision'],
        tuple((requirements.role, generation) for _, requirements, _, generation, _ in registrations)))
    journal.store.check_policy(_POLICY)
    scopes = tuple(
        ScopeSetup(selection.definition.name, selection.definition.revision, requirements,
            _BootstrapProfileManager(selection, requirements, bindings, generation, attesters, journal),
            bindings)
        for selection,requirements,bindings,generation,attesters in registrations
    )
    adapter = ManagedHostAdapter(profile=config['profile'], revision=config['revision'],
        operation_key=config['operation_key'], scopes=scopes, definitions=definitions,
        generations=tuple(item[3] for item in registrations), wheel=config['wheel_path'], wheel_sha256=wheel_hash,
        clock_id=clock_id, store=journal, local_approval=LocalProfileApproval(**config['local_approval']),
        local_appointments=True)
    uids = config['authorized_uids']
    if (type(uids) is not list or not 1 <= len(uids) <= 64
            or any(type(uid) is not int or not 0 <= uid < 2**32 - 1 for uid in uids)):
        raise ValueError('invalid_authorized_uids')
    return adapter, frozenset(uids), used


def main(argv=None):
    parser = argparse.ArgumentParser(prog='workeros managed serve-setup', description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--listen-fd', metavar='FD', type=int, help='preopened listening Unix stream socket')
    mode.add_argument('--describe', action='store_true', help='show pinned client identity without serving')
    mode.add_argument('--check-bindings', action='store_true', help='verify approved bindings without recording setup')
    mode.add_argument('--recover-interrupted', action='store_true',
                      help='read exact interrupted scope commits locally without live providers')
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != managed_cli._TRUSTED_UID:
            raise PermissionError('administrator_required')
        config = managed_cli._read_admin_json(_CONFIG_FILE)
        if args.recover_interrupted:
            recovered = _reconcile_local(config)
            print(json.dumps(recovered, sort_keys=True))
            return 1  # This is historical scope evidence, never setup completion.
        with ExitStack() as resources:
            adapter, uids, handles = _build(config, resources)
            if args.describe:
                print(json.dumps({'status':'configured','identity':adapter.identity,'profile':adapter.profile,
                                  'scopes':[scope.name for scope in adapter.scopes],
                                  'binding_check':adapter.binding_check_pins()}, sort_keys=True))
                return 0
            if args.check_bindings:
                checked = adapter.check_bindings()
                print(json.dumps(checked, sort_keys=True))
                return 0 if checked['status'] == 'bindings_verified' else 1
            if args.listen_fd < 3 or args.listen_fd in handles:
                raise ValueError('invalid_listener_descriptor')
            listener = resources.enter_context(socket.socket(fileno=os.dup(args.listen_fd)))
            managed_cli.serve_listener_once(listener, authorized_uids=uids, adapter=adapter)
            return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, EOFError, RecordError) as exc:
        code = str(exc)
        result = {'status': 'unavailable',
                  'code': code if code in _HOST_REFUSALS else 'managed_setup_host_unavailable'}
        if args.check_bindings:
            result.update(effect='not_attempted', readiness='not_checked',
                          independence='unverified', runtime_evidence='not_requested')
        if code == 'interval_custody_unsupported':
            result.update(effect='not_attempted',
                          next_action='Use a separately authorized custody workflow with evidence through cleanup.')
        print(json.dumps(result))
        return 1
