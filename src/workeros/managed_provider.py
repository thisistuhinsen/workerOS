"""Serve bounded, independently operated binding checks on preopened resources."""
import argparse
from contextlib import ExitStack
from dataclasses import asdict, replace
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
from time import monotonic, monotonic_ns

from . import managed_cli
from .appointment_registry import definition_sha256
from .evidence import EvidenceState, ScopePhase
from .lifecycle import Match, ProcessState
from .managed_bootstrap import _meter, _observer, _paired_interval_meter, setup_clock_id
from .profile_setup import ProfileDefinition, ProviderBinding
from .recording import _name
from .roles_cli import _canonical, _fields


_PEER = struct.Struct('=iII')
_SIZE = struct.Struct('!I')
_DIGEST = re.compile(r'[0-9a-f]{64}')
_POINT = ('observers', 'point')
_INTERVAL = ('observers', 'interval')
_CGROUP_METER = ('meters', 'cgroup-v2')
_LAUNCH_METADATA = {('executable', 'executable'), ('supervisor', 'scoped-launch')}
_SERVICE_METADATA = _LAUNCH_METADATA | {('streams', 'systemd-fd')}
_MAX_REQUESTS = 16
_SESSION_SECONDS = 30.0


class ProviderRefusal(ValueError):
    pass


def _read_registration(fd):
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != managed_cli._TRUSTED_UID
            or info.st_mode & 0o022 or info.st_nlink != 1
            or flags & os.O_PATH or flags & os.O_ACCMODE != os.O_RDONLY):
        raise ProviderRefusal('untrusted_provider_registration')
    if info.st_size > managed_cli._LIMIT:
        raise ProviderRefusal('provider_registration_too_large')
    raw = os.pread(fd, managed_cli._LIMIT + 1, 0)
    if len(raw) != info.st_size:
        raise ProviderRefusal('provider_registration_changed')
    return managed_cli.decode_policy(raw)


def _point_launch_metadata(definition, binding, observer, provider_uid):
    """Check the opt-in shape without removing metadata from the definition pin."""
    by_kind = {(entry.kind, entry.capability): entry for entry in definition.providers}
    if ((binding.kind, binding.capability) != _POINT or len(definition.providers) != 3
            or set(by_kind) != _LAUNCH_METADATA | {_POINT}):
        return False
    tool = by_kind['executable', 'executable']
    launcher = by_kind['supervisor', 'scoped-launch']
    return (all(entry.scope == definition.scope for entry in definition.providers)
            and _DIGEST.fullmatch(tool.reference) is not None and _DIGEST.fullmatch(launcher.reference) is not None
            and tool.principal == launcher.principal and binding.principal != launcher.principal
            and binding.independent_of is not None and type(observer) is dict
            and type(observer.get('uid')) is int and observer['uid'] != provider_uid)


def _service_evidence(definition):
    """Return the evidence-only view for shape checks, never for wire pins."""
    by_kind = {(entry.kind, entry.capability): entry for entry in definition.providers}
    if len(by_kind) != len(definition.providers) or not _SERVICE_METADATA <= by_kind.keys():
        return None
    evidence_kinds = by_kind.keys() - _SERVICE_METADATA
    if evidence_kinds not in ({_POINT}, {_CGROUP_METER}, {_POINT, _CGROUP_METER}, {_INTERVAL, _CGROUP_METER}):
        return None
    metadata = tuple(by_kind[kind] for kind in _SERVICE_METADATA)
    launcher = by_kind['supervisor', 'scoped-launch'].principal
    if (any(entry.scope != definition.scope for entry in definition.providers)
            or any(entry.principal != launcher or _DIGEST.fullmatch(entry.reference) is None
                   for entry in metadata)):
        return None
    evidence = tuple(entry for entry in definition.providers if (entry.kind, entry.capability) in evidence_kinds)
    principals = {entry.principal for entry in evidence}
    if (len(principals) != len(evidence) or principals & {launcher, definition.manager}
            or any(entry.independent_of is None or entry.independent_of in principals for entry in evidence)):
        return None
    return replace(definition, providers=evidence)


def _paired_meter(definition):
    return _paired_interval_meter(_service_evidence(definition) or definition)


def _registration(config):
    _fields(config, ('version', 'host_uid', 'provider_uid', 'definition', 'role',
                     'binding_generation', 'binding'), ('observer', 'meter'))
    if type(config['version']) is not int or config['version'] != 1:
        raise ProviderRefusal('unsupported_provider_version')
    host, provider = config['host_uid'], config['provider_uid']
    if (any(type(uid) is not int or not 0 <= uid < 2**32 - 1 for uid in (host, provider))
            or not provider or host == provider or os.getresuid() != (provider,) * 3):
        raise ProviderRefusal('provider_requires_distinct_uid')
    overflow_uid = int(Path('/proc/sys/kernel/overflowuid').read_text(encoding='ascii'))
    if overflow_uid in (host, provider):
        raise ProviderRefusal('provider_requires_mapped_uids')
    refs = config['definition']
    providers = tuple(ProviderBinding(**entry) for entry in refs['providers'])
    definition = ProfileDefinition(**{**refs, 'providers': providers})
    name = _name(config['binding'])
    selected = [binding for binding in providers if binding.name == name]
    if len(selected) != 1:
        raise ProviderRefusal('provider_binding_unavailable')
    binding, = selected
    supported = {_POINT, _CGROUP_METER}
    service = _service_evidence(definition)
    if (binding.kind, binding.capability) == _CGROUP_METER and _paired_interval_meter(service or definition):
        supported.add(_INTERVAL)
    if _point_launch_metadata(definition, binding, config.get('observer'), provider):
        supported.update(_LAUNCH_METADATA)
    if service is not None and (binding.kind, binding.capability) in {_POINT, _CGROUP_METER}:
        observer = config.get('observer')
        if (binding.kind, binding.capability) == _CGROUP_METER or (
                type(observer) is dict and type(observer.get('uid')) is int and observer['uid'] != provider):
            supported.update(_SERVICE_METADATA)
    kinds = {(entry.kind, entry.capability) for entry in providers}
    if kinds - supported or len(providers) != len(kinds):
        raise ProviderRefusal('provider_capability_unsupported')
    field = 'observer' if binding.kind == 'observers' else 'meter'
    if config.keys() & {'observer', 'meter'} != {field}:
        raise ProviderRefusal('provider_binding_mismatch')
    if binding.principal == definition.manager or any(
            binding.principal == provider.independent_of for provider in providers):
        raise ProviderRefusal('provider_source_conflict')
    if monotonic_ns() >= definition.expires_ns:
        raise ProviderRefusal('provider_registration_expired')
    try:
        clock = setup_clock_id()
    except ValueError as exc:
        raise ProviderRefusal('monotonic_clock_unavailable') from exc
    if definition.clock_id != clock:
        raise ProviderRefusal('setup_clock_mismatch')
    _name(config['role'])
    _name(config['binding_generation'])
    return definition, binding


def _point_digest(observer, *, require_readable, require_name):
    sample = observer.sample()
    if (sample.process != ProcessState.LIVE or sample.slot_match != Match.ORIGINAL
            or sample.flags is None
            or require_name and sample.name_match != Match.ORIGINAL
            or require_readable and (sample.flags & os.O_PATH
                                     or sample.flags & os.O_ACCMODE == os.O_WRONLY)):
        raise ProviderRefusal('point_observation_unavailable')
    return sha256(_canonical(asdict(sample))).hexdigest(), sample.finished_ns


def _meter_digest(meter):
    # Check one current reading only. This is neither a measurement pair nor
    # evidence that the scope is dedicated, empty or retired.
    sample = meter.sample(ScopePhase.METER_BEGIN)
    if (sample.report is None or sample.cpu_state is not EvidenceState.OBSERVED
            or sample.population_state is not EvidenceState.OBSERVED):
        raise ProviderRefusal('meter_observation_unavailable')
    return sha256(_canonical(asdict(sample))).hexdigest(), sample.finished_ns


def _credentials(connection):
    return _PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size))[:2]


def _remaining(deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError()
    return remaining


def _serve(listener, config, definition, binding, resource, *, max_requests=1):
    if type(max_requests) is not int or not 1 <= max_requests <= _MAX_REQUESTS:
        raise ProviderRefusal('provider_request_limit_invalid')
    if (listener.family != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
        raise ProviderRefusal('invalid_provider_listener')
    pid, uid = _credentials(listener)
    if pid <= 0 or uid != config['provider_uid']:
        raise ProviderRefusal('provider_listener_identity_mismatch')
    duration = managed_cli._TIMEOUT if max_requests == 1 else _SESSION_SECONDS
    deadline = min(monotonic() + duration, definition.expires_ns / 1_000_000_000)
    expected = {'definition_sha256': definition_sha256(definition), 'role': config['role'],
                'clock_id': definition.clock_id, 'generation': config['binding_generation']}
    scope_end = config['meter']['scope']['finished_ns'] if binding.kind == 'meters' else definition.expires_ns
    seen = set()
    for _ in range(max_requests):
        try:
            listener.settimeout(_remaining(min(deadline, monotonic() + managed_cli._TIMEOUT)))
            connection, _ = listener.accept()
        except TimeoutError:
            if seen:
                return
            raise
        with connection:
            _serve_once(connection, config, binding, resource, expected, seen,
                        min(definition.expires_ns, scope_end),
                        min(deadline, monotonic() + managed_cli._TIMEOUT))


def _serve_once(connection, config, binding, resource, expected, seen, evidence_end, deadline):
    pid, uid = _credentials(connection)
    if pid <= 0 or pid == os.getpid() or uid != config['host_uid']:
        raise ProviderRefusal('provider_host_untrusted')
    size, = _SIZE.unpack(managed_cli._read_exact(connection, _SIZE.size, deadline))
    if not 0 < size <= managed_cli._LIMIT:
        raise ProviderRefusal('invalid_provider_request')
    request = managed_cli.decode_policy(managed_cli._read_exact(connection, size, deadline))
    if (type(request) is not dict or request.keys() != expected.keys() | {'version', 'request_id'}
            or type(request['version']) is not int or request['version'] != 1
            or type(request['request_id']) is not str
            or not re.fullmatch(r'[0-9a-f]{32}', request['request_id'])
            or request['request_id'] in seen
            or any(request[key] != value for key, value in expected.items())):
        raise ProviderRefusal('invalid_provider_request')
    if binding.kind == 'meters':
        digest, observed_end_ns = _meter_digest(resource)
    else:
        plan = config['observer']
        digest, observed_end_ns = _point_digest(
            resource, require_readable=plan.get('require_readable', False), require_name='directory' in plan)
    expiry = min(evidence_end, observed_end_ns + 1_000_000_000)
    if monotonic_ns() >= expiry:
        raise ProviderRefusal('provider_registration_expired')
    reply = _canonical({**expected, 'request_id': request['request_id'], 'status': 'verified',
                        'source': binding.principal, 'evidence_sha256': digest,
                        'valid_until_ns': str(expiry)})
    connection.settimeout(_remaining(deadline))
    connection.sendall(_SIZE.pack(len(reply)) + reply)
    seen.add(request['request_id'])


def main(argv=None):
    parser = argparse.ArgumentParser(prog='workeros managed serve-provider', description=__doc__)
    parser.add_argument('--config-fd', type=int, required=True, help='preopened administrator registration')
    parser.add_argument('--listen-fd', type=int, required=True, help='Unix stream listener set up under the provider UID')
    parser.add_argument('--max-requests', type=int, default=1,
                        help='maximum fresh checks in one session (1–16, default 1)')
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.max_requests <= _MAX_REQUESTS:
            raise ProviderRefusal('provider_request_limit_invalid')
        if (args.config_fd < 0 or args.config_fd in (1, 2) or args.listen_fd < 3
                or args.config_fd == args.listen_fd):
            raise ProviderRefusal('invalid_provider_descriptors')
        config = _read_registration(args.config_fd)
        definition, binding = _registration(config)
        with ExitStack() as resources:
            used = {args.config_fd, args.listen_fd}
            listener = resources.enter_context(socket.socket(fileno=os.dup(args.listen_fd)))
            if binding.kind == 'meters':
                endpoint = ({'socket': listener.getsockname(), 'peer_uid': config['provider_uid']}
                            if _paired_meter(definition) else None)
                resource, _ = _meter(config['meter'], binding, definition, resources, used,
                                     paired_endpoint=endpoint)
            else:
                resource = _observer(config['observer'], binding, definition, resources, used)
            _serve(listener, config, definition, binding, resource, max_requests=args.max_requests)
        return 0
    except ProviderRefusal as exc:
        code = str(exc)
    except (OSError, ValueError, TypeError, KeyError, EOFError, OverflowError):
        code = 'provider_unavailable'
    print(json.dumps({'status': 'unavailable', 'code': code, 'effect': 'not_attempted'}))
    return 1
