#!/usr/bin/env python3
"""Render drafts for the installed guarded service without applying them."""

import argparse
from dataclasses import asdict
from hashlib import sha256
import os
from pathlib import Path
import stat
import sys
from time import monotonic_ns, time

from workeros import managed_registration, roles_cli
from workeros.appointment_registry import definition_sha256, launch_policy_sha256, launch_scope_sha256
from workeros.managed_bootstrap import setup_clock_id
from workeros.managed_cli import _LIMIT, _TRUSTED_UID, decode_policy
from workeros.managed_executor import authority_pin
from workeros.managed_launch import GUARDED_SERVICE, LaunchRolePolicy
from workeros.managed_service_scope import ServiceBundle
from workeros.profile_setup import ProfileDefinition, ProviderBinding
from workeros.verify_install import VerificationError, verify_install


def load(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('regular input required')
        return decode_policy(stream.read(_LIMIT + 1))


def digest(value):
    return sha256(roles_cli._canonical(value)).hexdigest()


def draft_one(spec):
    roles_cli._fields(spec, (
        'profile', 'revision', 'workflow', 'workflow_revision', 'generation',
        'role', 'principal', 'launcher', 'manager', 'authority', 'authority_socket',
        'authority_uid', 'wheel_path', 'wheel_sha256', 'executable_sha256',
        'expires_at', 'expires_ns', 'operation_key', 'service', 'run_uids', 'result_uids',
        'journal_directory', 'client_socket',
    ), ('holder', 'result_observer', 'rotate_from'))
    wheel = spec['wheel_sha256']
    version = verify_install(spec['wheel_path'], wheel)['version']
    service = ServiceBundle(**spec['service'])
    if not service.descriptors or service.parent is None or not service.parent.delegated_service:
        raise ValueError('expected a pinned delegated service and approved descriptors')
    principal = roles_cli._principal(spec['principal'])
    deadline, expiry = spec['expires_ns'], spec['expires_at']
    now = monotonic_ns()
    if (type(deadline) is not int or type(expiry) is not int
            or not now < deadline <= now + int((expiry - time()) * 1_000_000_000)):
        raise ValueError('service deadline exceeds approved role expiry')
    if principal.pw_gid != service.principal_gid:
        raise ValueError('worker primary group differs from the approved service')
    profile, revision = spec['profile'], spec['revision']
    workflow, generation, launcher = spec['workflow'], spec['generation'], spec['launcher']
    primary = service.descriptors[0].scope
    operations = ['launch']
    aliases = {item.name: {'scope': item.scope, 'capability': item.operation, 'provider_sha256': service.digest}
               for item in service.elevated_capabilities}
    delegated = {(item.scope, item.operation) for item in service.elevated_capabilities}
    native = sorted({operation for item in service.descriptors for operation in item.operations
                     if (item.scope, operation) not in delegated})
    role = {'name': spec['role'], 'principal': spec['principal'], 'expires_at': expiry,
            'scopes': [item.scope for item in service.descriptors],
            'operations': ['launch', *(['meter'] if service.metered else []), *native, *aliases],
            'privileged': [{'capability': name, 'scope': entry['scope'], 'approved': True}
                           for name, entry in aliases.items()],
            'operation_aliases': aliases,
            'resources': {item.scope: {'device': str(item.device), 'inode': str(item.inode)}
                          for item in service.descriptors}}
    declaration = {'version': 1, 'profile': profile, 'revision': revision, 'roles': [role]}
    roles_cli._validate(roles_cli._canonical(declaration))
    scope_pin = launch_scope_sha256(role, primary, operations)
    policy = {'version': 1, 'roles': {role['name']: {'operations': operations}},
              'workflows': {workflow: {'role': role['name'], 'operations': operations, 'bindings': {
                  'executable': 'approved-executable', 'supervisor': 'approved-supervisor',
                  'streams': {item.slot: 'approved-originals.' + item.slot for item in service.descriptors}}}}}
    definition = ProfileDefinition(workflow, spec['workflow_revision'], version, wheel, digest(policy),
        spec['manager'], primary, setup_clock_id(), deadline, (
            ProviderBinding('approved-executable', spec['executable_sha256'], primary,
                            'executable', launcher, 'executable'),
            ProviderBinding('approved-supervisor', scope_pin, primary, 'scoped-launch', launcher, 'supervisor'),
            ProviderBinding('approved-originals', service.digest, primary, 'systemd-fd', launcher, 'streams')))
    authority = spec['authority']
    endpoint = {'socket': spec['authority_socket'], 'uid': spec['authority_uid'], 'enforcement': GUARDED_SERVICE}
    launch = LaunchRolePolicy(workflow, definition_sha256(definition), generation, role['name'], principal.pw_name,
        spec['executable_sha256'], scope_pin, launcher, authority,
        authority_pin(authority, endpoint['socket'], endpoint['uid']), principal.pw_uid)
    policy_pin = launch_policy_sha256(launch)
    appointed = {**declaration, 'appointments': [{
        'workflow': workflow, 'workflow_revision': definition.revision, 'scope': primary,
        'definition_sha256': launch.definition_sha256, 'generation': generation, 'role': role['name'],
        'principal': principal.pw_name, 'operations': operations,
        'launch': {'scope_sha256': scope_pin, 'policy_sha256': policy_pin}}]}
    readers, callers = spec['result_uids'], spec['run_uids']
    pins = {'profile': profile, 'revision': revision, 'wheel_path': spec['wheel_path']}
    setup = {'version': 2, **pins, 'operation_key': spec['operation_key'],
             'authorized_uids': sorted(set(callers) | set(readers)),
             'local_approval': {'declaration_sha256': digest(declaration), 'intent_sha256': digest(appointed)},
             'journal_directory': spec['journal_directory'], 'scopes': [{
                 'definition': asdict(definition), 'policy': policy, 'role': role['name'],
                 'binding_generation': generation}]}
    entry = {'policy': asdict(launch), 'service': asdict(service), 'authority': endpoint,
             'run_uids': callers, 'result_uids': readers}
    entry.update({key: spec[key] for key in ('holder', 'result_observer') if key in spec})
    executor = {'version': 2, **pins, 'wheel_sha256': wheel, 'workflows': {workflow: entry}}
    client = {'version': 1, 'profile': profile, 'revision': revision,
              'peer_uid': _TRUSTED_UID, 'socket': spec['client_socket'], 'workflows': {workflow: policy_pin}}
    bundle = {'version': 1, 'profile': appointed, 'managed_setup': setup,
              'launch_executor': executor, 'launch_client': client}
    if 'rotate_from' in spec:
        bundle['rotate_from'] = spec['rotate_from']
    bundle = decode_policy(roles_cli._canonical(bundle))
    managed_registration._check_client(bundle['launch_client'], bundle['launch_executor'])
    return bundle


def draft(spec):
    if 'workflows' not in spec:
        return draft_one(spec)
    roles_cli._fields(spec, ('workflows',), ('rotate_from',))
    entries = spec['workflows']
    if type(entries) is not list or not entries:
        raise ValueError('expected named workflow inputs')
    bundles = [draft_one(entry) for entry in entries]
    combined = bundles[0]
    profile = combined['profile']
    setup = combined['managed_setup']
    executor, client = combined['launch_executor'], combined['launch_client']
    for item in bundles:
        if 'rotate_from' in item:
            raise ValueError('provide rotation pins once, outside the workflows')
    for item in bundles[1:]:
        other = item['managed_setup']
        if any(setup[key] != other[key] for key in
               ('profile', 'revision', 'wheel_path', 'operation_key', 'journal_directory')):
            raise ValueError('workflow drafts must share the setup registration')
        if (executor['wheel_sha256'] != item['launch_executor']['wheel_sha256']
                or client['socket'] != item['launch_client']['socket']
                or executor['workflows'].keys() & item['launch_executor']['workflows'].keys()):
            raise ValueError('workflow drafts must share client and wheel pins and have distinct names')
        profile['roles'].extend(item['profile']['roles'])
        profile['appointments'].extend(item['profile']['appointments'])
        setup['scopes'].extend(other['scopes'])
        setup['authorized_uids'] = sorted(set(setup['authorized_uids']) | set(other['authorized_uids']))
        executor['workflows'].update(item['launch_executor']['workflows'])
        client['workflows'].update(item['launch_client']['workflows'])
    declaration = {key: value for key, value in profile.items() if key != 'appointments'}
    roles_cli._validate(roles_cli._canonical(declaration))
    setup['local_approval'] = {'declaration_sha256': digest(declaration), 'intent_sha256': digest(profile)}
    managed_registration._check_client(client, executor)
    if 'rotate_from' in spec:
        combined['rotate_from'] = spec['rotate_from']
    return decode_policy(roles_cli._canonical(combined))


def guard(bundle, status, workflow, *, journal, lock):
    setup, executor = bundle['managed_setup'], bundle['launch_executor']
    approved = {'managed_setup_sha256': digest(setup), 'launch_executor_sha256': digest(executor)}
    if (status['status'] != 'configured' or status['managed_registration_pins'] != approved
            or (status['profile'], status['revision']) != (setup['profile'], setup['revision'])
            or workflow not in executor['workflows']):
        raise ValueError('status does not confirm the exact applied managed registration')
    if lock.st_uid != 0 or not stat.S_ISDIR(lock.st_mode) or stat.S_IMODE(lock.st_mode) != 0o700:
        raise ValueError('role store lock is not the protected directory')
    return {'version': 1, 'profile': setup['profile'], 'revision': setup['revision'], 'workflow': workflow,
            **approved, 'journal_directory': journal,
            'role_store_lock': {'device': lock.st_dev, 'inode': lock.st_ino}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    proposal = commands.add_parser('draft')
    proposal.add_argument('spec', type=Path)
    applied = commands.add_parser('guard')
    applied.add_argument('bundle', type=Path)
    applied.add_argument('status', type=Path)
    applied.add_argument('workflow')
    applied.add_argument('--journal', required=True)
    args = parser.parse_args()
    try:
        if args.operation == 'draft':
            result = draft(load(args.spec))
        else:
            lock = os.stat('/var/lib/workeros', follow_symlinks=False)
            result = guard(load(args.bundle), load(args.status), args.workflow, journal=args.journal, lock=lock)
    except (OSError, KeyError, TypeError, ValueError, VerificationError, roles_cli.Refusal):
        parser.exit(1, 'Guarded draft unavailable. Check the approved inputs, installed wheel, and reported pins.\n')
    sys.stdout.buffer.write(roles_cli._canonical(result) + b'\n')


if __name__ == '__main__':
    main()
