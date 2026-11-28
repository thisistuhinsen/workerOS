"""Administrator-owned, no-start role declarations; not OS grants."""
import argparse
from contextlib import contextmanager
from contextvars import ContextVar
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
from time import time, time_ns

from .configuration import _OPTIONS, _decode_json
from .recording import (EvidenceType, LocalStore, Persistence, RecordError,
                        RecordKey, RecordReceipt, StoragePolicy, _name)

_PARENT = '/var/lib'
_UID = 0
_POLICY = StoragePolicy()
_KIND = EvidenceType('role-declaration','application/json')
_COMMISSION_KIND = EvidenceType('managed-commission', 'application/json')
_DIGEST = re.compile(r'[0-9a-f]{64}')
_LIMIT = 65536
_APPROVAL_LOCK = ContextVar('workeros_role_approval_lock', default=None)


class Refusal(ValueError):
    def __init__(self, code, *, uncertain=False):
        super().__init__(code)
        self.uncertain = uncertain


def _principal(value, *, resolve=True):
    if (type(value) is not str or not value or len(value) > 128 or
            any(ord(char) < 33 or char in '/:' for char in value)):
        raise Refusal('invalid_principal')
    if not resolve: return None
    try: return pwd.getpwnam(value)
    except KeyError: raise Refusal('principal_missing') from None


def _fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() <= set(required)|set(optional):
        raise Refusal('invalid_fields')


def _operation_aliases(role):
    aliases = role.get('operation_aliases', {})
    if type(aliases) is not dict or len(aliases) > 64:
        raise Refusal('invalid_operation_aliases')
    for name, binding in aliases.items():
        _name(name)
        _fields(binding, ('capability', 'scope', 'provider_sha256'))
        if name in _OPTIONS or name not in role['operations']:
            raise Refusal('invalid_operation_alias')
        if type(binding['capability']) is not str or binding['capability'] not in ('read', 'write'):
            raise Refusal('unsupported_alias_capability')
        scope = _name(binding['scope'])
        if scope not in role['scopes'] or scope not in role.get('resources', {}):
            raise Refusal('operation_alias_resource_missing')
        pin = binding['provider_sha256']
        if type(pin) is not str or _DIGEST.fullmatch(pin) is None:
            raise Refusal('invalid_operation_alias_provider')
    return aliases


def _validate(data, *, resolve_principals=True, check_operations=True):
    try: document = _decode_json(data)
    except ValueError: raise Refusal('invalid_document') from None
    _fields(document,('version','profile','revision','roles'))
    if type(document['version']) is not int or document['version'] != 1: raise Refusal('invalid_version')
    _name(document['profile']); _name(document['revision'])
    roles=document['roles']
    if type(roles) is not list or not 1 <= len(roles) <= 64: raise Refusal('invalid_roles')
    seen=set()
    for role in roles:
        _fields(role,('name','principal','operations','scopes','expires_at'),
                ('independent_of','privileged','resources','operation_aliases'))
        _name(role['name'])
        if role['name'] in seen: raise Refusal('duplicate_role')
        seen.add(role['name'])
        principal=_principal(role['principal'],resolve=resolve_principals)
        if 'independent_of' in role:
            other=_principal(role['independent_of'],resolve=resolve_principals)
            if (role['principal'] == role['independent_of'] or
                    resolve_principals and principal.pw_uid == other.pw_uid):
                raise Refusal('independence_mismatch')
        for field in ('operations','scopes'):
            values=role[field]
            if type(values) is not list or not 1 <= len(values) <= 64: raise Refusal('invalid_'+field)
            for value in values: _name(value)
            if len(set(values)) != len(values): raise Refusal('duplicate_'+field)
        resources=role.get('resources',{})
        if type(resources) is not dict or not set(resources) <= set(role['scopes']): raise Refusal('invalid_resources')
        for scope, resource in resources.items():
            _name(scope); _fields(resource,('device','inode'))
            for field in ('device','inode'):
                value=resource[field]
                if (type(value) is not str or not value.isascii() or not value.isdecimal()
                        or len(value)>20 or str(int(value))!=value): raise Refusal('invalid_resource_identity')
        aliases = _operation_aliases(role)
        if check_operations and not set(role['operations']) <= _OPTIONS.keys() | aliases.keys():
            raise Refusal('unsupported_operation')
        privileged=role.get('privileged',[])
        if type(privileged) is not list or len(privileged)>64: raise Refusal('invalid_privileged')
        privileges=set()
        for grant in privileged:
            _fields(grant,('capability','scope','approved'))
            _name(grant['capability']); _name(grant['scope'])
            if type(grant['approved']) is not bool or not grant['approved']: raise Refusal('approval_required')
            if grant['scope'] not in role['scopes']: raise Refusal('scope_mismatch')
            pair=(grant['capability'],grant['scope'])
            if pair in privileges: raise Refusal('duplicate_privileged')
            privileges.add(pair)
        expiry=role['expires_at']
        if type(expiry) is not int or not 0 < expiry < 2**53: raise Refusal('invalid_expiry')
    return document


def _key(profile, revision, kind):
    return RecordKey(profile,sha256((kind+'\0'+revision).encode('ascii')).hexdigest())


def _commit(store,key, payload, *, kind=_KIND, admin_revision=None):
    source, scope, timestamp = None, None, 0
    if admin_revision is not None:
        if os.geteuid() != _UID:
            raise Refusal('administrator_required')
        prior = _read_stored(store, key)
        if prior is None:
            source, scope, timestamp = f'effective-uid-{_UID}', admin_revision, time_ns()
        else:
            # An exact retry uses the first receipt, including legacy attribution.
            source, scope = prior.receipt.source, prior.receipt.scope
            timestamp = prior.receipt.committed_ns
    receipt=RecordReceipt(key,kind,sha256(payload).hexdigest(),len(payload),timestamp,
                          source=source, scope=scope)
    return store.commit(receipt,payload,policy=_POLICY).state


def _read_stored(store,key):
    try:
        stored=store.read(key,policy=_POLICY)
        store.verify_durable(stored.receipt,policy=_POLICY)
        return stored
    except RecordError as exc:
        if exc.status is Persistence.MISSING: return None
        raise


def _read(store,key):
    stored = _read_stored(store, key)
    return None if stored is None else stored.payload


def _admin_event(stored, revision, action):
    receipt = stored.receipt
    attributed = (receipt.source == f'effective-uid-{_UID}' and receipt.scope == revision
                  and receipt.committed_ns > 0)
    actor = {'authentication': 'unverified'}
    if attributed:
        actor = {'authentication': 'kernel_effective_uid', 'uid': _UID}
    # A local administrator UID is an OS authority; it does not identify a human.
    return {'action': action, 'revision': revision, 'disposition': 'recorded', 'actor': actor,
            'captured_at_unix_ns': str(receipt.committed_ns) if attributed else None}


@contextmanager
def _store(*, create):
    if os.geteuid() != _UID: raise Refusal('administrator_required')
    flags=os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent=os.open(_PARENT,flags)
    try:
        info=os.fstat(parent)
        if info.st_uid != _UID or info.st_mode & 0o022: raise Refusal('untrusted_store')
        try: base=os.open('workeros',flags,dir_fd=parent)
        except FileNotFoundError:
            if not create: raise Refusal('profile_store_missing') from None
            os.mkdir('workeros',0o700,dir_fd=parent); os.fsync(parent)
            base=os.open('workeros',flags,dir_fd=parent)
        try:
            info=os.fstat(base)
            if info.st_uid != _UID or stat.S_IMODE(info.st_mode)!=0o700: raise Refusal('untrusted_store')
            try: fcntl.flock(base,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise Refusal('profile_store_busy') from None
            try: child=os.open('profiles',flags,dir_fd=base)
            except FileNotFoundError:
                if not create: raise Refusal('profile_store_missing') from None
                os.mkdir('profiles',0o700,dir_fd=base); os.fsync(base)
                child=os.open('profiles',flags,dir_fd=base)
            try:
                info=os.fstat(child)
                if info.st_uid != _UID or stat.S_IMODE(info.st_mode)!=0o700: raise Refusal('untrusted_store')
                token = _APPROVAL_LOCK.set(base)
                try:
                    yield LocalStore(Path(_PARENT)/'workeros'/'profiles')
                finally:
                    _APPROVAL_LOCK.reset(token)
            finally: os.close(child)
        finally: os.close(base)
    finally: os.close(parent)


def _requested_privileges(document):
    return frozenset((role['name'], request['scope'], request['capability'])
                     for role in document['roles'] for request in role.get('privileged', ()))


def _check_applicable(document, *, grants=(), appointments=(), service_grants=frozenset()):
    requested = _requested_privileges(document)
    supported = {(plan['role'], plan['scope'], capability.name) for plan, _, capability, _ in grants}
    if requested != supported | service_grants:
        raise Refusal('unsupported_privileged_enforcement')
    appointed = {entry['role'] for entry in appointments if 'launch' in entry}
    for role in document['roles']:
        aliases = role.get('operation_aliases', {})
        if aliases and role['name'] not in appointed:
            raise Refusal('operation_alias_appointment_required')
        native = {capability.operation for plan, _, capability, _ in grants if plan['role'] == role['name']}
        if not native <= set(role['operations']):
            raise Refusal('grant_operation_missing')
        allowed = _OPTIONS.keys() | native | aliases.keys()
        if not set(role['operations']) <= allowed:
            raise Refusal('unsupported_operation')
    if any(role['expires_at'] <= time() for role in document['roles']):
        raise Refusal('role_expired')


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _apply_declaration(store, document, canonical, *, grants=(), appointments=(), service_grants=frozenset()):
    _check_applicable(document, grants=grants, appointments=appointments, service_grants=service_grants)
    profile, revision = document['profile'], document['revision']
    if _read(store, _key(profile, revision, 'revoke')) is not None:
        raise Refusal('revision_revoked')
    key = _key(profile, revision, 'profile')
    state = _commit(store, key, canonical, admin_revision=revision)
    if _read(store, key) != canonical:
        raise Refusal('readback_mismatch', uncertain=True)
    return 'recorded' if state is Persistence.COMMITTED else 'unchanged'


def apply(data):
    """Record a declaration, without creating principals or granting access."""
    document = _validate(data)
    _check_applicable(document)
    profile,revision=document['profile'],document['revision']
    canonical = _canonical(document)
    with _store(create=True) as store:
        effect = _apply_declaration(store, document, canonical)
        history = _inspect_store(store, profile, revision)['admin_history']
    return {'status':'configured','effect':effect,
            'profile':profile,'revision':revision,'digest':sha256(canonical).hexdigest(),
            'admin_history': history,
            'enforcement':'not_commissioned','independence':'unverified',
            'next_action':'Commission host enforcement and verify any independent appointments before use.'}


def _inspect_store(store,profile,revision):
    applied = _read_stored(store, _key(profile, revision, 'profile'))
    if applied is None: raise Refusal('revision_missing')
    data = applied.payload
    revocation = _read_stored(store, _key(profile, revision, 'revoke'))
    history = [_admin_event(applied, revision, 'apply')]
    if revocation is not None:
        if revocation.payload != _revocation_payload(profile, revision, data):
            raise Refusal('revocation_record_mismatch', uncertain=True)
        history.append(_admin_event(revocation, revision, 'revoke'))
    document=_validate(data,resolve_principals=False,check_operations=False)
    if (document['profile'], document['revision']) != (profile, revision):
        raise Refusal('declaration_identity_mismatch', uncertain=True)
    expired=[role['name'] for role in document['roles'] if role['expires_at'] <= time()]
    return {'status':'revoked' if revocation is not None else 'expired' if expired else 'configured','effect':'not_attempted',
            'profile':profile,'revision':revision,'digest':sha256(data).hexdigest(),
            'admin_history': history,
            'roles':document['roles'],'expired_roles':expired,'enforcement':'not_commissioned','independence':'unverified'}


def inspect(profile,revision):
    _name(profile); _name(revision)
    with _store(create=False) as store:
        return _inspect_store(store,profile,revision)


def _managed_registration_pins(value):
    _fields(value, ('managed_setup_sha256', 'launch_executor_sha256'))
    if any(type(digest) is not str or _DIGEST.fullmatch(digest) is None for digest in value.values()):
        raise Refusal('invalid_managed_registration_pins')
    return dict(value)


def _commission_receipt(profile, revision, declaration_sha256, intent_sha256, *, appointments_sha256=None,
                        file_acl_plans_sha256=None, managed_registration_pins=None, service_grants_sha256=None):
    for digest, code in ((declaration_sha256, 'invalid_declaration_digest'),
                         (intent_sha256, 'invalid_intent_digest')):
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise Refusal(code)
    receipt = {'version': 1, 'profile': profile, 'revision': revision,
               'declaration_sha256': declaration_sha256, 'intent_sha256': intent_sha256}
    for field, digest, code in (('appointments_sha256', appointments_sha256, 'invalid_appointments_digest'),
                                ('file_acl_plans_sha256', file_acl_plans_sha256, 'invalid_file_acl_plans_digest')):
        if digest is not None:
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
                raise Refusal(code)
            receipt[field] = digest
    if managed_registration_pins is not None:
        if appointments_sha256 is None or file_acl_plans_sha256 is not None:
            raise Refusal('managed_registration_requires_appointments_without_file_acls')
        receipt['managed_registration_pins'] = _managed_registration_pins(managed_registration_pins)
    if service_grants_sha256 is not None:
        if (managed_registration_pins is None or type(service_grants_sha256) is not str
                or _DIGEST.fullmatch(service_grants_sha256) is None):
            raise Refusal('invalid_service_grants_digest')
        receipt['service_grants_sha256'] = service_grants_sha256
    return receipt


def _commission_result(status, effect, **fields):
    return {'status': status, 'effect': effect, 'readiness': 'not_checked',
            'independence': 'unverified', **fields}


def _commission_store(store, receipt):
    profile, revision = receipt['profile'], receipt['revision']
    payload = _canonical(receipt)
    key = _key(profile, revision, 'commission')
    declaration = _inspect_store(store, profile, revision)
    if declaration['status'] != 'configured':
        raise Refusal('revision_' + declaration['status'])
    if declaration['digest'] != receipt['declaration_sha256']:
        raise Refusal('declaration_digest_mismatch')
    try:
        state = _commit(store, key, payload, kind=_COMMISSION_KIND, admin_revision=revision)
    except RecordError as exc:
        if exc.status is Persistence.CONFLICT:
            raise Refusal('commission_intent_conflict') from exc
        raise
    stored = _read_stored(store, key)
    if stored is None or stored.payload != payload:
        raise Refusal('commission_readback_mismatch', uncertain=True)
    status = ('expired' if any(role['expires_at'] <= time() for role in declaration['roles'])
              else 'configured')
    history = _commission_history(declaration, stored, revision)
    return _commission_result(status, 'recorded' if state is Persistence.COMMITTED else 'unchanged',
                              **receipt, admin_history=history)


def _commission_history(declaration, stored, revision):
    history = list(declaration['admin_history'])
    history.insert(1, _admin_event(stored, revision, 'commission'))
    return history


def commission(profile, revision, declaration_sha256, intent_sha256):
    """Record the administrator's exact intent for an existing active declaration."""
    _name(profile)
    _name(revision)
    receipt = _commission_receipt(profile, revision, declaration_sha256, intent_sha256)
    with _store(create=False) as store:
        return _commission_store(store, receipt)


def _grant_plan(document, grant, registrations):
    from . import delegated_acl

    _fields(grant, ('capability', 'role', 'scope', 'path', 'principal_uid', 'exclusive_admin'),
            ('expiry', 'enforcement'))
    if grant.get('enforcement', 'principal') != 'principal':
        raise Refusal('process_scoped_enforcement_unavailable')
    if grant.get('expiry', 'manual') != 'manual':
        raise Refusal('automatic_acl_expiry_unsupported')
    uid = grant['principal_uid']
    if type(uid) is not int or not 0 <= uid < 2**32 - 1:
        raise Refusal('invalid_principal_uid')
    plan = {'version': 1, 'profile': document['profile'], 'revision': document['revision'],
            **{key: grant[key] for key in ('role', 'scope', 'path', 'exclusive_admin')}}
    capability = delegated_acl._BUILTIN
    if registrations is not None or grant['capability'] != capability.name:
        plan['capability'] = grant['capability']
        named = [registration for registration in registrations or ()
                 if registration.capability.name == grant['capability']]
        if not named:
            raise Refusal('unsupported_privileged_enforcement')
        capability = named[0].capability
        if any(entry.capability != capability for entry in named[1:]):
            raise Refusal('ambiguous_native_capability')
        if capability.name == delegated_acl.CAPABILITY and capability != delegated_acl._BUILTIN:
            raise Refusal('reserved_native_capability')
    try:
        delegated_acl._document(_canonical(plan))
    except delegated_acl.Refusal as exc:
        raise Refusal(str(exc)) from exc
    role = next((role for role in document['roles'] if role['name'] == grant['role']), None)
    if role is None:
        raise Refusal('unsupported_privileged_enforcement')
    if 'independent_of' in role:
        raise Refusal('independent_appointment_required')
    if _principal(role['principal']).pw_uid != uid:
        raise Refusal('principal_uid_mismatch')
    if 'capability' in plan:
        if not any(entry.permits(plan, role, uid) for entry in named):
            raise Refusal('native_grant_outside_approval')
    resource = role.get('resources', {}).get(plan['scope'])
    if resource is None:
        raise Refusal('approved_resource_missing')
    return plan, uid, capability, resource


def _plan_grants(document, requested, registrations):
    grants = tuple(_grant_plan(document, grant, registrations) for grant in requested)
    # This backend owns a single ACL on each exact inode. A repeated role/scope
    # would alias its journal key even on a different path.
    if (len({(plan['role'], plan['scope']) for plan, _, _, _ in grants}) != len(grants)
            or len({(resource['device'], resource['inode']) for _, _, _, resource in grants}) != len(grants)):
        raise Refusal('overlapping_file_acl_grants')
    return grants


def _grant_manifest(grants):
    return _canonical([{'plan': plan, 'uid': uid, 'operation': capability.operation,
                        'access': capability.access, 'resource': resource}
                       for plan, uid, capability, resource in grants])


def _read_grant_manifest(store, receipt):
    if 'file_acl_plans_sha256' not in receipt:
        return None
    manifest = _read(store, _key(receipt['profile'], receipt['revision'], 'file-acl-plans'))
    if manifest is None:
        return None
    if sha256(manifest).hexdigest() != receipt['file_acl_plans_sha256']:
        raise Refusal('grant_manifest_mismatch', uncertain=True)
    return manifest


def _preview_profile_grant(plan, document, digest, uid, capability):
    from . import delegated_acl

    try:
        return delegated_acl.preview_approved(
            plan, {**document, 'status': 'configured', 'digest': digest}, expected_uid=uid, capability=capability,
        )
    except delegated_acl.Refusal as exc:
        raise Refusal(str(exc)) from exc


def _observe_profile_grant(store, entry, *, action='check', capability=None):
    from . import delegated_acl

    plan = entry['plan']
    try:
        grant = (delegated_acl._run_locked('apply', plan, store, expected_uid=entry['uid'], capability=capability)
                 if action == 'apply' else
                 delegated_acl._recover(action, plan, store, expected=entry))
    except delegated_acl.Refusal as exc:
        grant = {'status': 'unknown' if action != 'apply' else 'refused',
                 'effect': 'not_attempted', 'code': str(exc)}
    except (OSError, RecordError):
        grant = {'status': 'unknown', 'effect': 'not_attempted' if action == 'check' else 'unknown',
                 'code': 'grant_state_unconfirmed'}
    if grant['status'] == 'acl_entry_verified' and (
            grant.get('principal_uid'), grant.get('access_mask'), grant.get('operation')) != (
                entry['uid'], entry['access'], entry['operation']):
        grant = {'status': 'unknown', 'effect': 'not_attempted', 'code': 'grant_readback_mismatch'}
    return {'plan': plan, 'grant': grant}


def _profile_grant_result(result, rows, *, revoke=False):
    grants = [row['grant'] for row in rows]
    retired = {'acl_entry_removed', 'acl_entry_absent'}
    if revoke and all(grant['status'] in retired for grant in grants):
        status = 'revoked'
    elif any(grant['status'] == 'unknown' for grant in grants):
        status = 'unknown'
    elif not revoke and all(grant['status'] == 'acl_entry_verified' for grant in grants):
        status = 'file_acl_verified'
    else:
        status = 'incomplete'
    effects = {grant['effect'] for grant in grants}
    effect = ('unknown' if 'unknown' in effects else 'observed' if 'observed' in effects else 'not_attempted')
    fields = {'file_access': rows, 'grant_effect': effect, 'setup_attachment': 'not_checked',
              'runtime_evidence': 'not_requested', 'scope_cleanup': 'not_requested',
              'manager_retirement': 'not_requested'}
    if len(rows) == 1:
        fields.update(grant_plan=rows[0]['plan'], grant=rows[0]['grant'])
    return {**result, **fields, 'status': status,
            'effect': result['effect'] if effect == 'not_attempted' else effect}


def _finish_profile_grants(store, result, manifest, capabilities, *, repeat):
    profile, revision = result['profile'], result['revision']
    key = _key(profile, revision, 'file-acl-plans')
    try:
        if not repeat:
            _commit(store, key, manifest)
        stored = _read_grant_manifest(store, result)
    except (OSError, RecordError, Refusal):
        return {**result, 'status': 'unknown', 'code': 'grant_manifest_unconfirmed',
                'grant_effect': 'not_attempted'}
    if stored is None:
        return {**result, 'status': 'unknown', 'code': 'grant_manifest_unconfirmed',
                'grant_effect': 'not_attempted'}
    rows = []
    allow_apply = not repeat
    for entry, capability in zip(_decode_json(stored), capabilities, strict=True):
        row = _observe_profile_grant(store, entry, action='apply' if allow_apply else 'check',
                                     capability=capability)
        rows.append(row)
        allow_apply = allow_apply and row['grant']['status'] == 'acl_entry_verified'
    return _profile_grant_result(result, rows)


def commission_apply(data, *, input_sha256, preview=False, acl_registrations=None, managed_registration_pins=None,
                     _service_grants=frozenset()):
    """Record intent and apply approved ACLs without starting work.

    Trusted host code can pass immutable FileAclRegistration objects.
    JSON and YAML can select a registered capability but cannot register one.
    """
    if os.geteuid() != _UID:
        raise Refusal('administrator_required')
    from . import appointment_registry, delegated_acl

    if acl_registrations is not None and (type(acl_registrations) is not tuple or any(
            type(entry) is not delegated_acl.FileAclRegistration
            or type(entry.capability) is not delegated_acl.FileAclCapability
            for entry in acl_registrations)):
        raise Refusal('invalid_native_acl_registration')

    try:
        requested = _decode_json(data)
    except ValueError as exc:
        raise Refusal('invalid_document') from exc
    has_appointments = type(requested) is dict and 'appointments' in requested
    appointments = requested.pop('appointments') if has_appointments else None
    has_grant = type(requested) is dict and 'grant' in requested
    has_grants = type(requested) is dict and 'grants' in requested
    if has_grant and has_grants:
        raise Refusal('conflicting_file_acl_grants')
    selected = requested.pop('grants') if has_grants else [requested.pop('grant')] if has_grant else []
    if has_grants and (type(selected) is not list or not 1 <= len(selected) <= 64):
        raise Refusal('invalid_file_acl_grants')
    if has_grants and acl_registrations is None:
        raise Refusal('file_acl_registration_required')
    document = _validate(_canonical(requested) if has_appointments or has_grant or has_grants else data,
                         check_operations=not (has_grant or has_grants))
    grants = _plan_grants(document, selected, acl_registrations)
    manifest = _grant_manifest(grants) if grants else None
    profile, revision = document['profile'], document['revision']
    canonical = _canonical(document)
    receipt = _commission_receipt(profile, revision, sha256(canonical).hexdigest(), input_sha256)
    registry = None
    if has_appointments:
        registry = appointment_registry._validate(_canonical({**receipt, 'appointments': appointments}))
        # Validate the entire request before opening or creating the role store.
        appointment_registry._check_approval(registry, {'status': 'configured', **receipt},
                                              {'status': 'configured', **document})
        receipt['appointments_sha256'] = sha256(_canonical(registry)).hexdigest()
    appointments = registry['appointments'] if registry else ()
    if _service_grants and (managed_registration_pins is None or registry is None or grants):
        raise Refusal('managed_service_grants_unpinned')
    _check_applicable(document, grants=grants, appointments=appointments, service_grants=_service_grants)
    if manifest is not None:
        receipt['file_acl_plans_sha256'] = sha256(manifest).hexdigest()
    if managed_registration_pins is not None:
        if registry is None or grants:
            raise Refusal('managed_registration_requires_appointments_without_file_acls')
        receipt['managed_registration_pins'] = _managed_registration_pins(managed_registration_pins)
    if _service_grants:
        receipt['service_grants_sha256'] = sha256(_canonical(sorted(_service_grants))).hexdigest()
    if preview:
        fields = {'appointments': registry['appointments']} if registry is not None else {}
        if grants:
            rows = [{'plan': plan, 'grant': _preview_profile_grant(
                plan, document, receipt['declaration_sha256'], uid, capability)}
                    for plan, uid, capability, _ in grants]
            fields['file_access'] = rows
            if len(rows) == 1:
                fields.update(grant_plan=rows[0]['plan'], grant=rows[0]['grant'])
        return _commission_result('preview', 'not_attempted', **receipt, **fields)
    with _store(create=True) as store:
        if registry is not None:
            try:
                prior_registry = _read(store, _key(profile, revision, 'appointments'))
            except (OSError, RecordError):
                return _commission_result('unknown', 'not_attempted',
                                          code='appointment_state_unconfirmed', **receipt)
            if prior_registry is not None and prior_registry != _canonical(registry):
                raise Refusal('appointment_registration_conflict')
        repeat = False
        if grants:
            try:
                prior = _read(store, _key(profile, revision, 'commission'))
            except (OSError, RecordError):
                return _commission_result('unknown', 'not_attempted', code='commission_state_unconfirmed',
                                          grant_effect='not_attempted', **receipt)
            repeat = prior is not None
            if repeat:
                previous = _decode_json(prior)
                if previous.get('intent_sha256') == receipt['intent_sha256'] and (
                        previous.get('file_acl_plans_sha256') != receipt['file_acl_plans_sha256']):
                    rows = [{'plan': plan, 'grant': {'status': 'unknown', 'effect': 'not_attempted',
                                                    'code': 'grant_readback_mismatch'}}
                            for plan, *_ in grants]
                    return _profile_grant_result(_commission_result('unknown', 'not_attempted', **receipt), rows)
            if not repeat:
                for plan, uid, capability, _ in grants:
                    _preview_profile_grant(plan, document, receipt['declaration_sha256'], uid, capability)
        result = _commission_apply_store(store, document, canonical, receipt, grants=grants,
                                         appointments=appointments, service_grants=_service_grants)
        if grants:
            result = {**result, 'grant_effect': 'not_attempted'}
        if result['status'] != 'configured':
            return result
        if registry is None:
            if grants:
                return _finish_profile_grants(store, result, manifest, [entry[2] for entry in grants], repeat=repeat)
            return result
        try:
            declaration = _inspect_store(store, profile, revision)
            effect = appointment_registry._register_store(store, registry, result, declaration)
        except Refusal as exc:
            return {**result, 'status': 'unknown' if exc.uncertain else 'incomplete',
                    'effect': 'unknown' if exc.uncertain else result['effect'], 'code': str(exc),
                    'commission_effect': result['effect'],
                    'appointment_effect': 'unknown' if exc.uncertain else 'not_attempted'}
        except (OSError, ValueError, RecordError):
            return {**result, 'status': 'unknown', 'effect': 'unknown', 'code': 'appointment_state_unconfirmed',
                    'commission_effect': result['effect'],
                    'appointment_effect': 'unknown'}
        status = 'expired' if any(role['expires_at'] <= time() for role in declaration['roles']) else 'configured'
        result = {**result, 'status': status, 'effect': 'recorded' if effect == 'recorded' else result['effect'],
                  'appointment_effect': effect, 'appointment_status': 'registered'}
        if grants and status == 'configured':
            return _finish_profile_grants(store, result, manifest, [entry[2] for entry in grants], repeat=repeat)
        return result


def _commission_apply_store(store, document, canonical, receipt, *, grants=(), appointments=(),
                            service_grants=frozenset()):
    profile, revision = receipt['profile'], receipt['revision']
    # An unresolved existing receipt blocks any new write. An exact receipt
    # must still reference the original declaration, even on a repeat.
    try:
        prior = _read(store, _key(profile, revision, 'commission'))
    except (OSError, RecordError):
        return _commission_result('unknown', 'not_attempted', code='commission_state_unconfirmed',
                                  declaration_effect='not_attempted', **receipt)
    if prior is not None:
        if prior != _canonical(receipt):
            raise Refusal('commission_intent_conflict')
        return {**_commission_store(store, receipt), 'declaration_effect': 'unchanged'}
    try:
        declaration_effect = _apply_declaration(store, document, canonical, grants=grants,
                                                appointments=appointments, service_grants=service_grants)
    except Refusal as exc:
        if not exc.uncertain:
            raise
        return _commission_result('unknown', 'unknown', code=str(exc),
                                  declaration_effect='unknown', **receipt)
    except RecordError as exc:
        if exc.status is Persistence.CONFLICT:
            raise Refusal('revision_conflict') from exc
        return _commission_result('unknown', 'unknown', code='declaration_state_unconfirmed',
                                  declaration_effect='unknown', **receipt)
    except OSError:
        return _commission_result('unknown', 'unknown', code='declaration_state_unconfirmed',
                                  declaration_effect='unknown', **receipt)
    try:
        result = _commission_store(store, receipt)
    except Refusal as exc:
        return _commission_result('unknown' if exc.uncertain else 'incomplete',
                                  'unknown' if exc.uncertain else declaration_effect,
                                  code=str(exc), declaration_effect=declaration_effect,
                                  commission_effect='unknown' if exc.uncertain else 'not_attempted', **receipt)
    except (OSError, ValueError, RecordError):
        return _commission_result('unknown', 'unknown', code='commission_state_unconfirmed',
                                  declaration_effect=declaration_effect, commission_effect='unknown', **receipt)
    return {**result, 'declaration_effect': declaration_effect}


def commission_status(profile, revision):
    """Read the exact receipt and current declaration state without making a record."""
    _name(profile)
    _name(revision)
    with _store(create=False) as store:
        receipt = _commission_status_store(store, profile, revision)
        if receipt['status'] == 'configured' and 'appointments_sha256' in receipt:
            from .appointment_registry import read_registry

            declaration = _inspect_store(store, profile, revision)
            registry = read_registry(store, profile, revision, receipt, declaration)
            receipt = {**receipt, 'appointment_status': 'registered' if registry is not None else 'unregistered'}
            if registry is None:
                receipt['status'] = 'incomplete'
        if 'file_acl_plans_sha256' in receipt:
            return _inspect_profile_grants(store, receipt)
        return receipt


def _inspect_profile_grants(store, receipt, *, revoke=False):
    manifest = _read_grant_manifest(store, receipt)
    if manifest is None:
        return {**receipt, 'status': 'unknown', 'code': 'grant_manifest_unconfirmed',
                'grant_effect': 'not_attempted'}
    rows = [_observe_profile_grant(store, entry, action='revoke' if revoke else 'check')
            for entry in _decode_json(manifest)]
    result = _profile_grant_result(receipt, rows, revoke=revoke or receipt['status'] == 'revoked')
    if receipt['status'] in ('expired', 'revoked', 'incomplete'):
        result['declaration_status'] = receipt['status']
    if not revoke and receipt.get('appointment_status') == 'unregistered' and result['status'] == 'file_acl_verified':
        result['status'] = 'incomplete'
    return result


def _commission_status_store(store, profile, revision):
    stored = _read_stored(store, _key(profile, revision, 'commission'))
    if stored is None:
        fields = {'profile': profile, 'revision': revision}
        try:
            declaration = _inspect_store(store, profile, revision)
        except Refusal as exc:
            if str(exc) != 'revision_missing':
                raise Refusal('commission_declaration_invalid', uncertain=True) from exc
        else:
            fields.update(declaration_status=declaration['status'], declaration_sha256=declaration['digest'],
                          admin_history=declaration['admin_history'])
        return _commission_result('unconfigured', 'not_attempted', **fields)
    payload = stored.payload
    try:
        receipt = _decode_json(payload)
        expected = _commission_receipt(profile, revision, receipt['declaration_sha256'],
                                       receipt['intent_sha256'],
                                       appointments_sha256=receipt.get('appointments_sha256'),
                                       file_acl_plans_sha256=receipt.get('file_acl_plans_sha256'),
                                       managed_registration_pins=receipt.get('managed_registration_pins'),
                                       service_grants_sha256=receipt.get('service_grants_sha256'))
        if payload != _canonical(expected):
            raise ValueError('invalid commission receipt')
    except (ValueError, TypeError, KeyError) as exc:
        raise Refusal('commission_receipt_invalid', uncertain=True) from exc
    try:
        declaration = _inspect_store(store, profile, revision)
    except Refusal as exc:
        code = ('commission_declaration_missing' if str(exc) == 'revision_missing'
                else 'commission_declaration_invalid')
        raise Refusal(code, uncertain=True) from exc
    if declaration['digest'] != expected['declaration_sha256']:
        raise Refusal('commission_declaration_mismatch', uncertain=True)
    if 'service_grants_sha256' in expected and expected['service_grants_sha256'] != sha256(
            _canonical(sorted(_requested_privileges(declaration)))).hexdigest():
        raise Refusal('commission_service_grants_mismatch', uncertain=True)
    return _commission_result(declaration['status'], 'not_attempted', **expected,
                              admin_history=_commission_history(declaration, stored, revision))


def _revocation_payload(profile, revision, declaration):
    return _canonical({'version': 1, 'profile': profile, 'revision': revision,
                       'digest': sha256(declaration).hexdigest()})


def _revoke_declaration(store, profile, revision):
    data = _read(store, _key(profile, revision, 'profile'))
    if data is None:
        raise Refusal('revision_missing')
    payload = _revocation_payload(profile, revision, data)
    key = _key(profile, revision, 'revoke')
    state = _commit(store, key, payload, admin_revision=revision)
    if _read(store, key) != payload:
        raise Refusal('readback_mismatch', uncertain=True)
    return 'recorded' if state is Persistence.COMMITTED else 'unchanged'


def revoke_profile(profile, revision):
    """Retire the declaration and remove any exact profile-managed ACLs."""
    _name(profile)
    _name(revision)
    with _store(create=False) as store:
        receipt = _commission_status_store(store, profile, revision)
        declaration = _inspect_store(store, profile, revision)
        if not receipt.keys() & {'file_acl_plans_sha256', 'service_grants_sha256'} and any(
                role.get('privileged') for role in declaration['roles']):
            raise Refusal('file_acl_manifest_missing')
        # Validate the pinned manifest before marking a revision revoked.
        if 'file_acl_plans_sha256' in receipt and _read_grant_manifest(store, receipt) is None:
            raise Refusal('grant_manifest_unconfirmed', uncertain=True)
        effect = _revoke_declaration(store, profile, revision)
        status = _commission_status_store(store, profile, revision)
        revoked = {**receipt, 'status': 'revoked', 'effect': effect, 'admin_history': status['admin_history']}
        if 'file_acl_plans_sha256' in receipt:
            return _inspect_profile_grants(store, revoked, revoke=True)
        if 'service_grants_sha256' in receipt:
            revoked['service_grants'] = 'new_use_denied'
        return revoked


def revoke(profile,revision):
    _name(profile); _name(revision)
    with _store(create=False) as store:
        effect = _revoke_declaration(store, profile, revision)
        history = _inspect_store(store, profile, revision)['admin_history']
    return {'status':'revoked','effect':effect,
            'profile':profile,'revision':revision,'admin_history':history,
            'next_action':'Use managed revoke-profile for profile-managed ACLs or roles grant-revoke for an exact standalone grant.'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    sub.add_parser('apply',help='read one declaration as JSON on stdin')
    sub.add_parser('preview',help='preview a declaration without applying it')
    for op in ('grant-preview','grant-apply','grant-check','grant-revoke'):
        sub.add_parser(op,help='use an approved named-UID read ACL plan from stdin')
    for op in ('show','revoke'):
        p=sub.add_parser(op); p.add_argument('profile'); p.add_argument('revision')
    args=parser.parse_args(argv)
    try:
        if args.operation in ('apply','preview','grant-preview','grant-apply','grant-check','grant-revoke'):
            data=sys.stdin.buffer.read(_LIMIT+1)
            if len(data)>_LIMIT: raise Refusal('document_too_large')
            if args.operation.startswith('grant-'):
                from . import delegated_acl
                try: result=delegated_acl.run(args.operation.removeprefix('grant-'),data)
                except delegated_acl.Refusal as exc: raise Refusal(str(exc)) from None
            elif args.operation == 'preview':
                if os.geteuid() != _UID: raise Refusal('administrator_required')
                document=_validate(data)
                if any(role.get('operation_aliases') for role in document['roles']):
                    raise Refusal('operation_alias_appointment_required')
                unsupported=any(role.get('privileged') for role in document['roles'])
                result={'status':'unsupported' if unsupported else 'preview','effect':'not_attempted',
                        'profile':document['profile'],'revision':document['revision'],'roles':document['roles'],
                        'enforcement':'not_commissioned','independence':'unverified',
                        'next_action':'Use managed apply-profile with an explicit supported grant, or ask the host administrator about this capability.' if unsupported else
                                      'Apply the declaration, then commission and verify host enforcement.'}
                if unsupported: result['code']='unsupported_privileged_enforcement'
            else: result=apply(data)
        elif args.operation == 'show': result=inspect(args.profile,args.revision)
        else: result=revoke(args.profile,args.revision)
    except (OSError,ValueError,RecordError) as exc:
        conflict=type(exc) is RecordError and exc.status is Persistence.CONFLICT
        uncertain=type(exc) is not Refusal and not conflict or type(exc) is Refusal and exc.uncertain
        code=str(exc) if type(exc) is Refusal else 'revision_conflict' if conflict else 'operation_unconfirmed'
        # A filesystem error can follow a write; never claim no effect.
        result={'status':'unknown' if uncertain else 'refused',
                'effect':'unknown' if uncertain else 'not_attempted',
                'code':code,'next_action':'Inspect this revision before retrying or ask the host administrator.'}
        if args.operation.startswith('grant-'):
            result['next_action']='Use grant-check for the exact plan; do not repeat grant-apply.'
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0 if result['status'] in ('configured','revoked','preview','acl_entry_verified','acl_entry_removed') else 1


if __name__=='__main__': sys.exit(main())
