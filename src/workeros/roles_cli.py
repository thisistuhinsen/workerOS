"""Administrator-owned, no-start role declarations; not OS grants."""
import argparse
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
from time import time

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


def _validate(data, *, resolve_principals=True):
    try: document = _decode_json(data)
    except ValueError: raise Refusal('invalid_document') from None
    _fields(document,('version','profile','revision','roles'))
    if type(document['version']) is not int or document['version'] != 1: raise Refusal('invalid_version')
    _name(document['profile']); _name(document['revision'])
    roles=document['roles']
    if type(roles) is not list or not 1 <= len(roles) <= 64: raise Refusal('invalid_roles')
    seen=set()
    for role in roles:
        _fields(role,('name','principal','operations','scopes','expires_at'),('independent_of','privileged','resources'))
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
        if not set(role['operations']) <= _OPTIONS.keys(): raise Refusal('unsupported_operation')
        resources=role.get('resources',{})
        if type(resources) is not dict or not set(resources) <= set(role['scopes']): raise Refusal('invalid_resources')
        for scope, resource in resources.items():
            _name(scope); _fields(resource,('device','inode'))
            for field in ('device','inode'):
                value=resource[field]
                if (type(value) is not str or not value.isascii() or not value.isdecimal()
                        or len(value)>20 or str(int(value))!=value): raise Refusal('invalid_resource_identity')
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


def _commit(store,key, payload, *, kind=_KIND):
    receipt=RecordReceipt(key,kind,sha256(payload).hexdigest(),len(payload),0)
    return store.commit(receipt,payload,policy=_POLICY).state


def _read(store,key):
    try:
        stored=store.read(key,policy=_POLICY)
        return store.verify_durable(stored.receipt,policy=_POLICY)
    except RecordError as exc:
        if exc.status is Persistence.MISSING: return None
        raise


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
                yield LocalStore(Path(_PARENT)/'workeros'/'profiles')
            finally: os.close(child)
        finally: os.close(base)
    finally: os.close(parent)


def _check_applicable(document):
    if any(role.get('privileged') for role in document['roles']):
        raise Refusal('unsupported_privileged_enforcement')
    if any(role['expires_at'] <= time() for role in document['roles']):
        raise Refusal('role_expired')


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _apply_declaration(store, document, canonical):
    _check_applicable(document)
    profile, revision = document['profile'], document['revision']
    if _read(store, _key(profile, revision, 'revoke')) is not None:
        raise Refusal('revision_revoked')
    key = _key(profile, revision, 'profile')
    state = _commit(store, key, canonical)
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
    return {'status':'configured','effect':effect,
            'profile':profile,'revision':revision,'digest':sha256(canonical).hexdigest(),
            'enforcement':'not_commissioned','independence':'unverified',
            'next_action':'Commission host enforcement and verify any independent appointments before use.'}


def _inspect_store(store,profile,revision):
    data=_read(store,_key(profile,revision,'profile'))
    if data is None: raise Refusal('revision_missing')
    revoked=_read(store,_key(profile,revision,'revoke')) is not None
    document=_validate(data,resolve_principals=False)
    if (document['profile'], document['revision']) != (profile, revision):
        raise Refusal('declaration_identity_mismatch', uncertain=True)
    expired=[role['name'] for role in document['roles'] if role['expires_at'] <= time()]
    return {'status':'revoked' if revoked else 'expired' if expired else 'configured','effect':'not_attempted',
            'profile':profile,'revision':revision,'digest':sha256(data).hexdigest(),
            'roles':document['roles'],'expired_roles':expired,'enforcement':'not_commissioned','independence':'unverified'}


def inspect(profile,revision):
    _name(profile); _name(revision)
    with _store(create=False) as store:
        return _inspect_store(store,profile,revision)


def _commission_receipt(profile, revision, declaration_sha256, intent_sha256, *, appointments_sha256=None):
    for digest, code in ((declaration_sha256, 'invalid_declaration_digest'),
                         (intent_sha256, 'invalid_intent_digest')):
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise Refusal(code)
    receipt = {'version': 1, 'profile': profile, 'revision': revision,
               'declaration_sha256': declaration_sha256, 'intent_sha256': intent_sha256}
    if appointments_sha256 is not None:
        if type(appointments_sha256) is not str or _DIGEST.fullmatch(appointments_sha256) is None:
            raise Refusal('invalid_appointments_digest')
        receipt['appointments_sha256'] = appointments_sha256
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
        state = _commit(store, key, payload, kind=_COMMISSION_KIND)
    except RecordError as exc:
        if exc.status is Persistence.CONFLICT:
            raise Refusal('commission_intent_conflict') from exc
        raise
    if _read(store, key) != payload:
        raise Refusal('commission_readback_mismatch', uncertain=True)
    status = ('expired' if any(role['expires_at'] <= time() for role in declaration['roles'])
              else 'configured')
    return _commission_result(status, 'recorded' if state is Persistence.COMMITTED else 'unchanged',
                              **receipt)


def commission(profile, revision, declaration_sha256, intent_sha256):
    """Record the administrator's exact intent for an existing active declaration."""
    _name(profile)
    _name(revision)
    receipt = _commission_receipt(profile, revision, declaration_sha256, intent_sha256)
    with _store(create=False) as store:
        return _commission_store(store, receipt)


def commission_apply(data, *, input_sha256, preview=False):
    """Record an approved declaration and its exact input digest under one lock."""
    if os.geteuid() != _UID:
        raise Refusal('administrator_required')
    from . import appointment_registry

    try:
        requested = _decode_json(data)
    except ValueError as exc:
        raise Refusal('invalid_document') from exc
    has_appointments = type(requested) is dict and 'appointments' in requested
    appointments = requested.pop('appointments') if has_appointments else None
    document = _validate(_canonical(requested) if has_appointments else data)
    _check_applicable(document)
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
    if preview:
        fields = {'appointments': registry['appointments']} if registry is not None else {}
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
        result = _commission_apply_store(store, document, canonical, receipt)
        if registry is None or result['status'] != 'configured':
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
    return {**result, 'status': status, 'effect': 'recorded' if effect == 'recorded' else result['effect'],
            'appointment_effect': effect, 'appointment_status': 'registered'}


def _commission_apply_store(store, document, canonical, receipt):
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
        declaration_effect = _apply_declaration(store, document, canonical)
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
            if registry is None:
                return {**receipt, 'status': 'incomplete', 'appointment_status': 'unregistered'}
            return {**receipt, 'appointment_status': 'registered'}
        return receipt


def _commission_status_store(store, profile, revision):
    payload = _read(store, _key(profile, revision, 'commission'))
    if payload is None:
        fields = {'profile': profile, 'revision': revision}
        try:
            declaration = _inspect_store(store, profile, revision)
        except Refusal as exc:
            if str(exc) != 'revision_missing':
                raise Refusal('commission_declaration_invalid', uncertain=True) from exc
        else:
            fields.update(declaration_status=declaration['status'], declaration_sha256=declaration['digest'])
        return _commission_result('unconfigured', 'not_attempted', **fields)
    try:
        receipt = _decode_json(payload)
        expected = _commission_receipt(profile, revision, receipt['declaration_sha256'],
                                       receipt['intent_sha256'],
                                       appointments_sha256=receipt.get('appointments_sha256'))
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
    return _commission_result(declaration['status'], 'not_attempted', **expected)


def revoke(profile,revision):
    _name(profile); _name(revision)
    with _store(create=False) as store:
        data=_read(store,_key(profile,revision,'profile'))
        if data is None: raise Refusal('revision_missing')
        payload=json.dumps({'version':1,'profile':profile,'revision':revision,'digest':sha256(data).hexdigest()},
                           sort_keys=True,separators=(',',':')).encode()
        state=_commit(store,_key(profile,revision,'revoke'),payload)
        if _read(store,_key(profile,revision,'revoke')) != payload: raise Refusal('readback_mismatch',uncertain=True)
    return {'status':'revoked','effect':'recorded' if state is Persistence.COMMITTED else 'unchanged',
            'profile':profile,'revision':revision,
            'next_action':'Revoke any actual host permissions through the existing host authority.'}


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
                unsupported=any(role.get('privileged') for role in document['roles'])
                result={'status':'unsupported' if unsupported else 'preview','effect':'not_attempted',
                        'profile':document['profile'],'revision':document['revision'],'roles':document['roles'],
                        'enforcement':'not_commissioned','independence':'unverified',
                        'next_action':'No built-in privileged enforcement backend is available.' if unsupported else
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
