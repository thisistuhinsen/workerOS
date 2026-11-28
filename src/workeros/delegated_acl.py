"""One named-user data ACL on an administrator-owned, pinned Linux file.

No privilege acquisition, child process or observer qualification is provided.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import stat
import struct
from time import time

from .configuration import _decode_json
from .recording import EvidenceType, LocalStore, Persistence, RecordError, RecordKey, RecordReceipt, StoragePolicy, _name
from . import roles_cli

_ADMIN_UID=0
_POLICY=StoragePolicy()
_KIND=EvidenceType('delegated-read-acl','application/json')
_XATTR='system.posix_acl_access'
_UNDEF=0xffffffff
CAPABILITY = 'named_uid_read_acl'


class Refusal(ValueError): pass


@dataclass(frozen=True)
class FileAclCapability:
    """Native translation from one host operation to Linux read/write bits."""

    name: str
    operation: str
    access: int

    def __post_init__(self):
        _name(self.name)
        _name(self.operation)
        if type(self.access) is not int or self.access not in (2, 4, 6):
            raise Refusal('unsupported_file_access')


@dataclass(frozen=True)
class FileAclRegistration:
    """An administrator's ceiling for a capability registered by trusted code."""

    capability: FileAclCapability
    profile: str
    revision: str
    role: str
    scope: str
    principal_uid: int
    path: str
    device: str
    inode: str
    maximum_access: int
    expires_at: int

    def permits(self, doc, role, uid):
        resource = role.get('resources', {}).get(doc['scope'], {})
        return (
            (doc['profile'], doc['revision'], doc['role'], doc['scope'], uid, doc['path'],
             resource.get('device'), resource.get('inode')) ==
            (self.profile, self.revision, self.role, self.scope, self.principal_uid, self.path,
             self.device, self.inode)
            and type(self.principal_uid) is int
            and type(self.maximum_access) is int and self.maximum_access in (2, 4, 6)
            and self.capability.access & self.maximum_access == self.capability.access
            and type(self.expires_at) is int and role['expires_at'] <= self.expires_at
        )


_BUILTIN = FileAclCapability(CAPABILITY, 'read', 4)


def _acl_entry(tag,perm,ident=_UNDEF): return struct.pack('<HHI',tag,perm,ident)


def _acl(uid, access=4):
    if type(uid) is not int or not 0 <= uid < _UNDEF: raise Refusal('principal_invalid')
    return (struct.pack('<I',2)+_acl_entry(1,6)+_acl_entry(2,access,uid)+_acl_entry(4,0)+
            _acl_entry(16,access)+_acl_entry(32,0))


def _base_acl(): return struct.pack('<I',2)+_acl_entry(1,6)+_acl_entry(4,0)+_acl_entry(32,0)


def _uid_mapped(uid):
    try:
        with open('/proc/self/uid_map',encoding='ascii') as stream:
            for line in stream:
                start,_,length=map(int,line.split())
                if start <= uid < start+length: return True
    except (OSError,ValueError): return False
    return False


def _no_acl(fd, *, directory=False):
    for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
        try: os.getxattr(fd,name)
        except OSError as exc:
            if exc.errno==errno.ENODATA: continue
            if exc.errno in (errno.ENOTSUP,errno.EOPNOTSUPP): raise Refusal('acl_backend_unavailable') from None
            raise
        else: raise Refusal('acl_already_present')


def _document(data):
    doc=_decode_json(data)
    required = {'version','profile','revision','role','scope','path','exclusive_admin'}
    if (type(doc) is not dict or not required <= doc.keys() <= required | {'capability'}
            or type(doc['version']) is not int or doc['version']!=1 or doc['exclusive_admin'] is not True):
        raise Refusal('invalid_or_nonexclusive_plan')
    for key in ('profile','revision','role','scope'): _name(doc[key])
    if 'capability' in doc: _name(doc['capability'])
    if type(doc['path']) is not str or not os.path.isabs(doc['path']) or '\0' in doc['path']:
        raise Refusal('invalid_path')
    return doc


def _approved(doc, declaration, *, expected_uid=None, capability=_BUILTIN):
    if os.geteuid()!=_ADMIN_UID: raise Refusal('administrator_required')
    if declaration['status']!='configured': raise Refusal('declaration_not_current')
    roles=[role for role in declaration['roles'] if role['name']==doc['role']]
    if len(roles)!=1: raise Refusal('role_missing')
    role=roles[0]
    if (capability.operation not in role['operations'] or doc['scope'] not in role['scopes'] or
            doc['scope'] not in role.get('resources',{})):
        raise Refusal('approved_resource_missing')
    if role['expires_at']<=time(): raise Refusal('role_expired')
    try: uid=pwd.getpwnam(role['principal']).pw_uid
    except KeyError: raise Refusal('principal_missing') from None
    if uid==_ADMIN_UID: raise Refusal('distinct_principal_required')
    if expected_uid is not None and uid != expected_uid: raise Refusal('principal_uid_mismatch')
    if not _uid_mapped(uid): raise Refusal('principal_unmapped')
    return role,uid


@contextmanager
def _held(doc,resource=None):
    parent=os.open(os.path.dirname(doc['path']),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        pi=os.fstat(parent)
        if pi.st_uid!=_ADMIN_UID or stat.S_IMODE(pi.st_mode)!=0o711: raise Refusal('protected_parent_required')
        _no_acl(parent,directory=True)
        fd=os.open(os.path.basename(doc['path']),os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise Refusal('resource_busy') from None
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=_ADMIN_UID or info.st_nlink!=1 or
                    (resource is not None and (str(info.st_dev),str(info.st_ino))!=(resource['device'],resource['inode']))):
                raise Refusal('approved_resource_mismatch')
            yield parent,fd,info
        finally: os.close(fd)
    finally: os.close(parent)


def _journal(parent, *, create):
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try: fd=os.open('.workeros-acl-grants',flags,dir_fd=parent)
    except FileNotFoundError:
        if not create: return None
        os.mkdir('.workeros-acl-grants',0o700,dir_fd=parent); os.fsync(parent)
        fd=os.open('.workeros-acl-grants',flags,dir_fd=parent)
    try:
        info=os.fstat(fd)
        if info.st_uid!=_ADMIN_UID or stat.S_IMODE(info.st_mode)!=0o700: raise Refusal('journal_untrusted')
        _no_acl(fd,directory=True)
    finally: os.close(fd)
    return LocalStore(Path('/proc/self/fd')/str(parent)/'.workeros-acl-grants')


def _read(store,key):
    try:
        item=store.read(key,policy=_POLICY)
        return store.verify_durable(item.receipt,policy=_POLICY)
    except RecordError as exc:
        if exc.status is Persistence.MISSING: return None
        raise


def _write(store,key,payload):
    receipt=RecordReceipt(key,_KIND,sha256(payload).hexdigest(),len(payload),0)
    return store.commit(receipt,payload,policy=_POLICY).state


def _response(status,effect,code,doc,uid,info,attempt):
    return {'status':status,'effect':effect,'code':code,'profile':doc['profile'],
            'revision':doc['revision'],'role':doc['role'],'scope':doc['scope'],
            'principal_uid':uid,'device':str(info.st_dev),'inode':str(info.st_ino),
            'attempt':attempt,'capability':doc.get('capability',CAPABILITY),'independent_observer':'not_verified',
            'next_action':'Use grant-check for this exact plan; do not repeat grant-apply.' if status=='unknown' else
                          'Use grant-revoke for this exact plan; already-open descriptors are unaffected.' if status=='cleanup_due' else
                          'Verify future opens are denied; already-open descriptors are unaffected.' if status=='acl_entry_removed' else
                          'Verify access as the appointed principal; ACL readback is not independent custody.'}


def _binding_key(doc):
    value={key:doc[key] for key in ('profile','revision','role','scope')}
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _declaration_state(store,doc,marker, *, resolve_account=True):
    """Observe declaration/account state; this does not authenticate an appointment."""
    if store is None: return 'unavailable'
    try:
        declaration=roles_cli._inspect_store(store,doc['profile'],doc['revision'])
        if declaration['digest']!=marker['declaration']: return 'changed'
        if declaration['status'] in ('revoked','expired'): return declaration['status']
        if declaration['status']!='configured': return 'unavailable'
        roles=[role for role in declaration['roles'] if role['name']==doc['role']]
        if len(roles)!=1: return 'changed'
        role=roles[0]
        if role['expires_at']<=time(): return 'expired'
        if not resolve_account: return 'current_account_unchecked'
        try: current_uid=pwd.getpwnam(role['principal']).pw_uid
        except KeyError: return 'principal_missing'
        if current_uid!=marker['principal_uid']: return 'principal_reassigned'
        return 'current'
    except (OSError,ValueError,RecordError,KeyError,TypeError):
        return 'unavailable'


def _recover(action,doc,role_store):
    """Observe or explicitly clean the retained original UID, never replay grant."""
    with _held(doc) as (parent,fd,info):
        store=_journal(parent,create=False)
        if store is None:
            return _response('unknown','not_attempted','binding_missing',doc,None,info,None)
        binding=_read(store,RecordKey(_binding_key(doc),'binding'))
        if binding is None:
            return _response('unknown','not_attempted','binding_missing',doc,None,info,None)
        try:
            marker=_decode_json(binding)
            fields={'version','profile','revision','declaration','role','scope','principal_uid','device','inode'}
            version = 2 if 'capability' in doc else 1
            if version == 2: fields |= {'capability','operation','access','path'}
            if (type(marker) is not dict or set(marker)!=fields or type(marker['version']) is not int
                    or marker['version']!=version or any(marker[k]!=doc[k] for k in ('profile','revision','role','scope'))
                    or type(marker['principal_uid']) is not int or not 0<=marker['principal_uid']<_UNDEF
                    or type(marker['declaration']) is not str or len(marker['declaration'])!=64
                    or any(c not in '0123456789abcdef' for c in marker['declaration'])
                    or (marker['device'],marker['inode'])!=(str(info.st_dev),str(info.st_ino))):
                raise ValueError()
            access = 4
            operation = 'read'
            if version == 2:
                access = marker['access']
                operation = _name(marker['operation'])
                if (marker['capability'] != doc['capability'] or marker['path'] != doc['path']
                        or type(access) is not int or access not in (2,4,6)):
                    raise ValueError()
        except (ValueError,TypeError,KeyError):
            return _response('unknown','not_attempted','binding_mismatch',doc,None,info,None)
        uid=marker['principal_uid']; attempt=sha256(binding).hexdigest()
        if not _uid_mapped(uid):
            return {**_response('unknown','not_attempted','original_uid_unmapped',doc,uid,info,attempt),
                    'declaration':_declaration_state(role_store,doc,marker,resolve_account=action!='revoke'),'appointment':'unverified',
                    'acl_presence':'unknown','cleanup':'unavailable'}
        expected=_acl(uid, access); mode=stat.S_IMODE(info.st_mode)
        granted_mode = 0o600 | access << 3
        keys=[RecordKey(attempt,name) for name in ('grant_claim','grant_result','revoke_claim','revoke_result')]
        claim,grant,rclaim,revoke=(_read(store,k) for k in keys)
        if any(value is not None and value!=binding for value in (claim,grant,rclaim,revoke)):
            return _response('unknown','not_attempted','journal_conflict',doc,uid,info,attempt)
        try: raw=os.getxattr(fd,_XATTR)
        except OSError as exc:
            if exc.errno!=errno.ENODATA: raise
            raw=None
        presence='present_exact' if mode==granted_mode and raw==expected else 'absent' if mode==0o600 and raw is None else 'unexpected'
        declaration=_declaration_state(role_store,doc,marker,resolve_account=action!='revoke')
        def report(status,effect,code,cleanup):
            result={**_response(status,effect,code,doc,uid,info,attempt),
                    'declaration':declaration,'appointment':'unverified','acl_presence':presence,'cleanup':cleanup,
                    'access_mask':access,'operation':operation}
            if status=='unknown' and cleanup=='available':
                result['next_action']='An administrator may use grant-revoke for this exact plan; do not repeat grant-apply.'
            elif status=='unknown' and presence=='absent' and rclaim is not None:
                result['next_action']='ACL is absent now; preserve the journal. Historical completion is unconfirmed; do not repeat cleanup.'
            return result
        if presence=='unexpected': return report('unknown','not_attempted','acl_changed','unavailable')
        if action=='check':
            if claim is not None and rclaim is not None and revoke is not None and presence=='absent':
                return report('acl_entry_removed','not_attempted','readback_verified','complete')
            if claim is not None and presence=='present_exact' and rclaim is None:
                if grant is None: return report('unknown','not_attempted','claim_only_acl_present','available')
                if declaration!='current': return report('cleanup_due','not_attempted','declaration_not_current','available')
                return report('acl_entry_verified','not_attempted','readback_verified','available')
            return report('unknown','not_attempted','reconcile_required','unconfirmed')
        if claim is None: return report('unknown','not_attempted','claim_missing','unavailable')
        if presence=='absent':
            if rclaim is not None and revoke is not None: return report('acl_entry_removed','not_attempted','already_removed','complete')
            return report('unknown','not_attempted','acl_absent_history_unconfirmed','unconfirmed')
        if rclaim is not None: return report('unknown','not_attempted','cleanup_already_attempted','unconfirmed')
        if _write(store,keys[2],binding) is not Persistence.COMMITTED:
            return report('unknown','unknown','reconcile_required','unconfirmed')
        try:
            before=os.fstat(fd)
            if ((before.st_dev,before.st_ino,stat.S_IMODE(before.st_mode))!=(info.st_dev,info.st_ino,granted_mode)
                    or os.getxattr(fd,_XATTR)!=expected):
                return report('unknown','not_attempted','acl_changed','unconfirmed')
            # Explicit cleanup only. The host must ensure exclusive ACL control;
            # the kernel offers no compare-and-swap for this replacement.
            presence='unknown'
            os.setxattr(fd,_XATTR,_base_acl(),os.XATTR_REPLACE)
            os.fsync(fd)
            after=os.fstat(fd)
            try: remaining=os.getxattr(fd,_XATTR)
            except OSError as exc:
                if exc.errno!=errno.ENODATA: raise
                remaining=None
            after_mode=stat.S_IMODE(after.st_mode)
            presence=('absent' if after_mode==0o600 and remaining is None else
                      'present_exact' if after_mode==granted_mode and remaining==expected else 'unexpected')
            if ((after.st_dev,after.st_ino,stat.S_IMODE(after.st_mode))!=(info.st_dev,info.st_ino,0o600)
                    or remaining is not None):
                return report('unknown','unknown','readback_unconfirmed','unconfirmed')
            if _write(store,keys[3],binding) not in (Persistence.COMMITTED,Persistence.EXISTING):
                return report('unknown','unknown','journal_unconfirmed','unconfirmed')
            presence='absent'
            return report('acl_entry_removed','observed','readback_verified','complete')
        except (OSError,RecordError,Refusal):
            return report('unknown','unknown','effect_unconfirmed','unconfirmed')


def run(action,data):
    if action not in ('preview','apply','check','revoke'): raise ValueError('invalid action')
    doc=_document(data)
    if os.geteuid()!=_ADMIN_UID: raise Refusal('administrator_required')
    if action in ('check','revoke'):
        with ExitStack() as stack:
            try: store=stack.enter_context(roles_cli._store(create=False))
            except (OSError,ValueError,RecordError): store=None
            return _recover(action,doc,store)
    if 'capability' in doc: raise Refusal('native_capability_not_registered')
    # Hold the same bounded role-store lock across authorization and effect so
    # a cooperating declaration revoke cannot race an approved grant.
    with roles_cli._store(create=False) as store:
        return _run_locked(action,doc,store)


def _marker(doc, declaration, uid, resource, capability):
    record = {
        'version':1,'profile':doc['profile'],'revision':doc['revision'],
        'declaration':declaration['digest'],'role':doc['role'],'scope':doc['scope'],
        'principal_uid':uid,'device':resource['device'],'inode':resource['inode'],
    }
    if 'capability' in doc:
        record.update(version=2, capability=capability.name, operation=capability.operation,
                      access=capability.access, path=doc['path'])
    return roles_cli._canonical(record)


def preview_approved(doc, declaration, *, expected_uid, capability=_BUILTIN):
    """Inspect the requested file without changing policy, ACLs, or journals."""
    role, uid = _approved(doc, declaration, expected_uid=expected_uid, capability=capability)
    resource = role['resources'][doc['scope']]
    with _held(doc, resource) as (_, fd, info):
        if stat.S_IMODE(info.st_mode) != 0o600: raise Refusal('baseline_not_private')
        _no_acl(fd)
        attempt = sha256(_marker(doc, declaration, uid, resource, capability)).hexdigest()
        return {**_response('preview','not_attempted','approved_plan',doc,uid,info,attempt),
                'before_mode':'0600','after_mode':format(0o600 | capability.access << 3, '04o'),
                'access_mask':capability.access,'operation':capability.operation,
                'side_effects':'Apply adds only the approved named-UID ACL and a private journal.',
                'expiry':'Manual revocation is required; declaration expiry does not remove ACLs.'}


def _run_locked(action,doc,store, *, expected_uid=None, capability=_BUILTIN):
    declaration=roles_cli._inspect_store(store,doc['profile'],doc['revision'])
    if action=='preview':
        return preview_approved(doc, declaration, expected_uid=expected_uid, capability=capability)
    role,uid=_approved(doc,declaration,expected_uid=expected_uid,capability=capability)
    role_store=store
    resource=role['resources'][doc['scope']]
    with _held(doc,resource) as (parent,fd,info):
        mode=stat.S_IMODE(info.st_mode)
        expected=_acl(uid, capability.access)
        granted_mode = 0o600 | capability.access << 3
        marker=_marker(doc,declaration,uid,resource,capability)
        attempt=sha256(marker).hexdigest()
        def verified(effect,code):
            state=_declaration_state(role_store,doc,_decode_json(marker))
            return {**_response('acl_entry_verified' if state=='current' else 'cleanup_due',effect,code,
                                doc,uid,info,attempt),
                    'declaration':state,'appointment':'unverified','acl_presence':'present_exact','cleanup':'available',
                    'access_mask':capability.access,'operation':capability.operation}
        store=_journal(parent,create=False)
        if store is None:
            if action!='apply': return _response('unknown','not_attempted','journal_missing',doc,uid,info,attempt)
            if mode!=0o600: raise Refusal('baseline_not_private')
            _no_acl(fd)
            store=_journal(parent,create=True)
        index=RecordKey(_binding_key(doc),'binding')
        previous=_read(store,index)
        if previous is None:
            if mode!=0o600: raise Refusal('baseline_not_private')
            _no_acl(fd)
            if _write(store,index,marker) is not Persistence.COMMITTED:
                return _response('unknown','unknown','reconcile_required',doc,uid,info,attempt)
            fresh=True
        else:
            if previous!=marker: raise Refusal('journal_conflict')
            fresh=False
        keys=[RecordKey(attempt,name) for name in ('grant_claim','grant_result','revoke_claim','revoke_result')]
        claim,grant,rclaim,revoke=(_read(store,k) for k in keys)
        for value in (claim,grant,rclaim,revoke):
            if value is not None and value!=marker: raise Refusal('journal_conflict')
        def current():
            try: return os.getxattr(fd,_XATTR)
            except OSError as exc:
                if exc.errno==errno.ENODATA: return None
                raise
        if claim is not None:
            if grant is not None and rclaim is None and mode==granted_mode and current()==expected:
                return verified('not_attempted','already_applied')
            return _response('unknown','not_attempted','reconcile_required',doc,uid,info,attempt)
        if not fresh:
            return _response('unknown','not_attempted','reconcile_required',doc,uid,info,attempt)
        if mode!=0o600: raise Refusal('baseline_not_private')
        _no_acl(fd)
        if _write(store,keys[0],marker) is not Persistence.COMMITTED:
            return _response('unknown','unknown','reconcile_required',doc,uid,info,attempt)
        result_key=keys[1]
        try:
            before=os.fstat(fd)
            if role['expires_at'] <= time():
                return _response('unknown','not_attempted','role_expired',doc,uid,info,attempt)
            if (before.st_dev,before.st_ino,stat.S_IMODE(before.st_mode))!=(info.st_dev,info.st_ino,mode):
                return _response('unknown','not_attempted','resource_changed',doc,uid,info,attempt)
            # CREATE refuses an ACL installed since the baseline check.
            os.setxattr(fd,_XATTR,expected,os.XATTR_CREATE)
            os.fsync(fd)
            after=os.fstat(fd); raw=current()
            if ((after.st_dev,after.st_ino)!=(info.st_dev,info.st_ino) or
                    (stat.S_IMODE(after.st_mode),raw)!=(granted_mode,expected)):
                return _response('unknown','unknown','readback_unconfirmed',doc,uid,info,attempt)
            if _write(store,result_key,marker) not in (Persistence.COMMITTED,Persistence.EXISTING):
                return _response('unknown','unknown','journal_unconfirmed',doc,uid,info,attempt)
            return verified('observed','readback_verified')
        except (OSError,RecordError,Refusal):
            return _response('unknown','unknown','effect_unconfirmed',doc,uid,info,attempt)
