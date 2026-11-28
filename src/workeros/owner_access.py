"""One-owner, one-file read permission: no privilege acquisition or observer claim."""
import argparse
from contextlib import contextmanager
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import stat
import sys

from .enrollment import decode_policy
from .recording import (EvidenceType, LocalStore, Persistence, RecordError,
                        RecordKey, RecordReceipt, StoragePolicy, _name)

_LIMIT=65536
_KIND=EvidenceType('owner-read-grant','application/json')
_POLICY=StoragePolicy()


class Refusal(ValueError): pass


def _acl_absent(fd, *, directory=False):
    names=['system.posix_acl_access']
    if directory: names.append('system.posix_acl_default')
    for name in names:
        try: os.getxattr(fd,name)
        except OSError as exc:
            if exc.errno not in (errno.ENODATA,errno.ENOTSUP): raise
        else: raise Refusal('acl_present')


def _input(data, *, planned):
    doc=decode_policy(data)
    basic={'version','path','principal','role','scope','exclusive_owner'}
    if type(doc) is not dict or set(doc)!=(basic | ({'device','inode'} if planned else set())):
        raise Refusal('invalid_plan')
    if type(doc['version']) is not int or doc['version']!=1: raise Refusal('invalid_plan')
    if doc['exclusive_owner'] is not True: raise Refusal('exclusive_control_required')
    path=doc['path']
    if type(path) is not str or not os.path.isabs(path) or '\0' in path or os.path.basename(path) in ('','.','..'):
        raise Refusal('invalid_path')
    for field in ('principal','role','scope'): _name(doc[field])
    if planned:
        for field in ('device','inode'):
            value=doc[field]
            if type(value) is not str or not value.isascii() or not value.isdecimal() or str(int(value))!=value:
                raise Refusal('invalid_identity')
    return doc


@contextmanager
def _held(doc):
    uid=os.geteuid()
    if uid == 0: raise Refusal('root_unsupported')
    try: principal=pwd.getpwnam(doc['principal'])
    except KeyError: raise Refusal('principal_missing') from None
    if principal.pw_uid != uid: raise Refusal('principal_not_current_owner')
    parent_path=os.path.dirname(doc['path']); leaf=os.path.basename(doc['path'])
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    parent=os.open(parent_path,flags)
    try:
        p=os.fstat(parent)
        if p.st_uid != uid or stat.S_IMODE(p.st_mode)!=0o700: raise Refusal('private_parent_required')
        _acl_absent(parent,directory=True)
        fd=os.open(leaf,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise Refusal('resource_busy') from None
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_nlink!=1:
                raise Refusal('unsupported_resource')
            _acl_absent(fd)
            if 'device' in doc and (str(info.st_dev),str(info.st_ino))!=(doc['device'],doc['inode']):
                raise Refusal('resource_changed')
            yield parent,fd,info
        finally: os.close(fd)
    finally: os.close(parent)


def _can_open(fd, expected):
    try: check=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
    except PermissionError: return False
    except OSError as exc:
        if exc.errno in (errno.ENOENT,errno.ENOTDIR,errno.ENOSYS):
            raise Refusal('backend_unavailable') from None
        raise
    try:
        actual=os.fstat(check)
        if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino): raise Refusal('resource_changed')
        return True
    finally: os.close(check)


def _store(parent, doc, *, create):
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    try: directory=os.open('.workeros-grants',flags,dir_fd=parent)
    except FileNotFoundError:
        if not create: return None
        os.mkdir('.workeros-grants',0o700,dir_fd=parent); os.fsync(parent)
        directory=os.open('.workeros-grants',flags,dir_fd=parent)
    try:
        info=os.fstat(directory)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: raise Refusal('journal_untrusted')
        _acl_absent(directory,directory=True)
    finally: os.close(directory)
    # Pin the journal under the already-open parent even if its pathname moves.
    return LocalStore(Path('/proc/self/fd')/str(parent)/'.workeros-grants')


def _attempt(doc):
    fields=[str(os.geteuid()),doc['device'],doc['inode'],doc['principal'],doc['role'],doc['scope']]
    return sha256('\0'.join(fields).encode()).hexdigest()


def _read(store,key):
    try:
        found=store.read(key,policy=_POLICY)
        return store.verify_durable(found.receipt,policy=_POLICY)
    except RecordError as exc:
        if exc.status is Persistence.MISSING: return None
        raise


def _write(store,key,payload):
    receipt=RecordReceipt(key,_KIND,sha256(payload).hexdigest(),len(payload),0)
    return store.commit(receipt,payload,policy=_POLICY).state


def _out(status,effect,doc,info,code):
    return {'status':status,'effect':effect,'code':code,'principal_uid':info.st_uid,
            'device':str(info.st_dev),'inode':str(info.st_ino),'role':doc['role'],'scope':doc['scope'],
            'attempt':_attempt(doc),'plan':doc,
            'capability':'owner_read','observer_independence':'not_verified',
            'next_action':'Reconcile this exact plan before any retry.' if status=='unknown' else
                          'Use this plan with revoke to remove the owner-read bit.' if status=='grant_verified' else
                          'Previously opened descriptors and other authority are not checked.'}


def preview(data):
    doc=_input(data,planned=False)
    with _held(doc) as (_,fd,info):
        if stat.S_IMODE(info.st_mode)!=0o200 or _can_open(fd,info): raise Refusal('baseline_not_write_only')
        plan={**doc,'device':str(info.st_dev),'inode':str(info.st_ino)}
        return {'status':'preview','effect':'not_attempted','plan':plan,'principal_uid':info.st_uid,
                'before':'0200','after':'0600','capability':'owner_read',
                'side_effects':'Apply creates a private journal and changes only the owner-read mode bit.',
                'exclusivity':'Caller asserts no noncooperating permission changes; flock is advisory.',
                'observer_independence':'not_verified'}


def run(action,data):
    doc=_input(data,planned=True)
    if action not in ('apply','revoke','check'): raise ValueError('invalid action')
    with _held(doc) as (parent,fd,info):
        store=_store(parent,doc,create=False)
        if store is None:
            if action!='apply': return _out('unknown','not_attempted',doc,info,'journal_missing')
            if stat.S_IMODE(info.st_mode)!=0o200 or _can_open(fd,info): raise Refusal('baseline_not_write_only')
            store=_store(parent,doc,create=True)
        attempt=_attempt(doc)
        claim=RecordKey(attempt,'grant_claim'); granted=RecordKey(attempt,'grant_result')
        rev_claim=RecordKey(attempt,'revoke_claim'); revoked=RecordKey(attempt,'revoke_result')
        marker=json.dumps({'version':1,'attempt':attempt,'device':doc['device'],'inode':doc['inode'],
                           'uid':info.st_uid,'role':doc['role'],'scope':doc['scope']},sort_keys=True,separators=(',',':')).encode()
        prior_claim=_read(store,claim); prior_grant=_read(store,granted); prior_revoke_claim=_read(store,rev_claim); prior_revoke=_read(store,revoked)
        for value in (prior_claim,prior_grant,prior_revoke_claim,prior_revoke):
            if value is not None and value!=marker: raise Refusal('journal_conflict')
        mode=stat.S_IMODE(info.st_mode)
        if action=='check':
            if prior_revoke is not None and mode==0o200 and not _can_open(fd,info): return _out('owner_read_removed','not_attempted',doc,info,'readback_verified')
            if prior_grant is not None and prior_revoke_claim is None and mode==0o600 and _can_open(fd,info): return _out('grant_verified','not_attempted',doc,info,'readback_verified')
            return _out('unknown','not_attempted',doc,info,'unresolved')
        if action=='apply':
            if prior_claim is not None:
                if prior_grant is not None and prior_revoke_claim is None and mode==0o600 and _can_open(fd,info):
                    return _out('grant_verified','not_attempted',doc,info,'already_applied')
                return _out('unknown','not_attempted',doc,info,'reconcile_required')
            if mode!=0o200 or _can_open(fd,info): raise Refusal('baseline_not_write_only')
            if _write(store,claim,marker) is not Persistence.COMMITTED: return _out('unknown','unknown',doc,info,'reconcile_required')
            desired=0o600; done=granted; success='grant_verified'
        else:
            if prior_grant is None: raise Refusal('grant_not_recorded')
            if prior_revoke_claim is not None:
                if prior_revoke is not None and mode==0o200 and not _can_open(fd,info):
                    return _out('owner_read_removed','not_attempted',doc,info,'already_removed')
                return _out('unknown','not_attempted',doc,info,'reconcile_required')
            if mode!=0o600 or not _can_open(fd,info): raise Refusal('resource_changed')
            if _write(store,rev_claim,marker) is not Persistence.COMMITTED: return _out('unknown','unknown',doc,info,'reconcile_required')
            desired=0o200; done=revoked; success='owner_read_removed'
        try:
            # Locked FD stays bound to the original inode. A noncooperating
            # same-UID writer can still race chmod; this is not a kernel CAS.
            before=os.fstat(fd); _acl_absent(fd)
            if (before.st_dev,before.st_ino,stat.S_IMODE(before.st_mode)) != (info.st_dev,info.st_ino,mode):
                return _out('unknown','not_attempted',doc,info,'resource_changed')
            os.fchmod(fd,desired)
            os.fsync(fd)
            after=os.fstat(fd); _acl_absent(fd)
            if ((after.st_dev,after.st_ino,stat.S_IMODE(after.st_mode))!=(info.st_dev,info.st_ino,desired)
                    or _can_open(fd,after)!=(action=='apply')):
                return _out('unknown','unknown',doc,info,'readback_unconfirmed')
            if _write(store,done,marker) not in (Persistence.COMMITTED,Persistence.EXISTING):
                return _out('unknown','unknown',doc,info,'journal_unconfirmed')
            return _out(success,'observed',doc,info,'readback_verified')
        except (OSError,RecordError,Refusal):
            return _out('unknown','unknown',doc,info,'effect_unconfirmed')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('preview','apply','check','revoke'))
    args=parser.parse_args(argv)
    plan=None
    try:
        data=sys.stdin.buffer.read(_LIMIT+1)
        if len(data)>_LIMIT: raise Refusal('document_too_large')
        if args.operation=='preview': result=preview(data)
        else:
            raw=decode_policy(data)
            if args.operation in ('apply','check') and type(raw) is dict and 'device' not in raw and 'inode' not in raw:
                if args.operation=='apply':
                    plan=preview(data)['plan']
                else:
                    original=_input(data,planned=False)
                    with _held(original) as (_,_,info):
                        plan={**original,'device':str(info.st_dev),'inode':str(info.st_ino)}
                data=json.dumps(plan,separators=(',',':')).encode()
            else:
                plan=_input(data,planned=True)
            result=run(args.operation,data)
    except (ValueError,OSError,RecordError) as exc:
        code=str(exc) if type(exc) is Refusal else 'operation_unconfirmed'
        advice={
            'principal_not_current_owner':'Use this backend only for the current file owner; choose another backend for a different principal.',
            'root_unsupported':'Run as the non-root file owner; this backend does not acquire privilege.',
            'acl_present':'Leave the ACL unchanged and use an authorized ACL backend.',
            'baseline_not_write_only':'Use an owned 0200 file in a private directory; do not overwrite existing permissions.',
            'resource_changed':'Stop and inspect the original object; do not retry against a replacement.',
            'exclusive_control_required':'Establish exclusive permission control before applying.',
            'resource_busy':'Wait for the current cooperative operation to finish, then inspect the plan.',
            'backend_unavailable':'Use a Linux host with an accessible procfs and owner-mode permission support.',
        }
        result={'status':'refused' if type(exc) is Refusal else 'unknown',
                'effect':'not_attempted' if type(exc) is Refusal else 'unknown','code':code,
                'next_action':advice.get(code,'Check the exact plan and journal before retrying.')}
        if plan is not None:
            result.update(plan=plan,attempt=_attempt(plan))
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0 if result['status'] in ('preview','grant_verified','owner_read_removed') else 1


if __name__=='__main__': sys.exit(main())
