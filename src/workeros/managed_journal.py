"""Durable, non-replaying setup journal in an already provisioned local store."""
from dataclasses import asdict
from hashlib import sha256
import json
import re

from .managed_host import AttemptRecord
from .profile_setup import ManagerReadback, ProfileDefinition, SetupResult
from .recording import (EvidenceType, LocalStore, Persistence, RecordError,
                        RecordKey, RecordReceipt, StoragePolicy, _name)

_HASH = re.compile(r'[0-9a-f]{64}')
_KIND = EvidenceType('managed-attempt', 'application/json')
_POLICY = StoragePolicy()
_STATES = frozenset(('accepted','refused','unknown','conflict','not_committed','recorded','absent'))
_EFFECTS = frozenset(('not_attempted','committed','not_committed','unknown'))


def _encoded(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')


class ManagedJournal:
    """Immutable claims and outcomes. Directory must already be trusted and private.

    A pending claim is never removed or replayed. Store errors remain unknown.
    This journal stores status only; it supplies no provider authentication.
    """
    def __init__(self, directory, *, definitions, scope_pins=None):
        if (type(definitions) is not tuple or not definitions or len(definitions) > 64
                or any(type(d) is not ProfileDefinition for d in definitions)
                or len({d.name for d in definitions}) != len(definitions)):
            raise ValueError('expected commissioned definitions')
        self.store = LocalStore(directory)
        self.definitions = definitions
        self._mappings = {}
        self._active_attempt = None
        if scope_pins is not None:
            profile, revision, roles_and_generations = scope_pins
            _name(profile)
            _name(revision)
            for definition, (role, generation) in zip(definitions, roles_and_generations, strict=True):
                _name(role)
                _name(generation)
                # Keep the existing immutable resource key. A different
                # revision or attempt cannot replace an existing mapping.
                key = RecordKey(profile, sha256(_encoded([
                    'point-mapping-v1', revision, definition.name, definition.revision])).hexdigest())
                mapping = {'definition': asdict(definition), 'role': role, 'generation': generation}
                self._mappings[definition.name] = (key, mapping)

    @staticmethod
    def _key(identity, operation_key, kind):
        if (type(identity) is not str or type(operation_key) is not str or
                not _HASH.fullmatch(identity) or not _HASH.fullmatch(operation_key)):
            raise ValueError('expected exact identity and operation key')
        return RecordKey(identity, operation_key+'-'+kind)

    def _read(self, key):
        stored = self.store.read(key, policy=_POLICY)
        payload = self.store.verify_durable(stored.receipt, policy=_POLICY)
        if payload is None: raise ValueError('missing durable payload')
        return json.loads(payload)

    def _commit(self, key, data):
        payload = _encoded(data)
        receipt = RecordReceipt(key, _KIND, sha256(payload).hexdigest(), len(payload), 0)
        return self.store.commit(receipt, payload, policy=_POLICY).state

    def _claim_doc(self, identity, operation_key):
        claim = {'version': 1, 'identity': identity, 'operation_key': operation_key, 'state': 'claimed'}
        if self._mappings:
            claim.update(version=2, scope_mapping_sha256=[
                sha256(_encoded(mapping)).hexdigest() for _, mapping in self._mappings.values()])
        return claim

    @staticmethod
    def _mapping_payload(value):
        """Return the mapping and optional exact operation on a durable record."""
        if type(value) is not dict:
            raise ValueError('invalid scope mapping')
        if set(value) == {'definition', 'role', 'generation'}:
            return value, None
        if (set(value) != {'version', 'identity', 'operation_key', 'disposition', 'mapping'}
                or type(value['version']) is not int or value['version'] != 2
                or value['disposition'] != 'committed' or type(value['mapping']) is not dict
                or set(value['mapping']) != {'definition', 'role', 'generation'}
                or any(type(value[field]) is not str or not _HASH.fullmatch(value[field])
                       for field in ('identity', 'operation_key'))):
            raise ValueError('invalid scope mapping')
        return value['mapping'], (value['identity'], value['operation_key'])

    def current_mapping(self, definition):
        key, expected = self._mappings[definition.name]
        if expected['definition'] != asdict(definition):
            return ManagerReadback('unavailable')
        try:
            mapping, _ = self._mapping_payload(self._read(key))
        except RecordError as exc:
            return ManagerReadback('absent' if exc.status is Persistence.MISSING else 'unavailable')
        except (OSError, ValueError, TypeError):
            return ManagerReadback('unavailable')
        if _encoded(mapping) != _encoded(expected):
            return ManagerReadback('unavailable')
        return ManagerReadback('present', definition)

    def commit_mapping(self, definition):
        if self._active_attempt is None:
            raise PermissionError('scope commit needs the process that claimed the attempt')
        identity, operation_key = self._active_attempt
        if self.read(identity, operation_key).state != 'pending':
            raise PermissionError('scope commit needs a pending durable claim')
        key, mapping = self._mappings[definition.name]
        if mapping['definition'] != asdict(definition):
            raise ValueError('scope definition changed')
        # This single immutable record is both the mapping and evidence of
        # its exact writer. No separate acknowledgment can be lost between them.
        return self._commit(key, {'version': 2, 'identity': identity, 'operation_key': operation_key,
                                  'disposition': 'committed', 'mapping': mapping})

    def recover_pending(self, identity, operation_key):
        """Read historical scope commits without reconstructing setup results."""
        if not self._mappings or self.read(identity, operation_key).state != 'pending':
            return ()
        try:
            claim = self._read(self._key(identity, operation_key, 'claim'))
            if claim != self._claim_doc(identity, operation_key):
                return ()  # Older claims never pinned how to attribute mappings.
        except (OSError, RecordError, ValueError, TypeError):
            return ()
        results = []
        for definition in self.definitions:
            key, expected = self._mappings[definition.name]
            try:
                mapping, attempt = self._mapping_payload(self._read(key))
            except (OSError, RecordError, ValueError, TypeError):
                # Missing or unavailable storage is not a durable no-commit
                # disposition. Keep the claim reserved and do not replay.
                result = SetupResult('unknown', 'scope_commit_unconfirmed', 'unknown')
            else:
                if _encoded(mapping) != _encoded(expected):
                    result = SetupResult('conflict', 'scope_mapping_conflict', 'unknown')
                elif attempt != (identity, operation_key):
                    result = SetupResult('unknown', 'scope_commit_unattributed', 'unknown')
                else:
                    result = SetupResult('recorded', 'scope_commit_verified', 'committed', definition)
            results.append((definition.name, result))
        return tuple(results)

    def read(self, identity, operation_key):
        claim, result = (self._key(identity,operation_key,kind) for kind in ('claim','result'))
        try:
            value = self._read(claim)
        except RecordError as exc:
            if exc.status is Persistence.MISSING:
                try:
                    self._read(result)
                except RecordError as result_exc:
                    if result_exc.status is Persistence.MISSING:
                        return AttemptRecord(identity,operation_key,'not_started')
                except (OSError, ValueError, TypeError):
                    pass
                return AttemptRecord(identity,operation_key,'unavailable')
            return AttemptRecord(identity,operation_key,'unavailable')
        except (OSError, ValueError, TypeError):
            return AttemptRecord(identity,operation_key,'unavailable')
        legacy = {'version': 1, 'identity': identity, 'operation_key': operation_key, 'state': 'claimed'}
        if (type(value) is not dict or type(value.get('version')) is not int or
                value not in (legacy, self._claim_doc(identity, operation_key))):
            return AttemptRecord(identity,operation_key,'unavailable')
        try:
            outcome = self._read(result)
        except RecordError as exc:
            return AttemptRecord(identity,operation_key,'pending' if exc.status is Persistence.MISSING else 'unavailable')
        except (OSError, ValueError, TypeError):
            return AttemptRecord(identity,operation_key,'unavailable')
        try:
            if (type(outcome) is not dict or set(outcome) != {'version','identity','operation_key','results'}
                    or type(outcome['version']) is not int or outcome['version'] != 1 or outcome['identity'] != identity
                    or outcome['operation_key'] != operation_key or type(outcome['results']) is not list
                    or len(outcome['results']) != len(self.definitions)):
                raise ValueError()
            results = []
            for definition, item in zip(self.definitions,outcome['results']):
                if (type(item) is not dict or set(item) != {'name','status','code','effect','has_definition','has_attempt'}
                        or item['name'] != definition.name or item['status'] not in _STATES
                        or item['effect'] not in _EFFECTS or type(item['code']) is not str
                        or not re.fullmatch(r'[a-z0-9_]{1,100}',item['code'])
                        or type(item['has_definition']) is not bool or type(item['has_attempt']) is not bool
                        or item['status'] == 'accepted' and not item['has_definition']):
                    raise ValueError()
                results.append((definition.name,SetupResult(item['status'],item['code'],item['effect'],
                    definition if item['has_definition'] else None, definition if item['has_attempt'] else None)))
            return AttemptRecord(identity,operation_key,'recorded',tuple(results))
        except (ValueError,TypeError,KeyError):
            return AttemptRecord(identity,operation_key,'unavailable')

    def claim(self, identity, operation_key):
        key = self._key(identity,operation_key,'claim')
        if self._mappings and self._active_attempt is not None:
            return 'existing'
        state = self._commit(key, self._claim_doc(identity, operation_key))
        if self._mappings and state is Persistence.COMMITTED:
            self._active_attempt = (identity, operation_key)
        return 'claimed' if state is Persistence.COMMITTED else 'existing'

    def finish(self, identity, operation_key, results):
        if self.read(identity,operation_key).state != 'pending': return False
        if type(results) is not tuple or len(results) != len(self.definitions): raise ValueError('invalid results')
        encoded=[]
        for definition,item in zip(self.definitions,results):
            if (type(item) is not tuple or len(item) != 2 or item[0] != definition.name
                    or type(item[1]) is not SetupResult): raise ValueError('invalid result')
            result=item[1]
            if (result.status not in _STATES or result.effect not in _EFFECTS
                    or type(result.code) is not str or not re.fullmatch(r'[a-z0-9_]{1,100}',result.code)
                    or result.definition is not None and result.definition != definition
                    or result.attempt is not None and result.attempt != definition
                    or result.status == 'accepted' and result.definition != definition):
                raise ValueError('invalid result')
            encoded.append({'name':definition.name,'status':result.status,'code':result.code,'effect':result.effect,
                            'has_definition':result.definition is not None,'has_attempt':result.attempt is not None})
        state=self._commit(self._key(identity,operation_key,'result'),
            {'version':1,'identity':identity,'operation_key':operation_key,'results':encoded})
        return state in (Persistence.COMMITTED,Persistence.EXISTING)
