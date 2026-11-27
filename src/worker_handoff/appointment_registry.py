"""Administrator-owned role appointment records in the existing profile store."""

from dataclasses import asdict
from hashlib import sha256
import argparse
import json
import sys

from . import roles_cli as roles
from .enrollment import _operations
from .profile_setup import ProfileDefinition
from .recording import EvidenceType, Persistence, RecordError, _name

_KIND = EvidenceType('role-appointments', 'application/json')


def definition_sha256(definition):
    """Pin the complete trusted definition, including its provider capabilities."""
    if type(definition) is not ProfileDefinition:
        raise ValueError('expected a trusted profile definition')
    return sha256(roles._canonical(asdict(definition))).hexdigest()


def _validate(data):
    document = roles._decode_json(data)
    roles._fields(document, ('version', 'profile', 'revision', 'declaration_sha256',
                             'intent_sha256', 'appointments'))
    if type(document['version']) is not int or document['version'] != 1:
        raise roles.Refusal('invalid_appointment_version')
    _name(document['profile'])
    _name(document['revision'])
    roles._commission_receipt(document['profile'], document['revision'],
                              document['declaration_sha256'], document['intent_sha256'])
    entries = document['appointments']
    if type(entries) is not list or not 1 <= len(entries) <= 64:
        raise roles.Refusal('invalid_appointments')
    seen = set()
    for entry in entries:
        roles._fields(entry, ('workflow', 'workflow_revision', 'definition_sha256',
                              'role', 'principal', 'scope', 'generation', 'operations'))
        for field in ('workflow', 'workflow_revision', 'role', 'scope', 'generation'):
            _name(entry[field])
        roles._principal(entry['principal'], resolve=False)
        digest = entry['definition_sha256']
        if type(digest) is not str or not roles._DIGEST.fullmatch(digest):
            raise roles.Refusal('invalid_appointment_definition')
        _operations(entry['operations'])
        if entry['workflow'] in seen:
            raise roles.Refusal('duplicate_appointment_workflow')
        seen.add(entry['workflow'])
    return document


def _check_approval(document, receipt, declaration):
    if receipt['status'] != 'configured' or declaration['status'] != 'configured':
        raise roles.Refusal('appointment_approval_inactive')
    if any(document[field] != receipt[field] for field in ('declaration_sha256', 'intent_sha256')):
        raise roles.Refusal('appointment_approval_mismatch')
    if ('appointments_sha256' in receipt
            and sha256(roles._canonical(document)).hexdigest() != receipt['appointments_sha256']):
        raise roles.Refusal('appointment_approval_mismatch')
    declared = {role['name']: role for role in declaration['roles']}
    for entry in document['appointments']:
        role = declared.get(entry['role'])
        if (role is None or entry['principal'] != role['principal'] or entry['scope'] not in role['scopes']
                or not set(entry['operations']) <= set(role['operations'])
                or role.get('resources') or role.get('independent_of') or role.get('privileged')):
            raise roles.Refusal('appointment_outside_declaration')


def read_registry(store, profile, revision, receipt, declaration):
    """Read an exact current record under the caller's existing administrator lock."""
    payload = roles._read(store, roles._key(profile, revision, 'appointments'))
    if payload is None:
        return None
    try:
        document = _validate(payload)
        if (document['profile'], document['revision']) != (profile, revision):
            raise ValueError('registration identity mismatch')
        if roles._canonical(document) != payload:
            raise ValueError('noncanonical registration')
    except ValueError as exc:
        raise roles.Refusal('appointment_record_invalid', uncertain=True) from exc
    _check_approval(document, receipt, declaration)
    return document


def _register_store(store, document, receipt, declaration):
    _check_approval(document, receipt, declaration)
    key = roles._key(document['profile'], document['revision'], 'appointments')
    payload = roles._canonical(document)
    try:
        state = roles._commit(store, key, payload, kind=_KIND)
    except RecordError as exc:
        if exc.status is Persistence.CONFLICT:
            raise roles.Refusal('appointment_registration_conflict') from exc
        raise
    if roles._read(store, key) != payload:
        raise roles.Refusal('appointment_readback_unconfirmed', uncertain=True)
    return 'recorded' if state is Persistence.COMMITTED else 'unchanged'


def register(data):
    """Commit one immutable registration set for an active approved revision."""
    document = _validate(data)
    profile, revision = document['profile'], document['revision']
    with roles._store(create=False) as store:
        receipt = roles._commission_status_store(store, profile, revision)
        if receipt['status'] != 'configured':
            raise roles.Refusal('appointment_approval_inactive')
        declaration = roles._inspect_store(store, profile, revision)
        effect = _register_store(store, document, receipt, declaration)
    return roles._commission_result('registered', effect, **document)


def status(profile, revision):
    """Report the local registration without touching provider state."""
    _name(profile)
    _name(revision)
    with roles._store(create=False) as store:
        receipt = roles._commission_status_store(store, profile, revision)
        if receipt['status'] != 'configured':
            return roles._commission_result(receipt['status'], 'not_attempted',
                                          profile=profile, revision=revision)
        declaration = roles._inspect_store(store, profile, revision)
        document = read_registry(store, profile, revision, receipt, declaration)
    if document is None:
        return roles._commission_result('unregistered', 'not_attempted',
                                      profile=profile, revision=revision)
    return roles._commission_result('registered', 'not_attempted', **document)


def main(operation, argv):
    parser = argparse.ArgumentParser(prog=f'workeros managed {operation}', description=__doc__)
    writing = operation == 'appointment-register'
    if not writing:
        parser.add_argument('profile')
        parser.add_argument('revision')
    args = parser.parse_args(argv)
    try:
        if writing:
            data = sys.stdin.buffer.read(roles._LIMIT + 1)
            if len(data) > roles._LIMIT:
                raise roles.Refusal('document_too_large')
            result = register(data)
        else:
            result = status(args.profile, args.revision)
    except roles.Refusal as exc:
        uncertain = exc.uncertain or str(exc) in ('profile_store_busy', 'untrusted_store')
        result = roles._commission_result('unknown' if uncertain else 'refused',
                                          'unknown' if writing and exc.uncertain else 'not_attempted',
                                          code=str(exc))
    except (OSError, RecordError):
        result = roles._commission_result('unknown', 'unknown' if writing else 'not_attempted',
                                          code='appointment_state_unconfirmed')
    except ValueError:
        result = roles._commission_result('refused', 'not_attempted', code='invalid_appointment_document')
    if result['status'] == 'registered':
        result['next_action'] = 'Use the managed host to verify live bindings and independent provider evidence.'
    elif result['status'] == 'unknown':
        result['next_action'] = 'Check appointment-status for the exact revision before any repeat.'
    print(json.dumps(result, separators=(',', ':'), sort_keys=True))
    return 0 if result['status'] == 'registered' else 1
