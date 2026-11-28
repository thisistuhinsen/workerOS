"""Durable copies of verified results with their original reader entitlement."""

from time import monotonic_ns

from . import roles_cli
from .enrollment import decode_policy
from .managed_launch import _digest, _uid, launch_result
from .recording import EvidenceType, Persistence, RecordError, _name


_KIND = EvidenceType('managed-service-history', 'application/json')


def _key(request):
    for field in ('profile', 'revision', 'workflow'):
        _name(request[field])
    _digest(request['request_id'])
    return roles_cli._key(request['profile'], request['revision'],
                          'service-history-' + request['workflow'] + '-' + request['request_id'])


def _read(store, request, caller_uid):
    from .managed_service_client import _response

    saved = roles_cli._read_stored(store, _key(request))
    if saved is None or saved.receipt.evidence_type != _KIND:
        return None
    record = decode_policy(saved.payload)
    roles_cli._fields(record, ('version', 'profile', 'revision', 'workflow', 'readers', 'result'))
    readers = record['readers']
    if type(readers) is not list:
        return None
    for reader in readers:
        _uid(reader)
    if caller_uid not in readers:
        return None
    if (record['version'] != 1 or type(record['version']) is not int
            or any(record[field] != request[field] for field in ('profile', 'revision', 'workflow'))
            or record['result'].get('code') != 'independent_service_result_verified'
            or 'history' in record['result']):
        return None
    return _response(record['result'], request)


def _marker(request, status):
    return {'status': status, 'profile': request['profile'], 'revision': request['revision']}


def read_history(request, caller_uid):
    """Return the same opaque result for an absent record and an unauthorized reader."""
    try:
        with roles_cli._store(create=False) as store:
            result = _read(store, request, caller_uid)
        if result is not None:
            return {**result, 'history': _marker(request, 'recorded')}
    except (OSError, ValueError, TypeError, KeyError, RecordError, roles_cli.Refusal):
        pass
    return launch_result('unknown', 'unknown', 'service_history_unavailable')


def read_history_summary(request, caller_uid, deadline_ns):
    """Count an explicit set under the primary record's exact authorized selection."""
    from .result_summary import summarize_archived_results

    primary = read_history(request, caller_uid)
    if 'history' not in primary:
        return primary
    selected, history = primary['selection'], primary['history']
    results = [primary]
    for identifier in dict.fromkeys(request['summary_ids']):
        if identifier == request['request_id']:
            continue
        if monotonic_ns() >= deadline_ns:
            results = None
            break
        entry = read_history({**request, 'request_id': identifier}, caller_uid)
        if entry.get('selection') != selected or entry.get('history') != history:
            results = None
            break
        results.append(entry)
    summary = summarize_archived_results(results, profile=history['profile'], revision=history['revision'],
                                         workflow=selected['workflow'], role=selected['role'],
                                         scope_sha256=selected['scope_sha256'])
    return {**primary, 'summary': summary}


def retain_history(request, caller_uid, readers, result):
    """Commit only a verified terminal, while its independent evidence is valid."""
    from .managed_service_client import _response

    if result.get('code') != 'independent_service_result_verified' or 'selection' not in result:
        return result
    try:
        _response(result, request)
        for reader in readers:
            _uid(reader)
        readers = sorted(set(readers))
        if caller_uid not in readers:
            return launch_result('unknown', 'unknown', 'service_history_unavailable')
        record = {'version': 1, **{key: request[key] for key in ('profile', 'revision', 'workflow')},
                  'readers': readers, 'result': result}
        with roles_cli._store(create=False) as store:
            prior = _read(store, request, caller_uid)
            if prior is not None:
                if (prior['invocation_key'], prior['receipt_sha256'], prior['observer_result']['receipt_sha256']) != (
                        result['invocation_key'], result['receipt_sha256'], result['observer_result']['receipt_sha256']):
                    return launch_result('unknown', 'unknown', 'service_history_conflict')
                return {**prior, 'history': _marker(request, 'recorded')}
            verified = result['observer_result']
            if verified['verified_ns'] <= monotonic_ns() < verified['expires_ns']:
                payload = roles_cli._canonical(record)
                state = roles_cli._commit(store, _key(request), payload, kind=_KIND)
                if state is Persistence.COMMITTED and _read(store, request, caller_uid) == result:
                    return {**result, 'history': _marker(request, 'recorded')}
    except (OSError, ValueError, TypeError, KeyError, RecordError, roles_cli.Refusal):
        pass
    return {**result, 'history': _marker(request, 'unconfirmed')}
