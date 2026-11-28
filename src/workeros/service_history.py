"""Durable copies of verified results with their original reader entitlement."""

from time import monotonic_ns

from . import roles_cli
from .enrollment import decode_policy
from .managed_launch import _digest, _uid, launch_result
from .recording import EvidenceType, Persistence, RecordError, _name


_KIND = EvidenceType('managed-service-history', 'application/json')
_GUARD_KIND = EvidenceType('managed-service-guard-history', 'application/json')


def _key(request, *, guard_only=False):
    for field in ('profile', 'revision', 'workflow'):
        _name(request[field])
    _digest(request['request_id'])
    prefix = 'service-guard-history-' if guard_only else 'service-history-'
    return roles_cli._key(request['profile'], request['revision'],
                          prefix + request['workflow'] + '-' + request['request_id'])


def _read(store, request, caller_uid, *, guard_only=False):
    from .managed_service_client import _response

    saved = roles_cli._read_stored(store, _key(request, guard_only=guard_only))
    if saved is None or saved.receipt.evidence_type != (_GUARD_KIND if guard_only else _KIND):
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
    code = 'service_terminal_reported' if guard_only else 'independent_service_result_verified'
    if (record['version'] != 1 or type(record['version']) is not int
            or any(record[field] != request[field] for field in ('profile', 'revision', 'workflow'))
            or record['result'].get('code') != code
            or 'selection' not in record['result'] or 'history' in record['result']):
        return None
    return _response(record['result'], request)


def _marker(request, status):
    return {'status': status, 'profile': request['profile'], 'revision': request['revision']}


def read_history(request, caller_uid, *, independent_only=False):
    """Return the same opaque result for an absent record and an unauthorized reader."""
    try:
        with roles_cli._store(create=False) as store:
            result = _read(store, request, caller_uid)
            if result is None and not independent_only:
                result = _read(store, request, caller_uid, guard_only=True)
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
    """Retain reader-bound terminal evidence at its observed strength."""
    from .managed_service_client import _response

    code = result.get('code')
    guard_only = code == 'service_terminal_reported'
    if (not guard_only and code != 'independent_service_result_verified') or 'selection' not in result:
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
            prior = _read(store, request, caller_uid, guard_only=guard_only)
            if prior is not None:
                if _receipt(prior, guard_only) != _receipt(result, guard_only):
                    return launch_result('unknown', 'unknown', 'service_history_conflict')
                return {**prior, 'history': _marker(request, 'recorded')}
            verified = result.get('observer_result')
            if guard_only or verified['verified_ns'] <= monotonic_ns() < verified['expires_ns']:
                payload = roles_cli._canonical(record)
                key = _key(request, guard_only=guard_only)
                state = roles_cli._commit(store, key, payload, kind=_GUARD_KIND if guard_only else _KIND)
                if state is Persistence.COMMITTED and _read(store, request, caller_uid, guard_only=guard_only) == result:
                    return {**result, 'history': _marker(request, 'recorded')}
    except (OSError, ValueError, TypeError, KeyError, RecordError, roles_cli.Refusal):
        pass
    return {**result, 'history': _marker(request, 'unconfirmed')}


def _receipt(result, guard_only):
    if guard_only:
        return result['invocation_key'], result['selection'], result['provider_report']
    return (result['invocation_key'], result['receipt_sha256'], result['observer_result']['receipt_sha256'])
