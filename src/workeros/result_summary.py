"""Project a count over the authorized part of a finite historical result set."""

from .managed_launch import _digest
from .recording import _name
from .result_export import RESULT_VERSION


def scoped_activity(result):
    """Label only the evidence in an authorized, exact-request response."""
    phase = result.get('phase_observation')
    if phase is not None:
        return {'state': 'active' if phase['populated'] else 'settling', 'basis': 'guard_cgroup_sample',
                'clock_id': phase['clock_id'], 'observed_ns': phase['observed_ns']}
    if result.get('code') == 'independent_service_result_verified':
        return {'state': 'completed', 'basis': 'independent_result'}
    if result.get('code') == 'service_terminal_reported':
        life = result['provider_report']['service']['lifecycle']
        failed = (life['terminal_disposition'], life['terminal_status']) != ('exited', 0)
        return {'state': 'failed' if failed else 'unknown', 'basis': 'guard_terminal'}
    state = result['status'] if result['status'] in ('refused', 'not_started') else 'unknown'
    return {'state': state, 'basis': 'managed_result'}


def _archived_proof(result):
    invocation = result['invocation_key']
    if (result['status'], result['effect'], result['code'], result.get('cleanup')) == (
            'terminal', 'dispatched', 'independent_service_result_verified', 'verified'):
        observer = result['observer_result']
        return (invocation, result['receipt_sha256'], observer['receipt_sha256'], observer['effect_sha256'])
    if (result['status'], result['effect'], result['code']) == ('unknown', 'unknown', 'service_terminal_reported'):
        report = result['provider_report']
        return invocation, report['receipt_sha256']
    return None


def summarize_archived_results(results, *, profile, revision, workflow, role, scope_sha256):
    """Count available historical evidence for one pinned selection.

    The caller supplies only historical responses already authorized and
    verified by the stock archive reader. Caller-owned report copies are not
    that source. This projection does not enumerate storage, establish that
    the input covers the whole selection, or report current activity.
    """
    for name in (profile, revision, workflow, role):
        _name(name)
    _digest(scope_sha256)
    summary = {'version': RESULT_VERSION, 'basis': 'verified_archived_requests', 'liveness': 'unavailable'}
    counts = dict.fromkeys(('active', 'settling', 'completed', 'refused', 'failed', 'unknown'))
    unavailable = {**summary, 'status': 'unavailable', 'code': 'verified_archive_unavailable',
                   'verified_count': None, 'counts': counts}
    if results is None:
        return unavailable

    requests = {}
    invocation_requests = {}
    for result in results:
        if type(result) is not dict:
            continue
        selected = result.get('selection')
        history = result.get('history')
        if (type(selected) is not dict or type(history) is not dict
                or (selected.get('workflow'), selected.get('role'), selected.get('scope_sha256'))
                != (workflow, role, scope_sha256)
                or (history.get('status'), history.get('profile'), history.get('revision'))
                != ('recorded', profile, revision)):
            continue
        try:
            request_id = result['request_id']
            proof = _archived_proof(result)
            if proof is None:
                continue
            state = scoped_activity(result)['state']
            if state not in ('completed', 'failed', 'unknown'):
                return unavailable
            _digest(request_id)
            for digest in proof:
                _digest(digest)
        except (KeyError, TypeError, ValueError):
            return unavailable
        invocation_key = proof[0]
        if (requests.setdefault(request_id, (proof, state)) != (proof, state)
                or invocation_requests.setdefault(invocation_key, request_id) != request_id):
            # Conflicting correlations in the selected archive do not
            # establish a count. Never choose one receipt by arrival order.
            return unavailable
    if not requests:
        return unavailable
    counts = {**counts, 'completed': 0, 'failed': 0, 'unknown': 0}
    for _, state in requests.values():
        counts[state] += 1
    return {**summary, 'status': 'reported', 'code': 'verified_archive_count',
            'verified_count': counts['completed'], 'counts': counts}
