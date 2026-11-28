"""Project a count over the authorized part of a finite historical result set."""

from .managed_launch import _digest
from .recording import _name
from .result_export import RESULT_VERSION


def summarize_archived_results(results, *, profile, revision, workflow, role, scope_sha256):
    """Count independently verified archived requests for one pinned selection.

    The caller supplies only historical responses already authorized and
    verified by the stock archive reader. Caller-owned report copies are not
    that source. This projection does not enumerate storage, establish that
    the input covers the whole selection, or report current activity.
    """
    for name in (profile, revision, workflow, role):
        _name(name)
    _digest(scope_sha256)
    summary = {'version': RESULT_VERSION, 'basis': 'verified_archived_requests', 'liveness': 'unavailable'}
    unavailable = {**summary, 'status': 'unavailable', 'code': 'verified_archive_unavailable',
                   'verified_count': None}
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
                != ('recorded', profile, revision)
                or (result.get('status'), result.get('effect'), result.get('code'), result.get('cleanup'))
                != ('terminal', 'dispatched', 'independent_service_result_verified', 'verified')):
            continue
        try:
            request_id = result['request_id']
            observer = result['observer_result']
            proof = (result['invocation_key'], result['receipt_sha256'],
                     observer['receipt_sha256'], observer['effect_sha256'])
            _digest(request_id)
            for digest in proof:
                _digest(digest)
        except (KeyError, TypeError, ValueError):
            return unavailable
        invocation_key = proof[0]
        if (requests.setdefault(request_id, proof) != proof
                or invocation_requests.setdefault(invocation_key, request_id) != request_id):
            # Conflicting correlations in the selected archive do not
            # establish a count. Never choose one receipt by arrival order.
            return unavailable
    if not requests:
        return unavailable
    return {**summary, 'status': 'reported', 'code': 'verified_archive_count',
            'verified_count': len(requests)}
