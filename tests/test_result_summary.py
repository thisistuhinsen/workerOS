"""Exercise the count over scoped historical records without an archive or host."""

from unittest import TestCase

from workeros.result_summary import summarize_archived_results


SELECTION = {'workflow': 'audit', 'role': 'auditor', 'scope_sha256': 'a' * 64}
PROFILE = {'profile': 'reports', 'revision': 'review-1'}


def archived(request, invocation, receipt, *, selection=SELECTION, profile=PROFILE):
    return {'status': 'terminal', 'effect': 'dispatched', 'code': 'independent_service_result_verified',
            'cleanup': 'verified', 'selection': selection, 'history': {'status': 'recorded', **profile},
            'request_id': request * 64, 'invocation_key': invocation * 64, 'receipt_sha256': receipt * 64,
            'observer_result': {'receipt_sha256': 'e' * 64, 'effect_sha256': 'f' * 64}}


class ResultSummaryTest(TestCase):
    def summarize(self, results):
        return summarize_archived_results(results, **PROFILE, **SELECTION)

    def test_counts_exact_scope_and_revision_once_per_request(self):
        one = archived('1', '2', '3')
        again = {**one, 'observer_result': {**one['observer_result'], 'verified_ns': 100}}
        two = archived('4', '5', '6')
        other_role = archived('7', '8', '9', selection={**SELECTION, 'role': 'writer'})
        other_scope = archived('8', '9', '0', selection={**SELECTION, 'scope_sha256': 'b' * 64})
        other_workflow = archived('9', '8', '0', selection={**SELECTION, 'workflow': 'ingest'})
        other_rev = archived('0', '1', '2', profile={**PROFILE, 'revision': 'review-2'})
        other_profile = archived('1', '0', '2', profile={**PROFILE, 'profile': 'other'})
        self.assertEqual(
            self.summarize([one, again, two, other_role, other_scope, other_workflow, other_rev, other_profile]),
            {'version': 1, 'basis': 'verified_archived_requests', 'status': 'reported',
             'code': 'verified_archive_count', 'verified_count': 2, 'liveness': 'unavailable'})

    def test_absent_or_unverified_history_has_no_count(self):
        record = archived('1', '2', '3')
        unarchived = {key: value for key, value in record.items() if key != 'history'}
        unknown = {**record, 'status': 'unknown', 'effect': 'unknown', 'code': 'service_terminal_reported'}
        unfinished = {**record, 'cleanup': 'unconfirmed'}
        foreign = {**record, 'selection': {**SELECTION, 'role': 'other'}}
        unavailable = {'version': 1, 'basis': 'verified_archived_requests', 'status': 'unavailable',
                       'code': 'verified_archive_unavailable', 'verified_count': None, 'liveness': 'unavailable'}
        for result in (None, [], [unarchived], [unknown], [unfinished], [foreign]):
            self.assertEqual(self.summarize(result), unavailable)

    def test_conflicting_receipts_or_correlations_have_no_count(self):
        one = archived('1', '2', '3')
        other_request_same_invocation = archived('4', '2', '3')
        different_receipt = archived('1', '2', '4')
        different_invocation = archived('1', '4', '3')
        missing_observer = {**one, 'observer_result': {}}
        for conflict in (other_request_same_invocation, different_receipt, different_invocation, missing_observer):
            with self.subTest(conflict=conflict.get('request_id')):
                result = self.summarize([one, conflict])
                self.assertEqual(result['status'], 'unavailable')
                self.assertIsNone(result['verified_count'])
