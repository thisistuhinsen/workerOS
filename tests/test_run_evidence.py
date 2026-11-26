from dataclasses import replace
import unittest

from worker_handoff.evidence import (
    EvidenceObservation,
    EvidenceState,
    RunBinding,
    RunEvent,
    validate_run_evidence,
)
from worker_handoff.supervisor import (
    CleanupResult,
    CleanupStatus,
    LifecycleStatus,
    SupervisionResult,
)


class RunEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.binding = RunBinding("run", "artifact", "local-clock", 100, 200)
        self.present = EvidenceObservation("receipt", EvidenceState.OBSERVED)

    def event(self, **changes):
        fields = {
            "binding": self.binding,
            "source_id": "recipient",
            "sequence": 1,
            "started_ns": 100,
            "finished_ns": 120,
            "observations": (self.present,),
        }
        fields.update(changes)
        return RunEvent(**fields)

    def test_ordered_intervals_can_touch_across_sources(self):
        events = (
            self.event(),
            self.event(source_id="observer", sequence=2, started_ns=120, finished_ns=200),
        )
        self.assertIs(validate_run_evidence(self.binding, events), events)

    def test_each_event_must_match_run_artifact_and_clock(self):
        for key, value in (
            ("run_id", "other-run"),
            ("artifact_id", "other-artifact"),
            ("clock_id", "other-clock"),
        ):
            with self.subTest(key=key):
                candidate = self.event(binding=replace(self.binding, **{key: value}))
                with self.assertRaises(ValueError):
                    validate_run_evidence(self.binding, (candidate,))

    def test_requires_well_formed_identifiers_and_external_clock_bounds(self):
        for changes in (
            {"run_id": ""},
            {"artifact_id": None},
            {"clock_id": None},
            {"started_ns": True},
            {"started_ns": 201},
            {"finished_ns": 1 << 63},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                binding = replace(self.binding, **changes)
                validate_run_evidence(binding, ())

    def test_rejects_invalid_time_sequence_and_source_without_mutating_batch(self):
        first = self.event()
        second = self.event(source_id="observer", sequence=2, started_ns=120, finished_ns=200)
        valid = (first, second)
        snapshot = (replace(first), replace(second))
        for changes in (
            {"source_id": ""},
            {"sequence": 1},
            {"sequence": 3},
            {"started_ns": 119},
            {"finished_ns": 119},
            {"finished_ns": 201},
            {"started_ns": True},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    candidate = (first, replace(second, **changes))
                    validate_run_evidence(self.binding, candidate)
                self.assertEqual(valid, snapshot)
                self.assertIs(validate_run_evidence(self.binding, valid), valid)
        with self.assertRaises(ValueError):
            validate_run_evidence(self.binding, (second,))
        with self.assertRaises(ValueError):
            validate_run_evidence(self.binding, (self.event(started_ns=99),))

    def test_required_observation_matches_source_and_observed_state(self):
        required = (("recipient", "receipt"),)
        optional = self.event(
            source_id="observer",
            observations=(EvidenceObservation("receipt", EvidenceState.UNAVAILABLE),),
        )
        with self.assertRaises(ValueError):
            validate_run_evidence(
                self.binding, (self.event(source_id="other-recipient"),), require_observed=required,
            )
        for state in (
            EvidenceState.OBSERVED,
            EvidenceState.CONFIRMED_ABSENT,
            EvidenceState.UNAVAILABLE,
            EvidenceState.INDETERMINATE,
            EvidenceState.NOT_REQUESTED,
        ):
            receipt = self.event(
                sequence=2, started_ns=120, finished_ns=140,
                observations=(EvidenceObservation("receipt", state),),
            )
            events = (optional, receipt)
            with self.subTest(state=state):
                if state is EvidenceState.OBSERVED:
                    self.assertIs(
                        validate_run_evidence(self.binding, events, require_observed=required), events,
                    )
                else:
                    with self.assertRaises(ValueError):
                        validate_run_evidence(self.binding, events, require_observed=required)
                self.assertEqual(validate_run_evidence(self.binding, events), events)
                self.assertIs(receipt.observations[0].state, state)
        with self.assertRaises(ValueError):
            validate_run_evidence(self.binding, (), require_observed=required)

    def test_receipt_exposure_and_effect_are_separate_reported_facts(self):
        observations = (
            EvidenceObservation("receipt", EvidenceState.UNAVAILABLE),
            EvidenceObservation("exposure", EvidenceState.INDETERMINATE),
            EvidenceObservation("sink-effect", EvidenceState.INDETERMINATE),
            EvidenceObservation("other-effect", EvidenceState.CONFIRMED_ABSENT),
        )
        events = (self.event(observations=observations, cleanup=CleanupStatus.REAPED),)
        self.assertEqual(validate_run_evidence(self.binding, events)[0].observations, observations)
        with self.assertRaises(ValueError):
            validate_run_evidence(self.binding, events, require_observed=(("recipient", "receipt"),))

    def test_events_require_a_fact_and_at_most_one_report_per_subject(self):
        for observations in (
            (),
            (self.present, EvidenceObservation("receipt", EvidenceState.INDETERMINATE)),
        ):
            with self.subTest(observations=observations), self.assertRaises(ValueError):
                event = self.event(observations=observations)
                validate_run_evidence(self.binding, (event,))

    def test_terminal_confirmation_needs_a_single_report_from_the_pinned_source(self):
        exited = self.event(
            source_id="supervisor", observations=(), lifecycle=LifecycleStatus.EXITED,
            returncode=7, cleanup=CleanupStatus.NOT_REQUESTED,
        )
        reap = self.event(
            source_id="supervisor", sequence=2, started_ns=120, finished_ns=140,
            observations=(), cleanup=CleanupStatus.REAPED,
        )
        complete = replace(reap, returncode=7)
        foreign_reap = replace(reap, source_id="observer")
        lone_exit = replace(exited, source_id="observer")
        for events in (
            (exited,),
            (replace(reap, sequence=1),),
            (exited, reap),
            (lone_exit, reap),
            (exited, foreign_reap),
            (exited, replace(foreign_reap, returncode=7)),
        ):
            with self.subTest(events=events):
                self.assertIs(validate_run_evidence(self.binding, events), events)
                with self.assertRaises(ValueError):
                    validate_run_evidence(self.binding, events, require_terminal_from="supervisor")
        events = (exited, complete)
        self.assertIs(validate_run_evidence(
            self.binding, events, require_terminal_from="supervisor",
        ), events)
        with self.assertRaises(ValueError):
            validate_run_evidence(
                self.binding, (exited, replace(reap, returncode=8)),
            )

    def test_terminal_source_requires_a_nonempty_identifier(self):
        for source in ("", " ", True):
            with self.subTest(source=source), self.assertRaises(ValueError):
                validate_run_evidence(self.binding, (), require_terminal_from=source)

    def test_external_observation_cannot_report_exit_code_or_reap(self):
        for code, cleanup in (
            (7, None), (None, CleanupStatus.REAPED), (7, CleanupStatus.REAPED),
        ):
            with self.subTest(code=code, cleanup=cleanup), self.assertRaises(ValueError):
                self.event(
                    observations=(), lifecycle=LifecycleStatus.OBSERVED,
                    returncode=code, cleanup=cleanup,
                )
        external = RunEvent.from_result(
            self.binding, "supervisor", 1, 100, 120,
            SupervisionResult(LifecycleStatus.OBSERVED, CleanupResult(CleanupStatus.OUTSIDE_SCOPE)),
        )
        self.assertIs(validate_run_evidence(self.binding, (external,))[0], external)
        with self.assertRaises(ValueError):
            validate_run_evidence(self.binding, (external,), require_terminal_from="supervisor")

    def test_pending_cleanup_cannot_follow_a_reported_reap(self):
        pending = self.event(observations=(), cleanup=CleanupStatus.PENDING)
        reaped = self.event(
            sequence=2, started_ns=120, finished_ns=140, observations=(),
            returncode=7, cleanup=CleanupStatus.REAPED,
        )
        events = (pending, reaped)
        self.assertIs(validate_run_evidence(
            self.binding, events, require_terminal_from="recipient",
        ), events)
        later_pending = replace(pending, sequence=3, started_ns=140, finished_ns=160)
        with self.assertRaises(ValueError):
            validate_run_evidence(self.binding, events + (later_pending,))

    def test_from_supervisor_preserves_wait_outcome_and_uses_reap_code(self):
        cleanup = CleanupResult(CleanupStatus.REAPED, -15)
        for lifecycle in (LifecycleStatus.TIMED_OUT, LifecycleStatus.CANCELLED):
            with self.subTest(lifecycle=lifecycle):
                result = SupervisionResult(lifecycle, cleanup)
                event = RunEvent.from_result(self.binding, "supervisor", 1, 100, 120, result)
                self.assertIs(event.lifecycle, lifecycle)
                self.assertEqual((event.returncode, event.cleanup), (-15, CleanupStatus.REAPED))
                self.assertEqual(
                    validate_run_evidence(self.binding, (event,), require_terminal_from="supervisor"),
                    (event,),
                )
        standalone = RunEvent.from_result(self.binding, "supervisor", 2, 120, 140, cleanup)
        self.assertIsNone(standalone.lifecycle)
        self.assertEqual((standalone.returncode, standalone.cleanup), (-15, CleanupStatus.REAPED))
        with self.assertRaises(ValueError):
            RunEvent.from_result(
                self.binding, "supervisor", 1, 100, 120,
                SupervisionResult(LifecycleStatus.EXITED, cleanup, 0),
            )

    def test_bool_is_not_an_exit_code(self):
        with self.assertRaises(ValueError):
            event = self.event(lifecycle=LifecycleStatus.EXITED, returncode=True)
            validate_run_evidence(self.binding, (event,))
