import errno
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from worker_handoff.managed import EffectStatus
from worker_handoff.recording import (
    Destination, EvidenceType, LocalStore, Persistence, RecordError, RecordKey, RecorderPolicy,
    Retention, Route, StoragePolicy,
)


class RecordingTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = RecordKey("attempt-1", "audit")
        self.kind = EvidenceType("audit", "application/octet-stream")
        self.payload = b"protected fixture bytes"

    def make_store(self, name, *, mode=0o700, **kwargs):
        path = self.root / name
        path.mkdir(mode=mode)
        path.chmod(mode)
        return LocalStore(path, **kwargs)

    def policy(self, store, **settings):
        return RecorderPolicy({"archive": Destination(store, StoragePolicy(**settings))},
                              (Route(self.kind, required=("archive",)),))

    def assert_disposition(self, state, fn, *args, **kwargs):
        with self.assertRaises(RecordError) as error:
            fn(*args, **kwargs)
        self.assertIs(error.exception.status, state)

    def test_routes_preserve_partial_result_missing_bytes_and_unknown_work_effect(self):
        archive = self.make_store("archive")
        review = LocalStore(self.root / "missing")
        policy = RecorderPolicy(
            {"archive": Destination(archive), "review": Destination(review)},
            (Route(self.kind, required=("archive",), optional=("review",)),),
        )
        missing = policy.record(self.key, self.kind, None)
        self.assertFalse(missing.required_complete)
        self.assertEqual([entry.state for entry in missing.destinations], [Persistence.MISSING] * 2)
        self.assertFalse(list(archive.directory.iterdir()))
        recorded = policy.record(self.key, self.kind, self.payload)
        self.assertIs(recorded.effect, EffectStatus.UNKNOWN)
        self.assertTrue(recorded.required_complete)
        committed, optional = recorded.destinations
        self.assertIs(committed.state, Persistence.COMMITTED)
        self.assertIs(optional.state, Persistence.REFUSED)
        self.assertEqual(policy.readback("archive", committed.receipt), self.payload)
        self.assertNotIn(self.payload.decode(), repr(recorded))

    def test_commit_reopen_idempotency_conflict_and_retention(self):
        store = self.make_store("archive")
        policy = self.policy(store, max_age_seconds=1)
        with patch("worker_handoff.recording.time_ns", return_value=1_000_000_000):
            first = policy.record(self.key, self.kind, self.payload).destinations[0]
        reopened = self.policy(LocalStore(store.directory), max_age_seconds=1)
        duplicate = reopened.record(self.key, self.kind, self.payload).destinations[0]
        self.assertIs(duplicate.state, Persistence.EXISTING)
        self.assertEqual(duplicate.receipt, first.receipt)
        other = reopened.record(self.key, self.kind, b"replacement").destinations[0]
        self.assertIs(other.state, Persistence.CONFLICT)
        at = reopened.purge
        with patch("worker_handoff.recording.time_ns", return_value=1_999_999_999):
            self.assertIs(at("archive", first.receipt, resolved=True), Retention.RETAINED_YOUNG)
        with patch("worker_handoff.recording.time_ns", return_value=2_000_000_000):
            self.assertIs(at("archive", first.receipt), Retention.RETAINED_UNRESOLVED)
            self.assertEqual(reopened.readback("archive", first.receipt), self.payload)
            self.assertIs(at("archive", first.receipt, resolved=True), Retention.PURGED)
        self.assert_disposition(Persistence.PURGED, reopened.readback, "archive", first.receipt)
        self.assertIs(reopened.record(self.key, self.kind, self.payload).destinations[0].state, Persistence.PURGED)
        self.assertIs(reopened.record(self.key, self.kind, b"replacement").destinations[0].state, Persistence.CONFLICT)

    def test_filesystem_permissions_are_checked_on_access(self):
        group = os.getegid()
        store = self.make_store("group", mode=0o2750, group_id=group)
        policy = self.policy(store, group_id=group)
        result = policy.record(self.key, self.kind, self.payload).destinations[0]
        self.assertIs(result.state, Persistence.COMMITTED)
        record = store.directory / self.key.filename()
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o640)
        self.assertEqual(record.stat().st_gid, group)
        self.assertEqual(policy.readback("archive", result.receipt), self.payload)
        record.chmod(0o660)
        self.assert_disposition(Persistence.REFUSED, policy.readback, "archive", result.receipt)
        private = self.make_store("private")
        owner_policy = self.policy(private)
        private_result = owner_policy.record(self.key, self.kind, self.payload).destinations[0]
        self.assertIs(private_result.state, Persistence.COMMITTED)
        self.assertEqual(stat.S_IMODE((private.directory / self.key.filename()).stat().st_mode), 0o600)
        private.directory.chmod(0o750)
        self.assert_disposition(Persistence.REFUSED, owner_policy.readback, "archive", private_result.receipt)

    def test_failed_dir_sync_is_unknown_and_exact_storage_commit_reconciles(self):
        store = self.make_store("archive")
        policy = self.policy(store)
        normal = os.fsync

        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "fixture")
            return normal(fd)

        with patch("worker_handoff.recording.os.fsync", side_effect=sync):
            failed = policy.record(self.key, self.kind, self.payload).destinations[0]
        self.assertIs(failed.state, Persistence.UNKNOWN)
        self.assertIsNone(failed.receipt)
        reopened = self.policy(LocalStore(store.directory))
        self.assertIs(reopened.record(self.key, self.kind, b"different").destinations[0].state, Persistence.CONFLICT)
        verified = reopened.record(self.key, self.kind, self.payload).destinations[0]
        self.assertIs(verified.state, Persistence.EXISTING)
        self.assertEqual(reopened.readback("archive", verified.receipt), self.payload)

    def test_crash_before_publish_leaves_unknown_and_preserves_pending_bytes(self):
        store = self.make_store("archive")
        script = """
import os
from pathlib import Path
import sys
from unittest.mock import patch
import worker_handoff.recording as recording

local = recording.LocalStore(Path(sys.argv[1]))
kind = recording.EvidenceType('audit', 'application/octet-stream')
policy = recording.RecorderPolicy(
    {'archive': recording.Destination(local)}, (recording.Route(kind, required=('archive',)),))
with patch.object(recording.os, 'link', side_effect=lambda *args, **kwargs: os._exit(23)):
    policy.record(recording.RecordKey('attempt-1', 'audit'), kind, b'protected fixture bytes')
"""
        crashed = subprocess.run([sys.executable, "-B", "-c", script, str(store.directory)], check=False, timeout=10)
        self.assertEqual(crashed.returncode, 23)
        reopened = self.policy(LocalStore(store.directory))
        self.assert_disposition(Persistence.UNKNOWN, store.read, self.key, policy=StoragePolicy())
        result = reopened.record(self.key, self.kind, self.payload).destinations[0]
        self.assertIs(result.state, Persistence.UNKNOWN)
        self.assertFalse((store.directory / self.key.filename()).exists())
        self.assertEqual(len(list(store.directory.iterdir())), 1)

    def test_existing_adapter_checks_actual_policy_and_reports_uncertain_commit(self):
        class ExistingAdapter:
            def __init__(self):
                self.policy = None
                self.accept = False
                self.attempts = 0

            def check_policy(self, policy):
                self.policy = policy
                return self.accept

            def commit(self, receipt, payload, *, policy):
                if policy != self.policy:
                    raise AssertionError("wrong policy")
                self.attempts += 1
                raise OSError("protected endpoint fixture")

            def read(self, key, *, policy):
                raise RecordError(Persistence.MISSING)

            def purge(self, expected, *, policy):
                raise RecordError(Persistence.UNKNOWN)

        adapter = ExistingAdapter()
        policy = self.policy(adapter, group_id=os.getegid())
        self.assertIs(policy.record(self.key, self.kind, self.payload).destinations[0].state, Persistence.REFUSED)
        self.assertEqual(adapter.attempts, 0)
        adapter.accept = True
        self.assertIs(policy.record(self.key, self.kind, self.payload).destinations[0].state, Persistence.UNKNOWN)
        self.assertEqual(adapter.attempts, 1)
