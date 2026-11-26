from dataclasses import asdict, replace
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from worker_handoff.managed import EffectStatus
from worker_handoff.recording import (
    Destination, EvidenceType, LocalStore, Persistence, RecordError, RecordKey, RecorderPolicy,
    RecordReceipt, Retention, RetentionStamp, Route, StoragePolicy, StoreCommit, StoredEvidence,
)


_SECOND = 1_000_000_000


class RecorderExpiryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.evidence = EvidenceType("result", "text/plain")
        self.payload = b"synthetic operation result"

    def policy(self, *, minimum=None, expiry=None):
        return RecorderPolicy(
            {"archive": Destination(LocalStore(self.directory), StoragePolicy(max_age_seconds=minimum,
                                                                             expire_after_seconds=expiry))},
            (Route(self.evidence, required=("archive",)),),
        )

    def commit(self, policy, name="record", *, seconds=1):
        with patch("worker_handoff.recording.time_ns", return_value=seconds * _SECOND):
            result = policy.record(RecordKey("run", name), self.evidence, self.payload,
                                   effect=EffectStatus.COMPLETE, source="owner", scope="local").destinations[0]
        self.assertIs(result.state, Persistence.COMMITTED)
        return result.receipt

    def assert_persistence(self, state, method, *args, **kwargs):
        with self.assertRaises(RecordError) as error:
            method(*args, **kwargs)
        self.assertIs(error.exception.status, state)

    def test_effect_source_scope_and_terms_bind_exact_readback_and_retry(self):
        policy = self.policy(minimum=9, expiry=10)
        expected = self.commit(policy)
        self.assertEqual(expected.retention, RetentionStamp(1, 9, 10))
        self.assertEqual(RecordReceipt.from_dict(json.loads(json.dumps(asdict(expected)))), expected)
        replay = policy.record(expected.key, self.evidence, self.payload, effect=expected.effect,
                               source="owner", scope="local").destinations[0]
        self.assertEqual((replay.state, replay.receipt), (Persistence.EXISTING, expected))
        for changed in (replace(expected, effect=EffectStatus.PARTIAL), replace(expected, source="other"),
                        replace(expected, scope="other")):
            result = policy.record(expected.key, self.evidence, self.payload, effect=changed.effect,
                                   source=changed.source, scope=changed.scope).destinations[0]
            self.assertIs(result.state, Persistence.CONFLICT)
            self.assert_persistence(Persistence.CONFLICT, policy.readback, "archive", changed)
        weakened = self.policy(minimum=1, expiry=2)
        result = weakened.record(expected.key, self.evidence, self.payload, effect=expected.effect,
                                 source="owner", scope="local").destinations[0]
        self.assertIs(result.state, Persistence.CONFLICT)
        self.assert_persistence(Persistence.CONFLICT, weakened.verify_durable, "archive",
                                replace(expected, retention=RetentionStamp(1, 1, 2)))
        self.assertEqual(weakened.readback("archive", expected), self.payload)

    def test_explicit_purge_uses_stricter_current_and_original_age_floors(self):
        expected = self.commit(self.policy(minimum=10, expiry=50))
        weaker = self.policy(minimum=2, expiry=3)
        stricter = self.policy(minimum=12, expiry=99)
        with patch("worker_handoff.recording.time_ns", return_value=5 * _SECOND):
            self.assertIs(weaker.purge("archive", expected, resolved=True), Retention.RETAINED_YOUNG)
        with patch("worker_handoff.recording.time_ns", return_value=11 * _SECOND):
            self.assertIs(stricter.purge("archive", expected, resolved=True), Retention.RETAINED_YOUNG)
            self.assertIs(stricter.purge("archive", expected), Retention.RETAINED_UNRESOLVED)
        with patch("worker_handoff.recording.time_ns", return_value=13 * _SECOND):
            self.assertIs(stricter.purge("archive", expected, resolved=True), Retention.PURGED)
        self.assert_persistence(Persistence.PURGED, stricter.readback, "archive", expected)

    def test_external_destination_receives_its_own_terms_and_legacy_expiry_is_unavailable(self):
        class Adapter:
            stored = None

            def check_policy(self, policy):
                return True

            def commit(self, receipt, payload, *, policy):
                self.stored = StoredEvidence(receipt, payload)
                return StoreCommit(Persistence.COMMITTED, receipt)

            def read(self, key, *, policy):
                return self.stored

            def purge(self, expected, *, policy):
                if self.stored.receipt != expected:
                    raise RecordError(Persistence.CONFLICT)
                self.stored = StoredEvidence(expected, None)

        remote = Adapter()
        local = LocalStore(self.directory)
        route = (Route(self.evidence, required=("archive", "remote")),)
        policy = RecorderPolicy({"archive": Destination(local, StoragePolicy(max_age_seconds=2)),
                                 "remote": Destination(remote, StoragePolicy(max_age_seconds=8))}, route)
        with patch("worker_handoff.recording.time_ns", return_value=0):
            result = policy.record(RecordKey("run", "two-stores"), self.evidence, self.payload)
        archive, external = [row.receipt for row in result.destinations]
        self.assertTrue(result.required_complete)
        self.assertEqual(archive.retention.min_age_seconds, 2)
        self.assertEqual(external.retention.min_age_seconds, 8)
        self.assertEqual(policy.lookup("remote", external.key), StoredEvidence(external, self.payload))
        self.assert_persistence(Persistence.CONFLICT, policy.lookup, "remote", RecordKey("run", "wrong-key"))
        self.assertEqual(policy.readback("remote", external), self.payload)
        self.assert_persistence(Persistence.REFUSED, policy.verify_durable, "remote", external)

        current = RecorderPolicy({"archive": Destination(local), "remote": Destination(remote)}, route)
        with patch("worker_handoff.recording.time_ns", return_value=7 * _SECOND):
            self.assertIs(current.purge("remote", external, resolved=True), Retention.RETAINED_YOUNG)
        self.assert_persistence(Persistence.REFUSED, current.sweep, "remote", [external], settled=lambda _: True)
        self.assertEqual(current.readback("remote", external), self.payload)

    def test_preflight_checks_only_required_local_destinations_and_is_effect_free(self):
        policy = RecorderPolicy(
            {"archive": Destination(LocalStore(self.directory)),
             "optional": Destination(LocalStore(self.directory / "missing"))},
            (Route(self.evidence, required=("archive",), optional=("optional",)),),
        )
        self.assertTrue(policy.check_required_local(self.evidence))
        with patch("worker_handoff.recording.os.access", return_value=False) as check_access:
            self.assert_persistence(Persistence.REFUSED, policy.check_required_local, self.evidence)
            check_access.assert_called_once()
            self.assertEqual(check_access.call_args.args, (".", os.W_OK | os.X_OK))
            self.assertIs(check_access.call_args.kwargs["effective_ids"], True)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_commit_and_verify_use_the_supplied_ordinary_parent_descriptor(self):
        parent = self.directory / "parent"
        parent.mkdir(mode=0o700)
        archive = parent / "archive"
        archive.mkdir(mode=0o700)
        store = LocalStore(archive)
        key = RecordKey("run", "pinned")
        receipt = RecordReceipt(key, self.evidence, sha256(self.payload).hexdigest(), len(self.payload), 0)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        moved = parent.rename(self.directory / "moved")
        try:
            saved = store.commit(receipt, self.payload, policy=StoragePolicy(), _parent_fd=fd)
            self.assertIs(saved.state, Persistence.COMMITTED)
            self.assertEqual(store.verify_durable(saved.receipt, policy=StoragePolicy(), _parent_fd=fd), self.payload)
        finally:
            os.close(fd)
        self.assertTrue((moved / "archive" / key.filename()).is_file())
        self.assertFalse(archive.exists())

    def test_expiry_batch_is_bounded_and_retain_manual_young_and_unsettled(self):
        original = self.policy(expiry=5)
        old = self.commit(original, "old")
        young = self.commit(original, "young", seconds=5)
        unsettled = self.commit(original, "unsettled")
        manual = self.commit(self.policy(), "manual")
        current = self.policy(expiry=6)
        receipts = [old, young, unsettled, manual]

        def settled(receipt):
            if receipt == unsettled:
                raise RuntimeError("settlement provider unavailable")
            return True

        with self.assertRaises(ValueError):
            current.sweep("archive", receipts, settled=settled, limit=3)
        with self.assertRaises(ValueError):
            current.sweep("archive", [old, replace(old, committed_ns=0)], settled=settled)
        self.assertEqual(current.readback("archive", old), self.payload)
        with patch("worker_handoff.recording.time_ns", return_value=7 * _SECOND):
            results = current.sweep("archive", receipts, settled=settled, limit=4)
        self.assertEqual([r.retention for r in results], [Retention.PURGED, Retention.RETAINED_YOUNG,
                                                       Retention.RETAINED_UNRESOLVED, Retention.RETAINED_MANUAL])
        self.assert_persistence(Persistence.PURGED, current.readback, "archive", old)
        for receipt in (young, manual, unsettled):
            self.assertEqual(current.readback("archive", receipt), self.payload)

    def test_legacy_v1_exact_readback_remains_but_destructive_maintenance_refuses(self):
        expected = RecordReceipt(RecordKey("run", "legacy"), self.evidence,
                                 sha256(self.payload).hexdigest(), len(self.payload), 0)
        metadata = {k: v for k, v in asdict(expected).items() if v is not None}
        header = json.dumps({"version": 1, "receipt": metadata, "purged": False}).encode("ascii")
        path = self.directory / expected.key.filename()
        path.write_bytes(struct.pack("!I", len(header)) + header + self.payload)
        path.chmod(0o600)
        policy = self.policy(expiry=1)
        self.assertEqual(policy.verify_durable("archive", RecordReceipt.from_dict(metadata)), self.payload)
        self.assertIs(policy.purge("archive", expected, resolved=True), Retention.RETAINED_LEGACY)
        self.assertIs(policy.sweep("archive", [expected], settled=lambda _: True)[0].retention,
                      Retention.RETAINED_LEGACY)
        self.assertEqual(policy.readback("archive", expected), self.payload)

    def test_exact_bytes_after_lost_ack_are_not_durable_until_fresh_sync(self):
        policy = self.policy(expiry=1)
        key = RecordKey("run", "lost-ack")
        original_fsync = os.fsync

        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "injected directory sync error")
            return original_fsync(fd)

        with patch("worker_handoff.recording.os.fsync", side_effect=fail_directory):
            with patch("worker_handoff.recording.time_ns", return_value=0):
                recorded = policy.record(key, self.evidence, self.payload).destinations[0]
            self.assertEqual((recorded.state, recorded.receipt), (Persistence.UNKNOWN, None))
            expected = LocalStore(self.directory).read(key, policy=StoragePolicy(expire_after_seconds=1)).receipt
            self.assertEqual(policy.readback("archive", expected), self.payload)
            self.assert_persistence(Persistence.UNKNOWN, policy.verify_durable, "archive", expected)
            result, = policy.sweep("archive", [expected], settled=lambda _: True)
            self.assertIs(result.persistence, Persistence.UNKNOWN)
            self.assertEqual(policy.readback("archive", expected), self.payload)
        self.assertEqual(policy.verify_durable("archive", expected), self.payload)

    def test_local_storage_returns_busy_while_another_holder_has_lock_and_can_retry(self):
        policy = self.policy(expiry=1)
        expected = self.commit(policy)
        fresh_key = RecordKey(expected.key.run_id, "fresh")
        script = """
import json
from pathlib import Path
import sys
from worker_handoff.recording import LocalStore, RecordError, RecordKey, RecordReceipt, RecorderPolicy

config = {'version': 1, 'destinations': {'archive': {'expire_after_seconds': 1}},
          'routes': [{'name': 'result', 'media_type': 'text/plain', 'required': ['archive']}]}
policy = RecorderPolicy.from_dict(config, stores={'archive': LocalStore(Path(sys.argv[1]))})
receipt = RecordReceipt.from_dict(json.loads(sys.argv[2]))
fresh_key = RecordKey(receipt.key.run_id, 'fresh')
recorded = policy.record(fresh_key, receipt.evidence_type, sys.argv[3].encode('ascii'))
print(recorded.destinations[0].state.value)
for run in (lambda: policy.readback('archive', receipt),
            lambda: policy.purge('archive', receipt, resolved=True),
            lambda: policy.verify_durable('archive', receipt)):
    try:
        run()
    except RecordError as error:
        print(error.status.value)
print(policy.sweep('archive', [receipt], settled=lambda _: True)[0].persistence.value)
"""
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            check = subprocess.run([sys.executable, "-B", "-c", script, str(self.directory),
                                    json.dumps(asdict(expected)), self.payload.decode("ascii")],
                                   check=True, capture_output=True, text=True, timeout=5)
        finally:
            os.close(fd)
        self.assertEqual(check.stdout.splitlines(), ["busy"] * 5)
        self.assertEqual({path.name for path in self.directory.iterdir()}, {expected.key.filename()})
        self.assertEqual(policy.readback("archive", expected), self.payload)
        self.assertEqual(policy.verify_durable("archive", expected), self.payload)
        retried = policy.record(fresh_key, self.evidence, self.payload).destinations[0]
        self.assertIs(retried.state, Persistence.COMMITTED)
        self.assertEqual(policy.verify_durable("archive", retried.receipt), self.payload)
