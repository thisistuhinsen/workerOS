from dataclasses import replace
import errno
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
import unittest
from unittest.mock import patch
from uuid import uuid4

from worker_handoff import (
    CleanupStatus, DirectChildSupervisor, LifecycleStatus, Original, SupervisionStartError,
    Worker, observe, receive_original, send_original,
)
from worker_handoff.evidence import (
    EvidenceObservation, EvidenceState, RunBinding, RunEvent, validate_run_evidence,
)
import worker_handoff.original as original_module


def _bind_run(payload):
    started = monotonic_ns()
    return RunBinding(uuid4().hex, sha256(payload).hexdigest(),
                      "launcher-monotonic", started, started + 10_000_000_000)


class RunEvidenceConsumerTest(unittest.TestCase):
    def test_held_file_and_owned_child_report_bind_to_one_run(self):
        supervisor = DirectChildSupervisor()
        try:
            supervisor.check_available("reader", "read")
        except (OSError, RuntimeError) as exc:
            self.skipTest(f"Linux pidfd supervision unavailable ({exc})")

        payload = b"synthetic input"
        binding = _bind_run(payload)
        deadline = binding.finished_ns
        with TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(payload)
            with path.open("rb") as held:
                start = monotonic_ns()
                sampled = observe(held.fileno())
                end = monotonic_ns()
                self.assertLessEqual(start, sampled.observed_ns)
                self.assertLessEqual(sampled.observed_ns, end)
                self.assertEqual(sampled.size, len(payload))
                self.assertEqual(sampled.flags & os.O_ACCMODE, os.O_RDONLY)
                original = EvidenceObservation(
                    "held-original", EvidenceState.OBSERVED,
                    f"device={sampled.identity.device}, inode={sampled.identity.inode}",
                )
                first = RunEvent(binding, "launcher", 1, start, end, observations=(original,))

                now = monotonic_ns()
                second = RunEvent(binding, "optional-observer", 2, now, now, observations=(
                    EvidenceObservation("child-slot", EvidenceState.UNAVAILABLE),
                ))

                code = (
                    'import os\n'
                    'fd = int(os.environ["WORKER_HANDOFF_FD_INPUT"])\n'
                    'raise SystemExit(7 if os.pread(fd, 32, 0) == b"synthetic input" else 9)\n'
                )
                try:
                    worker = supervisor.start_executable(
                        "reader", "read", [sys.executable, "-I", "-c", code],
                        due_ns=deadline, fds={"INPUT": held.fileno()}, env={},
                    )
                except SupervisionStartError as exc:
                    # Pinning failed, so the unused supervisor never took ownership.
                    exc.process.kill()
                    exc.process.wait(timeout=5)
                    raise
                self.addCleanup(lambda: supervisor.cleanup(
                    worker.name, due_ns=monotonic_ns() + 5_000_000_000,
                ))

                start = monotonic_ns()
                waited = supervisor.wait(worker.name, due_ns=deadline)
                third = RunEvent.from_result(binding, "supervisor", 3, start, monotonic_ns(), waited)
                self.assertEqual((third.lifecycle, third.returncode), (LifecycleStatus.EXITED, 7))
                self.assertEqual(third.cleanup, CleanupStatus.NOT_REQUESTED)

                start = monotonic_ns()
                cleanup = supervisor.cleanup(worker.name, due_ns=deadline)
                fourth = RunEvent.from_result(binding, "supervisor", 4, start, monotonic_ns(), cleanup)
                self.assertEqual((fourth.returncode, fourth.cleanup), (7, CleanupStatus.REAPED))
                self.assertFalse(cleanup.terminate_sent or cleanup.kill_sent)

        coverage = (("launcher", "held-original"),)
        events = (first, second, third, fourth)
        self.assertEqual(validate_run_evidence(
            binding, events, require_observed=coverage, require_terminal_from="supervisor",
        ), events)
        for incomplete in (
            events[:-1],
            events[:-1] + (replace(fourth, source_id="optional-observer"),),
        ):
            with self.subTest(incomplete=incomplete), self.assertRaises(ValueError):
                validate_run_evidence(binding, incomplete, require_terminal_from="supervisor")

    def assert_fd_closed(self, fd):
        with self.assertRaises(OSError) as raised:
            os.fstat(fd)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_peer_exposure_survives_sender_deadline_without_send_completion(self):
        payload, token = b"synthetic input", b"fixture"
        binding = _bind_run(payload)
        peer = Worker("loopback", "reader", os.getpid(), os.geteuid())
        checkpoint_due = 1_000_000_000
        with TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(payload)
            with path.open("rb") as held:
                identity = observe(held.fileno()).identity
                tx, rx = socket.socketpair()
                with tx, rx:
                    started = monotonic_ns()
                    with patch.object(original_module, "monotonic_ns", return_value=0) as checkpoint:
                        class LateSocket(socket.socket):
                            def sendmsg(self, *args):
                                sent = super().sendmsg(*args)
                                checkpoint.return_value = checkpoint_due
                                return sent

                        with LateSocket(fileno=tx.detach()) as sender:
                            sender_fd = sender.fileno()
                            with self.assertRaises(TimeoutError):
                                send_original(sender, held.fileno(), peer=peer, identity=identity,
                                              token=token, due_ns=checkpoint_due)
                            self.assert_fd_closed(sender_fd)
                            self.assertEqual(os.pread(held.fileno(), len(payload), 0), payload)
                    send_report = RunEvent(binding, "sender", 1, started, monotonic_ns(), observations=(
                        EvidenceObservation("send-completion", EvidenceState.UNAVAILABLE),
                        EvidenceObservation("socket-closed", EvidenceState.OBSERVED),
                    ))

                    started = monotonic_ns()
                    with receive_original(rx, peer=peer, identity=identity, token=token,
                                          due_ns=binding.finished_ns) as received:
                        received_fd = received.fileno()
                        self.assertEqual(os.pread(received_fd, len(payload), 0), payload)
                    self.assert_fd_closed(received_fd)
                    receive_report = RunEvent(binding, "peer", 2, started, monotonic_ns(), observations=(
                        EvidenceObservation("descriptor-exposure", EvidenceState.OBSERVED),
                        EvidenceObservation("descriptor-closed", EvidenceState.OBSERVED),
                    ))

        reports = (send_report, receive_report)
        self.assertIs(validate_run_evidence(binding, reports, require_observed=(
            ("peer", "descriptor-exposure"), ("peer", "descriptor-closed"),
        )), reports)
        with self.assertRaises(ValueError):
            validate_run_evidence(binding, reports, require_observed=(("sender", "send-completion"),))

    def test_sink_effect_and_close_survive_deadline_without_read_result(self):
        payload = b"synthetic input"
        checkpoint_due = 1_000_000_000
        with TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(payload)
            for stage, expected in (("write", payload[:3]), ("close", payload)):
                with self.subTest(stage=stage), path.open("rb") as held:
                    binding = _bind_run(payload)
                    started = monotonic_ns()
                    with patch.object(original_module, "monotonic_ns", return_value=0) as checkpoint:
                        class LateSink(BytesIO):
                            def write(self, data):
                                count = super().write(data)
                                checkpoint.return_value = checkpoint_due
                                return count

                        class LateClose(Original):
                            def close(self):
                                super().close()
                                checkpoint.return_value = checkpoint_due

                        sink = LateSink() if stage == "write" else BytesIO()
                        owner = LateClose if stage == "close" else Original
                        fd = os.dup(held.fileno())
                        with owner(fd, observe(held.fileno()).identity) as original:
                            with self.assertRaises(TimeoutError):
                                original.read_and_close(sink, due_ns=checkpoint_due, block_size=3)
                            self.assertEqual(sink.getvalue(), expected)
                            self.assert_fd_closed(fd)
                    report = RunEvent(binding, "reader", 1, started, monotonic_ns(), observations=(
                        EvidenceObservation("read-result", EvidenceState.UNAVAILABLE),
                        EvidenceObservation("sink-effect", EvidenceState.OBSERVED,
                                            f"{len(expected)} bytes retained"),
                        EvidenceObservation("descriptor-closed", EvidenceState.OBSERVED),
                    ))
                    reports = (report,)
                    self.assertIs(validate_run_evidence(binding, reports, require_observed=(
                        ("reader", "sink-effect"), ("reader", "descriptor-closed"),
                    )), reports)
                    with self.assertRaises(ValueError):
                        validate_run_evidence(binding, reports, require_observed=(("reader", "read-result"),))
