from importlib.resources import files
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
import unittest
from unittest.mock import Mock, patch
from base64 import b64encode

from workeros import DirectChildSupervisor, Worker, observe
from workeros.configuration import EvidenceInputs, Workflow, serve
from workeros.configuration_schema import configuration_schema
from workeros.evidence import (
    EvidenceObservation, EvidenceScope, EvidenceState, RunBinding, ScopePhase, ScopeReport,
)
from workeros.lifecycle import RegularFileObserver
from workeros.scope_meter import CgroupIdentity, CgroupSample, monotonic_clock_id


def document(operation, options):
    return dict(version=1, workflow="app", role="worker", operation=operation, options=options)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.deadline = monotonic_ns() + 15_000_000_000

    def run_request(self, workflow, request):
        data = request if type(request) is bytes else json.dumps(request).encode()
        output = StringIO()
        code = serve({"app": workflow}, BytesIO(data), output)
        return code, json.loads(output.getvalue())

    def test_schema_matches_installed_contract_and_invalid_requests_have_no_effect(self):
        self.assertEqual(json.loads(files("workeros").joinpath("configuration.schema.json").read_text()),
                         configuration_schema())
        guard = Mock(return_value=True)
        workflow = Workflow("worker", frozenset({"release", "launch"}), self.deadline, authorize=guard)
        for payload, expected in (
            (b'{"version":1,"version":1}', "duplicate_json_key"),
            (b'{"version":NaN}', "invalid_json"),
            (document("release", {"name": "sample", "argv": ["ignored"]}), "invalid_fields"),
            (document("launch", {"name": "sample", "require_terminal_from": "observer"}), "invalid_fields"),
            (document("launch", {"name": "sample", "timeout_ms": 0}), "invalid_integer"),
            (document("launch", {"name": "sample", "timeout_ms": 2**53}), "unsafe_json_integer"),
            (document("launch", {"name": "sample", "timeout_ms": str(2**63)}), "invalid_integer"),
            (document("release", {"name": "sample", "write": {"offset": str(2**63 - 1), "data": "QQ=="}}),
             "invalid_positional_write"),
            ({**document("launch", {"name": "sample"}), "recorder": {"arbitrary": 1}},
             "invalid_recorder_configuration"),
            ({**document("launch", {"name": "sample"}), "role": "alternate"}, "workflow_operation_not_enrolled"),
        ):
            with self.subTest(error=expected):
                self.assertEqual(self.run_request(workflow, payload), (1, {"status": "refused", "code": expected}))
        guard.assert_not_called()

    def test_actual_read_write_and_managed_release_use_prebound_owned_descriptors(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned"
            path.write_bytes(b"A")
            with path.open("rb") as reader, path.open("r+b", buffering=0) as writer:
                supervisor = DirectChildSupervisor()
                exact_plan = Mock(return_value=True)
                workflow = Workflow(
                    "worker", frozenset({"read", "write", "release"}), self.deadline,
                    identity=observe(reader.fileno()).identity, input_fd=reader.fileno(),
                    writer_fd=writer.fileno(), authorize=Mock(return_value=True), authorize_release=exact_plan,
                    sink=BytesIO(), supervisor=supervisor,
                    argv=(sys.executable, "-c", "import os; fd=int(os.environ['WORKER_HANDOFF_FD_INPUT']); "
                          "assert os.pread(fd,1,0) == b'C'; os.close(fd)"),
                )
                result = self.run_request(workflow, document("read", {"expected_size": "1"}))[1]["result"]
                self.assertEqual(result["bytes_read"], "1")
                self.assertEqual(workflow.sink.getvalue(), b"A")
                self.assertEqual(self.run_request(workflow, document("write", {"data": "Qg==", "sync": True}))
                                 [1]["result"]["effect"], "complete")
                workflow.require_custody = True
                request = document("release", {"name": "worker-1", "supervise": True,
                                               "write": {"offset": "0", "data": "Qw=="}})
                self.assertEqual(self.run_request(workflow, request)[1]["code"], "custody_required")
                request["options"]["custody"] = True
                self.assertEqual(self.run_request(workflow, request)[1]["code"], "custody_binding_missing")
                exact_plan.assert_not_called()
                self.assertEqual(path.read_bytes(), b"B")
                workflow.require_custody = False
                del request["options"]["custody"]
                code, result = self.run_request(workflow, request)
                self.assertEqual(code, 0)
                self.assertEqual(result["result"]["effect"], "complete")
                self.assertEqual(result["result"]["custody_status"], "not_requested")
                self.assertEqual(result["result"]["terminal"]["returncode"], "0")
                self.assertEqual(exact_plan.call_args.args[0].write.data, b"C")
                self.assertEqual(exact_plan.call_args.args[0].identity, workflow.identity)
                self.assertEqual(self.run_request(workflow, request)[1]["code"], "attempt_already_used")
                self.assertEqual(exact_plan.call_count, 1)
                self.assertEqual(os.pread(reader.fileno(), 1, 0), b"C")

    def test_uncertain_write_reports_once_and_wait_cleanup_is_authorized(self):
        class LostSync:
            def __init__(self, fd, identity):
                self.fd = fd

            def __enter__(self):
                return self

            def __exit__(self, *args):
                os.close(self.fd)

            def write(self, payload):
                return os.write(self.fd, payload)

            def flush(self, **args):
                raise OSError("protected fixture error")

        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned"
            with path.open("w+b", buffering=0) as writer:
                guard = Mock(return_value=True)
                workflow = Workflow("worker", frozenset({"write", "wait"}), self.deadline,
                                    writer_fd=writer.fileno(), identity=observe(writer.fileno()).identity,
                                    authorize=guard)
                with patch("workeros.configuration.Writer", LostSync):
                    status, reply = self.run_request(workflow, document("write", {"data": "QQ==", "sync": True}))
                self.assertEqual(status, 0)
                self.assertEqual(reply["result"], {"bytes_written": "1", "effect": "complete",
                                                   "sync": "unknown", "error": True})

                class PartialWrite(LostSync):
                    def write(self, payload):
                        super().write(payload[:1])
                        raise OSError("fixture write interrupted")

                with patch("workeros.configuration.Writer", PartialWrite):
                    status, reply = self.run_request(workflow, document("write", {"data": "QkM="}))
                self.assertEqual((status, reply["status"], reply["effect"]), (1, "unavailable", "unknown"))
                self.assertEqual(path.read_bytes(), b"AB")
                self.assertEqual(guard.call_count, 2)
                guard.return_value = False
                self.assertEqual(self.run_request(workflow, document("wait", {"name": "child", "cleanup_ms": "10"}))
                                 [1]["code"], "operation_not_authorized")

    def test_observe_held_self_slot_without_claiming_independent_custody(self):
        clock = monotonic_clock_id()
        at = monotonic_ns()
        scope_id = "a" * 64
        scope = EvidenceScope(RunBinding("run", "artifact", clock, at, self.deadline),
                              scope_id, at, self.deadline) if clock else None
        pin = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, pin)
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "held"
            path.write_bytes(b"x")
            with path.open("rb") as held, RegularFileObserver(
                scope=scope_id, due_ns=self.deadline, original_fd=held.fileno(),
                identity=observe(held.fileno()).identity, pidfd=pin,
                worker=Worker("self", "controller", os.getpid(), os.getuid()), slot=held.fileno(),
                evidence_scope=scope,
            ) as provider:
                workflow = Workflow("worker", frozenset({"observe"}), self.deadline,
                                    observers={"owned": (provider, scope, "observer")})
                raw = self.run_request(workflow, document("observe", {"scope": "owned"}))
                self.assertEqual(raw[0], 0, raw[1])
                self.assertEqual(raw[1]["result"]["sample"]["slot_match"], "original")
                code, reply = self.run_request(workflow, document("observe", {"scope": "owned", "subject": "slot"}))
        if clock is None:
            self.assertEqual((code, reply), (1, {"status": "refused", "code": "observation_scope_missing"}))
        else:
            self.assertEqual(code, 0, reply)
            self.assertEqual(reply["result"]["scope_report"]["observation"]["state"], "observed")

    def test_timeout_and_cancel_report_direct_child_cleanup_separately(self):
        supervisor = DirectChildSupervisor()
        workflow = Workflow(
            "worker", frozenset({"launch", "wait", "cancel", "cleanup"}), self.deadline,
            argv=(sys.executable, "-c", "import time; time.sleep(10)"), supervisor=supervisor,
            require_supervision=True, authorize=lambda _: True, cleanup_deadline_ns=self.deadline,
        )
        self.assertEqual(self.run_request(workflow, document("launch", {"name": "child"}))[1]["code"],
                         "supervision_required")
        code, reply = self.run_request(workflow, document("launch", {"name": "child", "supervise": True}))
        self.assertEqual(code, 0, reply)
        pid = int(reply["result"]["worker"]["pid"])
        self.addCleanup(supervisor.cleanup, "child", due_ns=self.deadline)
        waited = self.run_request(workflow, document("wait", {"name": "child", "timeout_ms": "1"}))[1]["result"]
        self.assertEqual(waited["lifecycle"], "timed_out")
        self.assertEqual(waited["cleanup"]["status"], "not_requested")
        cancelled = self.run_request(workflow, document("cancel", {"name": "child", "cleanup_ms": "2000"}))
        self.assertEqual(cancelled[1]["result"]["lifecycle"], "cancelled")
        self.assertEqual(cancelled[1]["result"]["cleanup"]["status"], "reaped")
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_reported_point_scope_quality_and_meter_cpu_remain_separate(self):
        past_safe_js = 2**53 + 313
        run = RunBinding("run", "artifact", "clock", past_safe_js + 5, past_safe_js + 7)
        scope = EvidenceScope(run, "scope", past_safe_js, past_safe_js + 20)
        optional = ScopeReport(scope, "observer", ScopePhase.OBSERVATION, past_safe_js + 1, past_safe_js + 2,
                               EvidenceObservation("optional-slot", EvidenceState.UNAVAILABLE))

        def meter(phase, at, usage):
            return CgroupSample(
                scope, "meter", phase, CgroupIdentity(1, 2**53 + 312, 3), "session", 4, 5, run.clock_id,
                at, at + 1, usage, EvidenceState.OBSERVED, True, EvidenceState.OBSERVED, (),
            )

        begin = meter(ScopePhase.METER_BEGIN, past_safe_js + 3, 2**53 + 1)
        end = meter(ScopePhase.METER_END, past_safe_js + 9, 2**53 + 17)
        provider = Mock()
        provider.sample.return_value = end
        workflow = Workflow(
            "worker", frozenset({"validate", "meter"}), self.deadline, meters={"scope": provider},
            evidence={"scope": EvidenceInputs(run, scope=scope, reports=(optional, begin.report, end.report),
                                              observer_id="observer", meter_id="meter", meter_samples=(begin, end))},
        )
        request = document("validate", {"scope": "scope", "require_meter_for":
                                        [str(run.started_ns), str(run.finished_ns)]})
        reply = self.run_request(workflow, request)[1]["result"]
        self.assertEqual(reply["validation"], "complete")
        self.assertIn("unavailable", reply["observation_states"])
        self.assertEqual(reply["cpu_delta"], {"status": "observed", "cpu_delta_usec": "16"})
        request["options"]["require_terminal_from"] = "owner"
        self.assertEqual(self.run_request(workflow, request)[1]["result"]["validation"], "incomplete")
        reply = self.run_request(workflow, document("meter", {"scope": "scope", "phase": "meter_end"}))[1]["result"]
        self.assertEqual(reply["sample"]["identity"]["inode"], str(2**53 + 312))
        self.assertEqual(reply["sample"]["memory_current_state"], "unavailable")

    def test_dedicated_process_sanitizes_enrolled_child_stdio(self):
        script = """
import sys
from time import monotonic_ns
from workeros import DirectChildSupervisor
from workeros.configuration import Workflow, serve_stdio

child = "import os; assert os.read(0, 200) == b''; print('worker stdout'); os.write(2, b'worker stderr')"
owner = DirectChildSupervisor()
due = monotonic_ns() + 5_000_000_000
workflow = Workflow(
    role='worker', operations=frozenset({'launch'}), deadline_ns=due,
    argv=(sys.executable, '-c', child), authorize=lambda _: True, supervisor=owner)
code = serve_stdio({'app': workflow})
assert owner.wait('fixture', due_ns=due).returncode == 0
raise SystemExit(code)
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", script],
            input=json.dumps(document("launch", {"name": "fixture", "supervise": True})),
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(json.loads(result.stdout)["result"]["delivery"], "dispatched")

    def test_installed_contract_receipt_can_be_read_by_another_process(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "archive").mkdir(mode=0o700)
            policy = {
                "version": 1, "destinations": {"archive": {"max_age_seconds": 5}, "review": {}},
                "routes": [{"name": "audit", "media_type": "application/octet-stream",
                            "required": ["archive"], "optional": ["review"]}],
            }
            command = [sys.executable, "-B", "-m", "workeros.configuration_cli", "--example-root", temporary]

            def invoke(request):
                result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return json.loads(result.stdout)["result"]

            request = dict(version=1, workflow="example", role="recorder", operation="record", recorder=policy,
                           options={"run_id": "fixture", "record_id": "result", "type": "audit",
                                    "data": b64encode(b"internal receipt fixture").decode("ascii")})
            recorded = invoke(request)
            committed, optional = recorded["destinations"]
            self.assertTrue(recorded["required_complete"])
            self.assertEqual(optional["state"], "refused")
            receipt = committed["receipt"]
            self.assertGreater(int(receipt["committed_ns"]), 2**53)
            read = invoke({**request, "operation": "readback", "options":
                           {"destination": "archive", "receipt": receipt}})
            self.assertEqual(read["persistence"], "verified")
            self.assertEqual(read["sha256"], receipt["sha256"])
            self.assertEqual(read["key"], receipt["key"])
