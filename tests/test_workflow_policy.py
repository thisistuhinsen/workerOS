"""End-to-end checks for persistent policy, local enrollment and one-shot invocation."""

from base64 import b64encode
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from workeros.configuration import ConfigurationError, EvidenceInputs, serve
from workeros.enrollment import HostBindings, compile_policy
from workeros.evidence import RunBinding
from workeros.recording import LocalStore, RecordKey, StoragePolicy


class WorkflowPolicyTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.policy_path = self.directory / "policy.json"
        self.marker = self.directory / "started"
        self.executable = self.directory / "worker"
        self.executable.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\n"
            "import sys\n"
            "assert sys.stdin.read() == ''\n"
            "print('separate worker stdout')\n"
            "print('separate worker stderr', file=sys.stderr)\n"
            "Path(__file__).with_name('started').write_text('started')\n"
            "raise SystemExit(7)\n"
        )
        self.executable.chmod(0o700)
        console = Path(sys.executable).with_name("workeros")
        self.command = ([str(console), "config"] if console.is_file()
                        else [sys.executable, "-B", "-m", "workeros.configuration_cli"])
        self.tool = ["--executable", "tool", str(self.executable)]

    def launch_policy(self):
        return {
            "version": 1,
            "roles": {"runner": {"operations": ["launch", "wait"]}},
            "workflows": {
                "run": {
                    "role": "runner",
                    "operations": ["launch"],
                    "timeout_ms": 5000,
                    "cleanup_ms": 1000,
                    "require_supervision": True,
                    "bindings": {"executable": "tool", "supervisor": "direct-child"},
                }
            },
        }

    def recorder_config(self, evidence_type, media_type):
        return {
            "version": 1,
            "destinations": {"archive": {"max_age_seconds": 60}},
            "routes": [{"name": evidence_type, "media_type": media_type, "required": ["archive"]}],
        }

    def capture_policy(self, *, optional=False):
        policy = self.launch_policy()
        operations = ["readback", "recover_receipt"]
        policy["roles"]["runner"]["operations"].extend(operations)
        workflow = policy["workflows"]["run"]
        workflow["operations"].extend(operations)
        workflow["recorder"] = "job-evidence"
        workflow["capture"] = {"launch": {"profile": "launch-terminal", "type": "job-result"}}
        recorder = self.recorder_config("job-result", "application/json")
        if optional:
            recorder["destinations"]["review"] = {}
            recorder["routes"][0]["optional"] = ["review"]
        policy["recorders"] = {"job-evidence": recorder}
        return policy

    def recorder_policy(self):
        return {
            "version": 1,
            "roles": {"auditor": {"operations": ["record", "readback", "verify_durable"]}},
            "workflows": {
                "fileless-audit": {
                    "role": "auditor",
                    "operations": ["record", "readback", "verify_durable"],
                    "timeout_ms": 5000,
                    "bindings": {},
                    "recorder": "audit-policy",
                }
            },
            "recorders": {"audit-policy": self.recorder_config("audit", "application/octet-stream")},
        }

    def request(self, operation, options, *, workflow="run", role="runner"):
        return {"version": 1, "workflow": workflow, "role": role, "operation": operation, "options": options}

    def save(self, policy):
        raw = json.dumps(policy).encode("utf-8")
        self.policy_path.write_bytes(raw)
        return sha256(raw).hexdigest()

    def invoke(self, command, *bindings, request=None, pass_fds=(), environment=None, events=None):
        result = subprocess.run(
            [*self.command, *command, *bindings],
            input="" if request is None else json.dumps(request),
            text=True,
            capture_output=True,
            pass_fds=pass_fds,
            env=environment,
            timeout=12,
        )
        self.assertEqual(len(result.stdout.splitlines()), 1, result.stdout + result.stderr)
        if events is None:
            self.assertEqual(result.stderr, "")
        else:
            events.extend(json.loads(line) for line in result.stderr.splitlines())
        return result.returncode, json.loads(result.stdout)

    def run_policy(self, digest, request, *bindings, pass_fds=(), environment=None, events=None):
        command = ["--run-policy", str(self.policy_path)]
        if digest is not None:
            command += ["--policy-sha256", digest]
        return self.invoke(
            command,
            *bindings,
            request=request,
            pass_fds=pass_fds,
            environment=environment,
            events=events,
        )

    def privileged_process(self):
        return os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid()

    def assert_refused(self, result):
        code, response = result
        self.assertEqual(code, 1, response)
        self.assertEqual(response["status"], "refused")
        self.assertNotIn("result", response)
        return response["code"]

    def test_installed_policy_runs_the_enrolled_worker_and_reports_its_exit(self):
        archive = self.directory / "archive"
        policy = self.capture_policy()
        other = deepcopy(policy["workflows"]["run"])
        other["operations"] = ["recover_receipt"]
        del other["capture"]
        policy["workflows"]["other"] = other
        digest = self.save(policy)
        flags = (*self.tool, "--store", "archive", str(archive))
        code, reply = self.invoke(["--check-policy", str(self.policy_path)], *flags)
        self.assertEqual(code, 0, reply)
        self.assertEqual(reply["status"], "checked")
        self.assertEqual(reply["policy_sha256"], digest)
        self.assertFalse(self.marker.exists())
        self.assertFalse(archive.exists())

        launch = self.request("launch", {"name": "child", "supervise": True})
        receipts = []
        for _ in range(2):
            events = []
            result = self.run_policy(digest, launch, *flags, events=events)
            if self.privileged_process():
                self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
                self.assertEqual(events, [])
                self.assertFalse(self.marker.exists())
                self.assertFalse(archive.exists())
                return

            code, reply = result
            self.assertEqual(code, 3, reply)
            self.assertEqual(reply["status"], "reported")
            self.assertTrue(self.marker.is_file())
            self.assertEqual(archive.stat().st_mode & 0o777, 0o700)
            report = reply["result"]
            self.assertEqual(report["delivery"], "dispatched")
            self.assertEqual(report["terminal"]["lifecycle"], "exited")
            self.assertEqual(str(report["terminal"]["returncode"]), "7")
            self.assertEqual(report["terminal"]["cleanup"]["status"], "reaped")
            attempt = report["attempt_id"]
            self.assertRegex(attempt, r"^attempt-.+$")
            self.assertEqual(events, [{
                "event": "launch_attempt", "attempt_id": attempt, "worker_name": "child",
                "workflow": "run", "policy_sha256": digest,
            }])

            capture = report["capture"]
            self.assertEqual(capture["status"], "reported")
            self.assertTrue(capture["required_complete"])
            receipt = capture["record"]["destinations"][0]["receipt"]
            receipts.append(receipt)
            self.assertEqual(receipt["key"], {"run_id": attempt, "record_id": "launch-terminal"})
            self.assertEqual(receipt["source"], "direct-child-supervisor")
            self.assertEqual(receipt["scope"], attempt)
            saved = LocalStore(archive).read(RecordKey(attempt, "launch-terminal"),
                                            policy=StoragePolicy(max_age_seconds=60))
            self.assertNotIn(b"separate worker", saved.payload)
            self.assertEqual(json.loads(saved.payload), {
                "lifecycle": "exited", "returncode": 7, "cleanup": "reaped",
                "attempt_id": attempt, "worker_name": "child", "workflow": "run", "policy_sha256": digest,
            })

        self.assertNotEqual(receipts[0]["key"]["run_id"], receipts[1]["key"]["run_id"])
        for receipt in receipts:
            request = self.request("readback", {"destination": "archive", "receipt": receipt})
            code, reply = self.run_policy(digest, request, *flags)
            self.assertEqual(code, 0, reply)
            self.assertEqual(reply["result"]["persistence"], "verified")
            self.assertEqual(reply["result"]["sha256"], receipt["sha256"])

        receipt = receipts[0]
        options = {"destination": "archive", "attempt_id": receipt["key"]["run_id"]}
        recover = self.request("recover_receipt", options)
        code, reply = self.run_policy(digest, recover, *flags)
        self.assertEqual(code, 0, reply)
        self.assertEqual(reply["result"]["persistence"], "verified")
        self.assertEqual(reply["result"]["durability"], "unconfirmed")
        self.assertEqual(reply["result"]["receipt"], receipt)

        code, reply = self.run_policy(digest, self.request("recover_receipt", options, workflow="other"), *flags)
        self.assertEqual(code, 3, reply)
        self.assertEqual(reply["result"]["persistence"], "conflict")

        with self.policy_path.open("ab") as stream:
            stream.write(b"\n")
        altered_digest = sha256(self.policy_path.read_bytes()).hexdigest()
        code, reply = self.run_policy(altered_digest, recover, *flags)
        self.assertEqual(code, 3, reply)
        self.assertEqual(reply["result"]["persistence"], "conflict")

    def test_capture_refuses_invalid_required_store_but_not_an_optional_store(self):
        archive = self.directory / "archive"
        archive.mkdir(mode=0o700)
        archive.chmod(0o755)
        digest = self.save(self.capture_policy())
        flags = (*self.tool, "--store", "archive", str(archive))
        launch = self.request("launch", {"name": "child", "supervise": True})
        result = self.run_policy(digest, launch, *flags)
        if self.privileged_process():
            self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
            self.assertFalse(self.marker.exists())
            return
        self.assertEqual(self.assert_refused(result), "required_capture_destination_unavailable")
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(archive.iterdir()), [])

        review = archive
        archive = self.directory / "required"
        digest = self.save(self.capture_policy(optional=True))
        flags = (*self.tool, "--store", "archive", str(archive), "--store", "review", str(review))
        events = []
        code, reply = self.run_policy(digest, launch, *flags, events=events)
        self.assertEqual(code, 3, reply)  # The enrolled child exits 7 even when capture succeeds.
        self.assertTrue(self.marker.is_file())
        self.assertEqual(len(events), 1)
        capture = reply["result"]["capture"]
        self.assertTrue(capture["required_complete"])
        self.assertEqual([(item["destination"], item["state"]) for item in capture["record"]["destinations"]],
                         [("archive", "committed"), ("review", "refused")])
        self.assertEqual(archive.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(review.iterdir()), [])

    def test_check_refuses_missing_unknown_and_unsupported_bindings_without_launching(self):
        for case in ("missing_tool", "missing_supervisor", "unknown_executable", "unsupported_observer", "inline_argv"):
            with self.subTest(case=case):
                policy = self.launch_policy()
                workflow = policy["workflows"]["run"]
                bindings = workflow["bindings"]
                if case == "missing_tool":
                    del bindings["executable"]
                elif case == "missing_supervisor":
                    del bindings["supervisor"]
                elif case == "unknown_executable":
                    bindings["executable"] = "other"
                elif case == "unsupported_observer":
                    policy["roles"]["runner"]["operations"].append("observe")
                    workflow["operations"].append("observe")
                    bindings["observers"] = {"point": "observer"}
                else:
                    bindings["executable"] = [str(self.executable)]
                self.save(policy)
                self.assert_refused(self.invoke(["--check-policy", str(self.policy_path)], *self.tool))
                self.assertFalse(self.marker.exists())

    def test_invocation_cannot_change_enrollment_policy_or_request_privileges(self):
        policy = self.launch_policy()
        digest = self.save(policy)
        launch = self.request("launch", {"name": "child", "supervise": True})
        self.assertEqual(self.assert_refused(self.run_policy("0" * 64, launch, *self.tool)),
                         "policy_digest_mismatch")
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.assert_refused(self.run_policy("malformed", launch, *self.tool)),
                         "invalid_policy_digest")
        self.assertFalse(self.marker.exists())
        if self.privileged_process():
            self.assertEqual(self.assert_refused(self.run_policy(digest, launch, *self.tool)),
                             "privileged_policy_cli_unsupported")
            self.assertFalse(self.marker.exists())
            return
        refused = (
            (digest, self.request("launch", {**launch["options"], "argv": [str(self.executable)]})),
            (digest, self.request("launch", launch["options"], role="other")),
            (digest, self.request("launch", {"name": "child", "supervise": False})),
            (digest, self.request("wait", {"name": "child"})),
        )
        for approved, request in refused:
            with self.subTest(request=request, approved=approved):
                self.assert_refused(self.run_policy(approved, request, *self.tool))
                self.assertFalse(self.marker.exists())

        # The requested pin still refers to the exact bytes, not the parsed document.
        with self.policy_path.open("ab") as stream:
            stream.write(b"\n")
        self.assertEqual(self.assert_refused(self.run_policy(digest, launch, *self.tool)),
                         "policy_digest_mismatch")
        self.assertFalse(self.marker.exists())

    def test_host_authorizer_remains_required_after_compiling_policy(self):
        guard = Mock(return_value=False)
        host = HostBindings(executables={"tool": (str(self.executable),)},
                            supervisors=frozenset({"direct-child"}), authorize=guard)
        workflow = compile_policy(self.launch_policy(), host)
        self.assertEqual(workflow["run"].operations, frozenset({"launch"}))
        self.assertTrue(workflow["run"].require_supervision)
        guard.assert_not_called()
        output = StringIO()
        launch = self.request("launch", {"name": "child", "supervise": True})
        code = serve(workflow, BytesIO(json.dumps(launch).encode()), output)
        self.assertEqual(self.assert_refused((code, json.loads(output.getvalue()))), "operation_not_authorized")
        guard.assert_called_once()
        self.assertFalse(self.marker.exists())

        unauthorized = self.launch_policy()
        unauthorized["workflows"]["run"]["operations"].append("record")
        with self.assertRaises((ConfigurationError, ValueError)):
            compile_policy(unauthorized, host)

    def test_configured_recorder_persists_with_independent_process_readback(self):
        archive = self.directory / "archive"
        policy = self.recorder_policy()
        digest = self.save(policy)
        flags = ("--store", "archive", str(archive))
        code, reply = self.invoke(["--check-policy", str(self.policy_path)], *flags)
        self.assertEqual(code, 0, reply)
        self.assertFalse(archive.exists())

        def audit(operation, options):
            return self.request(operation, options, workflow="fileless-audit", role="auditor")

        payload = b"synthetic evidence"
        record = audit("record", {"run_id": "test-run", "record_id": "end", "type": "audit",
                                  "data": b64encode(payload).decode("ascii")})
        result = self.run_policy(digest, record, *flags)
        if self.privileged_process():
            self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
            self.assertFalse(archive.exists())
            return
        code, reply = result
        self.assertEqual(code, 0, reply)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o700)
        self.assertTrue(reply["result"]["required_complete"])
        destination, = reply["result"]["destinations"]
        self.assertEqual(destination["state"], "committed")
        receipt = destination["receipt"]
        self.assertEqual(receipt["sha256"], sha256(payload).hexdigest())
        readback = audit("readback", {"destination": "archive", "receipt": receipt})
        code, reply = self.run_policy(digest, readback, *flags)
        self.assertEqual(code, 0, reply)
        self.assertEqual(reply["result"]["persistence"], "verified")
        self.assertEqual(reply["result"]["sha256"], receipt["sha256"])
        self.assertEqual(reply["result"]["durability"], "unconfirmed")
        verify = audit("verify_durable", readback["options"])
        code, reply = self.run_policy(digest, verify, *flags)
        self.assertEqual(code, 0, reply)
        self.assertEqual(reply["result"]["durability"], "confirmed")
        self.assertEqual(reply["result"]["sha256"], receipt["sha256"])

        # An invocation can never substitute recorder configuration for the policy.
        changed = deepcopy(policy["recorders"]["audit-policy"])
        changed["destinations"]["archive"]["max_age_seconds"] = 1
        record["recorder"] = changed
        self.assert_refused(self.run_policy(digest, record, *flags))

    def test_native_policy_authorizes_readback_before_contacting_store(self):
        archive = self.directory / "archive"
        archive.mkdir(mode=0o700)
        adapter = Mock(wraps=LocalStore(archive))
        guard = Mock(return_value=False)
        compiled = compile_policy(self.recorder_policy(), HostBindings(stores={"archive": adapter}, authorize=guard))
        receipt = {
            "key": {"run_id": "demo", "record_id": "end"},
            "evidence_type": {"name": "audit", "media_type": "application/octet-stream"},
            "sha256": sha256(b"").hexdigest(),
            "size": "0",
            "committed_ns": "1",
        }
        request = self.request("readback", {"destination": "archive", "receipt": receipt},
                               workflow="fileless-audit", role="auditor")
        output = StringIO()
        code = serve(compiled, BytesIO(json.dumps(request).encode()), output)
        self.assertEqual(self.assert_refused((code, json.loads(output.getvalue()))), "operation_not_authorized")
        guard.assert_called_once()
        adapter.read.assert_not_called()

    def test_protected_original_workflow_cannot_enroll_standalone_access(self):
        host = HostBindings(authorize=lambda request: True)
        for operation in ("read", "write", "launch"):
            with self.subTest(operation=operation):
                policy = self.launch_policy()
                policy["roles"]["runner"]["operations"] = ["release", operation]
                workflow = policy["workflows"]["run"]
                workflow["operations"] = ["release", operation]
                workflow["require_custody"] = True
                with self.assertRaisesRegex(ConfigurationError, "protected_original_requires_release"):
                    compile_policy(policy, host)

    def test_compiled_scope_selects_only_named_host_provider(self):
        @dataclass(frozen=True)
        class Observation:
            at_ns: int

        observer = Mock()
        observer.sample.return_value = Observation(2**53 + 3)
        unused = Mock()
        binding = RunBinding("run", "artifact", "trusted-clock", 102, 109)
        host = HostBindings(
            authorize=lambda request: True,
            observers={"enrolled": (observer, None, "trusted"), "unused": (unused, None, "unused")},
            evidence={"event-source": EvidenceInputs(binding)},
        )
        policy = {
            "version": 1,
            "roles": {"auditor": {"operations": ["observe", "validate"]}},
            "workflows": {"events": {"role": "auditor", "operations": ["observe", "validate"],
                                     "timeout_ms": 1000, "bindings": {
                                         "observers": {"owned": "enrolled"},
                                         "evidence": {"owned": "event-source"},
                                     }}},
        }
        compiled = compile_policy(policy, host)

        def invoke(operation, scope):
            request = self.request(operation, {"scope": scope}, workflow="events", role="auditor")
            output = StringIO()
            code = compiled.serve(BytesIO(json.dumps(request).encode()), output)
            return code, json.loads(output.getvalue())

        self.assertEqual(invoke("observe", "owned"),
                         (0, {"status": "reported", "result": {"sample": {"at_ns": str(2**53 + 3)}}}))
        self.assert_refused(invoke("observe", "unused"))
        observer.sample.assert_called_once_with()
        unused.sample.assert_not_called()
        code, result = invoke("validate", "owned")
        self.assertEqual(code, 0, result)
        self.assertEqual(result["result"]["validation"], "complete")

    def test_installed_launch_passes_multiple_explicit_inherited_descriptors(self):
        self.executable.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "source = int(os.environ['WORKER_HANDOFF_FD_INPUT'])\n"
            "target = int(os.environ['WORKER_HANDOFF_FD_OUTPUT'])\n"
            "assert os.environ['WORKER_HANDOFF_ACCESS_INPUT'] == 'read'\n"
            "assert os.environ['WORKER_HANDOFF_ACCESS_OUTPUT'] == 'read-write'\n"
            "os.pwrite(target, os.pread(source, 32, 0), 0)\n"
        )
        source = self.directory / "source"
        target = self.directory / "target"
        source.write_bytes(b"preheld input")
        target.touch()
        policy = self.launch_policy()
        policy["workflows"]["run"]["bindings"]["inherited"] = {"INPUT": "source", "OUTPUT": "target"}
        digest = self.save(policy)
        request = self.request("launch", {"name": "fd-child", "supervise": True})
        with source.open("rb") as input_file, target.open("r+b") as output_file:
            input_fd, output_fd = input_file.fileno(), output_file.fileno()
            result = self.run_policy(
                digest, request, *self.tool, "--inherit-fd", "source", str(input_fd),
                "--inherit-fd", "target", str(output_fd), pass_fds=(input_fd, output_fd),
            )
            if self.privileged_process():
                self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
                self.assertEqual(output_file.read(), b"")
                return
            code, reply = result
            self.assertEqual(code, 0, reply)
            self.assertEqual(reply["result"]["terminal"]["returncode"], "0")
            self.assertEqual(reply["result"]["terminal"]["cleanup"]["status"], "reaped")
            self.assertEqual(input_file.tell(), 0)
            self.assertEqual(output_file.read(), b"preheld input")

    def test_installed_bare_launch_uses_enrolled_args_cwd_environment_and_stream(self):
        self.executable.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "assert sys.argv[1:] == ['approved arg', 'end']\n"
            "assert os.path.basename(os.getcwd()) == 'working'\n"
            "assert os.environ['RUN_FLAG'] == 'enabled'\n"
            "assert os.environ['RUN_SECRET'] == 'synthetic from host'\n"
            "assert 'UNENROLLED_ENV' not in os.environ\n"
            "assert sys.stdin.read() == ''\n"
            "print('ordinary tool output')\n"
        )
        working = self.directory / "working"
        working.mkdir()
        policy = self.launch_policy()
        workflow = policy["workflows"]["run"]
        for key in ("timeout_ms", "cleanup_ms", "require_supervision"):
            del workflow[key]
        del workflow["bindings"]["supervisor"]
        workflow["bindings"]["streams"] = {"stdout": "output"}
        workflow.update(args=["approved arg", "end"], cwd="working",
                        env={"RUN_FLAG": "flag", "RUN_SECRET": "secret"})
        digest = self.save(policy)
        request = self.request("launch", {"name": "child"})
        environment = {**os.environ, "WORKEROS_TEST_HOST_SECRET": "synthetic from host",
                       "UNENROLLED_ENV": "should not reach child"}
        with (self.directory / "tool.stdout").open("w+b") as output:
            fd = output.fileno()
            result = self.run_policy(None, request, *self.tool, "--cwd", "working", str(working),
                                     "--env", "flag", "enabled",
                                     "--secret-env", "secret", "WORKEROS_TEST_HOST_SECRET",
                                     "--stream-fd", "output", str(fd), pass_fds=(fd,),
                                     environment=environment)
            output.seek(0)
            if self.privileged_process():
                self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
                self.assertEqual(output.read(), b"")
                return
            code, reply = result
            self.assertEqual(code, 0, reply)
            self.assertEqual(reply["policy_sha256"], digest)
            self.assertEqual(reply["result"]["supervision"], "not_requested")
            self.assertEqual(reply["result"]["terminal"]["returncode"], "0")
            self.assertEqual(reply["result"]["terminal"]["cleanup"]["status"], "reaped")
            self.assertEqual(output.read(), b"ordinary tool output\n")
            self.assertNotIn("synthetic from host", repr(reply))

    def test_incomplete_required_persistence_is_reported_with_exit_three(self):
        archive = self.directory / "archive"
        archive.mkdir(mode=0o755)
        archive.chmod(0o755)
        digest = self.save(self.recorder_policy())
        flags = ("--store", "archive", str(archive))
        request = self.request(
            "record", {"run_id": "incomplete", "record_id": "end", "type": "audit"},
            workflow="fileless-audit", role="auditor",
        )
        for data, expected in ((None, "missing"), ("dGVzdA==", "refused")):
            with self.subTest(expected=expected):
                if data is not None:
                    request["options"]["data"] = data
                result = self.run_policy(digest, request, *flags)
                if self.privileged_process():
                    self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
                else:
                    code, reply = result
                    self.assertEqual(code, 3, reply)
                    self.assertEqual(reply["status"], "reported")
                    self.assertFalse(reply["result"]["required_complete"])
                    self.assertEqual(reply["result"]["destinations"][0]["state"], expected)
                self.assertEqual(list(archive.iterdir()), [])

    def test_selected_workflows_sweep_exact_receipts_only_after_host_settlement_and_age(self):
        archive = self.directory / "archive"
        policy = self.recorder_policy()
        policy["recorders"]["audit-policy"]["destinations"]["archive"]["expire_after_seconds"] = 3600
        policy["roles"]["maintainer"] = {"operations": ["sweep"]}
        policy["workflows"]["maintenance"] = {
            "role": "maintainer", "operations": ["sweep"], "bindings": {}, "recorder": "audit-policy",
        }
        digest = self.save(policy)
        store = ("--store", "archive", str(archive))
        check = ["--check-policy", str(self.policy_path)]
        write_flags = (*store, "--workflow", "fileless-audit")
        code, checked = self.invoke(check, *write_flags)
        self.assertEqual(code, 0, checked)
        self.assertEqual(checked["workflows"], ["fileless-audit"])
        self.assertEqual(self.assert_refused(self.invoke(check, *store, "--workflow", "maintenance")),
                         "settlement_binding_required")
        self.assertFalse(archive.exists())
        self.assert_refused(self.invoke(check, *store, "--workflow", "unknown"))

        receipts = []
        for run_id in ("settled", "outstanding"):
            record = self.request(
                "record", {"run_id": run_id, "record_id": "end", "type": "audit", "data": "dGVzdA=="},
                workflow="fileless-audit", role="auditor",
            )
            result = self.run_policy(digest, record, *write_flags)
            if self.privileged_process():
                self.assertEqual(self.assert_refused(result), "privileged_policy_cli_unsupported")
                self.assertFalse(archive.exists())
                return
            code, reply = result
            self.assertEqual(code, 0, reply)
            receipts.append(reply["result"]["destinations"][0]["receipt"])

        action = self.request(
            "sweep", {"destination": "archive", "receipts": receipts, "limit": 2},
            workflow="maintenance", role="maintainer",
        )
        code, reply = self.run_policy(digest, action, *store, "--workflow", "maintenance",
                                      "--settled-run", "settled")
        self.assertEqual(code, 0, reply)
        reported = reply["result"]["sweep"]
        self.assertEqual([entry["receipt"] for entry in reported], receipts)
        self.assertEqual([entry["retention"] for entry in reported],
                         ["retained_young", "retained_unresolved"])
        for receipt in receipts:
            verify = self.request(
                "readback", {"destination": "archive", "receipt": receipt},
                workflow="fileless-audit", role="auditor",
            )
            code, reply = self.run_policy(digest, verify, *write_flags)
            self.assertEqual(code, 0, reply)
            self.assertEqual(reply["result"]["persistence"], "verified")
