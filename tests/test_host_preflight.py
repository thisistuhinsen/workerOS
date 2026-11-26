"""Preflight checks using ordinary caller-owned resources."""

import errno
from contextlib import ExitStack
from hashlib import sha256
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import select
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
import unittest
from unittest.mock import patch

from worker_handoff import Worker, Writer, observe
from worker_handoff.configuration import ConfigurationError, parse_request
from worker_handoff.enrollment import DescriptorBinding, HostBindings, compile_policy
from worker_handoff.evidence import EvidenceScope, EvidenceState, RunBinding
from worker_handoff.lifecycle import Match, ProcessState, RegularFileObserver
from worker_handoff.scope_meter import monotonic_clock_id


def policy(operations, bindings, *, cleanup=False):
    workflow = {"role": "operator", "operations": operations, "bindings": bindings}
    if cleanup:
        workflow["cleanup_ms"] = 5000
    return {
        "version": 1,
        "roles": {"operator": {"operations": operations}},
        "workflows": {"selected": workflow},
    }


def document(operation, options):
    return {"version": 1, "workflow": "selected", "role": "operator",
            "operation": operation, "options": options}


class HostPreflightTest(unittest.TestCase):
    def test_selected_policy_preflights_real_held_child_and_keeps_retirement_unmeasured(self):
        with ExitStack() as owned:
            path = Path(owned.enter_context(TemporaryDirectory())) / "original"
            path.write_bytes(b"A")
            held = owned.enter_context(path.open("rb"))
            writer = owned.enter_context(path.open("r+b", buffering=0))
            identity = observe(held.fileno()).identity
            child = subprocess.Popen(
                [sys.executable, "-c", "import os,sys; assert os.pread(int(sys.argv[1]),1,0)==b'A'; "
                 "os.write(1,b'R'); raise SystemExit(7 if os.read(0,1)==b'G' else 8)", str(held.fileno())],
                pass_fds=(held.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            )
            supervisor = None

            def finish():
                if supervisor is None:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
                else:
                    supervisor.cleanup("child", due_ns=monotonic_ns() + 5_000_000_000)

            owned.callback(finish)
            owned.callback(child.stdin.close)
            owned.callback(child.stdout.close)
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "owned child did not become ready")
            self.assertEqual(os.read(child.stdout.fileno(), 1), b"R")
            pin = os.pidfd_open(child.pid)
            owned.callback(os.close, pin)

            now = monotonic_ns()
            due = now + 20_000_000_000
            scope_id = sha256(b"ordinary host fixture").hexdigest()
            clock = monotonic_clock_id()
            run = RunBinding("fixture-run", "fixture-artifact", clock, now, due) if clock else None
            scope = EvidenceScope(run, scope_id, now, due) if run is not None else None
            observer = owned.enter_context(RegularFileObserver(
                scope=scope_id, due_ns=due, original_fd=held.fileno(), identity=identity,
                pidfd=pin, worker=Worker("child", "operator", child.pid, os.getuid()),
                slot=held.fileno(), evidence_scope=scope,
            ))
            approvals = []

            def authorize(request):
                approvals.append(request.operation)
                return True

            def host(observers):
                return HostBindings(
                    authorize=authorize,
                    descriptors={"source": DescriptorBinding(identity, writer_fd=writer.fileno())},
                    supervisors=frozenset({"direct-child"}), observers=observers,
                )

            spec = policy(["observe", "write", "wait", "cleanup"], {
                "descriptors": "source", "supervisor": "direct-child", "observers": {"held": "provider"},
            }, cleanup=True)
            for bindings, code in ((None, "unsupported_binding"), ({}, "unknown_binding")):
                with self.subTest(code=code), self.assertRaisesRegex(ConfigurationError, code):
                    compile_policy(spec, host(bindings), workflow="selected")
            self.assertEqual(approvals, [])
            self.assertEqual(path.read_bytes(), b"A")

            compiled = compile_policy(
                spec, host({"provider": (observer, scope, "fixture")}), workflow="selected",
            )
            owner = compiled["selected"].supervisor
            owner.adopt("child", "operator", child, uid=os.getuid())
            supervisor = owner

            def operation(operation_name, **options):
                return compiled.execute(parse_request(document(operation_name, options)))

            live = operation("observe", scope="held")["sample"]
            self.assertEqual((live["process"], live["slot_match"], live["name_match"]),
                             (ProcessState.LIVE, Match.ORIGINAL, Match.NOT_REQUESTED))
            if scope is None:
                with self.assertRaisesRegex(ConfigurationError, "observation_scope_missing"):
                    operation("observe", scope="held", subject="slot")
            else:
                report = operation("observe", scope="held", subject="slot")["scope_report"]
                self.assertEqual(report["scope"]["run"]["run_id"], run.run_id)
                self.assertIs(report["observation"]["state"], EvidenceState.OBSERVED)

            self.assertEqual(operation("write", data="Qg==")["effect"], "complete")
            self.assertEqual(path.read_bytes(), b"B")
            self.assertEqual(os.write(child.stdin.fileno(), b"G"), 1)
            waited = operation("wait", name="child")
            self.assertEqual((waited["lifecycle"], waited["returncode"]), ("exited", 7))
            self.assertEqual(operation("cleanup", name="child", cleanup_ms=1000)["status"], "reaped")
            later = operation("observe", scope="held")["sample"]
            self.assertEqual((later["process"], later["slot_match"], later["name_match"]),
                             (ProcessState.EXITED, Match.UNKNOWN, Match.NOT_REQUESTED))
            self.assertEqual(observe(held.fileno()).identity, identity)

    def test_close_error_after_a_real_write_reports_unknown_without_replaying(self):
        closed = []

        class LostClose(Writer):
            def close(self):
                closed.append(self.fileno())
                super().close()
                raise OSError(errno.EIO, "synthetic lost close acknowledgement")

        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "target"
            path.write_bytes(b"A")
            with path.open("r+b", buffering=0) as borrowed:
                fd = borrowed.fileno()
                binding = DescriptorBinding(observe(fd).identity, writer_fd=fd)
                compiled = compile_policy(
                    policy(["write"], {"descriptors": "target"}),
                    HostBindings(authorize=lambda _: True, descriptors={"target": binding}),
                )
                request = BytesIO(json.dumps(document("write", {"data": "Qg=="})).encode())
                output = StringIO()
                with patch("worker_handoff.configuration.Writer", LostClose):
                    code = compiled.serve(request, output)
                self.assertEqual((code, json.loads(output.getvalue())), (1, {
                    "status": "unavailable", "code": "operation_result_unavailable", "effect": "unknown",
                }))
                duplicate, = closed
                self.assertNotEqual(duplicate, fd)
                with self.assertRaises(OSError) as error:
                    os.fstat(duplicate)
                self.assertEqual(error.exception.errno, errno.EBADF)
                self.assertEqual(os.pread(fd, 2, 0), b"B")
