"""Exercise the enrolled append path with an actual preheld file and journal."""

from contextlib import redirect_stdout
from hashlib import sha256
import importlib.util
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import patch

from workeros import AppendWrite, Writer, cli, observe, owner_append
from workeros.configuration import ConfigurationError, parse_request
from workeros.custody import IndependentCustody
from workeros.enrollment import HostBindings, compile_policy, decode_policy
from workeros.owner_append import OwnerAppendBinding
from workeros.recording import LocalStore


class OwnerAppendTest(TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / "original"
        self.path.write_bytes(b"prefix")
        fd = os.open(self.path, os.O_WRONLY | os.O_CLOEXEC)
        self.writer = self.enterContext(Writer(fd, observe(fd).identity))
        self.reader = self.enterContext(self.path.open("rb"))
        self.journal = self.root / "journal"
        self.journal.mkdir(mode=0o700)
        local, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.enterContext(local)
        self.enterContext(peer)
        custody = IndependentCustody(local, observer_pid=os.getpid() + 1, observer_uid=os.getuid() + 1)
        self.enterContext(patch.object(owner_append, "monotonic_clock_id", return_value="fixture-clock"))
        self.binding = OwnerAppendBinding("compile-reports", "report-owner", "add_entry", "report-source", "r1",
                                          os.getuid(), self.writer, self.reader.fileno(), custody,
                                          monotonic_ns() + 15_000_000_000, LocalStore(self.journal))
        self.host = HostBindings(authorize=lambda _: True, owner_appends={self.binding.pin: self.binding})
        ops = ["owner_append", "owner_append_status"]
        self.document = {
            "version": 1, "roles": {"report-owner": {"operations": ops}},
            "workflows": {"compile-reports": {"role": "report-owner", "operations": ops,
                          "bindings": {"owner_appends": {"add_entry": self.binding.pin}}}},
        }
        self.policy = compile_policy(self.document, self.host)

    def request(self, *, readback=False, **changes):
        options = {"alias": "add_entry", "attempt_id": "report-1"}
        options.update({"data_sha256": sha256(b":new").hexdigest()} if readback else {"data": "Om5ldw=="})
        options.update(changes)
        return {"version": 1, "workflow": "compile-reports", "role": "report-owner",
                "operation": "owner_append_status" if readback else "owner_append", "options": options}

    def dispatch(self, **changes):
        return self.policy.execute(parse_request(self.request(**changes)))

    def authorize_test_custody(self, custody, *, identity, operation, scope, due_ns):
        # This fixture exercises the owner, real append and journal. The
        # independently commissioned peer is not available in this test venue.
        self.assertIs(custody, self.binding.custody)
        self.assertEqual(identity, observe(self.reader.fileno()).identity)
        self.assertEqual(operation, "owner-append")
        expected = [self.binding.pin, "report-1", sha256(b":new").hexdigest()]
        self.assertEqual(scope, sha256(owner_append._canonical(expected)).hexdigest())
        self.assertLessEqual(due_ns, self.binding.expires_ns)

    def custody_fixture(self):
        return patch.object(owner_append, "require_custody", side_effect=self.authorize_test_custody)

    def test_untrusted_socket_or_missing_binding_refuses_before_reservation(self):
        with self.assertRaisesRegex(ConfigurationError, "owner_append_binding_missing"):
            compile_policy(self.document, HostBindings(authorize=lambda _: True))
        with self.assertRaisesRegex(ConfigurationError, "owner_append_binding_mismatch"):
            host = HostBindings(authorize=lambda _: True, owner_appends={self.binding.pin: object()})
            compile_policy(self.document, host)
        with self.assertRaisesRegex(ConfigurationError, "owner_append_binding_missing"):
            self.dispatch(alias="unapproved")
        self.assertEqual(self.dispatch()["effect"], "not-attempted")
        self.assertEqual(self.path.read_bytes(), b"prefix")
        self.assertEqual(list(self.journal.iterdir()), [])

    def test_changed_clock_refuses_without_using_the_journal(self):
        with patch.object(owner_append, "monotonic_clock_id", return_value=None), self.custody_fixture() as approval:
            self.assertEqual(self.dispatch()["code"], "owner_append_unavailable")
        approval.assert_not_called()
        self.assertEqual(list(self.journal.iterdir()), [])

    def test_json_yaml_policy_binding_and_standalone_refusal(self):
        documents = {"json": json.dumps(self.document).encode()}
        if importlib.util.find_spec("yaml") is not None:
            documents["yaml"] = (
                "version: 1\nroles:\n  report-owner:\n    operations: [owner_append, owner_append_status]\n"
                "workflows:\n  compile-reports:\n    role: report-owner\n    operations: [owner_append, owner_append_status]\n"
                f"    bindings:\n      owner_appends:\n        add_entry: '{self.binding.pin}'\n"
            ).encode()
        for suffix, policy_bytes in documents.items():
            normalized = cli._yaml_to_json(policy_bytes) if suffix == "yaml" else policy_bytes
            compiled = compile_policy(decode_policy(normalized), self.host)
            self.assertEqual(compiled[self.binding.workflow].owner_appends, {self.binding.alias: self.binding})
            path = self.root / ("approved." + suffix)
            path.write_bytes(policy_bytes)
            argv = ["config", "--check-policy", str(path), "--format", suffix,
                    "--policy-sha256", sha256(policy_bytes).hexdigest()]
            capture = StringIO()
            with redirect_stdout(capture):
                self.assertEqual(cli.main(argv), 1)
            self.assertEqual(json.loads(capture.getvalue())["code"], "owner_append_binding_missing")
            path.write_bytes(policy_bytes + b" ")
            capture = StringIO()
            with redirect_stdout(capture):
                self.assertEqual(cli.main(argv), 1)
            self.assertEqual(json.loads(capture.getvalue())["code"], "policy_digest_mismatch")

    def test_stock_cli_runs_from_protected_registration_and_reconciles_in_fresh_process(self):
        if not hasattr(os, "RWF_APPEND"):
            self.skipTest("this Python build has no kernel append interface")
        self.document["workflows"]["compile-reports"]["bindings"]["owner_appends"]["add_entry"] = "report-anchor"
        policy = self.root / "approved.json"
        raw = json.dumps(self.document).encode()
        policy.write_bytes(raw)
        config = self.root / "workeros"
        config.mkdir(mode=0o700)
        registration = config / "owner-append.json"
        identity = self.writer.identity
        record = {
            "version": 1, "policy_sha256": sha256(raw).hexdigest(), "workflow": self.binding.workflow,
            "role": self.binding.role, "alias": self.binding.alias, "scope": self.binding.scope,
            "generation": self.binding.generation, "reference": "report-anchor", "owner_uid": os.getuid(),
            "device": str(identity.device), "inode": str(identity.inode), "writer_fd": self.writer.fileno(),
            "reader_fd": self.reader.fileno(), "observer_fd": self.binding.custody.channel.fileno(),
            "observer_pid": self.binding.custody.observer_pid, "observer_uid": self.binding.custody.observer_uid,
            "expires_ns": str(self.binding.expires_ns), "journal_directory": str(self.journal),
        }
        registration.write_text(json.dumps(record))
        registration.chmod(0o600)
        self.enterContext(patch.multiple("workeros.managed_cli", _CONFIG_PARENT=str(self.root),
                                        _TRUSTED_UID=os.getuid()))

        def run(request, *, attest):
            source = self.root / "request"
            output = self.root / "response"
            source.write_text(json.dumps(request))
            pid = os.fork()
            if pid == 0:
                try:
                    with source.open("rb") as stdin, output.open("wb") as stdout:
                        os.dup2(stdin.fileno(), 0)
                        os.dup2(stdout.fileno(), 1)
                        with patch.object(owner_append, "require_custody", side_effect=attest):
                            result = cli.main(["config", "--run-policy", str(policy), "--registered-owner-append"])
                        sys.stdout.flush()
                    os._exit(result)
                except BaseException:
                    os._exit(98)
            _, status = os.waitpid(pid, 0)
            return os.waitstatus_to_exitcode(status), json.loads(output.read_text())

        def owner_custody(_observer, *, identity, operation, scope, due_ns):
            # The independent endpoint is synthetic. The owner, retained
            # descriptors, protected config and journal are exercised as installed.
            if identity != self.writer.identity or operation != "owner-append":
                raise AssertionError("unexpected custody request")

        def no_contact(*_args, **_kwargs):
            raise AssertionError("readback must not contact the custody peer")

        registration.chmod(0o666)
        code, reply = run(self.request(), attest=no_contact)
        self.assertEqual((code, reply["code"]), (1, "owner_append_registration_unavailable"))
        self.assertEqual(list(self.journal.iterdir()), [])
        registration.chmod(0o600)
        registration.write_text(json.dumps({**record, "inode": str(identity.inode + 1)}))
        code, crossed = run(self.request(), attest=no_contact)
        self.assertEqual((code, crossed["code"]), (1, "owner_append_registration_unavailable"))
        self.assertEqual(list(self.journal.iterdir()), [])
        registration.write_text(json.dumps(record))
        code, reply = run(self.request(), attest=owner_custody)
        self.assertEqual(code, 0, reply)
        self.assertEqual(reply["result"]["bytes_written"], "4")
        code, readback = run(self.request(readback=True), attest=no_contact)
        self.assertEqual((code, readback["result"]), (0, reply["result"]))
        code, repeat = run(self.request(), attest=no_contact)
        self.assertEqual((code, repeat["result"]), (0, reply["result"]))
        self.assertEqual(os.pread(self.reader.fileno(), 40, 0), b"prefix:new")

    def test_managed_append_and_same_key_readback_do_not_replay(self):
        self.path.rename(self.root / "original-retained")
        self.path.write_bytes(b"replacement")
        with self.custody_fixture() as approval:
            output = StringIO()
            self.assertEqual(self.policy.serve(BytesIO(json.dumps(self.request()).encode()), output), 0)
            result = json.loads(output.getvalue())["result"]
            if not hasattr(os, "RWF_APPEND"):
                self.assertEqual(result["code"], "owner_append_unavailable")
                self.assertEqual(list(self.journal.iterdir()), [])
                return
            self.assertEqual((result["effect"], result["timeliness"], result["bytes_written"]),
                             ("complete", "within_deadline", "4"))
            self.assertEqual(self.dispatch(readback=True)["bytes_written"], 4)
            self.assertEqual(self.dispatch()["bytes_written"], 4)
            self.assertEqual(self.dispatch(data="OmFi")["code"], "append_attempt_conflict")
            approval.assert_called_once()
        self.assertEqual(os.pread(self.reader.fileno(), 40, 0), b"prefix:new")
        self.assertEqual(self.path.read_bytes(), b"replacement")

    def test_full_write_after_deadline_is_known_late(self):
        if not hasattr(os, "RWF_APPEND"):
            self.skipTest("this Python build has no kernel append interface")
        with self.custody_fixture(), patch.object(owner_append, "monotonic_ns", return_value=self.binding.expires_ns + 1):
            result = self.dispatch()
        self.assertEqual((result["effect"], result["timeliness"], result["bytes_written"]), ("complete", "late", 4))
        self.assertEqual(self.dispatch(readback=True), result)
        self.assertEqual(self.path.read_bytes(), b"prefix:new")

    def exercise_short_write(self, failed):
        if not hasattr(os, "RWF_APPEND"):
            self.skipTest("this Python build has no kernel append interface")
        append = Writer.append

        def write_partial(writer, operation, *, due_ns):
            count = append(writer, AppendWrite(operation.data[:1]), due_ns=due_ns)
            if failed:
                raise OSError("write response unavailable")
            return count

        with self.custody_fixture(), patch.object(Writer, "append", autospec=True, side_effect=write_partial) as write:
            outcome = self.dispatch()
            self.assertEqual(self.dispatch(readback=True), outcome)
            self.assertEqual(self.dispatch(), outcome)
            write.assert_called_once()
        self.assertEqual((outcome["effect"], outcome["bytes_written"]),
                         ("unknown", None) if failed else ("partial", 1))
        self.assertEqual(self.path.read_bytes(), b"prefix:")

    def test_short_write_keeps_count(self):
        self.exercise_short_write(failed=False)

    def test_indeterminate_error_keeps_unknown(self):
        self.exercise_short_write(failed=True)

    def test_missing_outcome_record_never_replays_known_local_effect(self):
        if not hasattr(os, "RWF_APPEND"):
            self.skipTest("this Python build has no kernel append interface")
        commit = owner_append._commit

        def fail_result(store, key, kind, data):
            if kind == owner_append._RESULT:
                raise OSError("journal write unavailable")
            return commit(store, key, kind, data)

        with self.custody_fixture(), patch.object(owner_append, "_commit", side_effect=fail_result):
            outcome = self.dispatch()
        self.assertEqual((outcome["effect"], outcome["bytes_written"], outcome["readback"]),
                         ("complete", 4, "unconfirmed"))
        reported = self.dispatch(readback=True)
        self.assertEqual(reported["effect"], "unknown")
        self.assertEqual(self.dispatch(), reported)
        self.assertEqual(self.path.read_bytes(), b"prefix:new")
