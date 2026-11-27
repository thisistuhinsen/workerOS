"""Point-provider tests over owned handles, with no independence claim."""

from contextlib import ExitStack, redirect_stdout
from dataclasses import asdict, replace
import fcntl
from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import struct
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic_ns
from unittest import TestCase, skipUnless
from unittest.mock import patch

from worker_handoff import Worker, observe
from worker_handoff.managed_cli import _TRUSTED_UID
from worker_handoff.lifecycle import Match, ProcessState, RegularFileObserver
from worker_handoff.managed_provider import ProviderRefusal, _point_digest, _registration
from worker_handoff.profile_setup import ProfileDefinition, ProviderBinding
from worker_handoff.roles_cli import _canonical
from worker_handoff.appointment_registry import definition_sha256
from worker_handoff.evidence import EvidenceScope, EvidenceState, RunBinding, ScopePhase
from worker_handoff.scope_meter import CgroupScopeMeter, ScopeMeterUnavailable, monotonic_clock_id


@skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux pidfd required")
class PointProviderTest(TestCase):
    def setUp(self):
        self.owned = self.enterContext(ExitStack())
        self.root = Path(self.owned.enter_context(TemporaryDirectory()))
        self.path = self.root / "held-original"
        self.path.write_bytes(b"point-provider fixture")
        self.original = self.fd(self.path, os.O_RDONLY)
        self.directory = self.fd(self.root, os.O_DIRECTORY | os.O_RDONLY)
        self.pidfd = os.pidfd_open(os.getpid())
        self.owned.callback(os.close, self.pidfd)

    def fd(self, path, flags):
        descriptor = os.open(path, flags | os.O_CLOEXEC)
        self.owned.callback(os.close, descriptor)
        return descriptor

    def observer(self, slot):
        return self.owned.enter_context(RegularFileObserver(
            scope="1a" * 32, due_ns=monotonic_ns() + 10_000_000_000,
            original_fd=self.original, identity=observe(self.original).identity,
            pidfd=self.pidfd, worker=Worker("fixture", "reader", os.getpid(), os.getuid()),
            slot=slot, directory_fd=self.directory, leaf=self.path.name,
        ))

    def test_live_readable_slot_and_exact_name(self):
        observer = self.observer(self.original)
        sample = observer.sample()
        self.assertEqual((sample.process, sample.slot_match, sample.name_match),
                         (ProcessState.LIVE, Match.ORIGINAL, Match.ORIGINAL))
        before = monotonic_ns()
        digest, finished = _point_digest(observer, require_readable=True, require_name=True)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue(before <= finished <= monotonic_ns())

    def test_wrong_or_absent_slot_is_not_evidence(self):
        other = self.root / "other"
        other.write_bytes(b"unrelated")
        wrong = self.observer(self.fd(other, os.O_RDONLY))
        self.assertIs(wrong.sample().slot_match, Match.OTHER)
        abandoned = fcntl.fcntl(self.original, fcntl.F_DUPFD_CLOEXEC, 64)
        try:
            absent = self.observer(abandoned)
        finally:
            os.close(abandoned)
        self.assertIs(absent.sample().slot_match, Match.ABSENT)
        for label, observer in (("wrong", wrong), ("absent", absent)):
            with self.subTest(slot=label), self.assertRaises(ProviderRefusal):
                _point_digest(observer, require_readable=True, require_name=False)

    def test_metadata_only_slot_is_not_readable_evidence(self):
        observer = self.observer(self.fd(self.path, os.O_PATH))
        sample = observer.sample()
        self.assertIs(sample.slot_match, Match.ORIGINAL)
        self.assertTrue(sample.flags & os.O_PATH)
        digest, _ = _point_digest(observer, require_readable=False, require_name=False)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        with self.assertRaises(ProviderRefusal):
            _point_digest(observer, require_readable=True, require_name=False)

    def test_changed_name_cannot_satisfy_named_point(self):
        observer = self.observer(self.original)
        self.path.rename(self.root / "retired-name")
        self.path.write_bytes(b"replacement")
        sample = observer.sample()
        self.assertEqual((sample.slot_match, sample.name_match), (Match.ORIGINAL, Match.OTHER))
        with self.assertRaises(ProviderRefusal):
            _point_digest(observer, require_readable=True, require_name=True)

    def registration(self, *, host_uid, capability="point"):
        identity = observe(self.original).identity
        plan = dict(device=identity.device, inode=identity.inode, pid=os.getpid(), uid=os.getuid(),
                    slot=self.original, scope_sha256="1a"*32, require_readable=True)
        binding = ProviderBinding("observer", sha256(_canonical(plan)).hexdigest(), "scope",
                                  capability, "fixture-provider", "observers")
        # These profile identifiers are only inputs for early refusals. No
        # provider, matching real clock, package or policy is commissioned here.
        definition = ProfileDefinition("workflow", "revision", "0.8.0", "b"*64, "c"*64,
                                       "fixture-host", "scope", "fixture-clock",
                                       monotonic_ns() + 10_000_000_000, (binding,))
        return dict(version=1, host_uid=host_uid, provider_uid=os.getuid(),
                    definition=asdict(definition), role="operator", binding_generation="generation",
                    binding=binding.name, observer={**plan, "original_fd":self.original, "pidfd":self.pidfd})

    def test_registration_refuses_same_uid(self):
        with self.assertRaisesRegex(ProviderRefusal, "^provider_requires_distinct_uid$"):
            _registration(self.registration(host_uid=os.getuid()))

    def test_registration_refuses_interval_before_clock_or_observation(self):
        if os.getresuid() != (os.getuid(),)*3 or not os.getuid():
            self.skipTest("ordinary provider principal required")
        with self.assertRaisesRegex(ProviderRefusal, "^provider_capability_unsupported$"):
            _registration(self.registration(host_uid=0, capability="interval"))

    def test_registration_selects_one_matching_observer_or_meter(self):
        if os.getresuid() != (os.getuid(),) * 3 or not os.getuid():
            self.skipTest("ordinary provider principal required")
        config = self.registration(host_uid=0)
        observer_entry = config["definition"]["providers"][0]
        meter_entry = {**observer_entry, "name": "meter", "kind": "meters",
                       "capability": "cgroup-v2", "reference": "c" * 64}
        config["definition"]["providers"] = (observer_entry, meter_entry)
        # Scope/identity checking here is structural; the clock is stubbed
        # because this container lacks the required monotonic clock context.
        with patch("worker_handoff.managed_provider.setup_clock_id", return_value="fixture-clock"):
            definition, selected = _registration(config)
            self.assertEqual((selected.kind, selected.capability), ("observers", "point"))
            meter_config = {**config, "binding": "meter", "meter": {"test": "placeholder"}}
            del meter_config["observer"]
            meter_definition, selected = _registration(meter_config)
            self.assertEqual(meter_definition, definition)
            self.assertEqual((selected.kind, selected.capability), ("meters", "cgroup-v2"))
            both = {**meter_config, "observer": config["observer"]}
            with self.assertRaisesRegex(ProviderRefusal, "^provider_binding_mismatch$"):
                _registration(both)
            neither = {key: value for key, value in meter_config.items() if key != "meter"}
            with self.assertRaisesRegex(ProviderRefusal, "^provider_binding_mismatch$"):
                _registration(neither)
            wrong = {**meter_config, "observer": config["observer"]}
            del wrong["meter"]
            with self.assertRaisesRegex(ProviderRefusal, "^provider_binding_mismatch$"):
                _registration(wrong)

    def test_owned_unix_listener_handles_bounded_serial_requests(self):
        # This is a real socket exchange and point sample. The executor runs
        # both ends under one UID, so only the credential boundary is stubbed.
        from worker_handoff.managed_provider import _serve
        config = self.registration(host_uid=0)
        providers = tuple(ProviderBinding(**entry) for entry in config["definition"]["providers"])
        definition = ProfileDefinition(**{**config["definition"], "providers": providers})
        binding, = providers
        observer = self.observer(self.original)
        errors = []
        def credentials(sock):
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                return os.getpid(), config["provider_uid"]
            return os.getpid() + 1, config["host_uid"]

        def exact(sock, length):
            result = b""
            while len(result) < length:
                chunk = sock.recv(length - len(result))
                if not chunk:
                    self.fail("provider closed before its reply")
                result += chunk
            return result

        def request(number, path):
            message = {
                "definition_sha256": definition_sha256(definition),
                "role": config["role"], "clock_id": definition.clock_id,
                "generation": config["binding_generation"], "version": 1,
                "request_id": f"{number:032x}",
            }
            encoded = _canonical(message)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(4)
                client.connect(str(path))
                client.sendall(struct.pack("!I", len(encoded)) + encoded)
                size, = struct.unpack("!I", exact(client, 4))
                response = json.loads(exact(client, size))
            self.assertEqual(response["request_id"], message["request_id"])
            self.assertEqual(response["definition_sha256"], message["definition_sha256"])
            self.assertEqual((response["status"], response["source"]), ("verified", binding.principal))
            self.assertRegex(response["evidence_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(int(response["valid_until_ns"]), monotonic_ns())

        for count in (1, 2):
            with self.subTest(count=count), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                path = self.root / f"provider-{count}.sock"
                listener.bind(str(path))
                listener.listen(2)
                def run():
                    try:
                        options = {} if count == 1 else {"max_requests": count}
                        _serve(listener, config, definition, binding, observer, **options)
                    except BaseException as exc:
                        errors.append(exc)
                with patch("worker_handoff.managed_provider._credentials", side_effect=credentials):
                    thread = Thread(target=run, daemon=True)
                    thread.start()
                    try:
                        for number in range(count):
                            request(number + 1, path)
                    finally:
                        thread.join(5)
                    self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_meter_digest_reads_own_visible_cgroup_without_cleanup_claim(self):
        from worker_handoff.managed_provider import _meter_digest

        rows = Path("/proc/self/cgroup").read_text().splitlines()
        groups = [PurePosixPath(row[3:]) for row in rows if row.startswith("0::")]
        if len(groups) != 1 or not groups[0].is_absolute() or ".." in groups[0].parts:
            self.skipTest("own cgroup v2 membership is unavailable or not visible")
        # This direct path is used only when the visible cgroup v2 root is /.
        # Never probe a different principal or alternate mount after refusal.
        if groups[0] != PurePosixPath("/"):
            self.skipTest("fixture supports the caller's visible cgroup root only")
        clock = monotonic_clock_id()
        if clock is None:
            self.skipTest("own monotonic clock context unavailable")
        start = monotonic_ns()
        end = start + 10_000_000_000
        run = RunBinding("fixture-run", "fixture-artifact", clock, start, end)
        scope = EvidenceScope(run, "fixture-scope", start, end)
        try:
            descriptor = self.fd(Path("/sys/fs/cgroup"), os.O_RDONLY | os.O_DIRECTORY)
            meter = self.owned.enter_context(CgroupScopeMeter(
                scope=scope, provider_id="fixture-meter", directory_fd=descriptor))
            sample = meter.sample(ScopePhase.METER_BEGIN)
        except (OSError, ScopeMeterUnavailable, ValueError) as exc:
            self.skipTest(f"own cgroup meter unavailable: {type(exc).__name__}")
        if sample.cpu_state is not EvidenceState.OBSERVED or sample.population_state is not EvidenceState.OBSERVED:
            self.skipTest("own cgroup CPU or population is unavailable")
        digest, finished = _meter_digest(meter)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertLessEqual(sample.finished_ns, finished)
        self.assertLessEqual(finished, monotonic_ns())
        # A shared cgroup point reading does not prove exclusivity or retirement.
        with patch.object(meter, "sample", return_value=replace(
                sample, cpu_state=EvidenceState.UNAVAILABLE, usage_usec=None)):
            with self.assertRaises(ProviderRefusal):
                _meter_digest(meter)

    def test_point_requests_refuse_cross_scope_and_reused_challenges(self):
        from worker_handoff.managed_provider import _serve_once
        from time import monotonic
        config = self.registration(host_uid=0)
        providers = tuple(ProviderBinding(**entry) for entry in config["definition"]["providers"])
        definition = ProfileDefinition(**{**config["definition"], "providers": providers})
        binding, = providers
        observer = self.observer(self.original)
        expected = {"definition_sha256": definition_sha256(definition), "role": config["role"],
                    "clock_id": definition.clock_id, "generation": config["binding_generation"]}
        seen = set()
        def exercise(request):
            errors = []
            server, client = socket.socketpair()
            with server, client:
                def run():
                    try:
                        _serve_once(server, config, binding, observer, expected, seen,
                                    definition.expires_ns, monotonic() + 3)
                    except BaseException as exc:
                        errors.append(exc)
                    finally:
                        server.shutdown(socket.SHUT_WR)
                with patch("worker_handoff.managed_provider._credentials",
                           return_value=(os.getpid() + 1, config["host_uid"])):
                    thread = Thread(target=run, daemon=True)
                    thread.start()
                    payload = _canonical(request)
                    client.sendall(struct.pack("!I", len(payload)) + payload)
                    client.settimeout(3)
                    response = b""
                    while chunk := client.recv(65536):
                        response += chunk
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
            return response, errors
        request = {**expected, "request_id": "1" * 32, "version": 1}
        response, errors = exercise(request)
        self.assertTrue(response)
        self.assertEqual(errors, [])
        for rejected in (request, {**request, "request_id": "2" * 32, "definition_sha256": "0" * 64}):
            with self.subTest(request_id=rejected["request_id"]):
                response, errors = exercise(rejected)
                self.assertEqual(response, b"")
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], ProviderRefusal)
                self.assertEqual(str(errors[0]), "invalid_provider_request")
        self.assertEqual(seen, {"1" * 32})

    def test_provider_request_limit_rejects_nonpositive_or_unbounded_values(self):
        from worker_handoff.managed_provider import _serve
        for count in (0, 17, True, "2"):
            with self.subTest(count=count), self.assertRaisesRegex(ProviderRefusal, "^provider_request_limit_invalid$"):
                _serve(None, None, None, None, None, max_requests=count)

    def test_cli_refuses_bad_request_limit_before_reading_descriptors(self):
        from worker_handoff.managed_provider import main
        for value in ("0", "-1", "17", "999999999999999999999"):
            with self.subTest(value=value), patch(
                    "worker_handoff.managed_provider._read_registration") as read_registration:
                output = StringIO()
                with redirect_stdout(output):
                    result = main(["--config-fd", "3", "--listen-fd", "4", "--max-requests", value])
                self.assertEqual(result, 1)
                self.assertEqual(json.loads(output.getvalue()), {
                    "status": "unavailable", "code": "provider_request_limit_invalid",
                    "effect": "not_attempted",
                })
                read_registration.assert_not_called()

        # Omitting the option preserves the one-request default and proceeds
        # to normal registration validation.
        with patch("worker_handoff.managed_provider._read_registration",
                   side_effect=ProviderRefusal("registration_checked")) as read_registration:
            output = StringIO()
            with redirect_stdout(output):
                result = main(["--config-fd", "3", "--listen-fd", "4"])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(output.getvalue())["code"], "registration_checked")
            read_registration.assert_called_once_with(3)

    def test_installed_entry_refuses_untrusted_registration_descriptor(self):
        if not os.environ.get("WORKEROS_TEST_WHEEL"):
            self.skipTest("exact installed wheel path required")
        script = Path(sys.prefix) / "bin" / "workeros"
        self.assertTrue(script.is_file())
        registration = self.root / "registration.json"
        registration.write_text(json.dumps(self.registration(host_uid=os.getuid())))
        # The ordinary fixture cannot supply the administrator's owner UID.
        # An already-admin test process can still exercise the writable-FD rule.
        descriptor = self.fd(registration, os.O_RDWR if os.getuid() == _TRUSTED_UID else os.O_RDONLY)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.root / "provider.sock"))
            listener.listen(1)
            result = subprocess.run([str(script), "managed", "serve-provider",
                                     "--config-fd", str(descriptor), "--listen-fd", str(listener.fileno())],
                                    pass_fds=(descriptor, listener.fileno()), capture_output=True,
                                    text=True, timeout=8, cwd=self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "status": "unavailable", "effect": "not_attempted", "code": "untrusted_provider_registration",
        })
