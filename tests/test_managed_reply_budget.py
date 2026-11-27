"""Deterministic controls for the managed binding-check reply budget."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
from struct import pack, unpack
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from worker_handoff import managed_bootstrap as bootstrap
from worker_handoff import managed_cli
from worker_handoff.aggregate_setup import AggregateSetup
from worker_handoff.appointment_registry import definition_sha256
from worker_handoff.configuration import ConfigurationError
from worker_handoff.managed_host import ManagedHostAdapter
from worker_handoff.profile_setup import ManagedProfileSetup, ManagerSelection, ProfileDefinition


def framed(body):
    data = json.dumps(body, separators=(",", ":")).encode()
    return pack("!I", len(data)) + data


class Clock:
    seconds = 10.0

    def now(self):
        return self.seconds

    def ns(self):
        return round(self.seconds * 1_000_000_000)


class FrameSocket:
    def __init__(self, clock, frame=b"", *, pid=22, uid=1000, delay=0.0):
        self.clock, self.frame = clock, frame
        self.pid, self.uid, self.delay = pid, uid, delay
        self.sent = []

    def settimeout(self, timeout):
        self.timeout = timeout

    def getsockopt(self, *unused):
        return pack("3i", self.pid, self.uid, self.uid)

    def recv(self, count):
        delay, self.delay = self.delay, 0
        if delay >= self.timeout:
            self.clock.seconds += self.timeout
            raise TimeoutError()
        self.clock.seconds += delay
        data, self.frame = self.frame[:count], self.frame[count:]
        return data

    def sendall(self, frame):
        self.sent.append(frame)


def exercise(point_delay, meter_delay, *, wheel_read=0.0, approval_read=0.0,
             point_return_delay=0.0, reply_processing=0.0):
    assert managed_cli._TIMEOUT == 5.0
    clock = Clock()
    scope = "point"
    profile = "inert-profile"
    generation = "one"
    role = "inert-role"
    definition = ProfileDefinition(scope, "one", "0.8.0", "a" * 64, "b" * 64, "inert-manager",
                                   "inert-scope", "e" * 64, clock.ns() + 20_000_000_000)
    selection = ManagerSelection(definition, b"{}", definition.clock_id, definition.expires_ns)
    requirements = SimpleNamespace(role=role)
    plan = [
        ("/inert/point.sock", os.getuid() + 1, "point-provider", point_delay),
        ("/inert/meter.sock", os.getuid() + 2, "meter-provider", meter_delay),
    ]
    observations = []

    class ProviderSocket(FrameSocket):
        def connect(self, address):
            address_pin, uid, source, delay = plan[len(observations)]
            assert address == address_pin
            self.uid, self.source, self.delay = uid, source, delay
            observations.append({"provider": source, "begin_ms": round((clock.now() - 10.0) * 1000),
                                 "socket_budget_ms": round(self.timeout * 1000)})

        def sendall(self, frame):
            length, = unpack("!I", frame[:4])
            assert len(frame[4:]) == length
            request = json.loads(frame[4:])
            assert request["role"] == role and request["generation"] == generation
            assert request["definition_sha256"] == definition_sha256(definition)
            body = {key: request[key] for key in ("request_id", "role", "definition_sha256",
                                                  "generation", "clock_id")}
            self.frame = framed({**body, "source": self.source, "status": "verified",
                                 "evidence_sha256": "f" * 64,
                                 "valid_until_ns": str(round((clock.now() + self.delay + 1) * 1_000_000_000))})

        def __enter__(self):
            return self

        def __exit__(self, *unused):
            pass

    namespace = SimpleNamespace(socket=lambda *_: ProviderSocket(clock), AF_UNIX=managed_cli.socket.AF_UNIX,
                                SOCK_STREAM=managed_cli.socket.SOCK_STREAM, SOL_SOCKET=managed_cli.socket.SOL_SOCKET,
                                SO_PEERCRED=managed_cli.socket.SO_PEERCRED)
    providers = tuple(bootstrap._EvidenceProvider(address, uid, source) for address, uid, source, _ in plan)
    manager = bootstrap._BootstrapProfileManager(selection, requirements, None, generation, providers, None)
    adapter = object.__new__(ManagedHostAdapter)
    adapter.profile, adapter.identity, adapter.operation_key = profile, "0" * 64, "1" * 64
    adapter.revision, adapter.clock_id = definition.revision, definition.clock_id
    adapter.scopes = (SimpleNamespace(name=scope, revision=definition.revision),)
    adapter.definitions = (definition,)
    adapter.wheel, adapter.wheel_sha256 = Path("/inert/wheel.whl"), definition.package_sha256
    adapter.aggregate = object.__new__(AggregateSetup)
    adapter.aggregate._scopes = adapter.scopes
    attester = SimpleNamespace(valid_until_ns=None)
    adapter.aggregate._attesters = {scope: attester}
    setup = object.__new__(ManagedProfileSetup)
    adapter.aggregate._clients = {scope: setup}
    local_phases = []

    def select(*_):
        evidence = manager.attest(selection, requirements, generation)
        # The actual aggregate rejects a stale combined attestation at
        # aggregate_setup.py:124. Model only that boundary here.
        if evidence.expires_ns <= clock.ns():
            raise ConfigurationError("independent_evidence_invalid")
        attester.valid_until_ns = evidence.expires_ns
        return selection

    setup._selection = select

    def verify(*_):
        local_phases.append("wheel")
        clock.seconds += wheel_read

    @contextmanager
    def approval(_):
        local_phases.append("approval")
        clock.seconds += approval_read
        yield None

    attest = bootstrap._EvidenceProvider.attest
    validate = managed_cli._binding_response

    def attest_with_delay(provider, *args):
        result = attest(provider, *args)
        if provider is providers[0]:
            clock.seconds += point_return_delay
        return result

    def validate_with_delay(*args):
        result = validate(*args)
        clock.seconds += reply_processing
        return result

    request = framed({"version": 1, "operation": "check-bindings", "profile": profile,
                      "identity": adapter.identity, "operation_key": adapter.operation_key})
    connection = FrameSocket(clock, request)
    timeout_site = None
    with (
        patch.object(bootstrap, "socket", namespace),
        patch.object(bootstrap, "monotonic", clock.now),
        patch.object(bootstrap, "monotonic_ns", clock.ns),
        patch.object(managed_cli, "monotonic", clock.now),
        patch.object(managed_cli, "monotonic_ns", clock.ns),
        patch.object(managed_cli, "_binding_response", validate_with_delay),
        patch.object(bootstrap._EvidenceProvider, "attest", attest_with_delay),
        patch("worker_handoff.managed_host.verify_install", verify),
        patch("worker_handoff.managed_host.monotonic_ns", clock.ns),
        patch("worker_handoff.aggregate_setup.monotonic_ns", clock.ns),
        patch.object(ManagedHostAdapter, "_approval", approval),
    ):
        try:
            managed_cli.serve_connection(connection, authorized_uids=frozenset({1000}), adapter=adapter)
        except TimeoutError:
            timeout_site = True
        deadline_context = getattr(managed_cli, "_CHECK_WORK_DEADLINE", None)
        assert deadline_context is None or deadline_context.get() is None
    response = json.loads(connection.sent[0][4:]) if connection.sent else None
    if response:
        assert all(response[key] == value for key, value in managed_cli._CHECK_BOUNDARY.items())
    return {"provider_waits": observations, "elapsed_ms": round((clock.now() - 10) * 1000),
            "local_phases": local_phases, "reply": response, "reply_deadline_expired": bool(timeout_site)}


class ManagedReplyBudgetTest(unittest.TestCase):
    def test_two_provider_waits_share_the_reply_budget(self):
        result = exercise(4.95, 4.6)
        self.assertEqual(result["elapsed_ms"], 5000)
        self.assertEqual([call["socket_budget_ms"] for call in result["provider_waits"]], [5000, 50])
        self.assertEqual([call["begin_ms"] for call in result["provider_waits"]], [0, 4950])
        self.assertTrue(result["reply_deadline_expired"])
        self.assertIsNone(result["reply"])

    def test_exhausted_first_provider_does_not_start_second(self):
        result = exercise(5.2, 0)
        self.assertEqual(result["elapsed_ms"], 5000)
        self.assertEqual(len(result["provider_waits"]), 1)
        self.assertTrue(result["reply_deadline_expired"])
        self.assertIsNone(result["reply"])

    def test_synchronous_reads_can_consume_budget_before_downstream_work(self):
        for phases, args in ((["wheel"], {"wheel_read": 5.1}),
                             (["wheel", "approval"], {"approval_read": 5.1})):
            with self.subTest(phases=phases):
                result = exercise(0, 0, **args)
                self.assertEqual(result["elapsed_ms"], 5100)
                self.assertEqual(result["local_phases"], phases)
                self.assertEqual(result["provider_waits"], [])
                self.assertTrue(result["reply_deadline_expired"])
                self.assertIsNone(result["reply"])

    def test_fresh_pair_near_deadline_can_use_actual_remaining_time(self):
        for processing, elapsed in ((0, 4950), (0.02, 4970)):
            with self.subTest(processing=processing):
                result = exercise(4.95, 0, reply_processing=processing)
                self.assertEqual(len(result["provider_waits"]), 2)
                self.assertEqual(result["elapsed_ms"], elapsed)
                self.assertEqual(result["reply"]["status"], "bindings_verified")
        too_late = exercise(4.95, 0, reply_processing=0.06)
        self.assertEqual(too_late["elapsed_ms"], 5010)
        self.assertTrue(too_late["reply_deadline_expired"])
        self.assertIsNone(too_late["reply"])

    def test_timely_reply_and_evidence_freshness(self):
        quick = exercise(0.2, 0.3)
        self.assertEqual((quick["reply"]["status"], quick["elapsed_ms"]), ("bindings_verified", 500))
        stale = exercise(0.7, 4.6)
        self.assertEqual(stale["elapsed_ms"], 1700)
        self.assertEqual([call["socket_budget_ms"] for call in stale["provider_waits"]], [5000, 1000])
        self.assertEqual(stale["reply"]["status"], "incomplete")
        self.assertEqual(stale["reply"]["scopes"][0]["code"], "independent_evidence_invalid")
        already_stale = exercise(0.2, 0, point_return_delay=1.1)
        self.assertEqual(len(already_stale["provider_waits"]), 1)
        self.assertEqual(already_stale["reply"]["status"], "incomplete")
        self.assertEqual(already_stale["reply"]["scopes"][0]["code"], "independent_evidence_invalid")
