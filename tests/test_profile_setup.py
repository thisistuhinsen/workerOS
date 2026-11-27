"""No-start setup against a synthetic, explicitly trusted manager."""
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import patch

from worker_handoff.profile_setup import (
    ManagedProfileSetup, ManagerReadback, ManagerSelection, ProfileDefinition, ProviderBinding,
    ProfileRequirements, ProviderRequirement,
)
import worker_handoff.profile_setup as profile_setup

PACKAGE_HASH = "a" * 64
CLOCK = "fixture-clock"
EXPIRY = 2**62
POLICY = json.dumps({
    "version": 1,
    "roles": {"operator": {"operations": ["observe"]}},
    "workflows": {
        "profile": {"role": "operator", "operations": ["observe"],
                    "bindings": {"observers": {"slot": "trusted-observer"}}},
    },
}, separators=(",", ":")).encode()
PROVIDER = ProviderBinding("trusted-observer", "appointment-1", "scope-1", "point",
                           "observer-user", "observers", "writer-user")
DEFINITION = ProfileDefinition("profile", "revision-1", "0.8.0", PACKAGE_HASH,
                               sha256(POLICY).hexdigest(), "manager", "run-scope", CLOCK, EXPIRY, (PROVIDER,))


class SyntheticManager:
    """Registry selection and authoritative state are separate test fixtures."""

    def __init__(self, definition=DEFINITION, policy=POLICY):
        self.selection = ManagerSelection(definition, policy, definition.clock_id, definition.expires_ns)
        self.state = {}
        self.reads = 0
        self.creates = 0
        self.starts = 0
        self.denied = False
        self.unavailable = False
        self.lose_create_reply = False
        self.hide_readback = False
        self.revoked = False
        self.pending = False

    def select(self, name, revision):
        if self.denied:
            raise PermissionError("synthetic denied caller")
        if self.unavailable:
            raise OSError("synthetic unavailable manager")
        return self.selection

    def readback(self, name, revision):
        self.reads += 1
        if self.hide_readback:
            return ManagerReadback("unavailable")
        if self.revoked:
            return ManagerReadback("revoked")
        if self.pending:
            return ManagerReadback("pending")
        record = self.state.get((name, revision))
        return ManagerReadback("present", record) if record else ManagerReadback("absent")

    def create(self, selected):
        self.creates += 1
        self.state[(selected.definition.name, selected.definition.revision)] = selected.definition
        if self.lose_create_reply:
            raise OSError("synthetic lost acknowledgement")


class ProfileSetupTest(TestCase):
    def setUp(self):
        self.package_version = self.enterContext(
            patch("worker_handoff.profile_setup.version", return_value="0.8.0")
        )
        self.manager = SyntheticManager()
        self.setup = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)

    def test_selected_requirements_refuse_wrong_capability_scope_role_or_independence(self):
        expected = ProviderRequirement("observers", "trusted-observer", "point", "scope-1", "writer-user")
        for requirements in (
            ProfileRequirements("other-role", "run-scope", (expected,)),
            ProfileRequirements("operator", "wrong-scope", (expected,)),
            ProfileRequirements("operator", "run-scope", (replace(expected, capability="interval"),)),
            ProfileRequirements("operator", "run-scope", (replace(expected, scope="other-scope"),)),
            ProfileRequirements("operator", "run-scope", (replace(expected, independent_of="other-user"),)),
        ):
            setup = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH,
                                        requirements=requirements)
            result = setup.setup("profile", "revision-1")
            self.assertEqual(result.status, "refused")
            self.assertIsNone(result.definition)
        self.assertEqual(self.manager.creates, 0)
        setup = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH,
                                    requirements=ProfileRequirements("operator", "run-scope", (expected,)))
        self.assertEqual(setup.setup("profile", "revision-1").status, "accepted")
        self.assertEqual(self.manager.starts, 0)

    def test_historical_readback_does_not_claim_current_readiness_or_repeat_create(self):
        self.manager.state[("profile", "revision-1")] = DEFINITION
        self.manager.revoked = True
        self.manager.read_history = lambda name, revision: ManagerReadback("present", self.manager.state[(name, revision)])
        result = self.setup.history(DEFINITION)
        self.assertEqual((result.status, result.code, result.effect),
                         ("recorded", "manager_history_verified", "unknown"))
        self.assertEqual(self.setup.reconcile("profile", "revision-1", expected=DEFINITION).status, "refused")
        self.assertEqual(self.manager.creates, 0)
        other = replace(DEFINITION, scope="other-scope")
        self.assertEqual(self.setup.history(other).status, "conflict")

    def test_setup_reads_manager_state_after_commit_and_repeat_never_starts(self):
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.effect),
                         ("accepted", "manager_readback_verified", "unknown"))
        self.assertEqual(result.definition, DEFINITION)
        self.assertEqual((self.manager.creates, self.manager.reads, self.manager.starts), (1, 2, 0))
        repeated = self.setup.setup("profile", "revision-1")
        self.assertEqual((repeated.status, self.manager.creates), ("accepted", 1))
        repeat = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
        result = repeat.setup("profile", "revision-1")
        self.assertEqual((result.status, result.effect, self.manager.creates),
                         ("accepted", "not_attempted", 1))

    def test_optional_provider_is_not_required_for_plain_profile(self):
        policy = json.dumps({
            "version": 1,
            "roles": {"operator": {"operations": ["launch"]}},
            "workflows": {"profile": {"role": "operator", "operations": ["launch"],
                                      "bindings": {"executable": "tool"}}},
        }).encode()
        executable = ProviderBinding("tool", "executable-ref", "run-scope", "launch", "operator",
                                     "executable")
        definition = replace(DEFINITION, providers=(executable,), policy_sha256=sha256(policy).hexdigest())
        manager = SyntheticManager(definition, policy)
        result = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH).setup(
            "profile", "revision-1"
        )
        self.assertEqual(result.status, "accepted")
        self.assertEqual((manager.creates, manager.starts), (1, 0))
        self.assertEqual(result.definition.providers, (executable,))

    def test_preopened_descriptor_requires_typed_scoped_reference_and_is_never_persisted(self):
        policy = json.dumps({
            "version": 1,
            "roles": {"operator": {"operations": ["read"]}},
            "workflows": {"profile": {"role": "operator", "operations": ["read"],
                                      "bindings": {"descriptors": "preopened"}}},
        }).encode()
        base = replace(DEFINITION, providers=(), policy_sha256=sha256(policy).hexdigest())
        manager = SyntheticManager(base, policy)
        api = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
        missing = api.setup("profile", "revision-1")
        self.assertEqual((missing.status, missing.code), ("refused", "profile_provider_set_mismatch"))
        self.assertEqual(manager.creates, 0)

        preopened = ProviderBinding("preopened", "manager-original-ref", "file-scope",
                                    "read", "reader-user", "descriptors")
        approved = replace(base, providers=(preopened,))
        manager.selection = replace(manager.selection, definition=approved)
        manager.state[("profile", "revision-1")] = replace(
            approved, providers=(replace(preopened, scope="wrong-file-scope"),))
        result = api.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.definition),
                         ("conflict", "profile_revision_conflict", None))
        manager.state.clear()
        result = api.setup("profile", "revision-1")
        self.assertEqual((result.status, result.definition), ("accepted", approved))
        saved = manager.state[("profile", "revision-1")]
        self.assertEqual(saved.providers[0].reference, "manager-original-ref")
        self.assertNotIn("fd", saved.providers[0].__slots__)
        self.assertNotIn("handle", saved.providers[0].__slots__)
        for raw in (3, object()):
            with self.subTest(raw=type(raw)), self.assertRaises(ValueError):
                replace(preopened, reference=raw)
        self.assertEqual((manager.creates, manager.starts), (1, 0))

    def test_denied_unavailable_expired_and_wrong_scope_refuse_or_stay_unknown(self):
        self.manager.denied = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.effect),
                         ("refused", "manager_selection_denied", "not_attempted"))
        self.manager.denied = False
        self.manager.unavailable = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.effect),
                         ("unknown", "manager_selection_unavailable", "not_attempted"))
        self.manager.unavailable = False
        self.manager.selection = replace(self.manager.selection, definition=replace(DEFINITION, expires_ns=1),
                                         expires_ns=1)
        self.assertEqual(self.setup.setup("profile", "revision-1").code, "manager_selection_stale")
        self.manager.selection = replace(self.manager.selection,
                                         definition=replace(DEFINITION, clock_id="wrong"),
                                         expires_ns=EXPIRY, clock_id="wrong")
        self.assertEqual(self.setup.setup("profile", "revision-1").code, "manager_selection_stale")
        self.assertEqual((self.manager.creates, self.manager.starts), (0, 0))

    def test_policy_and_package_identity_mismatches_refuse_before_write(self):
        self.manager.selection = replace(self.manager.selection, policy=POLICY+b" ")
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.effect),
                         ("refused", "policy_binding_mismatch", "not_attempted"))
        self.manager.selection = replace(self.manager.selection, policy=POLICY)
        other = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256="b"*64)
        self.assertEqual(other.setup("profile", "revision-1").code, "package_binding_mismatch")
        self.assertEqual((self.manager.creates, self.manager.starts), (0, 0))

    def test_authoritative_mismatch_and_revocation_never_supply_a_receipt(self):
        conflicting_provider = replace(PROVIDER, scope="different-scope")
        conflicting = replace(DEFINITION, providers=(conflicting_provider,))
        self.manager.state[("profile", "revision-1")] = conflicting
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.definition),
                         ("conflict", "profile_revision_conflict", None))
        self.manager.revoked = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.definition),
                         ("refused", "profile_revoked", None))
        self.assertEqual((self.manager.creates, self.manager.starts), (0, 0))

    def test_changed_appointment_expiry_or_clock_conflicts_with_stored_revision(self):
        key = ("profile", "revision-1")
        self.manager.state[key] = DEFINITION
        for field, value in (("expires_ns", EXPIRY - 1), ("clock_id", "old-clock")):
            with self.subTest(field=field):
                self.manager.state[key] = replace(DEFINITION, **{field: value})
                result = self.setup.setup(*key)
                self.assertEqual((result.status, result.code, result.definition),
                                 ("conflict", "profile_revision_conflict", None))
        self.manager.state[key] = DEFINITION
        self.assertEqual(self.setup.setup(*key).status, "accepted")
        self.assertEqual(self.manager.creates, 0)

    def test_selection_cannot_relabel_the_appointment_clock_or_extend_its_expiry(self):
        for changes in ({"clock_id": "other-clock"}, {"expires_ns": EXPIRY + 1}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "must match"):
                replace(self.manager.selection, **changes)

    def test_same_principal_cannot_self_attest_independence(self):
        with self.assertRaisesRegex(ValueError, "not independent"):
            replace(PROVIDER, independent_of=PROVIDER.principal)
        with self.assertRaisesRegex(ValueError, "self-attest"):
            replace(DEFINITION, manager=PROVIDER.principal)

    def test_lost_create_reply_is_reconciled_without_repeating_create(self):
        self.manager.lose_create_reply = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.effect, result.definition),
                         ("unknown", "manager_create_unconfirmed", "unknown", None))
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code), ("unknown", "reconciliation_required"))
        result = self.setup.reconcile("profile", "revision-1")
        self.assertEqual((result.status, result.definition), ("accepted", DEFINITION))
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual(result.status, "accepted")
        self.assertEqual((self.manager.creates, self.manager.starts), (1, 0))

    def test_readback_unavailable_never_reports_accepted(self):
        self.manager.hide_readback = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.definition, result.effect),
                         ("unknown", None, "not_attempted"))
        self.assertEqual((self.manager.creates, self.manager.starts), (0, 0))

    def test_pending_create_survives_new_client_and_blocks_replay(self):
        self.manager.pending = True
        fresh = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
        result = fresh.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.definition),
                         ("unknown", "manager_create_pending", None))
        self.assertEqual((self.manager.creates, self.manager.starts), (0, 0))

    def test_missing_policy_provider_refuses_without_writing(self):
        definition = replace(DEFINITION, providers=())
        self.manager.selection = replace(self.manager.selection, definition=definition)
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code, result.definition),
                         ("refused", "profile_provider_set_mismatch", None))
        self.assertEqual((self.manager.creates, self.manager.starts), (0, 0))

    def test_invalid_policy_or_missing_observer_refuses_without_commit(self):
        baseline = json.loads(POLICY)
        missing_observer = json.loads(POLICY)
        missing_observer["workflows"]["profile"]["bindings"]["observers"] = {}
        no_roles = json.loads(POLICY)
        del no_roles["roles"]
        no_operations = json.loads(POLICY)
        del no_operations["workflows"]["profile"]["operations"]
        for doc in (missing_observer, no_roles, no_operations):
            with self.subTest(policy=doc):
                raw = json.dumps(doc).encode()
                definition = replace(DEFINITION, policy_sha256=sha256(raw).hexdigest())
                manager = SyntheticManager(definition, raw)
                result = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH).setup(
                    "profile", "revision-1")
                self.assertNotEqual(result.status, "accepted")
                self.assertIsNone(result.definition)
                self.assertEqual((manager.creates, manager.starts), (0, 0))

    def test_record_without_recorder_or_read_with_cwd_refuses_before_commit(self):
        cases = (
            ({"role": "operator", "operations": ["record"], "bindings": {}},
             "recorder_binding_required"),
            ({"role": "operator", "operations": ["read"], "bindings": {"descriptors": "preopened"},
              "cwd": "workdir"}, "launch_context_requires_ordinary_launch"),
        )
        for workflow, code in cases:
            with self.subTest(workflow=workflow):
                doc = {"version": 1, "roles": {"operator": {"operations": workflow["operations"]}},
                       "workflows": {"profile": workflow}}
                raw = json.dumps(doc).encode()
                descriptors = () if "descriptors" not in workflow["bindings"] else (
                    ProviderBinding("preopened", "file-ref", "file-scope", "read", "operator", "descriptors"),
                )
                definition = replace(DEFINITION, policy_sha256=sha256(raw).hexdigest(),
                                     providers=descriptors)
                manager = SyntheticManager(definition, raw)
                result = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH).setup(
                    "profile", "revision-1")
                self.assertEqual((result.status, result.effect, result.definition),
                                 ("refused", "not_attempted", None))
                self.assertEqual(result.code, code)
                self.assertEqual((manager.creates, manager.starts), (0, 0))

    def test_observer_and_meter_named_the_same_require_both_provider_kinds(self):
        doc = json.loads(POLICY)
        role = doc["roles"]["operator"]["operations"]
        workflow = doc["workflows"]["profile"]
        role.append("meter")
        workflow["operations"].append("meter")
        workflow["bindings"]["meters"] = {"measurement": "trusted-observer"}
        raw = json.dumps(doc).encode()
        definition = replace(DEFINITION, policy_sha256=sha256(raw).hexdigest())
        manager = SyntheticManager(definition, raw)
        api = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
        result = api.setup("profile", "revision-1")
        self.assertEqual((result.status, result.code), ("refused", "profile_provider_set_mismatch"))
        self.assertEqual(manager.creates, 0)
        meter = replace(PROVIDER, kind="meters", reference="meter-appointment",
                        principal="meter-user", scope="meter-scope")
        manager.selection = replace(manager.selection, definition=replace(
            definition, providers=(PROVIDER, meter)))
        self.assertEqual(api.setup("profile", "revision-1").status, "accepted")
        self.assertEqual((manager.creates, manager.starts), (1, 0))

    def test_uncertain_attempt_cannot_reconcile_a_concurrent_changed_definition(self):
        self.manager.lose_create_reply = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual((result.effect, result.attempt), ("unknown", DEFINITION))
        changed = replace(DEFINITION, providers=(replace(PROVIDER, reference="appointment-2"),))
        self.manager.selection = replace(self.manager.selection, definition=changed)
        self.manager.state[("profile", "revision-1")] = changed
        result = self.setup.reconcile("profile", "revision-1")
        self.assertEqual((result.status, result.effect, result.definition, result.attempt),
                         ("conflict", "unknown", None, DEFINITION))
        fresh = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
        result = fresh.reconcile("profile", "revision-1", expected=DEFINITION)
        self.assertEqual((result.status, result.definition), ("conflict", None))
        self.assertEqual((self.manager.creates, self.manager.starts), (1, 0))

    def test_restarted_client_requires_original_expected_attempt(self):
        self.manager.lose_create_reply = True
        uncertain = self.setup.setup("profile", "revision-1")
        self.assertEqual((uncertain.status, uncertain.effect, uncertain.attempt),
                         ("unknown", "unknown", DEFINITION))
        restarted = ManagedProfileSetup(self.manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
        missing = restarted.reconcile("profile", "revision-1")
        self.assertEqual((missing.status, missing.code, missing.effect, missing.definition),
                         ("unknown", "attempt_definition_required", "unknown", None))
        wrong = replace(DEFINITION, scope="wrong-scope")
        mismatch = restarted.reconcile("profile", "revision-1", expected=wrong)
        self.assertEqual((mismatch.status, mismatch.definition, mismatch.effect),
                         ("conflict", None, "unknown"))
        verified = restarted.reconcile("profile", "revision-1", expected=uncertain.attempt)
        self.assertEqual((verified.status, verified.definition), ("accepted", DEFINITION))
        self.assertEqual((self.manager.creates, self.manager.starts), (1, 0))

    def test_denied_selection_after_unknown_preserves_the_effect_and_attempt(self):
        self.manager.lose_create_reply = True
        result = self.setup.setup("profile", "revision-1")
        self.assertEqual(result.effect, "unknown")
        self.manager.denied = True
        for invoke in (self.setup.setup, self.setup.reconcile):
            result = invoke("profile", "revision-1")
            self.assertEqual((result.status, result.code, result.effect, result.attempt),
                             ("refused", "manager_selection_denied", "unknown", DEFINITION))
            self.assertIsNone(result.definition)
        self.assertEqual((self.manager.creates, self.manager.starts), (1, 0))

    def test_concurrent_calls_do_not_submit_duplicate_creates(self):
        entered, proceed = Event(), Event()
        original_select = self.manager.select

        def blocked_select(name, revision):
            entered.set()
            if not proceed.wait(3):
                raise RuntimeError("synthetic manager fixture timed out")
            return original_select(name, revision)

        self.manager.select = blocked_select
        results = []
        worker = Thread(target=lambda: results.append(self.setup.setup("profile", "revision-1")))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            busy = self.setup.setup("profile", "revision-1")
            self.assertEqual((busy.status, busy.code, busy.effect, busy.definition),
                             ("unknown", "manager_setup_busy", "unknown", None))
            self.assertEqual(self.manager.creates, 0)
        finally:
            proceed.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual((len(results), results[0].status, self.manager.creates, self.manager.starts),
                         (1, "accepted", 1, 0))

    def test_expiry_after_commit_cannot_report_an_accepted_profile(self):
        manager = self.manager
        original_create = manager.create

        def create_then_expire(selection):
            original_create(selection)
            manager.selection = replace(manager.selection, definition=replace(DEFINITION, expires_ns=1),
                                        expires_ns=1)

        manager.create = create_then_expire
        result = self.setup.setup("profile", "revision-1")
        self.assertNotEqual(result.status, "accepted")
        self.assertIsNone(result.definition)
        self.assertEqual((manager.creates, manager.starts), (1, 0))

    def test_reopen_in_second_process_reads_manager_file_without_create(self):
        from dataclasses import asdict

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_file = root / "manager.json"

            class FileManager(SyntheticManager):
                def readback(self, name, revision):
                    self.reads += 1
                    if not state_file.exists():
                        return ManagerReadback("absent")
                    data = json.loads(state_file.read_text())
                    data["providers"] = tuple(ProviderBinding(**entry) for entry in data["providers"])
                    return ManagerReadback("present", ProfileDefinition(**data))

                def create(self, selection):
                    self.creates += 1
                    state_file.write_text(json.dumps(asdict(selection.definition)))

            manager = FileManager()
            setup = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
            self.assertEqual(setup.setup("profile", "revision-1").status, "accepted")
            self.assertEqual((manager.creates, manager.starts), (1, 0))

            child = """
import json, sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from worker_handoff.profile_setup import ManagedProfileSetup, ManagerReadback, ProfileDefinition, ProviderBinding
from test_profile_setup import SyntheticManager, CLOCK, PACKAGE_HASH
class Reopened(SyntheticManager):
    def readback(self, name, revision):
        data = json.loads(Path(sys.argv[1]).read_text())
        data["providers"] = tuple(ProviderBinding(**item) for item in data["providers"])
        return ManagerReadback("present", ProfileDefinition(**data))
    def create(self, selection):
        raise AssertionError("readback must never create")
manager = Reopened()
with patch("worker_handoff.profile_setup.version", return_value="0.8.0"):
    result = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH).reconcile(
        "profile", "revision-1", expected=manager.selection.definition)
print(json.dumps({"status": result.status, "effect": result.effect,
                  "profile": result.definition.name, "starts": manager.starts}))
"""
            env = {"PATH": os.environ["PATH"], "PYTHONPATH": os.pathsep.join((
                str(Path(profile_setup.__file__).resolve().parent.parent),
                str(Path(__file__).resolve().parent),
            ))}
            process = subprocess.run([sys.executable, "-c", child, str(state_file)], env=env,
                                     text=True, capture_output=True, timeout=10, check=True)
            self.assertEqual(json.loads(process.stdout), {
                "status": "accepted", "effect": "unknown", "profile": "profile", "starts": 0,
            })

    def test_setup_with_synthetic_external_manager_and_independent_reopen(self):
        # The JSON subprocess protocol belongs only to this test fixture.
        # A real deployment must authenticate its own manager and appointments.
        server = """
import json, os, sys
from dataclasses import asdict
from pathlib import Path
from time import monotonic_ns
from test_profile_setup import DEFINITION, POLICY, CLOCK, EXPIRY
state, log = map(Path, sys.argv[1:3])
req = json.loads(sys.stdin.read())
with log.open("a") as output:
    output.write(req["operation"] + "\\n")
if req["operation"] == "select":
    result = {"definition": asdict(DEFINITION), "policy": POLICY.decode(),
              "clock_id": CLOCK, "expires_ns": EXPIRY}
elif req["operation"] == "readback":
    result = {"state": "present", "definition": json.loads(state.read_text())} if state.exists() else {"state": "absent"}
elif req["operation"] == "create":
    if req["definition"] != json.loads(json.dumps(asdict(DEFINITION))) or state.exists():
        raise SystemExit("refused")
    temp = state.with_suffix(".tmp")
    with temp.open("x") as output:
        json.dump(req["definition"], output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, state)
    result = {"state": "written"}
else:
    raise SystemExit("unsupported operation")
print(json.dumps(result))
"""
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "manager.py"
            state = root / "state.json"
            calls = root / "calls.txt"
            script.write_text(server)
            env = {"PATH": os.environ["PATH"], "PYTHONPATH": os.pathsep.join((
                str(Path(profile_setup.__file__).resolve().parent.parent),
                str(Path(__file__).resolve().parent),
            ))}

            def call(operation, **kwargs):
                result = subprocess.run([sys.executable, str(script), str(state), str(calls)],
                                        input=json.dumps({"operation": operation, **kwargs}),
                                        env=env, text=True, capture_output=True, timeout=10, check=True)
                return json.loads(result.stdout)

            def definition(data):
                data["providers"] = tuple(ProviderBinding(**item) for item in data["providers"])
                return ProfileDefinition(**data)

            class ExternalManager:
                def select(self, name, revision):
                    result = call("select", name=name, revision=revision)
                    return ManagerSelection(definition(result["definition"]), result["policy"].encode(),
                                            result["clock_id"], result["expires_ns"])

                def readback(self, name, revision):
                    result = call("readback", name=name, revision=revision)
                    return ManagerReadback(result["state"], definition(result["definition"])
                                           if result["state"] == "present" else None)

                def create(self, selection):
                    from dataclasses import asdict
                    call("create", definition=asdict(selection.definition))

            manager = ExternalManager()
            result = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH).setup(
                "profile", "revision-1")
            self.assertEqual((result.status, result.definition), ("accepted", DEFINITION))
            reopened = ManagedProfileSetup(manager, clock_id=CLOCK, package_sha256=PACKAGE_HASH)
            self.assertEqual(reopened.reconcile("profile", "revision-1", expected=DEFINITION).status, "accepted")
            actions = calls.read_text().splitlines()
            self.assertEqual(actions.count("create"), 1)
            self.assertGreaterEqual(actions.count("readback"), 3)
            self.assertEqual(set(actions), {"select", "readback", "create"})
