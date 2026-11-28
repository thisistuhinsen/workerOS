"""Setup-only orchestration for independently authorized host profiles."""

from dataclasses import dataclass
import re
from time import monotonic_ns

from .configuration import ConfigurationError, EvidenceInputs
from .custody import IndependentCustody
from .enrollment import HostBindings, compile_policy, decode_policy
from .managed_cli import _binding_check_time_available
from .profile_setup import ManagedProfileSetup, ManagerSelection, ProfileDefinition, ProfileRequirements, SetupResult
from .recording import _name
from .verify_install import VerificationError, verify_install


@dataclass(frozen=True, slots=True)
class ScopeEvidence:
    """Independently sourced evidence authenticated by the trusted host manager.

    The manager verifies the source and evidence; this object alone is not proof.
    It binds one complete profile definition, role, evidence digest and expiry.
    """

    definition: ProfileDefinition
    role: str
    source: str
    evidence_sha256: str
    clock_id: str
    expires_ns: int
    verified: bool
    binding_generation: str

    def __post_init__(self):
        if type(self.definition) is not ProfileDefinition:
            raise ValueError("expected exact profile definition")
        for value in (self.role, self.source, self.clock_id, self.binding_generation):
            _name(value)
        if type(self.evidence_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", self.evidence_sha256):
            raise ValueError("expected evidence SHA-256")
        if type(self.expires_ns) is not int or not 0 < self.expires_ns < 2**63:
            raise ValueError("expected bounded evidence expiry")
        if type(self.verified) is not bool:
            raise ValueError("expected explicit evidence state")


@dataclass(frozen=True, slots=True)
class ScopeSetup:
    """Host-owned manager, bindings and independently selected requirements."""

    name: str
    revision: str
    requirements: ProfileRequirements
    manager: object
    bindings: HostBindings

    def __post_init__(self):
        _name(self.name)
        _name(self.revision)
        if type(self.requirements) is not ProfileRequirements or type(self.bindings) is not HostBindings:
            raise ValueError("expected host-provided requirements and bindings")
        if any(not callable(getattr(self.manager, method, None))
               for method in ("select", "readback", "create", "verify_bindings", "attest")):
            raise ValueError("expected authenticated manager with independent attestation")


@dataclass(frozen=True, slots=True)
class AggregateResult:
    status: str
    package: str
    scopes: tuple[tuple[str, SetupResult], ...]
    final_checks: tuple[tuple[str, SetupResult], ...] = ()
    observed_start_ns: int | None = None
    observed_end_ns: int | None = None
    valid_until_ns: int | None = None


class _AttestedManager:
    """Recheck real bindings and independent evidence on every manager selection."""

    def __init__(self, scope, clock_id):
        self.scope = scope
        self.clock_id = clock_id
        self.manager = scope.manager
        self._generation = None
        self.valid_until_ns = None

    def select(self, name, revision):
        selected = self.manager.select(name, revision)
        if type(selected) is not ManagerSelection:
            raise ConfigurationError("manager_selection_unavailable")
        definition = selected.definition
        requirements = self.scope.requirements
        try:
            compiled = compile_policy(decode_policy(selected.policy), self.scope.bindings, workflow=name)
            workflow = compiled[name]
            if any(type(entry) is not tuple or len(entry) != 3 or
                   not callable(getattr(entry[0], "sample", None)) or
                   (entry[1] is not None and not callable(getattr(entry[0], "sample_for_scope", None)))
                   for entry in workflow.observers.values()):
                raise ConfigurationError("observer_binding_unavailable")
            if any(not callable(getattr(entry, "sample", None)) for entry in workflow.meters.values()):
                raise ConfigurationError("meter_binding_unavailable")
            if any(type(entry) is not EvidenceInputs for entry in workflow.evidence.values()):
                raise ConfigurationError("evidence_binding_unavailable")
            if workflow.custody is not None and type(workflow.custody) is not IndependentCustody:
                raise ConfigurationError("custody_binding_unavailable")
        except (ConfigurationError, TypeError, ValueError) as exc:
            raise ConfigurationError("host_bindings_unavailable") from exc
        # Trusted host checks actual compiled objects and enrolled resource
        # identities, not just names, against its authoritative registry.
        generation = self.manager.verify_bindings(selected, compiled, self.scope.bindings)
        try:
            _name(generation)
        except (ValueError, TypeError) as exc:
            raise ConfigurationError("binding_generation_unavailable") from exc
        if self._generation is not None and generation != self._generation:
            raise ConfigurationError("binding_generation_changed")
        if not _binding_check_time_available():
            raise TimeoutError()
        evidence = self.manager.attest(selected, requirements, generation)
        if type(evidence) is not ScopeEvidence:
            raise ConfigurationError("independent_evidence_missing")
        if (not evidence.verified or evidence.definition != definition or evidence.role != requirements.role
                or definition.scope != requirements.scope or evidence.source == definition.manager
                or evidence.binding_generation != generation
                or evidence.clock_id != self.clock_id or evidence.clock_id != definition.clock_id
                or monotonic_ns() >= evidence.expires_ns or evidence.expires_ns > definition.expires_ns):
            raise ConfigurationError("independent_evidence_invalid")
        for requirement in requirements.providers:
            if requirement.independent_of is not None and evidence.source == requirement.independent_of:
                raise ConfigurationError("independent_evidence_invalid")
        self._generation = generation
        self.valid_until_ns = min(definition.expires_ns, evidence.expires_ns)
        return selected

    def readback(self, name, revision):
        return self.manager.readback(name, revision)

    def create(self, selection):
        return self.manager.create(selection)

    def read_attempt(self, expected):
        reader = getattr(self.manager, "read_attempt", None)
        if not callable(reader):
            raise ConfigurationError("attempt_history_unavailable")
        return reader(expected)


class AggregateSetup:
    """Orchestrate independent setup outcomes through already authorized host managers.

    Each manager authenticates its caller, validates bindings, verifies its
    independently sourced evidence and protects concurrent or unresolved writes.
    Setup never launches workers. READY describes setup evidence only.
    """

    def __init__(self, scopes, *, wheel, wheel_sha256, clock_id):
        if (type(scopes) is not tuple or not scopes or len(scopes) > 64
                or any(type(scope) is not ScopeSetup for scope in scopes)
                or len({scope.name for scope in scopes}) != len(scopes)
                or len({scope.requirements.scope for scope in scopes}) != len(scopes)):
            raise ValueError("expected distinct named scope setups")
        _name(clock_id)
        self._scopes = scopes
        self._wheel = wheel
        self._wheel_sha256 = wheel_sha256
        self._attesters = {scope.name: _AttestedManager(scope, clock_id) for scope in scopes}
        self._clients = {scope.name: ManagedProfileSetup(
            self._attesters[scope.name], clock_id=clock_id,
            package_sha256=wheel_sha256, requirements=scope.requirements) for scope in scopes}

    def _check_bindings(self, definitions):
        start = monotonic_ns()
        checks = []
        for scope, expected in zip(self._scopes, definitions, strict=True):
            if not _binding_check_time_available():
                checks.append((scope.name, SetupResult("unknown", "manager_selection_unavailable", "not_attempted")))
                continue
            selected, refusal = self._clients[scope.name]._prepare(scope.name, scope.revision)
            if refusal is not None:
                result = refusal
            elif selected.definition != expected:
                result = SetupResult("refused", "commissioned_mapping_mismatch", "not_attempted")
            else:
                result = SetupResult("bindings_verified", "bindings_verified", "not_attempted")
            checks.append((scope.name, result))
        end = monotonic_ns()
        until = None
        if all(result.status == "bindings_verified" for _, result in checks):
            until = min(self._attesters[name].valid_until_ns for name, _ in checks)
        status = "bindings_verified" if until is not None and end < until else "incomplete"
        return AggregateResult(status, "matched", tuple(checks),
                               observed_start_ns=start, observed_end_ns=end, valid_until_ns=until)

    def setup(self):
        """Check the installed package then attempt each scope once, without rollback."""
        try:
            verify_install(self._wheel, self._wheel_sha256)
        except VerificationError as exc:
            return AggregateResult("refused", str(exc), ())
        results = tuple((scope.name, self._clients[scope.name].setup(scope.name, scope.revision))
                        for scope in self._scopes)
        # Preserve the original effect results separately from a non-writing
        # final sweep; independently changing scopes do not form a transaction.
        start = monotonic_ns()
        final = tuple((scope.name, self._clients[scope.name].reconcile(
            scope.name, scope.revision, expected=result.definition))
            for scope, (_, result) in zip(self._scopes, results)
            if result.status == "accepted" and result.definition is not None)
        end = monotonic_ns()
        limits = [self._attesters[name].valid_until_ns for name, _ in final]
        until = min(limits) if limits and all(limit is not None for limit in limits) else None
        status = "ready" if (len(final) == len(results) and until is not None and end < until and
                             all(result.status == "accepted" for _, result in final)) else "incomplete"
        return AggregateResult(status, "matched", results, final, start, end, until)

    def observe(self, definitions):
        """Read each exact mapping once; report the bounded observation interval."""
        if (type(definitions) is not tuple or len(definitions) != len(self._scopes)
                or any(type(d) is not ProfileDefinition for d in definitions)):
            raise ValueError("expected exact commissioned definitions")
        start = monotonic_ns()
        final = tuple((s.name, self.reconcile(s.name, expected=d)) for s,d in zip(self._scopes, definitions))
        end = monotonic_ns()
        limits = [self._attesters[name].valid_until_ns for name, _ in final]
        until = min(limits) if limits and all(limit is not None for limit in limits) else None
        status = "ready" if until is not None and end < until and all(r.status == "accepted" for _,r in final) else "incomplete"
        return AggregateResult(status, "matched", (), final, start, end, until)

    def reconcile(self, name, *, expected):
        """Reconcile one exact retained attempt without issuing a new create."""
        if name not in self._clients or type(expected) is not ProfileDefinition:
            raise ValueError("expected an enrolled scope and original definition")
        try:
            verify_install(self._wheel, self._wheel_sha256)
        except VerificationError as exc:
            return SetupResult("unknown", str(exc), "unknown", attempt=expected)
        scope = next(item for item in self._scopes if item.name == name)
        return self._clients[name].reconcile(name, scope.revision, expected=expected)

    def resolve_attempt(self, name, *, expected):
        """Read exact historical outcome separately from present scope readiness."""
        if name not in self._clients or type(expected) is not ProfileDefinition:
            raise ValueError("expected an enrolled scope and original definition")
        scope = next(item for item in self._scopes if item.name == name)
        if (expected.name, expected.revision, expected.scope) != (name, scope.revision, scope.requirements.scope):
            raise ValueError("attempt does not match enrolled scope")
        return self._clients[name].resolve_attempt(expected)
