"""Setup-only managed profiles using an already authorized host manager.

The manager owns authentication, provider qualification and durable storage.
This module does not open handles, start workers or appoint OS principals.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
import re
from threading import Lock
from time import monotonic_ns
from typing import Protocol

from .configuration import ConfigurationError, _bool, _fields, _identifier
from .enrollment import _ABI_NAME, _ENV_NAME, _PROJECTABLE, _RECORDING, _budget, _named, _operations, decode_policy
from .recording import _decode_policy, _name


_HASH = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ProviderRequirement:
    """A host-selected capability, scope and optional independence requirement."""

    kind: str
    name: str
    capability: str
    scope: str
    independent_of: str | None = None

    def __post_init__(self):
        for value in (self.kind, self.name, self.capability, self.scope):
            _name(value)
        if self.independent_of is not None:
            _name(self.independent_of)


@dataclass(frozen=True, slots=True)
class ProfileRequirements:
    """Trusted consumer requirements, checked before any setup write."""

    role: str
    scope: str
    providers: tuple[ProviderRequirement, ...] = ()

    def __post_init__(self):
        _name(self.role)
        _name(self.scope)
        if (type(self.providers) is not tuple or len(self.providers) > 64
                or any(type(item) is not ProviderRequirement for item in self.providers)
                or len({(item.kind, item.name) for item in self.providers}) != len(self.providers)):
            raise ValueError("expected distinct provider requirements")


@dataclass(frozen=True, slots=True)
class ProviderBinding:
    """Manager-verified reference, capability, and scope, without a live handle."""

    name: str
    reference: str
    scope: str
    capability: str
    principal: str
    kind: str
    independent_of: str | None = None

    def __post_init__(self):
        for value in (self.name, self.reference, self.scope, self.capability, self.principal):
            _name(value)
        if self.kind not in ("observers", "meters", "evidence", "custody",
                             "descriptors", "executable", "supervisor", "inherited", "streams"):
            raise ValueError("expected a supported provider kind")
        if self.independent_of is not None:
            _name(self.independent_of)
            if self.independent_of == self.principal:
                raise ValueError("provider is not independent of the declared principal")


@dataclass(frozen=True, slots=True)
class ProfileDefinition:
    """The exact profile and package identity selected by the trusted manager."""

    name: str
    revision: str
    package_version: str
    package_sha256: str
    policy_sha256: str
    manager: str
    scope: str
    clock_id: str
    expires_ns: int
    providers: tuple[ProviderBinding, ...] = ()

    def __post_init__(self):
        for value in (self.name, self.revision, self.package_version, self.manager, self.scope, self.clock_id):
            _name(value)
        if type(self.expires_ns) is not int or not 0 < self.expires_ns < 2**63:
            raise ValueError("expected a bounded appointment expiry")
        for value in (self.package_sha256, self.policy_sha256):
            if type(value) is not str or _HASH.fullmatch(value) is None:
                raise ValueError("expected exact lowercase SHA-256")
        if (type(self.providers) is not tuple or len(self.providers) > 64
                or any(type(p) is not ProviderBinding for p in self.providers)
                or len({(p.kind, p.name) for p in self.providers}) != len(self.providers)):
            raise ValueError("expected distinct provider bindings")
        if any(p.independent_of is not None and p.principal == self.manager for p in self.providers):
            raise ValueError("manager cannot self-attest provider independence")


@dataclass(frozen=True, slots=True)
class ManagerSelection:
    """Authenticated manager selection, valid only in the stated clock context.

    The host must validate all referenced providers, scopes, capabilities,
    revocation and any declared independence before returning this selection.
    The clock ID must identify the same boot, time namespace and monotonic
    domain as the caller's monotonic_ns clock.
    """
    definition: ProfileDefinition
    policy: bytes
    clock_id: str
    expires_ns: int

    def __post_init__(self):
        if type(self.definition) is not ProfileDefinition:
            raise ValueError("expected an approved profile")
        if type(self.policy) is not bytes or not 0 < len(self.policy) <= 1_048_576:
            raise ValueError("expected bounded policy bytes")
        _name(self.clock_id)
        if type(self.expires_ns) is not int or not 0 < self.expires_ns < 2**63:
            raise ValueError("expected bounded expiry")
        if (self.clock_id, self.expires_ns) != (self.definition.clock_id, self.definition.expires_ns):
            raise ValueError("selection clock and expiry must match its appointment")


@dataclass(frozen=True, slots=True)
class ManagerReadback:
    """Authoritative manager readback for a specific profile revision.

    State is present, absent, revoked, pending or unavailable. The manager may
    report absent only when its authoritative durable state proves no create
    for this revision is still unresolved. A present record carries the mapping
    read independently from the manager's durable state.
    """
    state: str
    definition: ProfileDefinition | None = None

    def __post_init__(self):
        if self.state not in ("present", "absent", "revoked", "pending", "unavailable"):
            raise ValueError("invalid manager readback")
        if (self.state == "present") != (type(self.definition) is ProfileDefinition):
            raise ValueError("present readback requires the exact profile definition")


@dataclass(frozen=True, slots=True)
class SetupResult:
    status: str
    code: str
    effect: str
    definition: ProfileDefinition | None = None
    attempt: ProfileDefinition | None = None


@dataclass(frozen=True, slots=True)
class AttemptHistory:
    """Authenticated history for the exact retained attempt."""

    state: str
    definition: ProfileDefinition

    def __post_init__(self):
        if self.state not in ("committed", "not_committed", "pending", "unavailable"):
            raise ValueError("invalid attempt history")
        if type(self.definition) is not ProfileDefinition:
            raise ValueError("expected exact attempted definition")


class ProfileManager(Protocol):
    """Already-authorized manager. Methods must not start a workload.

    select authenticates the caller and the manager, verifies the package and
    all selected provider authorities and policy requirements, and returns
    current ManagerSelection. The manager must compile the policy against
    actual authorized HostBindings before runtime use. Setup readback verifies
    the mapping only, without claiming live bindings or qualification.
    readback independently reads authoritative committed state.
    create atomically revalidates caller authority, provider appointments,
    revocation, expiry, and the exact selected mapping before creating the
    selected revision. It returns no assertion;
    duplicate/concurrent create must never replace a different mapping. The
    manager durably tracks unresolved creates, even across process restarts,
    and reports pending or unavailable until they are reconciled. It must
    refuse a create for any pending revision. An exception from create may
    follow an effect. The caller must reconcile without retrying create.
    After process death the host retrieves the exact original attempted
    definition from its authenticated, retained manager selection and passes
    it as reconcile's expected argument. It must not guess this identity
    from a newer selection or accept it from an untrusted request.
    """
    def select(self, name: str, revision: str) -> ManagerSelection: ...
    def readback(self, name: str, revision: str) -> ManagerReadback: ...
    def create(self, selection: ManagerSelection) -> None: ...


class ManagedProfileSetup:
    """One no-start setup attempt. The manager and callbacks are trusted host code."""

    def __init__(self, manager: ProfileManager, *, clock_id: str, package_sha256: str,
                 requirements: ProfileRequirements | None = None):
        for method in ("select", "readback", "create"):
            if not callable(getattr(manager, method, None)):
                raise ValueError("expected an authorized profile manager")
        _name(clock_id)
        if type(package_sha256) is not str or _HASH.fullmatch(package_sha256) is None:
            raise ValueError("expected the installed package SHA-256")
        if requirements is not None and type(requirements) is not ProfileRequirements:
            raise ValueError("expected trusted profile requirements")
        self._manager = manager
        self._clock_id = clock_id
        self._package_sha256 = package_sha256
        self._requirements = requirements
        self._attempted = {}
        self._confirmed = set()
        self._lock = Lock()

    def _selection(self, name, revision):
        _name(name)
        _name(revision)
        selected = self._manager.select(name, revision)
        if type(selected) is not ManagerSelection:
            raise ConfigurationError("manager_selection_unavailable")
        definition = selected.definition
        if (definition.name, definition.revision) != (name, revision):
            raise ConfigurationError("manager_selection_mismatch")
        if selected.clock_id != self._clock_id or monotonic_ns() >= selected.expires_ns:
            raise ConfigurationError("manager_selection_stale")
        try:
            installed_version = version("workeros")
        except PackageNotFoundError as exc:
            raise ConfigurationError("installed_package_unavailable") from exc
        if (definition.package_version != installed_version
                or definition.package_sha256 != self._package_sha256):
            raise ConfigurationError("package_binding_mismatch")
        if sha256(selected.policy).hexdigest() != definition.policy_sha256:
            raise ConfigurationError("policy_binding_mismatch")
        document = decode_policy(selected.policy)
        if (type(document) is not dict or type(document.get("version")) is not int
                or document["version"] != 1 or type(document.get("workflows")) is not dict
                or name not in document["workflows"]):
            raise ConfigurationError("profile_workflow_missing")
        _fields(document, "version roles workflows", "recorders")
        workflow = document["workflows"][name]
        if type(workflow) is not dict or type(workflow.get("bindings")) is not dict:
            raise ConfigurationError("invalid_profile_bindings")
        _fields(workflow, "role operations bindings",
                "timeout_ms cleanup_ms require_supervision require_custody recorder capture args cwd env")
        _fields(workflow["bindings"], "",
                "executable descriptors supervisor custody inherited observers meters evidence streams")
        roles = _named(document.get("roles"))
        role = _identifier(workflow.get("role"))
        if self._requirements is not None:
            if (role, definition.scope) != (self._requirements.role, self._requirements.scope):
                raise ConfigurationError("profile_requirements_mismatch")
            registered = {(item.kind, item.name): item for item in definition.providers}
            for required in self._requirements.providers:
                item = registered.get((required.kind, required.name))
                if (item is None or (item.capability, item.scope) != (required.capability, required.scope)
                        or (required.independent_of is not None
                            and item.independent_of != required.independent_of)):
                    raise ConfigurationError("provider_requirements_unsatisfied")
        if type(role) is not str or role not in roles or type(roles[role]) is not dict:
            raise ConfigurationError("unknown_role")
        if set(roles[role]) != {"operations"}:
            raise ConfigurationError("invalid_role_fields")
        role_ops = _operations(roles[role]["operations"])
        operations = _operations(workflow.get("operations"))
        if not operations <= role_ops:
            raise ConfigurationError("role_operation_forbidden")
        _budget(workflow.get("timeout_ms", 30_000), 86_400_000)
        if "cleanup_ms" in workflow:
            _budget(workflow["cleanup_ms"], 60_000)
        bindings = workflow["bindings"]
        supervision = _bool(workflow.get("require_supervision", False))
        strict = _bool(workflow.get("require_custody", False))
        recorder_name = workflow.get("recorder")
        if recorder_name is not None:
            recorders = _named(document.get("recorders", {}))
            recorder_name = _identifier(recorder_name)
            if recorder_name not in recorders:
                raise ConfigurationError("unknown_recorder")
            try:
                _, routes = _decode_policy(recorders[recorder_name])
            except (TypeError, ValueError) as exc:
                raise ConfigurationError("invalid_enrolled_recorder") from exc
        else:
            routes = ()
        if operations & _RECORDING and recorder_name is None:
            raise ConfigurationError("recorder_binding_required")
        if "args" in workflow:
            args = workflow["args"]
            if ("executable" not in bindings or type(args) is not list or len(args) > 128
                    or any(type(value) is not str or len(value) > 4096 or "\0" in value for value in args)):
                raise ConfigurationError("invalid_program_arguments")
        env = _named(workflow.get("env", {}))
        if "cwd" in workflow:
            _identifier(workflow["cwd"])
        for key, value in env.items():
            _identifier(value)
            if not _ENV_NAME.fullmatch(key) or key.startswith("WORKER_HANDOFF_"):
                raise ConfigurationError("invalid_environment_binding")
        if ("cwd" in workflow or env or bindings.get("streams")) and (
                "launch" not in operations or "release" in operations):
            raise ConfigurationError("launch_context_requires_ordinary_launch")
        captures = _named(workflow.get("capture", {}))
        route_names = {route.evidence_type.name for route in routes}
        for operation, entry in captures.items():
            _fields(entry, "profile type")
            _identifier(entry["profile"])
            if operation not in operations & _PROJECTABLE or recorder_name is None:
                raise ConfigurationError("invalid_capture_operation")
            if _identifier(entry["type"]) not in route_names:
                raise ConfigurationError("capture_type_not_registered")
        if operations & {"launch", "release"} and "executable" not in bindings:
            raise ConfigurationError("executable_binding_required")
        if operations & {"read", "write", "release"} and "descriptors" not in bindings:
            raise ConfigurationError("descriptor_binding_required")
        if (supervision or operations & {"wait", "cancel", "cleanup"}) and "supervisor" not in bindings:
            raise ConfigurationError("supervision_binding_required")
        if "cleanup" in operations and "cleanup_ms" not in workflow:
            raise ConfigurationError("cleanup_budget_required")
        if strict and (operations & {"read", "write", "launch"} or bindings.get("inherited")):
            raise ConfigurationError("protected_original_requires_release")
        required = set()
        for operation, kind in (("observe", "observers"), ("meter", "meters"), ("validate", "evidence"),
                                (None, "inherited"), (None, "streams")):
            entries = bindings.get(kind, {})
            if type(entries) is not dict or any(type(value) is not str for value in entries.values()):
                raise ConfigurationError("invalid_profile_bindings")
            for alias, target in entries.items():
                _identifier(alias)
                _identifier(target)
            if kind == "inherited" and (entries and ("launch" not in operations
                    or any(not _ABI_NAME.fullmatch(alias) for alias in entries))):
                raise ConfigurationError("invalid_inherited_binding")
            if kind == "streams" and not entries.keys() <= {"stdin", "stdout", "stderr"}:
                raise ConfigurationError("invalid_stream_binding")
            if operation in operations and not entries:
                raise ConfigurationError(operation + "_binding_required")
            required.update((kind, value) for value in entries.values())
        for kind in ("custody", "descriptors", "executable", "supervisor"):
            if kind not in bindings:
                continue
            if type(bindings[kind]) is not str:
                raise ConfigurationError("invalid_profile_bindings")
            _identifier(bindings[kind])
            required.add((kind, bindings[kind]))
        if required != {(item.kind, item.name) for item in definition.providers}:
            raise ConfigurationError("profile_provider_set_mismatch")
        if strict and ("custody" not in bindings or "release" not in operations):
            raise ConfigurationError("profile_custody_binding_missing")
        return selected

    def _readback(self, selection, effect):
        definition = selection.definition
        try:
            read = self._manager.readback(definition.name, definition.revision)
            if type(read) is not ManagerReadback:
                raise ValueError("invalid authoritative readback")
        except Exception:
            return SetupResult("unknown", "manager_readback_unavailable", effect)
        if read.state == "revoked":
            return SetupResult("refused", "profile_revoked", effect)
        if read.state == "unavailable":
            return SetupResult("unknown", "manager_readback_unavailable", effect)
        if read.state == "pending":
            return SetupResult("unknown", "manager_create_pending", effect)
        if read.state == "absent":
            return SetupResult("unknown" if effect == "unknown" else "absent",
                               "profile_not_observed", effect)
        if read.definition != definition:
            return SetupResult("conflict", "profile_revision_conflict", effect)
        try:
            current = self._selection(definition.name, definition.revision)
            if current.definition != definition or current.policy != selection.policy:
                return SetupResult("refused", "manager_selection_changed", effect)
        except ConfigurationError as exc:
            return SetupResult("refused", str(exc), effect)
        except PermissionError:
            return SetupResult("refused", "manager_selection_denied", effect)
        except Exception:
            return SetupResult("unknown", "manager_selection_unavailable", effect)
        self._confirmed.add((definition.name, definition.revision))
        return SetupResult("accepted", "manager_readback_verified", effect, definition)

    def _prepare(self, name, revision, *, effect="not_attempted", attempt=None):
        try:
            return self._selection(name, revision), None
        except PermissionError:
            return None, SetupResult("refused", "manager_selection_denied", effect, attempt=attempt)
        except ConfigurationError as exc:
            return None, SetupResult("refused", str(exc), effect, attempt=attempt)
        except Exception:
            return None, SetupResult("unknown", "manager_selection_unavailable", effect, attempt=attempt)

    def reconcile(self, name, revision, *, expected=None):
        """Read manager state without writing, including after an uncertain create."""
        if not self._lock.acquire(blocking=False):
            return SetupResult("unknown", "manager_setup_busy", "unknown")
        try:
            return self._reconcile(name, revision, expected=expected)
        finally:
            self._lock.release()

    def history(self, expected):
        """Read an authenticated historical mapping without claiming current readiness.

        The optional manager read_history method must authenticate the caller and
        read its authoritative retained record. Expiry and revocation can prevent
        a current selection even when an older commit is visible in history.
        """
        if type(expected) is not ProfileDefinition:
            raise ValueError("expected the originally approved profile definition")
        history = getattr(self._manager, "read_history", None)
        if not callable(history):
            return SetupResult("unknown", "manager_history_unavailable", "unknown")
        try:
            read = history(expected.name, expected.revision)
        except Exception:
            return SetupResult("unknown", "manager_history_unavailable", "unknown")
        if type(read) is not ManagerReadback or read.state in ("unavailable", "pending"):
            return SetupResult("unknown", "manager_history_unavailable", "unknown")
        if read.state == "absent":
            return SetupResult("absent", "manager_history_absent", "unknown")
        if read.state != "present" or read.definition != expected:
            return SetupResult("conflict", "manager_history_mismatch", "unknown")
        return SetupResult("recorded", "manager_history_verified", "unknown", expected)

    def resolve_attempt(self, expected):
        """Read exact authenticated attempt history without retrying any write.

        The optional manager callback must establish the outcome for the original
        attempt, including concurrent and pending writes, using its durable state.
        Since a definition has no unique attempt ID, the manager must guarantee
        at most one create attempt per revision for its entire retained lifetime;
        otherwise it must report an unresolved result.
        """
        if type(expected) is not ProfileDefinition:
            raise ValueError("expected the originally attempted profile definition")
        resolver = getattr(self._manager, "read_attempt", None)
        if not callable(resolver):
            return SetupResult("unknown", "attempt_history_unavailable", "unknown", attempt=expected)
        try:
            result = resolver(expected)
        except Exception:
            return SetupResult("unknown", "attempt_history_unavailable", "unknown", attempt=expected)
        if type(result) is not AttemptHistory or result.definition != expected:
            return SetupResult("unknown", "attempt_history_mismatch", "unknown", attempt=expected)
        if result.state == "not_committed":
            return SetupResult("not_committed", "attempt_not_committed", "not_committed", attempt=expected)
        if result.state == "committed":
            return SetupResult("recorded", "attempt_committed", "committed", attempt=expected)
        return SetupResult("unknown", "attempt_unresolved", "unknown", attempt=expected)

    def _reconcile(self, name, revision, *, expected=None):
        key = (name, revision)
        prior = self._attempted.get(key)
        if expected is not None and (type(expected) is not ProfileDefinition
                                     or (expected.name, expected.revision) != key):
            raise ValueError("expected the original attempted profile definition")
        if prior is not None and expected is not None and expected != prior:
            return SetupResult("conflict", "attempt_definition_mismatch", "unknown", attempt=prior)
        expected = prior if prior is not None else expected
        if expected is None:
            return SetupResult("unknown", "attempt_definition_required", "unknown")
        selected, error = self._prepare(name, revision, effect="unknown", attempt=expected)
        if error:
            return error
        if selected.definition != expected:
            return SetupResult("conflict", "attempt_definition_mismatch", "unknown", attempt=expected)
        result = self._readback(selected, "unknown")
        if result.status != "accepted":
            return replace(result, attempt=expected)
        return result

    def setup(self, name, revision):
        """Attempt setup once. Reconcile uncertain outcomes; do not replay create."""
        if not self._lock.acquire(blocking=False):
            return SetupResult("unknown", "manager_setup_busy", "unknown")
        try:
            return self._setup(name, revision)
        finally:
            self._lock.release()

    def _setup(self, name, revision):
        key = (name, revision)
        prior_attempt = self._attempted.get(key)
        effect = "unknown" if prior_attempt is not None and key not in self._confirmed else "not_attempted"
        selected, error = self._prepare(name, revision, effect=effect, attempt=prior_attempt if effect == "unknown" else None)
        if error:
            return error
        if key in self._attempted:
            if selected.definition != prior_attempt:
                return SetupResult("conflict", "attempt_definition_mismatch", effect, attempt=prior_attempt)
            if key in self._confirmed:
                return self._readback(selected, "not_attempted")
            return SetupResult("unknown", "reconciliation_required", "unknown", attempt=prior_attempt)
        prior = self._readback(selected, "not_attempted")
        if prior.status != "absent":
            return prior
        if monotonic_ns() >= selected.expires_ns:
            return SetupResult("refused", "manager_selection_stale", "not_attempted")
        self._attempted[key] = selected.definition
        try:
            self._manager.create(selected)
        except PermissionError:
            return SetupResult("unknown", "manager_create_unconfirmed", "unknown", attempt=selected.definition)
        except Exception:
            return SetupResult("unknown", "manager_create_unconfirmed", "unknown", attempt=selected.definition)
        result = self._readback(selected, "unknown")
        if result.status != "accepted":
            return SetupResult(result.status, result.code, result.effect, attempt=selected.definition)
        return result
