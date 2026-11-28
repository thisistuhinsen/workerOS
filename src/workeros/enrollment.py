"""Compile operator-approved policy against resources already enrolled by the host."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
import re
from time import monotonic_ns

from . import Identity
from .configuration import (
    ConfigurationError, Workflow, _OPTIONS, _REQUEST_OPTIONS, _bool, _decode_json, _fields,
    _identifier, _integer, _require, _serve, execute,
)
from .managed import EffectStatus
from .recording import RecordError, RecordKey, RecorderPolicy, _decode_policy
from .supervisor import DirectChildSupervisor


_BINDINGS = "executable descriptors supervisor custody inherited observers meters evidence streams owner_appends"
_LIFECYCLE = frozenset(("wait", "cancel", "cleanup"))
_RECORDING = frozenset(("record", "readback", "purge", "verify_durable", "recover_receipt", "sweep"))
_PROJECTABLE = frozenset(("read", "write", "launch", "release", "wait", "cancel", "cleanup",
                           "observe", "meter", "validate"))
_ABI_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


@dataclass(frozen=True, slots=True)
class DescriptorBinding:
    """Borrowed originals and optional sink, kept stable by their existing owner."""

    identity: Identity
    input_fd: int | None = None
    writer_fd: int | None = None
    sink: object = None


@dataclass(frozen=True, slots=True, kw_only=True)
class HostBindings:
    """Trusted registries. A None registry marks an unsupported capability."""

    authorize: object = None
    authorize_release: object = None
    settled: object = None
    executables: Mapping | None = None
    descriptors: Mapping | None = None
    inherited: Mapping | None = None
    supervisors: frozenset[str] | None = None
    custody: Mapping | None = None
    observers: Mapping | None = None
    meters: Mapping | None = None
    evidence: Mapping | None = None
    stores: Mapping | None = None
    projectors: Mapping | None = None
    directories: Mapping | None = None
    environment: Mapping | None = field(default=None, repr=False)
    streams: Mapping | None = None
    owner_appends: Mapping | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class ProjectedEvidence:
    key: RecordKey
    data: bytes = field(repr=False)
    effect: EffectStatus = EffectStatus.UNKNOWN
    source: str | None = None
    scope: str | None = None


class CompiledPolicy(Mapping):
    """One authorized host session with separate owned state for each workflow."""

    def __init__(self, workflows, capture):
        self._workflows = dict(workflows)
        self._capture = dict(capture)

    def __getitem__(self, key):
        return self._workflows[key]

    def __iter__(self):
        return iter(self._workflows)

    def __len__(self):
        return len(self._workflows)

    def execute(self, request, *, finish=None, announce_capture=None):
        """Dispatch once and optionally project an operation result into evidence."""
        _require(request.recorder is None, "inline_recorder_not_supported")
        capture = self._capture.get((request.workflow, request.operation))

        def before(workflow):
            if request.operation == "launch" and capture is not None:
                try:
                    workflow.recorder.check_required_local(capture[1])
                except (OSError, RecordError) as exc:
                    raise ConfigurationError("required_capture_destination_unavailable") from exc
                if announce_capture is not None:
                    announce_capture()

        result = execute(request, self, _before=before)
        if finish is not None:
            result = finish(request, result)
        if capture is not None:
            project, kind = capture
            try:
                selected = project(request, result)
                if type(selected) is not ProjectedEvidence:
                    raise ValueError("expected a typed evidence projection")
                receipt = self[request.workflow].recorder.record(
                    selected.key, kind, selected.data, effect=selected.effect,
                    source=selected.source, scope=selected.scope,
                )
                evidence = {"status": "reported", "record": asdict(receipt),
                            "required_complete": receipt.required_complete}
            except Exception:
                evidence = {"status": "unavailable", "required_complete": False}
            return {**result, "capture": evidence}
        return result

    def serve(self, source, destination, *, max_bytes=1_048_576):
        return _serve(self.execute, source, destination, max_bytes)


def decode_policy(data):
    """Decode the approved policy bytes with duplicate-key rejection."""
    return _decode_json(data)


def _named(value):
    _require(type(value) is dict, "invalid_policy_map")
    return {_identifier(key): item for key, item in value.items()}


def _operations(value, *, allowed=_OPTIONS):
    _require(type(value) is list and bool(value), "invalid_operation_list")
    names = [_identifier(item) for item in value]
    choices = frozenset(names)
    _require(len(names) == len(choices) and choices <= allowed.keys(), "invalid_operation_list")
    return choices


def _resolve(catalog, ref):
    name = _identifier(ref)
    _require(catalog is not None, "unsupported_binding")
    _require(name in catalog, "unknown_binding")
    return catalog[name]


def _resolve_map(catalog, refs):
    return {key: _resolve(catalog, name) for key, name in _named(refs).items()}


def _budget(value, maximum):
    value = _integer(value, minimum=1)
    _require(value <= maximum, "policy_budget_out_of_range")
    return value * 1_000_000


def _recorder(config, stores):
    _require(stores is not None, "unsupported_binding")
    try:
        return RecorderPolicy.from_dict(config, stores=stores)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("invalid_enrolled_recorder") from exc


def _workflow(name, spec, roles, recorders, host, now):
    _fields(spec, "role operations bindings",
            "timeout_ms cleanup_ms require_supervision require_custody recorder capture args cwd env")
    role = _identifier(spec["role"])
    operations = _operations(spec["operations"], allowed=_REQUEST_OPTIONS)
    _require(role in roles, "unknown_role")
    _require(operations <= roles[role], "role_operation_forbidden")
    refs = _fields(spec["bindings"], "", _BINDINGS)
    append_ops = operations & {"owner_append", "owner_append_status"}
    owner_appends = {}
    if append_ops or "owner_appends" in refs:
        from .owner_append import OwnerAppendBinding

        _require(append_ops and refs.get("owner_appends") and host.owner_appends is not None,
                 "owner_append_binding_missing")
        owner_appends = _resolve_map(host.owner_appends, refs["owner_appends"])
        for alias, binding in owner_appends.items():
            _require(type(binding) is OwnerAppendBinding and
                     (binding.workflow, binding.role, binding.alias, binding.registry_reference) ==
                     (name, role, alias, refs["owner_appends"][alias]), "owner_append_binding_mismatch")
    active = now + _budget(spec.get("timeout_ms", 30_000), 86_400_000)
    cleanup = active + _budget(spec["cleanup_ms"], 60_000) if "cleanup_ms" in spec else None
    supervised = _bool(spec.get("require_supervision", False))
    strict = _bool(spec.get("require_custody", False))
    if strict:
        _require("release" in operations and not operations & {"read", "write", "launch"}
                 and not refs.get("inherited"), "protected_original_requires_release")

    if "executable" in refs:
        argv = _resolve(host.executables, refs["executable"])
        _require(type(argv) is tuple and bool(argv) and all(
            type(item) is str and "\0" not in item for item in argv
        ) and bool(argv[0]), "invalid_executable_binding")
    else:
        argv = ()
    _require(not operations & {"launch", "release"} or argv, "executable_binding_required")
    if "args" in spec:
        args = spec["args"]
        _require(argv and type(args) is list and len(args) <= 128 and all(
            type(value) is str and len(value) <= 4096 and "\0" not in value for value in args
        ), "invalid_program_arguments")
        argv = (*argv, *args)
    cwd = _resolve(host.directories, spec["cwd"]) if "cwd" in spec else None
    env = _resolve_map(host.environment, spec.get("env", {}))
    streams = _resolve_map(host.streams, refs.get("streams", {}))
    _require(not (cwd is not None or env or streams) or ("launch" in operations and "release" not in operations),
             "launch_context_requires_ordinary_launch")
    _require(all(_ENV_NAME.fullmatch(key) and not key.startswith("WORKER_HANDOFF_")
                 and type(value) is str and "\0" not in value for key, value in env.items()),
             "invalid_environment_binding")
    _require(streams.keys() <= {"stdin", "stdout", "stderr"}
             and all(type(fd) is int and fd >= 3 for fd in streams.values()), "invalid_stream_binding")

    descriptors = _resolve(host.descriptors, refs["descriptors"]) if "descriptors" in refs else None
    if descriptors is not None:
        _require(type(descriptors) is DescriptorBinding and type(descriptors.identity) is Identity,
                 "invalid_descriptor_binding")
    if operations & {"read", "release"}:
        _require(descriptors is not None and descriptors.input_fd is not None, "read_binding_required")
    if "read" in operations:
        _require(descriptors.sink is not None, "read_sink_required")
    if "write" in operations:
        _require(descriptors is not None and descriptors.writer_fd is not None, "writer_binding_required")
    if "release" in operations:
        _require(callable(host.authorize_release), "release_authority_missing")

    inherited = _resolve_map(host.inherited, refs.get("inherited", {}))
    if inherited:
        _require("launch" in operations and all(_ABI_NAME.fullmatch(key) and type(fd) is int and fd >= 3
                                                for key, fd in inherited.items()), "invalid_inherited_binding")
    supervisor = None
    if "supervisor" in refs:
        choice = _identifier(refs["supervisor"])
        _require(host.supervisors is not None, "unsupported_binding")
        _require(choice in host.supervisors, "unknown_binding")
        supervisor = DirectChildSupervisor()
    _require(not (supervised or operations & _LIFECYCLE) or supervisor is not None,
             "supervision_binding_required")
    _require("cleanup" not in operations or cleanup is not None, "cleanup_budget_required")
    custody = _resolve(host.custody, refs["custody"]) if "custody" in refs else None
    _require(not strict or custody is not None, "custody_binding_required")

    sources = {
        key: _resolve_map(getattr(host, key), refs.get(key, {}))
        for key in ("observers", "meters", "evidence")
    }
    for op, key in (("observe", "observers"), ("meter", "meters"), ("validate", "evidence")):
        _require(op not in operations or sources[key], op + "_binding_required")

    recorder = None
    recorder_config = None
    if "recorder" in spec:
        recorder_name = _identifier(spec["recorder"])
        _require(recorder_name in recorders, "unknown_recorder")
        recorder_config = recorders[recorder_name]
        recorder = _recorder(recorder_config, host.stores)
    _require(not operations & _RECORDING or recorder is not None, "recorder_binding_required")
    _require(not operations & {"purge", "sweep"} or callable(host.settled), "settlement_binding_required")

    capture = {}
    for op, entry in _named(spec.get("capture", {})).items():
        _fields(entry, "profile type")
        _require(op in operations & _PROJECTABLE and recorder is not None, "invalid_capture_operation")
        project = _resolve(host.projectors, entry["profile"])
        _require(callable(project), "invalid_projection_binding")
        try:
            kind = recorder.evidence_type(_identifier(entry["type"]))
        except KeyError as exc:
            raise ConfigurationError("capture_type_not_registered") from exc
        capture[name, op] = project, kind

    workflow = Workflow(
        role, operations, active, argv=argv, launch_fds=inherited, launch_cwd=cwd, launch_env=env,
        launch_streams=streams, supervisor=supervisor, custody=custody,
        require_supervision=supervised, require_custody=strict, cleanup_deadline_ns=cleanup,
        identity=descriptors.identity if descriptors else None,
        input_fd=descriptors.input_fd if descriptors else None,
        writer_fd=descriptors.writer_fd if descriptors else None,
        sink=descriptors.sink if descriptors else None,
        recorder=recorder, recorder_config=recorder_config, authorize=host.authorize, authorize_all=True,
        authorize_release=host.authorize_release, settled=host.settled, owner_appends=owner_appends, **sources,
    )
    return workflow, capture


def compile_policy(document, host, *, workflow=None):
    """Compile trusted policy and registry without running a workload or writing a store."""
    _fields(document, "version roles workflows", "recorders")
    _require(type(document["version"]) is int and document["version"] == 1, "unsupported_policy_version")
    _require(type(host) is HostBindings and callable(host.authorize), "host_authority_missing")
    roles = {}
    for name, spec in _named(document["roles"]).items():
        try:
            _fields(spec, "operations")
            roles[name] = _operations(spec["operations"], allowed=_REQUEST_OPTIONS)
        except ConfigurationError as exc:
            exc.path = f"/roles/{name}"
            raise
    workflows = {}
    captures = {}
    recorders = _named(document.get("recorders", {}))
    for name, config in recorders.items():
        try:
            _decode_policy(config)
        except (ValueError, TypeError) as exc:
            error = ConfigurationError("invalid_enrolled_recorder")
            error.path = f"/recorders/{name}"
            raise error from exc
    selections = _named(document["workflows"])
    _require(roles and selections, "empty_policy")
    if workflow is not None:
        selection = _identifier(workflow)
        _require(selection in selections, "unknown_workflow")
        selections = {selection: selections[selection]}
    now = monotonic_ns()
    for name, spec in selections.items():
        try:
            workflows[name], capture = _workflow(name, spec, roles, recorders, host, now)
        except ConfigurationError as exc:
            exc.path = f"/workflows/{name}"
            raise
        captures.update(capture)
    return CompiledPolicy(workflows, captures)
