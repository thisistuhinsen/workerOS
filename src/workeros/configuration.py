"""Versioned JSON requests for workflows already enrolled by an application."""

import base64
import binascii
from dataclasses import asdict, dataclass, field
import json
import os
import re
from threading import Event
from time import monotonic_ns
from typing import Mapping

from .evidence import EvidenceScope, RunBinding, ScopePhase, validate_run_evidence, validate_scope_evidence
from .managed import EffectStatus, PositionalWrite, ReleasePlan, release_executable
from .original import AppendWrite, Identity, Original, Writer
from .recording import RecordError, RecordKey, RecordReceipt, RecorderPolicy, _decode_policy, _name
from .scope_meter import CgroupSample, cpu_delta_usec
from .supervisor import SupervisionStartError
from .workers import WorkerRoster


class ConfigurationError(ValueError):
    """A fixed request error code. No request contents are printed."""


@dataclass(frozen=True, slots=True)
class EvidenceInputs:
    binding: RunBinding
    events: tuple = ()
    scope: EvidenceScope | None = None
    reports: tuple = ()
    observer_id: str | None = None
    meter_id: str | None = None
    meter_samples: tuple[CgroupSample, ...] = ()

    def __post_init__(self):
        if self.scope is not None and self.scope.run != self.binding:
            raise ValueError("scope and evidence run binding differ")
        if type(self.meter_samples) is not tuple or len(self.meter_samples) not in (0, 2) or any(
            type(sample) is not CgroupSample for sample in self.meter_samples
        ):
            raise ValueError("expected zero or two cgroup samples")


@dataclass(slots=True)
class Workflow:
    """Trusted application-side registrations. JSON cannot create these bindings."""

    role: str
    operations: frozenset[str]
    deadline_ns: int
    identity: Identity | None = None
    input_fd: int | None = None
    writer_fd: int | None = None
    sink: object = None
    argv: tuple[str, ...] = ()
    launch_env: Mapping = field(default_factory=dict, repr=False)
    roster: WorkerRoster = field(default_factory=WorkerRoster)
    supervisor: object = None
    custody: object = None
    require_supervision: bool = False
    require_custody: bool = False
    cancel: Event | None = None
    cleanup_deadline_ns: int | None = None
    observers: Mapping = field(default_factory=dict)
    meters: Mapping = field(default_factory=dict)
    evidence: Mapping[str, EvidenceInputs] = field(default_factory=dict)
    recorder: RecorderPolicy | None = None
    recorder_config: dict | None = None
    authorize: object = None
    authorize_release: object = None
    settled: object = None
    # Keep native launch results for the existing owner to reconcile uncertain launches.
    releases: dict = field(default_factory=dict, init=False)
    unadopted: dict = field(default_factory=dict, init=False)
    launch_fds: Mapping = field(default_factory=dict)
    authorize_all: bool = False
    launch_cwd: str | None = None
    launch_streams: Mapping = field(default_factory=dict)
    recover_receipt: object = field(default=None, repr=False)
    owner_appends: Mapping = field(default_factory=dict, repr=False)


@dataclass(frozen=True, slots=True)
class Request:
    workflow: str
    role: str
    operation: str
    options: dict = field(repr=False)
    recorder: dict | None = field(default=None, repr=False)


def _fields(value, required, optional=""):
    if type(value) is not dict or not set(required.split()) <= value.keys() <= set((required + " " + optional).split()):
        raise ConfigurationError("invalid_fields")
    return value


def _identifier(value):
    try:
        return _name(value)
    except ValueError as exc:
        raise ConfigurationError("invalid_identifier") from exc


def _integer(value, *, minimum=0):
    if type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        value = int(value)
    elif type(value) is int and value > 2**53 - 1:
        raise ConfigurationError("unsafe_json_integer")
    if type(value) is not int or not minimum <= value < 2**63:
        raise ConfigurationError("invalid_integer")
    return value


def _bool(value):
    if type(value) is not bool:
        raise ConfigurationError("invalid_boolean")
    return value


def _bytes(value):
    if type(value) is not str:
        raise ConfigurationError("invalid_base64")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ConfigurationError("invalid_base64") from exc


def _enum(kind, value):
    try:
        return kind(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("invalid_enum") from exc


def _receipt(value):
    try:
        fields = dict(_fields(value, "key evidence_type sha256 size committed_ns", "effect source scope retention"))
        for key in ("size", "committed_ns"):
            fields[key] = _integer(fields[key])
        if fields.get("retention") is not None:
            retention = dict(_fields(fields["retention"], "version min_age_seconds expire_after_seconds"))
            retention["version"] = _integer(retention["version"], minimum=1)
            for key in ("min_age_seconds", "expire_after_seconds"):
                if retention[key] is not None:
                    retention[key] = _integer(retention[key], minimum=1)
            fields["retention"] = retention
        return RecordReceipt.from_dict(fields)
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError("invalid_receipt") from exc


# Required and optional request fields are shared by all clients.
_OPTIONS = {
    "read": ("", "expected_size block_size timeout_ms"),
    "write": ("data", "sync"),
    "launch": ("name", "supervise timeout_ms"),
    "release": ("name", "supervise custody timeout_ms cleanup_ms write"),
    "wait": ("name", "timeout_ms cleanup_ms"),
    "cancel": ("name", "cleanup_ms"),
    "cleanup": ("name cleanup_ms", ""),
    "observe": ("scope", "subject"),
    "meter": ("scope phase", ""),
    "validate": ("scope", "require_observed require_terminal_from require_meter_for"),
    "record": ("run_id record_id type", "data effect"),
    "readback": ("destination receipt", ""),
    "purge": ("destination receipt", ""),
    "verify_durable": ("destination receipt", ""),
    "recover_receipt": ("destination attempt_id", ""),
    "sweep": ("destination receipts", "limit"),
}
_OWNER_APPEND_OPTIONS = {"owner_append": ("alias attempt_id data", "timeout_ms"),
                         "owner_append_status": ("alias attempt_id data_sha256", "")}
_REQUEST_OPTIONS = {**_OPTIONS, **_OWNER_APPEND_OPTIONS}
_EFFECTFUL = frozenset(("write", "launch", "cancel", "cleanup", "record", "purge", "sweep", "owner_append"))


def _pairs(items):
    if type(items) is not list or any(type(item) is not list or len(item) != 2 for item in items):
        raise ConfigurationError("expected_observation_pairs")
    return tuple(tuple(_identifier(value) for value in pair) for pair in items)


def _interval(value):
    if type(value) is not list or len(value) != 2:
        raise ConfigurationError("expected_meter_interval")
    begin, end = map(_integer, value)
    if begin > end:
        raise ConfigurationError("expected_meter_interval")
    return begin, end


def parse_request(document):
    """Decode a JSON object without enrollment, I/O or authorization."""
    _fields(document, "version workflow role operation", "options recorder")
    if type(document["version"]) is not int or document["version"] != 1:
        raise ConfigurationError("unsupported_version")
    workflow, role, operation = map(_identifier, (document["workflow"], document["role"], document["operation"]))
    if operation not in _REQUEST_OPTIONS:
        raise ConfigurationError("unsupported_operation")
    options = dict(_fields(document.get("options", {}), *_REQUEST_OPTIONS[operation]))
    for key in ("name", "scope", "run_id", "record_id", "type", "destination", "require_terminal_from", "attempt_id",
                "alias"):
        if key in options:
            options[key] = _identifier(options[key])
    for key in ("supervise", "custody", "sync"):
        if key in options:
            options[key] = _bool(options[key])
    for key in ("expected_size", "block_size", "timeout_ms", "cleanup_ms"):
        if key in options:
            options[key] = _integer(options[key], minimum=0 if key == "expected_size" else 1)
    if "data" in options:
        options["data"] = _bytes(options["data"])
    if operation == "owner_append":
        _require(bool(options["data"]), "empty_append")
    if "data_sha256" in options:
        digest = options["data_sha256"]
        _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "invalid_append_digest")
    if "effect" in options:
        options["effect"] = _enum(EffectStatus, options["effect"])
    if "phase" in options:
        options["phase"] = _enum(ScopePhase, options["phase"])
        if options["phase"] is ScopePhase.OBSERVATION:
            raise ConfigurationError("expected_meter_phase")
    if "subject" in options and options["subject"] not in ("slot", "name", "process"):
        raise ConfigurationError("invalid_observation_subject")
    if "write" in options:
        value = _fields(options["write"], "offset data", "exclusive")
        payload, offset = _bytes(value["data"]), _integer(value["offset"])
        if not payload or offset + len(payload) >= 2**63:
            raise ConfigurationError("invalid_positional_write")
        options["write"] = PositionalWrite(offset, payload), _bool(value.get("exclusive", False))
    if "require_observed" in options:
        options["require_observed"] = _pairs(options["require_observed"])
    if "require_meter_for" in options:
        options["require_meter_for"] = _interval(options["require_meter_for"])
    if "receipt" in options:
        options["receipt"] = _receipt(options["receipt"])
    if "receipts" in options:
        values = options["receipts"]
        _require(type(values) is list and 0 < len(values) <= 128, "invalid_sweep_receipts")
        options["receipts"] = tuple(_receipt(value) for value in values)
    if "limit" in options:
        options["limit"] = _integer(options["limit"], minimum=1)
        _require(options["limit"] <= 128, "invalid_sweep_limit")
    recorder = document.get("recorder")
    if "recorder" in document:
        try:
            _decode_policy(recorder)
        except ValueError as exc:
            raise ConfigurationError("invalid_recorder_configuration") from exc
    return Request(workflow, role, operation, options, recorder)


def _require(value, code):
    if not value:
        raise ConfigurationError(code)


def _deadline(workflow, options):
    now = monotonic_ns()
    due = workflow.deadline_ns
    if "timeout_ms" in options:
        due = min(due, now + options["timeout_ms"] * 1_000_000)
    _require(now < due < 2**63, "deadline_unavailable")
    return due


def _cleanup_deadline(workflow, options, *, after=None):
    if "cleanup_ms" not in options:
        return None
    now = monotonic_ns()
    limit = workflow.cleanup_deadline_ns
    _require(type(limit) is int and now < limit < 2**63, "cleanup_deadline_unavailable")
    return min(limit, (now if after is None else after) + options["cleanup_ms"] * 1_000_000)


def _snapshot(worker):
    return {key: getattr(worker, key) for key in ("name", "role", "pid", "uid")}


def _terminal(result):
    return {"lifecycle": result.lifecycle.value, "returncode": result.returncode,
            "cleanup": _clean(result.cleanup), "error": result.error is not None}


def _clean(result):
    return {"status": result.status.value, "returncode": result.returncode,
            "terminate_sent": result.terminate_sent, "kill_sent": result.kill_sent,
            "error": result.error is not None}


def _read(workflow, options):
    _require(workflow.input_fd is not None and workflow.identity is not None and workflow.sink is not None,
             "read_binding_missing")
    due = _deadline(workflow, options)
    read_options = {key: options[key] for key in ("expected_size", "block_size") if key in options}
    with Original(os.dup(workflow.input_fd), workflow.identity) as original:
        return asdict(original.read_and_close(workflow.sink, due_ns=due, **read_options))


def _write(workflow, options):
    _require(not workflow.require_custody, "custody_requires_managed_release")
    _require(workflow.writer_fd is not None and workflow.identity is not None, "writer_binding_missing")
    _deadline(workflow, options)
    with Writer(os.dup(workflow.writer_fd), workflow.identity) as writer:
        count = writer.write(options["data"])
        sync = options.get("sync", False)
        try:
            writer.flush(sync=sync)
        except (OSError, ValueError, RuntimeError):
            return {"bytes_written": count, "effect": EffectStatus.COMPLETE,
                    "sync": "unknown" if sync else "not_requested", "error": True}
    return {"bytes_written": count, "effect": EffectStatus.COMPLETE,
            "sync": "complete" if sync else "not_requested", "error": False}


def _launch(workflow, options, *, before=None):
    _require(bool(workflow.argv), "executable_binding_missing")
    _require(not workflow.require_supervision or options.get("supervise"), "supervision_required")
    launcher = workflow.supervisor if options.get("supervise", False) else workflow.roster
    _require(launcher is not None, "supervision_binding_missing")
    name = options["name"]
    _require(name not in workflow.unadopted, "attempt_already_used")
    due = _deadline(workflow, options)
    if before is not None:
        before(workflow)
    try:
        worker = launcher.start_executable(
            name, workflow.role, workflow.argv, due_ns=due,
            env=workflow.launch_env, fds=dict(workflow.launch_fds), cwd=workflow.launch_cwd,
            **workflow.launch_streams,
        )
    except SupervisionStartError as exc:
        workflow.unadopted[name] = exc.process
        return {"delivery": "dispatched", "supervision": "unknown", "pid": exc.process.pid}
    return {"delivery": "dispatched", "supervision": "active" if options.get("supervise") else "not_requested",
            "worker": _snapshot(worker)}


def _release(workflow, options):
    _require(workflow.input_fd is not None and workflow.identity is not None and bool(workflow.argv),
             "release_binding_missing")
    name = options["name"]
    supervise, strict = options.get("supervise", False), options.get("custody", False)
    _require(not workflow.require_supervision or supervise, "supervision_required")
    _require(not workflow.require_custody or strict, "custody_required")
    _require(not supervise or workflow.supervisor is not None, "supervision_binding_missing")
    _require(not strict or workflow.custody is not None, "custody_binding_missing")
    _require(supervise or "cleanup_ms" not in options, "cleanup_requires_supervision")
    write, exclusive = options.get("write", (None, False))
    _require(write is None or workflow.writer_fd is not None, "writer_binding_missing")
    _require(callable(workflow.authorize_release), "release_authority_missing")
    due = _deadline(workflow, options)
    cleanup = _cleanup_deadline(workflow, options, after=due)
    plan = ReleasePlan(name, workflow.role, workflow.argv, workflow.identity, due, write, exclusive)
    reservation = object()
    _require(workflow.releases.setdefault(name, reservation) is reservation, "attempt_already_used")
    result = release_executable(
        plan, input_fd=workflow.input_fd, authorize=workflow.authorize_release,
        writer_fd=None if write is None else workflow.writer_fd,
        supervisor=workflow.supervisor if supervise else None, strict_custody=strict,
        custody=workflow.custody if strict else None, cancel=workflow.cancel, cleanup_due_ns=cleanup,
    )
    workflow.releases[name] = result
    return {"delivery": result.delivery, "effect": result.effect, "bytes_written": result.bytes_written,
            "custody": asdict(result.custody) if result.custody is not None else None,
            "custody_status": "not_requested" if not strict else
                ("receipt_reported" if result.custody is not None else "incomplete"),
            "supervision": "not_requested" if not supervise else
                ("terminal_reported" if result.lifecycle is not None else "incomplete"),
            "worker": _snapshot(result.worker) if result.worker is not None else None,
            "terminal": _terminal(result.lifecycle) if result.lifecycle is not None else None,
            "error": result.error is not None, "descriptor_cleanup_error": bool(result.cleanup)}


def _supervision(workflow, operation, options):
    supervisor = workflow.supervisor
    _require(supervisor is not None, "supervision_binding_missing")
    if operation == "cleanup":
        deadline = _cleanup_deadline(workflow, options)
        return _clean(supervisor.cleanup(options["name"], due_ns=deadline))
    due = workflow.deadline_ns if operation == "cancel" else _deadline(workflow, options)
    cleanup = _cleanup_deadline(workflow, options, after=None if operation == "cancel" else due)
    cancel = workflow.cancel
    if operation == "cancel":
        cancel = Event()
        cancel.set()
    return _terminal(supervisor.wait(options["name"], due_ns=due, cancel=cancel, cleanup_due_ns=cleanup))


def _observe(workflow, options):
    entry = workflow.observers.get(options["scope"])
    _require(entry is not None, "observation_binding_missing")
    observer, scope, provider_id = entry
    if "subject" not in options:
        return {"sample": asdict(observer.sample())}
    _require(scope is not None, "observation_scope_missing")
    sample, report = observer.sample_for_scope(scope, provider_id=provider_id, subject=options["subject"])
    return {"sample": asdict(sample), "scope_report": asdict(report)}


def _meter(workflow, options):
    meter = workflow.meters.get(options["scope"])
    _require(meter is not None, "meter_binding_missing")
    sample = meter.sample(options["phase"])
    report = sample.report
    return {"sample": asdict(sample), "scope_report": asdict(report) if report is not None else None}


def _validate(workflow, options):
    evidence = workflow.evidence.get(options["scope"])
    _require(evidence is not None, "evidence_binding_missing")
    requested_interval = options.get("require_meter_for")
    meter_result = {"status": "not_requested"}
    try:
        events = validate_run_evidence(evidence.binding, evidence.events,
                                       require_observed=options.get("require_observed", ()),
                                       require_terminal_from=options.get("require_terminal_from"))
        reports = evidence.reports
        if evidence.scope is not None:
            reports = validate_scope_evidence(
                evidence.scope, reports, observer_id=evidence.observer_id, meter_id=evidence.meter_id,
                require_meter_for=requested_interval,
            )
        else:
            _require(not reports and requested_interval is None, "meter_scope_missing")
    except ConfigurationError:
        raise
    except ValueError:
        return {"validation": "incomplete", "code": "evidence_requirements_unsatisfied"}
    if requested_interval is not None:
        meter_result = {"status": "unavailable"}
        if evidence.meter_samples:
            begin, end = evidence.meter_samples
            if begin.report in reports and end.report in reports:
                try:
                    meter_result = {"status": "observed",
                                    "cpu_delta_usec": cpu_delta_usec(begin, end, require_meter_for=requested_interval)}
                except ValueError:
                    pass
    return {"validation": "complete", "validated_events": len(events), "validated_reports": len(reports),
            "observation_states": [report.observation.state for report in reports], "cpu_delta": meter_result}


def _recording(workflow, operation, options, *, source=None):
    recorder = workflow.recorder
    _require(recorder is not None, "recorder_binding_missing")
    if operation == "record":
        try:
            evidence_type = recorder.evidence_type(options["type"])
        except KeyError as exc:
            raise ConfigurationError("evidence_type_not_registered") from exc
        result = recorder.record(RecordKey(options["run_id"], options["record_id"]), evidence_type,
                                 options.get("data"), effect=options.get("effect", EffectStatus.UNKNOWN),
                                 source=source, scope=options["run_id"] if source is not None else None)
        return {**asdict(result), "required_complete": result.required_complete}
    name = options["destination"]
    try:
        if operation == "recover_receipt":
            _require(callable(workflow.recover_receipt), "receipt_recovery_binding_missing")
            return workflow.recover_receipt(name, options["attempt_id"])
        if operation == "sweep":
            _require(callable(workflow.settled), "settlement_binding_required")
            entries = recorder.sweep(name, options["receipts"], settled=workflow.settled,
                                     limit=options.get("limit", 32))
            return {"sweep": [asdict(entry) for entry in entries]}
        receipt = options["receipt"]
        if operation == "purge":
            settled = workflow.settled is not None and workflow.settled(receipt) is True
            return {"retention": recorder.purge(name, receipt, resolved=settled)}
        if operation == "verify_durable":
            payload = recorder.verify_durable(name, receipt)
        else:
            payload = recorder.readback(name, receipt)
    except KeyError as exc:
        raise ConfigurationError("destination_not_enrolled") from exc
    except RecordError as exc:
        return {"persistence": exc.status}
    response = {"persistence": "verified", "key": asdict(receipt.key), "sha256": receipt.sha256, "size": len(payload)}
    if workflow.authorize_all or operation == "verify_durable":
        response["durability"] = "confirmed" if operation == "verify_durable" else "unconfirmed"
        response["receipt"] = asdict(receipt)
    return response


def execute(request, workflows: Mapping[str, Workflow], *, _before=None):
    """Execute exactly one enrolled operation. Results carry no original bytes."""
    if type(request) is not Request:
        raise ConfigurationError("invalid_request")
    workflow = workflows.get(request.workflow)
    _require(workflow is not None and request.role == workflow.role and request.operation in workflow.operations,
             "workflow_operation_not_enrolled")
    if request.recorder is not None:
        _require(workflow.recorder is not None and workflow.recorder_config is not None
                 and json.dumps(request.recorder, sort_keys=True) ==
                 json.dumps(workflow.recorder_config, sort_keys=True), "recorder_configuration_not_enrolled")
    operation, options = request.operation, request.options
    cleanup_on_wait = operation == "wait" and "cleanup_ms" in options
    operation_deadline = None
    if workflow.authorize_all or operation in _EFFECTFUL or operation in _OWNER_APPEND_OPTIONS or cleanup_on_wait:
        if operation in _EFFECTFUL - {"cleanup", "cancel", "purge", "sweep"} or cleanup_on_wait:
            operation_deadline = _deadline(workflow, options)
        _require(workflow.authorize is not None and workflow.authorize(request) is True, "operation_not_authorized")
    if operation == "launch":
        return _launch(workflow, options, before=_before)
    if operation in _OWNER_APPEND_OPTIONS:
        from .owner_append import OwnerAppendBinding

        binding = workflow.owner_appends.get(options["alias"])
        _require(type(binding) is OwnerAppendBinding and
                 (binding.workflow, binding.role, binding.alias) == (request.workflow, request.role, options["alias"]),
                 "owner_append_binding_missing")
        attempt = options["attempt_id"]
        if operation == "owner_append_status":
            result = binding.status(attempt, options["data_sha256"])
        else:
            result = binding.append(attempt, AppendWrite(options["data"]),
                                    due_ns=operation_deadline, cancel=workflow.cancel)
        return {**result, "attempt_id": attempt}
    if operation in ("read", "write", "release", "observe", "meter", "validate"):
        return {
            "read": _read, "write": _write, "release": _release,
            "observe": _observe, "meter": _meter, "validate": _validate,
        }[operation](workflow, options)
    if operation in ("wait", "cancel", "cleanup"):
        return _supervision(workflow, operation, options)
    return _recording(workflow, operation, options, source=request.workflow if workflow.authorize_all else None)


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ConfigurationError("duplicate_json_key")
        value[key] = item
    return value


def _invalid_constant(_):
    raise ConfigurationError("invalid_json")


def _decode_json(data):
    try:
        if type(data) is bytes:
            data = data.decode("utf-8")
        return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ConfigurationError):
            raise
        raise ConfigurationError("invalid_json") from exc


def decode_request(data):
    """Decode a strict JSON document using the common validation contract."""
    return parse_request(_decode_json(data))


def _wire(value):
    # Encode all result integers uniformly, including IDs larger than 2**53.
    if type(value) is int:
        return str(value)
    if isinstance(value, dict):
        return {k: _wire(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_wire(v) for v in value]
    return value


def serve(workflows, source, destination, *, max_bytes=1_048_576):
    """Read one bounded JSON document from a binary stream. Write one redacted JSON reply."""
    return _serve(lambda request: execute(request, workflows), source, destination, max_bytes)


def _serve(invoke, source, destination, max_bytes, *, reported_exit=None, policy_sha256=None):
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("expected a positive request byte limit")
    try:
        data = source.read(max_bytes + 1)
        _require(len(data) <= max_bytes, "request_too_large")
        request = decode_request(data)
        result = invoke(request)
        reply = {"status": "reported", "result": result}
    except ConfigurationError as exc:
        reply = {"status": "refused", "code": str(exc)}
    except Exception:
        reply = {"status": "unavailable", "code": "operation_result_unavailable", "effect": "unknown"}
    if policy_sha256 is not None:
        reply["policy_sha256"] = policy_sha256
    destination.write(json.dumps(_wire(reply), separators=(",", ":")) + "\n")
    destination.flush()
    if reply["status"] != "reported":
        return 1
    return reported_exit(request, result) if reported_exit is not None else 0


def serve_stdio(workflows, *, max_bytes=1_048_576):
    """One request in a dedicated controller process, with separate child stdio."""
    return _serve_isolated(lambda request: execute(request, workflows), max_bytes)


def _serve_isolated(invoke, max_bytes=1_048_576, *, reported_exit=None, policy_sha256=None):
    with os.fdopen(os.dup(0), "rb") as source, os.fdopen(os.dup(1), "w", encoding="utf-8") as output:
        null = os.open(os.devnull, os.O_RDWR | os.O_CLOEXEC)
        try:
            for fd in (0, 1, 2):
                os.dup2(null, fd)
        finally:
            os.close(null)
        return _serve(invoke, source, output, max_bytes, reported_exit=reported_exit,
                      policy_sha256=policy_sha256)
