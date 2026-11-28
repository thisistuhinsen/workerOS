"""Machine schema for the installed, versioned controller JSON contract."""

from .configuration import _REQUEST_OPTIONS
from .evidence import ScopePhase
from .managed import EffectStatus


def _object(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


def _array(item, *, minimum=None, maximum=None):
    return {"type": "array", "items": item, **({"minItems": minimum} if minimum is not None else {}),
            **({"maxItems": maximum} if maximum is not None else {})}


def configuration_schema():
    name = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"}
    media = {"type": "string", "pattern": "^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$"}
    boolean = {"type": "boolean"}
    data = {"type": "string", "contentEncoding": "base64"}
    integer = {"anyOf": [
        {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
        {"type": "string", "pattern": "^(0|[1-9][0-9]{0,18})$"},
    ]}
    positive = {"anyOf": [
        {"type": "integer", "minimum": 1, "maximum": 2**53 - 1},
        {"type": "string", "pattern": "^[1-9][0-9]{0,18}$"},
    ]}
    nullable_name = {"anyOf": [name, {"type": "null"}]}
    nullable_age = {"anyOf": [positive, {"type": "null"}]}
    retention = _object({
        "version": {"anyOf": [{"const": 1}, {"const": "1"}]},
        "min_age_seconds": nullable_age, "expire_after_seconds": nullable_age,
    }, ("version", "min_age_seconds", "expire_after_seconds"))
    receipt = _object({
        "key": _object({"run_id": name, "record_id": name}, ("run_id", "record_id")),
        "evidence_type": _object({"name": name, "media_type": media}, ("name", "media_type")),
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "size": integer, "committed_ns": integer,
        "effect": {"enum": [None] + [status.value for status in EffectStatus]},
        "source": nullable_name, "scope": nullable_name,
        "retention": {"anyOf": [retention, {"type": "null"}]},
    }, ("key", "evidence_type", "sha256", "size", "committed_ns"))
    fields = dict.fromkeys(("name", "scope", "run_id", "record_id", "type", "destination", "attempt_id",
                            "require_terminal_from", "alias"), name)
    fields.update(dict.fromkeys(("supervise", "custody", "sync"), boolean))
    fields.update(dict.fromkeys(("block_size", "timeout_ms", "cleanup_ms"), positive))
    fields.update({
        "expected_size": integer,
        "data": data,
        "data_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "effect": {"enum": [status.value for status in EffectStatus]},
        "phase": {"enum": [phase.value for phase in ScopePhase if phase is not ScopePhase.OBSERVATION]},
        "subject": {"enum": ["slot", "name", "process"]},
        "write": _object({"offset": integer, "data": data, "exclusive": boolean}, ("offset", "data")),
        "require_observed": _array(_array(name, minimum=2, maximum=2)),
        "require_meter_for": _array(integer, minimum=2, maximum=2),
        "receipt": receipt,
        "receipts": _array(receipt, minimum=1, maximum=128),
        "limit": {"anyOf": [{"type": "integer", "minimum": 1, "maximum": 128},
                            {"type": "string", "pattern": "^[1-9][0-9]{0,2}$"}]},
    })
    settings = _object({
        "group_id": {"type": ["integer", "null"], "minimum": 0, "maximum": 2**32 - 2},
        "max_age_seconds": {"type": ["integer", "null"], "minimum": 1, "maximum": 2**53 - 1},
        "expire_after_seconds": {"type": ["integer", "null"], "minimum": 1, "maximum": 2**53 - 1},
    })
    policy = _object({
        "version": {"const": 1},
        "destinations": {"type": "object", "propertyNames": name, "additionalProperties": settings},
        "routes": _array(_object({
            "name": name, "media_type": media, "required": _array(name), "optional": _array(name),
        }, ("name", "media_type"))),
    }, ("version", "destinations", "routes"))
    choices = []
    for operation, (required, optional) in _REQUEST_OPTIONS.items():
        fields_for_operation = {key: fields[key] for key in (required + " " + optional).split()}
        choices.append({
            "if": {"properties": {"operation": {"const": operation}}},
            "then": {
                "properties": {"options": _object(fields_for_operation, required.split())},
                **({"required": ["options"]} if required else {}),
            },
        })
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "WorkerOS controller request version 1",
        **_object({
            "version": {"const": 1},
            "workflow": name, "role": name, "operation": {"enum": list(_REQUEST_OPTIONS)},
            "options": {"type": "object"}, "recorder": policy,
        }, ("version", "workflow", "role", "operation")),
        "allOf": choices,
    }
