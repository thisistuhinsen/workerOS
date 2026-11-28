"""An enrolled file owner can append once while keeping the writer private."""

from contextlib import closing, contextmanager, ExitStack
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
from threading import Lock
from time import monotonic_ns

from .custody import CustodyRefused, IndependentCustody, require_custody
from .managed import EffectStatus
from .original import AppendWrite, HandoffError, Identity, Writer, _before, _check
from .recording import EvidenceType, LocalStore, Persistence, RecordError, RecordKey, RecordReceipt, StoragePolicy, _name
from .scope_meter import monotonic_clock_id


_POLICY = StoragePolicy()
_CLAIM = EvidenceType("owner-append-claim", "application/json")
_RESULT = EvidenceType("owner-append-result", "application/json")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _read(store, key, kind):
    try:
        stored = store.read(key, policy=_POLICY)
        if stored.receipt.evidence_type != kind:
            raise RecordError(Persistence.CONFLICT)
        data = store.verify_durable(stored.receipt, policy=_POLICY)
        return json.loads(data)
    except RecordError as exc:
        if exc.status is Persistence.MISSING:
            return None
        raise


def _commit(store, key, kind, data):
    payload = _canonical(data)
    receipt = RecordReceipt(key, kind, sha256(payload).hexdigest(), len(payload), 0)
    return store.commit(receipt, payload, policy=_POLICY).state


def _result(effect, *, count=None, timeliness="unknown", code):
    return {"effect": effect, "bytes_written": count, "timeliness": timeliness, "code": code}


@dataclass(frozen=True, slots=True)
class OwnerAppendBinding:
    """Trusted registration for one live owner, original and custody window.

    The independent observer holds its own RO original and attests coverage
    on the exact scope. The local RO descriptor is a separate same-inode pin.
    The trusted host retains both local handles for this registration's life.
    """

    workflow: str
    role: str
    alias: str
    scope: str
    generation: str
    owner_uid: int
    writer: Writer = field(repr=False)
    reader_fd: int = field(repr=False)
    custody: IndependentCustody = field(repr=False)
    expires_ns: int
    store: LocalStore = field(repr=False)
    reference: str | None = field(default=None, kw_only=True)
    policy_sha256: str | None = field(default=None, kw_only=True)
    _owner_pid: int = field(init=False, repr=False)
    _writer_slot: int = field(init=False, repr=False)
    _identity: Identity = field(init=False, repr=False)
    _journal_identity: tuple = field(init=False, repr=False)
    _clock_id: str = field(init=False, repr=False)
    _approval_pin: str = field(init=False, repr=False)
    _lock: object = field(default_factory=Lock, init=False, repr=False, compare=False)
    pin: str = field(init=False)

    def __post_init__(self):
        for value in (self.workflow, self.role, self.alias, self.scope, self.generation):
            _name(value)
        if self.reference is not None:
            _name(self.reference)
        if self.policy_sha256 is not None and (type(self.policy_sha256) is not str
                                               or re.fullmatch(r"[0-9a-f]{64}", self.policy_sha256) is None):
            raise ValueError("invalid owner append policy digest")
        if (type(self.owner_uid) is not int or not 0 < self.owner_uid < 2**32 - 1
                or type(self.writer) is not Writer or type(self.custody) is not IndependentCustody
                or type(self.store) is not LocalStore or self.store.owner_uid != self.owner_uid
                or type(self.expires_ns) is not int or not 0 < self.expires_ns < 2**63
                or self.store.group_id is not None or self.custody.observer_uid == self.owner_uid
                or self.custody.observer_pid == os.getpid()):
            raise ValueError("invalid owner append registration")
        object.__setattr__(self, "_owner_pid", os.getpid())
        object.__setattr__(self, "_writer_slot", self.writer.fileno())
        object.__setattr__(self, "_identity", self.writer.identity)
        object.__setattr__(self, "_journal_identity", self._journal())
        clock = monotonic_clock_id()
        if clock is None:
            raise HandoffError("owner append clock unavailable")
        object.__setattr__(self, "_clock_id", clock)
        self._verify_original()
        self.store.check_policy(_POLICY)
        identity = self._identity
        record = ["owner-append-v1", self.workflow, self.role, self.alias, self.scope, self.generation,
                  identity.device, identity.inode, self.owner_uid,
                  self.custody.observer_pid, self.custody.observer_uid,
                  self._clock_id, self.expires_ns, self._journal_identity, self.reference, self.policy_sha256]
        approval = sha256(_canonical(record)).hexdigest()
        object.__setattr__(self, "_approval_pin", approval)
        object.__setattr__(self, "pin", sha256(_canonical([approval, self._owner_pid, self._writer_slot])).hexdigest())

    @property
    def registry_reference(self):
        return self.reference if self.reference is not None else self.pin

    def _journal(self):
        info = self.store.directory.stat(follow_symlinks=False)
        return info.st_dev, info.st_ino

    def _verify_original(self):
        if (os.getuid() != self.owner_uid or os.geteuid() != self.owner_uid
                or os.getpid() != self._owner_pid or monotonic_clock_id() != self._clock_id
                or self.writer.identity != self._identity
                or self.writer._writable() != self._writer_slot or self._journal() != self._journal_identity):
            raise HandoffError("owner append slot unavailable")
        _check(self.reader_fd, self._identity, (os.O_RDONLY,))

    def _lookup(self, attempt, digest):
        if self._journal() != self._journal_identity:
            raise RecordError(Persistence.CONFLICT)
        claim = _read(self.store, RecordKey(attempt, _CLAIM.name), _CLAIM)
        if claim is None:
            if _read(self.store, RecordKey(attempt, _RESULT.name), _RESULT) is None:
                return None
            return _result(EffectStatus.UNKNOWN, code="append_outcome_unconfirmed")
        if (type(claim) is not dict or set(claim) != {"approval", "binding", "data_sha256"}
                or (claim["approval"], claim["data_sha256"]) != (self._approval_pin, digest)
                or type(claim["binding"]) is not str or re.fullmatch(r"[0-9a-f]{64}", claim["binding"]) is None):
            return _result(EffectStatus.UNKNOWN, code="append_attempt_conflict")
        outcome = _read(self.store, RecordKey(attempt, _RESULT.name), _RESULT)
        if (type(outcome) is not dict or set(outcome) != {"claim", "outcome"} or outcome["claim"] != claim
                or type(outcome["outcome"]) is not dict
                or set(outcome["outcome"]) != {"effect", "bytes_written", "timeliness", "code"}):
            return _result(EffectStatus.UNKNOWN, code="append_outcome_unconfirmed")
        return outcome["outcome"]

    def status(self, attempt, digest):
        """Read only a matching prior attempt. Keep its original timing result."""
        try:
            known = self._lookup(attempt, digest)
        except (OSError, ValueError, RecordError):
            return _result(EffectStatus.UNKNOWN, code="append_outcome_unconfirmed")
        return known if known is not None else _result(EffectStatus.UNKNOWN, code="append_attempt_unrecorded")

    def append(self, attempt, operation, *, due_ns, cancel):
        if type(operation) is not AppendWrite:
            raise TypeError("expected an AppendWrite")
        if not self._lock.acquire(blocking=False):
            return _result(EffectStatus.UNKNOWN, code="append_registration_busy")
        try:
            return self._append_once(attempt, operation, min(self.expires_ns, due_ns), cancel)
        finally:
            self._lock.release()

    def _append_once(self, attempt, operation, deadline, cancel):
        digest = sha256(operation.data).hexdigest()
        claim = {"approval": self._approval_pin, "binding": self.pin, "data_sha256": digest}
        try:
            known = self._lookup(attempt, digest)
        except (OSError, ValueError, RecordError):
            return _result(EffectStatus.UNKNOWN, code="append_outcome_unconfirmed")
        if known is not None:
            return known
        with closing(self.custody):
            try:
                self._verify_original()
                _before(deadline)
                if (cancel is not None and cancel.is_set()
                        or not hasattr(os, "RWF_APPEND") or not hasattr(os, "pwritev")):
                    return _result(EffectStatus.NOT_ATTEMPTED, code="owner_append_unavailable")
                scope = sha256(_canonical([self.pin, attempt, digest])).hexdigest()
                require_custody(self.custody, identity=self._identity, operation="owner-append",
                                scope=scope, due_ns=deadline)
                self._verify_original()
                _before(deadline)
                if cancel is not None and cancel.is_set():
                    raise HandoffError("append cancelled")
            except CustodyRefused:
                return _result(EffectStatus.NOT_ATTEMPTED, code="append_custody_refused")
            except (OSError, HandoffError):
                return _result(EffectStatus.NOT_ATTEMPTED, code="owner_append_unavailable")
        try:
            state = _commit(self.store, RecordKey(attempt, _CLAIM.name), _CLAIM, claim)
            if state is not Persistence.COMMITTED:
                return self.status(attempt, digest)
        except (OSError, ValueError, RecordError):
            return _result(EffectStatus.UNKNOWN, code="append_reservation_unconfirmed")

        try:
            self._verify_original()
            _before(deadline)
            if cancel is not None and cancel.is_set():
                raise HandoffError("append cancelled")
        except (OSError, HandoffError):
            outcome = _result(EffectStatus.NOT_ATTEMPTED, code="owner_append_unavailable")
        else:
            try:
                count = self.writer.append(operation, due_ns=deadline)
            except (OSError, ValueError, NotImplementedError):
                outcome = _result(EffectStatus.UNKNOWN, code="append_write_unconfirmed")
            else:
                timing = "within_deadline" if monotonic_ns() < deadline else "late"
                effect = EffectStatus.COMPLETE if count == len(operation.data) else EffectStatus.PARTIAL
                outcome = _result(effect, count=count, timeliness=timing, code="append_observed")
        try:
            _commit(self.store, RecordKey(attempt, _RESULT.name), _RESULT, {"claim": claim, "outcome": outcome})
            if self._lookup(attempt, digest) != outcome:
                return {**outcome, "readback": "unconfirmed"}
        except (OSError, ValueError, RecordError):
            return {**outcome, "readback": "unconfirmed"}
        return outcome


@contextmanager
def open_registered_owner(policy_sha256):
    """Bind the stock CLI to a protected appointment and already-held local FDs."""
    from . import managed_cli
    from .configuration import ConfigurationError, _fields, _integer, _require
    from .enrollment import HostBindings

    with ExitStack() as held:
        try:
            document = managed_cli._read_admin_json("owner-append.json")
            _fields(document, "version policy_sha256 workflow role alias scope generation reference owner_uid"
                    " device inode writer_fd reader_fd observer_fd observer_pid observer_uid expires_ns journal_directory")
            _require(type(document["version"]) is int and document["version"] == 1
                     and document["policy_sha256"] == policy_sha256
                     and type(document["owner_uid"]) is int and document["owner_uid"] == os.getuid() == os.geteuid() != 0,
                     "owner_append_registration_mismatch")
            slots = [document[name] for name in ("writer_fd", "reader_fd", "observer_fd")]
            _require(all(type(slot) is int and 3 <= slot < 2**31 for slot in slots) and len(set(slots)) == 3,
                     "owner_append_slots_invalid")
            identity = Identity(_integer(document["device"]), _integer(document["inode"], minimum=1))
            directory = Path(document["journal_directory"])
            _require(directory.is_absolute(), "owner_append_journal_invalid")
            writer = held.enter_context(Writer(os.dup(slots[0]), identity))
            reader = os.dup(slots[1])
            held.callback(os.close, reader)
            peer_slot = os.dup(slots[2])
            try:
                channel = socket.socket(fileno=peer_slot)
            except OSError:
                os.close(peer_slot)
                raise
            held.callback(channel.close)
            custody = IndependentCustody(channel, observer_pid=document["observer_pid"],
                                         observer_uid=document["observer_uid"])
            binding = OwnerAppendBinding(
                *(document[name] for name in ("workflow", "role", "alias", "scope", "generation", "owner_uid")),
                writer, reader, custody, _integer(document["expires_ns"], minimum=1), LocalStore(directory),
                reference=document["reference"], policy_sha256=policy_sha256,
            )
        except ConfigurationError:
            raise
        except (OSError, ValueError, RuntimeError, RecordError, TypeError, KeyError) as exc:
            raise ConfigurationError("owner_append_registration_unavailable") from exc

        def authorize(request):
            return ((request.workflow, request.role, request.options.get("alias"))
                    == (binding.workflow, binding.role, binding.alias)
                    and request.operation in ("owner_append", "owner_append_status"))

        yield HostBindings(authorize=authorize, owner_appends={binding.registry_reference: binding})
