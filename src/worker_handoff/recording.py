"""Opt-in application evidence recording. Nothing here authorizes a worker or an effect."""

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
from time import time_ns
from typing import Mapping, Protocol

from .managed import EffectStatus


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_MEDIA = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}")
_SHA = re.compile(r"[0-9a-f]{64}")
_HEADER_SIZE = struct.Struct("!I")
_MAX_HEADER = 4096
_MAX_SWEEP = 256
_RETENTION_VERSION = 1


def _name(value):
    if type(value) is not str or not _NAME.fullmatch(value):
        raise ValueError("expected a bounded evidence identifier")
    return value


def _check_age(age):
    if age is not None and (type(age) is not int or not 1 <= age <= 2**53 - 1):
        raise ValueError("expected positive retention ages or None")


def _check_provenance(source, scope):
    if (source is None) != (scope is None):
        raise ValueError("expected both provenance source and scope or neither")
    if source is not None:
        _name(source)
        _name(scope)


@dataclass(frozen=True, slots=True)
class EvidenceType:
    name: str
    media_type: str

    def __post_init__(self):
        _name(self.name)
        if type(self.media_type) is not str or not _MEDIA.fullmatch(self.media_type):
            raise ValueError("expected a lowercase type/subtype media type")


@dataclass(frozen=True, slots=True)
class RecordKey:
    run_id: str
    record_id: str

    def __post_init__(self):
        _name(self.run_id)
        _name(self.record_id)

    def filename(self):
        return sha256(f"{self.run_id}\0{self.record_id}".encode("ascii")).hexdigest() + ".evidence"


@dataclass(frozen=True, slots=True)
class StoragePolicy:
    """Set access, the explicit purge age floor, and opt-in expiry eligibility."""

    group_id: int | None = None
    max_age_seconds: int | None = None
    expire_after_seconds: int | None = None

    def __post_init__(self):
        if self.group_id is not None and (type(self.group_id) is not int or not 0 <= self.group_id < 2**32 - 1):
            raise ValueError("expected an existing group ID or None")
        _check_age(self.max_age_seconds)
        _check_age(self.expire_after_seconds)


@dataclass(frozen=True, slots=True)
class RetentionStamp:
    """The destination's retention terms at the time of commit."""

    version: int
    min_age_seconds: int | None
    expire_after_seconds: int | None

    def __post_init__(self):
        if type(self.version) is not int or self.version != _RETENTION_VERSION:
            raise ValueError("unsupported retention enforcement version")
        _check_age(self.min_age_seconds)
        _check_age(self.expire_after_seconds)

    @classmethod
    def from_policy(cls, policy):
        return cls(_RETENTION_VERSION, policy.max_age_seconds, policy.expire_after_seconds)


@dataclass(frozen=True, slots=True)
class RecordReceipt:
    key: RecordKey
    evidence_type: EvidenceType
    sha256: str
    size: int
    committed_ns: int
    effect: EffectStatus | None = None
    source: str | None = None
    scope: str | None = None
    retention: RetentionStamp | None = None

    def __post_init__(self):
        if type(self.key) is not RecordKey or type(self.evidence_type) is not EvidenceType:
            raise ValueError("expected a record key and evidence type")
        if type(self.sha256) is not str or not _SHA.fullmatch(self.sha256):
            raise ValueError("expected an exact SHA-256")
        if type(self.size) is not int or self.size < 0 or type(self.committed_ns) is not int or self.committed_ns < 0:
            raise ValueError("invalid receipt size or timestamp")
        if self.effect is not None and type(self.effect) is not EffectStatus:
            raise ValueError("expected a reported effect status")
        _check_provenance(self.source, self.scope)
        if self.retention is not None and type(self.retention) is not RetentionStamp:
            raise ValueError("expected exact retention terms")

    def identity(self):
        return (self.key, self.evidence_type, self.sha256, self.size, self.effect, self.source,
                self.scope, self.retention)

    @classmethod
    def from_dict(cls, value):
        required = {"key", "evidence_type", "sha256", "size", "committed_ns"}
        allowed = required | {"effect", "source", "scope", "retention"}
        if (type(value) is not dict or not required <= value.keys() <= allowed
                or type(value["key"]) is not dict or type(value["evidence_type"]) is not dict):
            raise ValueError("invalid record receipt fields")
        fields = dict(value)
        fields["key"] = RecordKey(**fields["key"])
        fields["evidence_type"] = EvidenceType(**fields["evidence_type"])
        if fields.get("effect") is not None:
            fields["effect"] = EffectStatus(fields["effect"])
        if fields.get("retention") is not None:
            if type(fields["retention"]) is not dict:
                raise ValueError("expected retention terms")
            fields["retention"] = RetentionStamp(**fields["retention"])
        return cls(**fields)


class Persistence(str, Enum):
    COMMITTED = "committed"
    EXISTING = "existing"
    MISSING = "missing"
    FAILED = "failed"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    REFUSED = "refused"
    PURGED = "purged"
    BUSY = "busy"


class Retention(str, Enum):
    PURGED = "purged"
    RETAINED_UNRESOLVED = "retained_unresolved"
    RETAINED_YOUNG = "retained_young"
    RETAINED_MANUAL = "retained_manual"
    RETAINED_LEGACY = "retained_legacy"


@dataclass(frozen=True, slots=True)
class SweepResult:
    receipt: RecordReceipt
    retention: Retention | None = None
    persistence: Persistence | None = None


class RecordError(RuntimeError):
    """A redacted storage disposition. It carries no record bytes or path."""

    def __init__(self, status):
        if type(status) is not Persistence:
            raise ValueError("expected a persistence status")
        super().__init__(status.value)
        self.status = status


@dataclass(frozen=True, slots=True)
class StoreCommit:
    state: Persistence
    receipt: RecordReceipt


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    receipt: RecordReceipt
    payload: bytes | None = field(repr=False)


class StoreAdapter(Protocol):
    """A pre-provisioned transport under the caller's administrative trust.

    Policy checks must attest actual store configuration. Commit must atomically
    create or compare a key, return only after durable acknowledgment, and
    compare tombstones too. Preserve the retention terms in force at commit.
    Purge must enforce the original and current age floors, avoid unbounded
    lock waits, and conditionally replace the exact receipt with a tombstone.
    Raise RecordError for a known disposition. Unclassified write exceptions
    are indeterminate.
    """

    def check_policy(self, policy: StoragePolicy) -> bool: ...
    def commit(self, receipt: RecordReceipt, payload: bytes, *, policy: StoragePolicy) -> StoreCommit: ...
    def read(self, key: RecordKey, *, policy: StoragePolicy) -> StoredEvidence: ...
    def purge(self, expected: RecordReceipt, *, policy: StoragePolicy) -> None: ...


@dataclass(frozen=True, slots=True)
class Destination:
    store: StoreAdapter
    policy: StoragePolicy = StoragePolicy()

    def __post_init__(self):
        if type(self.policy) is not StoragePolicy or any(not callable(getattr(self.store, method, None))
                for method in ("check_policy", "commit", "read", "purge")):
            raise ValueError("expected a registered store and a storage policy")

    def check(self):
        try:
            accepted = self.store.check_policy(self.policy)
        except Exception as exc:
            raise RecordError(Persistence.REFUSED) from exc
        if accepted is not True:
            raise RecordError(Persistence.REFUSED)


@dataclass(frozen=True, slots=True)
class Route:
    evidence_type: EvidenceType
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.evidence_type) is not EvidenceType or any(type(names) is not tuple
                for names in (self.required, self.optional)):
            raise ValueError("expected a declared evidence type and destination tuples")
        names = self.required + self.optional
        if not names or len({_name(name) for name in names}) != len(names):
            raise ValueError("expected distinct named route destinations")


@dataclass(frozen=True, slots=True)
class DestinationResult:
    destination: str
    required: bool
    state: Persistence
    receipt: RecordReceipt | None = None


@dataclass(frozen=True, slots=True)
class RecordResult:
    key: RecordKey
    effect: EffectStatus
    destinations: tuple[DestinationResult, ...]

    @property
    def required_complete(self):
        return all(not d.required or d.state in (Persistence.COMMITTED, Persistence.EXISTING)
                   for d in self.destinations)


def _decode_policy(config):
    if type(config) is not dict or set(config) != {"version", "destinations", "routes"} or (
        type(config["version"]) is not int or config["version"] != 1
    ) or type(config["destinations"]) is not dict or type(config["routes"]) is not list:
        raise ValueError("expected recorder policy version 1")
    policies = {}
    for name, settings in config["destinations"].items():
        if type(settings) is not dict or not settings.keys() <= {
            "group_id", "max_age_seconds", "expire_after_seconds",
        }:
            raise ValueError("expected supported storage options")
        policies[_name(name)] = StoragePolicy(**settings)
    routes = []
    names = set()
    for item in config["routes"]:
        if type(item) is not dict or not {"name", "media_type"} <= item.keys() <= {
            "name", "media_type", "required", "optional",
        } or any(type(item[k]) is not list for k in ("required", "optional") if k in item):
            raise ValueError("invalid evidence route")
        route = Route(EvidenceType(item["name"], item["media_type"]),
                      tuple(item.get("required", ())), tuple(item.get("optional", ())))
        if route.evidence_type.name in names or not set(route.required + route.optional) <= policies.keys():
            raise ValueError("expected distinct routes to declared destinations")
        routes.append(route)
        names.add(route.evidence_type.name)
    return policies, tuple(routes)


class RecorderPolicy:
    """Route declared evidence to pre-registered destinations. No I/O at setup."""

    def __init__(self, destinations: Mapping[str, Destination], routes: tuple[Route, ...]):
        self._destinations = dict(destinations)
        if any(type(value) is not Destination for value in self._destinations.values()):
            raise ValueError("expected named Destination registrations")
        for name in self._destinations:
            _name(name)
        self._routes = {}
        for route in routes:
            if type(route) is not Route or route.evidence_type.name in self._routes:
                raise ValueError("expected distinct typed routes")
            if any(name not in self._destinations for name in route.required + route.optional):
                raise ValueError("route uses an unregistered destination")
            self._routes[route.evidence_type.name] = route

    @classmethod
    def from_dict(cls, config, *, stores: Mapping[str, StoreAdapter]):
        """Resolve versioned JSON policy names against stores supplied by the application."""
        policies, routes = _decode_policy(config)
        if not policies.keys() <= stores.keys():
            raise ValueError("expected pre-registered stores")
        destinations = {name: Destination(stores[name], policy) for name, policy in policies.items()}
        return cls(destinations, routes)

    def evidence_type(self, name):
        return self._routes[name].evidence_type

    def check_required_local(self, evidence_type):
        """Check writable access to required local destinations without committing."""
        route = self._routes.get(evidence_type.name)
        if route is None or route.evidence_type != evidence_type:
            raise ValueError("evidence type does not match a configured route")
        for name in route.required:
            destination = self._destinations[name]
            if (isinstance(destination.store, LocalStore)
                    and destination.store.check_writable(destination.policy) is not True):
                raise RecordError(Persistence.REFUSED)
        return True

    def record(self, key, evidence_type, payload, *, effect=EffectStatus.UNKNOWN, source=None, scope=None):
        if (type(key) is not RecordKey or type(evidence_type) is not EvidenceType
                or type(effect) is not EffectStatus or (payload is not None and type(payload) is not bytes)):
            raise ValueError("expected a key, declared evidence type, bytes or None, and effect status")
        _check_provenance(source, scope)
        route = self._routes.get(evidence_type.name)
        if route is None or route.evidence_type != evidence_type:
            raise ValueError("evidence type does not match a configured route")
        receipt = None if payload is None else RecordReceipt(
            key, evidence_type, sha256(payload).hexdigest(), len(payload), time_ns(), effect, source, scope,
        )
        results = []
        for required, names in ((True, route.required), (False, route.optional)):
            for name in names:
                state, stored = Persistence.MISSING, None
                if receipt is not None:
                    destination = self._destinations[name]
                    try:
                        destination.check()
                        expected = replace(receipt, retention=RetentionStamp.from_policy(destination.policy))
                        answer = destination.store.commit(expected, payload, policy=destination.policy)
                        if (type(answer) is not StoreCommit or type(answer.state) is not Persistence or answer.state not in (
                            Persistence.COMMITTED, Persistence.EXISTING, Persistence.PURGED,
                        ) or type(answer.receipt) is not RecordReceipt
                                or answer.receipt.identity() != expected.identity()):
                            raise RecordError(Persistence.UNKNOWN)
                        state, stored = answer.state, answer.receipt
                    except RecordError as exc:
                        state = exc.status
                    except Exception:
                        state = Persistence.UNKNOWN
                results.append(DestinationResult(name, required, state, stored))
        return RecordResult(key, effect, tuple(results))

    def lookup(self, name, key):
        """Verify a known key's visible stored envelope without claiming durability."""
        if type(key) is not RecordKey:
            raise ValueError("expected the exact record key")
        destination = self._destinations[name]
        destination.check()
        try:
            stored = destination.store.read(key, policy=destination.policy)
            _verify_stored(stored)
        except RecordError:
            raise
        except Exception as exc:
            raise RecordError(Persistence.FAILED) from exc
        if stored.receipt.key != key:
            raise RecordError(Persistence.CONFLICT)
        return stored

    def readback(self, name, expected):
        """Match the stored bytes to the receipt without claiming durability."""
        if type(expected) is not RecordReceipt:
            raise ValueError("expected the original commit receipt")
        stored = self.lookup(name, expected.key)
        if stored.receipt != expected:
            raise RecordError(Persistence.CONFLICT)
        if stored.payload is None:
            raise RecordError(Persistence.PURGED)
        return stored.payload

    def verify_durable(self, name, expected):
        """Confirm exact local bytes with fresh file and directory sync."""
        if type(expected) is not RecordReceipt:
            raise ValueError("expected the original commit receipt")
        destination = self._destinations[name]
        if not isinstance(destination.store, LocalStore):
            raise RecordError(Persistence.REFUSED)
        return destination.store.verify_durable(expected, policy=destination.policy)

    def purge(self, name, expected, *, resolved=False):
        """Attempt maintenance on an explicitly settled receipt. Never runs automatically."""
        if type(expected) is not RecordReceipt or type(resolved) is not bool:
            raise ValueError("expected a receipt and explicit settlement flag")
        if not resolved:
            return Retention.RETAINED_UNRESOLVED
        destination = self._destinations[name]
        local = isinstance(destination.store, LocalStore)
        original = expected.retention
        if original is None and not local:
            return Retention.RETAINED_LEGACY
        age = max((value for value in (
            destination.policy.max_age_seconds, original.min_age_seconds if original is not None else None,
        ) if value is not None), default=None)
        if age is not None and time_ns() - expected.committed_ns < age * 1_000_000_000:
            return Retention.RETAINED_YOUNG
        try:
            destination.check()
            if local:
                return destination.store._maintain(expected, destination.policy)
            destination.store.purge(expected, policy=destination.policy)
        except RecordError:
            raise
        except Exception as exc:
            raise RecordError(Persistence.UNKNOWN) from exc
        return Retention.PURGED

    def sweep(self, name, receipts, *, settled, limit=32):
        """Consider one finite batch of exact receipts from the host's own index."""
        if (type(limit) is not int or not 1 <= limit <= _MAX_SWEEP
                or type(receipts) not in (list, tuple) or len(receipts) > limit or not callable(settled)):
            raise ValueError("expected a bounded receipt batch and settlement callback")
        receipts = tuple(receipts)
        if (any(type(receipt) is not RecordReceipt for receipt in receipts)
                or len({receipt.key for receipt in receipts}) != len(receipts)):
            raise ValueError("expected distinct exact receipts")
        destination = self._destinations[name]
        if not isinstance(destination.store, LocalStore):
            raise RecordError(Persistence.REFUSED)
        if destination.policy.expire_after_seconds is None:
            return tuple(SweepResult(receipt, Retention.RETAINED_MANUAL) for receipt in receipts)
        results = []
        for receipt in receipts:
            try:
                resolved = settled(receipt) is True
            except Exception:
                resolved = False
            if not resolved:
                results.append(SweepResult(receipt, Retention.RETAINED_UNRESOLVED))
                continue
            try:
                state = destination.store._maintain(receipt, destination.policy, expiry=True)
            except RecordError as exc:
                results.append(SweepResult(receipt, persistence=exc.status))
            except Exception:
                results.append(SweepResult(receipt, persistence=Persistence.UNKNOWN))
            else:
                results.append(SweepResult(receipt, state))
        return tuple(results)


def _verify_stored(stored):
    if type(stored) is not StoredEvidence or type(stored.receipt) is not RecordReceipt:
        raise RecordError(Persistence.FAILED)
    if stored.payload is not None and (
        type(stored.payload) is not bytes or len(stored.payload) != stored.receipt.size
        or sha256(stored.payload).hexdigest() != stored.receipt.sha256
    ):
        raise RecordError(Persistence.FAILED)


class LocalStore:
    """Linux directory-backed records with immutable bytes and nonblocking locks."""

    def __init__(self, directory, *, group_id=None, owner_uid=None):
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            raise ValueError("local store requires a trusted absolute directory")
        self.group_id = StoragePolicy(group_id).group_id
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
        if type(self.owner_uid) is not int or self.owner_uid < 0:
            raise ValueError("expected an owner UID")

    @property
    def _file_mode(self):
        return 0o600 if self.group_id is None else 0o640

    def _check_acl(self, fd, names):
        for name in names:
            try:
                os.getxattr(fd, name)
            except OSError as exc:
                if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
                    raise
            else:
                raise RecordError(Persistence.REFUSED)

    def _check_file(self, fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                or stat.S_IMODE(info.st_mode) != self._file_mode
                or (self.group_id is not None and info.st_gid != self.group_id)):
            raise RecordError(Persistence.REFUSED)
        self._check_acl(fd, ("system.posix_acl_access",))

    @contextmanager
    def _open(self, policy, *, write=False, lock=True, _parent_fd=None):
        if (sys.platform != "linux" or policy.group_id != self.group_id
                or (write and os.geteuid() != self.owner_uid)):
            raise RecordError(Persistence.REFUSED)
        import fcntl
        import grp

        if self.group_id is not None:
            try:
                grp.getgrgid(self.group_id)
            except KeyError as exc:
                raise RecordError(Persistence.REFUSED) from exc
        try:
            target = self.directory if _parent_fd is None else self.directory.name
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=_parent_fd)
        except OSError as exc:
            raise RecordError(Persistence.REFUSED) from exc
        try:
            info = os.fstat(fd)
            modes = (0o700,) if self.group_id is None else (0o750, 0o2750)
            if (info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) not in modes
                    or (self.group_id is not None and info.st_gid != self.group_id)):
                raise RecordError(Persistence.REFUSED)
            self._check_acl(fd, ("system.posix_acl_access", "system.posix_acl_default"))
            if lock:
                operation = fcntl.LOCK_EX if write else fcntl.LOCK_SH
                try:
                    fcntl.flock(fd, operation | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise RecordError(Persistence.BUSY) from exc
            yield fd
        finally:
            os.close(fd)

    def check_policy(self, policy):
        with self._open(policy, lock=False):
            return True

    def check_writable(self, policy):
        with self._open(policy, write=True, lock=False) as directory:
            try:
                allowed = os.access(".", os.W_OK | os.X_OK, dir_fd=directory, effective_ids=True)
            except (OSError, NotImplementedError) as exc:
                raise RecordError(Persistence.REFUSED) from exc
            if not allowed:
                raise RecordError(Persistence.REFUSED)
            return True

    @contextmanager
    def _read_open(self, directory, key):
        try:
            fd = os.open(key.filename(), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        except FileNotFoundError as exc:
            try:
                os.stat(self._staged_name(key), dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                raise RecordError(Persistence.MISSING) from exc
            except OSError as stat_error:
                raise RecordError(Persistence.UNKNOWN) from stat_error
            raise RecordError(Persistence.UNKNOWN) from exc
        except OSError as exc:
            raise RecordError(Persistence.FAILED) from exc
        with os.fdopen(fd, "rb") as stream:
            self._check_file(stream.fileno())
            try:
                (length,) = _HEADER_SIZE.unpack(stream.read(_HEADER_SIZE.size))
                if not 0 < length <= _MAX_HEADER:
                    raise ValueError("invalid header size")
                header = json.loads(stream.read(length))
                if (type(header) is not dict or set(header) != {"version", "receipt", "purged"}
                        or type(header["version"]) is not int or header["version"] not in (1, 2)
                        or type(header["purged"]) is not bool):
                    raise ValueError("invalid record header")
                receipt = RecordReceipt.from_dict(header["receipt"])
                if receipt.key != key or (receipt.retention is None) != (header["version"] == 1):
                    raise ValueError("record key or retention version mismatch")
                remaining = os.fstat(stream.fileno()).st_size - _HEADER_SIZE.size - length
                if remaining != (0 if header["purged"] else receipt.size):
                    raise ValueError("incorrect record length")
                stored = StoredEvidence(receipt, None if header["purged"] else stream.read())
                _verify_stored(stored)
            except (ValueError, KeyError, TypeError, struct.error) as exc:
                raise RecordError(Persistence.FAILED) from exc
            yield stored, stream.fileno()

    def read(self, key, *, policy):
        with self._open(policy) as directory, self._read_open(directory, key) as (stored, _):
            return stored

    @staticmethod
    def _sync_record(fd, directory):
        try:
            os.fsync(fd)
            os.fsync(directory)
        except OSError as exc:
            raise RecordError(Persistence.UNKNOWN) from exc

    def verify_durable(self, expected, *, policy, _parent_fd=None):
        with (
            self._open(policy, _parent_fd=_parent_fd) as directory,
            self._read_open(directory, expected.key) as (stored, fd),
        ):
            if stored.receipt != expected:
                raise RecordError(Persistence.CONFLICT)
            if stored.payload is None:
                raise RecordError(Persistence.PURGED)
            self._sync_record(fd, directory)
            return stored.payload

    @staticmethod
    def _staged_name(key):
        return "." + key.filename() + ".pending"

    def _reconcile_staging(self, directory, receipt):
        # A final durable record is the basis for removing its own stale staging entry.
        try:
            os.unlink(self._staged_name(receipt.key), dir_fd=directory)
        except FileNotFoundError:
            pass

    def _publish(self, directory, receipt, payload, *, replace=False):
        header = json.dumps({"version": 2, "receipt": asdict(receipt), "purged": payload is None},
                            sort_keys=True, separators=(",", ":")).encode("ascii")
        name = receipt.key.filename()
        temporary = self._staged_name(receipt.key)
        published = False
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
        except FileExistsError as exc:
            raise RecordError(Persistence.UNKNOWN) from exc
        except OSError as exc:
            raise RecordError(Persistence.FAILED) from exc
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(_HEADER_SIZE.pack(len(header)))
                stream.write(header)
                if payload is not None:
                    stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), self._file_mode)
                self._check_file(stream.fileno())
                os.fsync(stream.fileno())
            if replace:
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            published = True
            if not replace:
                os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
        except OSError as exc:
            raise RecordError(Persistence.UNKNOWN if published else Persistence.FAILED) from exc
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise RecordError(Persistence.UNKNOWN) from exc

    def commit(self, receipt, payload, *, policy, _parent_fd=None):
        if type(payload) is not bytes:
            raise ValueError("expected raw evidence bytes")
        _verify_stored(StoredEvidence(receipt, payload))
        required = RetentionStamp.from_policy(policy)
        if receipt.retention is None:
            receipt = replace(receipt, retention=required)
        elif receipt.retention != required:
            raise RecordError(Persistence.REFUSED)
        with self._open(policy, write=True, _parent_fd=_parent_fd) as directory:
            try:
                with self._read_open(directory, receipt.key) as (prior, fd):
                    if prior.receipt.identity() != receipt.identity():
                        raise RecordError(Persistence.CONFLICT)
                    # A previous caller may have lost acknowledgment after publishing.
                    self._reconcile_staging(directory, prior.receipt)
                    self._sync_record(fd, directory)
                    state = Persistence.PURGED if prior.payload is None else Persistence.EXISTING
                    return StoreCommit(state, prior.receipt)
            except RecordError as exc:
                if exc.status is not Persistence.MISSING:
                    raise
                self._publish(directory, receipt, payload)
                return StoreCommit(Persistence.COMMITTED, receipt)

    def purge(self, expected, *, policy):
        if self._maintain(expected, policy) is not Retention.PURGED:
            raise RecordError(Persistence.REFUSED)

    def _maintain(self, expected, policy, *, expiry=False):
        with (
            self._open(policy, write=True) as directory,
            self._read_open(directory, expected.key) as (stored, fd),
        ):
            original = stored.receipt.retention
            if stored.receipt != expected:
                raise RecordError(Persistence.CONFLICT)
            if stored.payload is None:
                self._sync_record(fd, directory)
                return Retention.PURGED
            if original is None:
                # V1 recorded no enforcement terms, so no safe age floor can be recovered.
                return Retention.RETAINED_LEGACY
            terms = [original.min_age_seconds, policy.max_age_seconds]
            if expiry:
                if original.expire_after_seconds is None or policy.expire_after_seconds is None:
                    return Retention.RETAINED_MANUAL
                terms.extend((original.expire_after_seconds, policy.expire_after_seconds))
            age = max((term for term in terms if term is not None), default=None)
            if age is not None and time_ns() - stored.receipt.committed_ns < age * 1_000_000_000:
                return Retention.RETAINED_YOUNG
            # A readable but still indeterminate commit must not be removed.
            self._sync_record(fd, directory)
            self._reconcile_staging(directory, stored.receipt)
            self._publish(directory, expected, None, replace=True)
            return Retention.PURGED
