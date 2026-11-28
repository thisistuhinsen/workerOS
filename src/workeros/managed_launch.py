"""Trusted in-process contract for one externally enforced managed invocation."""
from dataclasses import asdict, dataclass, replace
import re
from secrets import token_hex
from signal import NSIG
from threading import Lock
from time import monotonic_ns
from typing import Callable

from .recording import _name
from .scope_meter import CgroupIdentity, _MAX_COUNTER

_HASH = re.compile(r'[0-9a-f]{64}')
_SERVICE_UNIT = re.compile(r'workeros-[0-9a-f]{64}\.service')
_SYSTEMD_INVOCATION = re.compile(r'[0-9a-f]{32}')


def _digest(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError('expected an exact SHA-256 pin')


def _uid(value):
    if type(value) is not int or not 0 <= value < 2**32 - 1:
        raise ValueError('expected an exact Linux UID')


def _unsigned(value, *, positive=False, maximum=(1 << 63) - 1):
    if type(value) is not int or not int(positive) <= value <= maximum:
        raise ValueError('invalid service observation integer')


def _service_cgroup(value):
    if type(value) is dict:
        value = CgroupIdentity(**value)
    if type(value) is not CgroupIdentity:
        raise ValueError('expected exact cgroup identity')
    _unsigned(value.device, maximum=_MAX_COUNTER)
    _unsigned(value.inode, positive=True, maximum=_MAX_COUNTER)
    _unsigned(value.mount_id, positive=True, maximum=_MAX_COUNTER)
    return value


@dataclass(frozen=True, slots=True)
class _LaunchBinding:
    workflow: str
    definition_sha256: str
    generation: str
    role: str
    principal: str
    executable_sha256: str
    scope_sha256: str
    launcher: str
    authority: str
    authority_sha256: str

    def __post_init__(self):
        for value in (self.workflow, self.generation, self.role, self.principal,
                      self.launcher, self.authority):
            _name(value)
        for value in (self.definition_sha256, self.executable_sha256,
                      self.scope_sha256, self.authority_sha256):
            _digest(value)
        if self.authority in (self.launcher, self.principal):
            raise ValueError('launch authority must be independent')


@dataclass(frozen=True, slots=True)
class LaunchRolePolicy(_LaunchBinding):
    """Reusable host approval for one exact role, executable, and scope."""

    principal_uid: int

    def __post_init__(self):
        _LaunchBinding.__post_init__(self)
        _uid(self.principal_uid)


@dataclass(frozen=True, slots=True)
class LaunchPlan(_LaunchBinding):
    """One host-approved invocation with no executable path or caller arguments."""

    invocation_key: str
    principal_uid: int | None = None

    def __post_init__(self):
        _LaunchBinding.__post_init__(self)
        _digest(self.invocation_key)
        if self.principal_uid is not None:
            _uid(self.principal_uid)


def new_launch_request():
    """Return an opaque request ID that the caller can retain before invoking."""
    return token_hex(32)


@dataclass(frozen=True, slots=True)
class ServiceWindow:
    """One persisted monotonic authority window for active work and cleanup."""

    active_until_ns: int
    cleanup_until_ns: int

    def __post_init__(self):
        _unsigned(self.active_until_ns, positive=True)
        _unsigned(self.cleanup_until_ns, positive=True)
        if self.active_until_ns >= self.cleanup_until_ns:
            raise ValueError('invalid managed service window')


@dataclass(frozen=True, slots=True)
class LaunchInvocation:
    profile_identity: str
    clock_id: str
    plan: LaunchPlan
    service_window: ServiceWindow | None = None

    def __post_init__(self):
        _digest(self.profile_identity)
        _name(self.clock_id)
        if type(self.plan) is not LaunchPlan:
            raise ValueError('expected exact launch plan')
        if type(self.service_window) is dict:
            object.__setattr__(self, 'service_window', ServiceWindow(**self.service_window))
        if self.service_window is not None and type(self.service_window) is not ServiceWindow:
            raise ValueError('expected exact managed service window')


@dataclass(frozen=True, slots=True)
class LaunchAuthorization:
    """An authenticated authority's one-invocation ticket reference."""

    invocation: LaunchInvocation
    source: str
    source_sha256: str
    ticket_sha256: str
    expires_ns: int
    guard_sha256: str | None = None

    def __post_init__(self):
        if type(self.invocation) is not LaunchInvocation:
            raise ValueError('expected exact launch invocation')
        _name(self.source)
        _digest(self.source_sha256)
        _digest(self.ticket_sha256)
        if self.guard_sha256 is not None:
            _digest(self.guard_sha256)
            if self.guard_sha256 == '0' * 64:
                raise ValueError('expected a nonzero armed service guard pin')
        if type(self.expires_ns) is not int or not 0 < self.expires_ns < 2**63:
            raise ValueError('expected an exact monotonic expiry')


@dataclass(frozen=True, slots=True)
class ServiceLimits:
    """Protected active and cleanup budgets and required scope accounting."""

    active_ms: int
    cleanup_ms: int
    metered: bool

    def __post_init__(self):
        if (type(self.active_ms) is not int or not 0 < self.active_ms <= 86_400_000
                or type(self.cleanup_ms) is not int or not 0 < self.cleanup_ms <= 60_000
                or type(self.metered) is not bool):
            raise ValueError('invalid managed service limits')


@dataclass(frozen=True, slots=True)
class ServiceMeterReading:
    """Observed endpoint counters for one retained cgroup."""

    observed_ns: int
    cgroup: CgroupIdentity
    usage_usec: int
    memory_current_bytes: int
    memory_peak_bytes: int
    populated: bool

    def __post_init__(self):
        object.__setattr__(self, 'cgroup', _service_cgroup(self.cgroup))
        _unsigned(self.observed_ns)
        for value in (self.usage_usec, self.memory_current_bytes, self.memory_peak_bytes):
            _unsigned(value, maximum=_MAX_COUNTER)
        if self.memory_current_bytes > self.memory_peak_bytes:
            raise ValueError('service memory current exceeds observed peak')
        if self.populated is not False:
            raise ValueError('expected an observed empty meter endpoint')


@dataclass(frozen=True, slots=True)
class ServiceLifecycle:
    """Observations for the service InvocationID and scope in its envelope."""

    clock_id: str
    start_ns: int
    cgroup: CgroupIdentity
    terminal_ns: int | None = None
    terminal_disposition: str | None = None
    terminal_status: int | None = None
    empty_ns: int | None = None
    retired_ns: int | None = None
    handles_closed_ns: int | None = None
    meter_begin: ServiceMeterReading | None = None
    meter_end: ServiceMeterReading | None = None

    def __post_init__(self):
        _name(self.clock_id)
        _unsigned(self.start_ns)
        object.__setattr__(self, 'cgroup', _service_cgroup(self.cgroup))
        for field in ('meter_begin', 'meter_end'):
            reading = getattr(self, field)
            if type(reading) is dict:
                reading = ServiceMeterReading(**reading)
                object.__setattr__(self, field, reading)
            if reading is not None and (type(reading) is not ServiceMeterReading or reading.cgroup != self.cgroup):
                raise ValueError('service meter scope mismatch')
        if self.meter_begin is not None and self.meter_begin.observed_ns > self.start_ns:
            raise ValueError('service meter began after start')
        cleanup = (self.empty_ns, self.retired_ns, self.handles_closed_ns)
        if self.terminal_ns is None:
            if any(value is not None for value in (*cleanup, self.terminal_disposition,
                                                   self.terminal_status, self.meter_end)):
                raise ValueError('service cleanup or disposition without terminal observation')
            return
        _unsigned(self.terminal_ns)
        if self.terminal_ns < self.start_ns or type(self.terminal_status) is not int:
            raise ValueError('invalid terminal observation')
        if not (self.terminal_disposition == 'exited' and 0 <= self.terminal_status < 256
                or self.terminal_disposition == 'signaled' and 0 < self.terminal_status < NSIG):
            raise ValueError('invalid terminal disposition')
        for tick in cleanup:
            if tick is not None:
                _unsigned(tick)
                if tick < self.terminal_ns:
                    raise ValueError('service cleanup preceded terminal observation')
        if self.empty_ns is not None and self.retired_ns is not None and self.retired_ns < self.empty_ns:
            raise ValueError('service retired before observed emptiness')
        if self.meter_end is not None:
            self._check_meter_end()

    def _check_meter_end(self):
        end = self.meter_end
        if (end.observed_ns < (self.empty_ns if self.empty_ns is not None else self.terminal_ns)
                or any(tick is not None and end.observed_ns > tick
                       for tick in (self.retired_ns, self.handles_closed_ns))):
            raise ValueError('service meter ended outside the retained cleanup scope')
        begin = self.meter_begin
        if begin is not None and (end.usage_usec < begin.usage_usec or end.memory_peak_bytes < begin.memory_peak_bytes):
            raise ValueError('service accounting counter regressed')


@dataclass(frozen=True, slots=True)
class ServiceProcessIdentity:
    """Incarnation of the actual guarded sandbox process in the host PID view."""

    pid: int
    start_ticks: int
    pid_namespace_inode: int

    def __post_init__(self):
        _unsigned(self.pid, positive=True, maximum=(1 << 31) - 1)
        _unsigned(self.start_ticks, positive=True)
        _unsigned(self.pid_namespace_inode, positive=True)


@dataclass(frozen=True, slots=True)
class ManagedServiceEvidence:
    """Independent effective service scope and optional cleanup observations."""

    unit: str
    invocation_id: str | None
    scope_sha256: str
    group_empty: bool | None = None
    handles_closed: bool | None = None
    lifecycle: ServiceLifecycle | None = None
    manager_run_id: str | None = None
    reaped_process: ServiceProcessIdentity | None = None

    def __post_init__(self):
        if type(self.unit) is not str or _SERVICE_UNIT.fullmatch(self.unit) is None:
            raise ValueError('expected an exact managed service unit')
        if self.manager_run_id is None:
            if (type(self.invocation_id) is not str
                    or _SYSTEMD_INVOCATION.fullmatch(self.invocation_id) is None
                    or self.invocation_id == '0' * 32):
                raise ValueError('expected a nonzero systemd InvocationID')
        elif (self.invocation_id is not None or type(self.manager_run_id) is not str
              or _SYSTEMD_INVOCATION.fullmatch(self.manager_run_id) is None or self.manager_run_id == '0' * 32):
            raise ValueError('expected one exact delegated manager run identity')
        _digest(self.scope_sha256)
        if any(value is not None and type(value) is not bool for value in (self.group_empty, self.handles_closed)):
            raise ValueError('expected independent cleanup observations')
        if type(self.lifecycle) is dict:
            object.__setattr__(self, 'lifecycle', ServiceLifecycle(**self.lifecycle))
        if self.lifecycle is not None:
            if type(self.lifecycle) is not ServiceLifecycle:
                raise ValueError('expected exact service lifecycle')
            if (self.group_empty is False and self.lifecycle.empty_ns is not None
                    or self.handles_closed is False and self.lifecycle.handles_closed_ns is not None):
                raise ValueError('contradictory service cleanup observations')
        if type(self.reaped_process) is dict:
            object.__setattr__(self, 'reaped_process', ServiceProcessIdentity(**self.reaped_process))
        if self.reaped_process is not None and (
                type(self.reaped_process) is not ServiceProcessIdentity or self.manager_run_id is None
                or self.lifecycle is None or self.lifecycle.terminal_ns is None):
            raise ValueError('service reaped process requires a delegated terminal report')


def service_cleanup(evidence, status, *, limits=None, clock_id=None, window=None):
    """Classify verified terminal cleanup separately from effect and outcome."""
    if type(evidence) is not ManagedServiceEvidence or status not in ('started', 'terminal'):
        raise ValueError('expected exact service readback')
    lifecycle = evidence.lifecycle
    if lifecycle is not None and (
            (clock_id is not None and lifecycle.clock_id != clock_id)
            or (status == 'terminal') != (lifecycle.terminal_ns is not None)):
        raise ValueError('crossed clock or service lifecycle status')
    if limits is not None and (type(limits) is not ServiceLimits or lifecycle is None or clock_id is None):
        raise ValueError('missing selected service lifecycle')
    if window is not None and (
            type(window) is not ServiceWindow or limits is None
            or window.cleanup_until_ns - window.active_until_ns > limits.cleanup_ms * 1_000_000):
        raise ValueError('unbound managed service window')
    if status == 'started':
        if evidence.group_empty is not None or evidence.handles_closed is not None:
            raise ValueError('cleanup observations require terminal service evidence')
        if window is not None and lifecycle.start_ns >= window.active_until_ns:
            raise ValueError('service started beyond its authorized window')
        return 'not_observed'
    if evidence.group_empty is not True or evidence.handles_closed is not True:
        return 'unconfirmed'
    if limits is None:
        return 'verified'
    if (lifecycle.empty_ns is None or lifecycle.retired_ns is None or lifecycle.handles_closed_ns is None
            or (limits.metered and (lifecycle.meter_begin is None or lifecycle.meter_end is None))):
        return 'unconfirmed'
    finished_ns = max(lifecycle.retired_ns, lifecycle.handles_closed_ns)
    if (lifecycle.terminal_ns - lifecycle.start_ns > limits.active_ms * 1_000_000
            or finished_ns - lifecycle.terminal_ns > limits.cleanup_ms * 1_000_000):
        return 'unconfirmed'
    if window is not None and (lifecycle.terminal_ns >= window.active_until_ns
                               or finished_ns >= window.cleanup_until_ns):
        return 'unconfirmed'
    return 'verified'


@dataclass(frozen=True, slots=True)
class UnreleasedServiceEvidence:
    """Same-leaf retirement of a trusted gate that never received worker resources."""

    unit: str
    scope_sha256: str
    clock_id: str
    manager_run_id: str
    cgroup: CgroupIdentity
    placed_ns: int
    reaped_ns: int
    empty_ns: int
    retired_ns: int

    def __post_init__(self):
        if (type(self.unit) is not str or _SERVICE_UNIT.fullmatch(self.unit) is None
                or type(self.manager_run_id) is not str or _SYSTEMD_INVOCATION.fullmatch(self.manager_run_id) is None
                or self.manager_run_id == '0' * 32):
            raise ValueError('unreleased_service_identity_invalid')
        _digest(self.scope_sha256)
        _name(self.clock_id)
        object.__setattr__(self, 'cgroup', _service_cgroup(self.cgroup))
        for tick in (self.placed_ns, self.reaped_ns, self.empty_ns, self.retired_ns):
            _unsigned(tick, positive=True)
        if not self.placed_ns <= self.reaped_ns <= self.empty_ns <= self.retired_ns:
            raise ValueError('unreleased_service_order_invalid')

    def matches(self, invocation, scope_sha256):
        window = invocation.service_window
        return (window is not None and self.clock_id == invocation.clock_id and self.scope_sha256 == scope_sha256
                and self.unit == f'workeros-{invocation.plan.invocation_key}.service'
                and self.placed_ns < window.active_until_ns and self.retired_ns < window.cleanup_until_ns)


@dataclass(frozen=True, slots=True)
class LaunchReadback:
    """Independent observation. Effective fields describe the actual invocation."""

    invocation: LaunchInvocation
    source: str
    source_sha256: str
    status: str
    effective_principal: str | None = None
    effective_executable_sha256: str | None = None
    effective_scope_sha256: str | None = None
    receipt_sha256: str | None = None
    effective_principal_uid: int | None = None
    service: ManagedServiceEvidence | None = None
    unreleased: UnreleasedServiceEvidence | None = None

    def __post_init__(self):
        if type(self.invocation) is not LaunchInvocation:
            raise ValueError('expected exact launch invocation')
        _name(self.source)
        _digest(self.source_sha256)
        if self.status not in ('not_started', 'pending', 'started', 'terminal', 'unknown', 'unreleased'):
            raise ValueError('invalid launch readback state')
        if type(self.unreleased) is dict:
            object.__setattr__(self, 'unreleased', UnreleasedServiceEvidence(**self.unreleased))
        if self.status == 'unreleased':
            if (type(self.unreleased) is not UnreleasedServiceEvidence
                    or not self.unreleased.matches(self.invocation, self.unreleased.scope_sha256)):
                raise ValueError('unreleased_service_binding_unverified')
        elif self.unreleased is not None:
            raise ValueError('unexpected unreleased service evidence')
        if type(self.service) is dict:
            object.__setattr__(self, 'service', ManagedServiceEvidence(**self.service))
        if self.service is not None and type(self.service) is not ManagedServiceEvidence:
            raise ValueError('expected exact managed service evidence')
        fields = (self.effective_principal, self.effective_executable_sha256,
                  self.effective_scope_sha256, self.receipt_sha256)
        if self.status in ('started', 'terminal'):
            _name(self.effective_principal)
            for value in fields[1:]:
                _digest(value)
            if self.effective_principal_uid is not None:
                _uid(self.effective_principal_uid)
            if self.service is not None:
                service_cleanup(self.service, self.status, clock_id=self.invocation.clock_id)
        elif any(value is not None for value in (*fields, self.effective_principal_uid, self.service)):
            raise ValueError('unexpected effective launch evidence')


@dataclass(frozen=True, slots=True)
class LaunchRegistration:
    """Supplied by trusted deployment code after authenticating its two endpoints.

    The independent authority authenticates authorization and readback. The
    launcher must atomically reserve the exact key and validate and consume the
    ticket before starting a worker. It must enforce the plan at the point of
    launch and retain durable no-replay state across processes and restarts.
    A reusable role policy needs the stock local approval and reservation store.
    Set require_ticket_claim when dispatch runs locally through that locked
    store and must consume the authority ticket before executing.
    """

    plan: LaunchPlan | LaunchRolePolicy
    authorize: Callable[..., LaunchAuthorization | None]
    dispatch_once: Callable[..., None]
    readback: Callable[..., LaunchReadback]
    bounded: bool = False
    service_scope_sha256: str | None = None
    service_limits: ServiceLimits | None = None
    service_enforcement: str | None = None
    require_ticket_claim: bool = False
    observe_result: Callable[..., dict] | None = None

    def __post_init__(self):
        if (type(self.plan) not in (LaunchPlan, LaunchRolePolicy) or type(self.bounded) is not bool
                or type(self.require_ticket_claim) is not bool
                or not all(callable(value) for value in (self.authorize, self.dispatch_once, self.readback))):
            raise ValueError('expected trusted launch and authority callbacks')
        if self.dispatch_once in (self.authorize, self.readback):
            raise ValueError('launcher callback cannot verify itself')
        if self.service_scope_sha256 is not None:
            _digest(self.service_scope_sha256)
            if self.plan.principal_uid is None:
                raise ValueError('managed service readback requires a pinned Linux UID')
        if type(self.service_limits) is dict:
            object.__setattr__(self, 'service_limits', ServiceLimits(**self.service_limits))
        if self.service_limits is not None and (type(self.service_limits) is not ServiceLimits
                                                 or self.service_scope_sha256 is None):
            raise ValueError('service limits require an exact managed service scope')
        if self.service_enforcement is not None and (
                self.service_enforcement != GUARDED_SERVICE or self.service_limits is None):
            raise ValueError('guarded enforcement requires bounded service registration')
        if self.observe_result is not None and (self.service_enforcement != GUARDED_SERVICE
                                               or not self.bounded or not callable(self.observe_result)):
            raise ValueError('result observer requires guarded service')

    def _for_attempt(self, key):
        return replace(self, plan=LaunchPlan(**asdict(self.plan), invocation_key=key))


def launch_result(status, effect, code, **fields):
    return {'status': status, 'effect': effect, 'code': code, **fields}


GUARDED_SERVICE = 'guarded-service-v1'


class LaunchArmingUnconfirmed(ValueError):
    """The reserved invocation may have been armed but cannot be submitted."""


class ScopedLaunch:
    """Verify pinned authority and use independent readback instead of a launch reply."""

    def __init__(self, registration, identity, clock_id, *, already_reserved=False, service_window=None):
        self.registration = registration
        self.invocation = LaunchInvocation(identity, clock_id, registration.plan, service_window)
        self._requested = already_reserved
        self._dispatch_lock = Lock()

    def _call(self, callback, *args, deadline_ns):
        if not self.registration.bounded:
            return callback(*args)
        if deadline_ns is None or monotonic_ns() >= deadline_ns:
            raise TimeoutError()
        result = callback(*args, deadline_ns=deadline_ns)
        if monotonic_ns() >= deadline_ns:
            raise TimeoutError()
        return result

    def _read(self, deadline_ns):
        plan = self.registration.plan
        try:
            report = self._call(self.registration.readback, self.invocation, deadline_ns=deadline_ns)
        except Exception:
            return None
        if (type(report) is not LaunchReadback or report.invocation != self.invocation
                or (report.source, report.source_sha256) != (plan.authority, plan.authority_sha256)):
            return None
        if report.status in ('started', 'terminal') and (
                report.effective_principal, report.effective_executable_sha256, report.effective_scope_sha256
        ) != (plan.principal, plan.executable_sha256, plan.scope_sha256):
            return None
        if (report.status in ('started', 'terminal') and plan.principal_uid is not None
                and report.effective_principal_uid != plan.principal_uid):
            return None
        service_scope = self.registration.service_scope_sha256
        if report.status == 'unreleased' and (
                self.registration.service_enforcement != GUARDED_SERVICE
                or not report.unreleased.matches(self.invocation, service_scope)):
            return None
        if service_scope is not None and report.status in ('started', 'terminal'):
            service = report.service
            if (service is None or service.unit != f'workeros-{plan.invocation_key}.service'
                    or service.scope_sha256 != service_scope):
                return None
            try:
                if self.registration.service_limits is not None and self.invocation.service_window is None:
                    return None
                service_cleanup(service, report.status, limits=self.registration.service_limits,
                                clock_id=self.invocation.clock_id, window=self.invocation.service_window)
            except ValueError:
                return None
        return report

    def _result(self, report, *, deadline_ns=None):
        key = self.registration.plan.invocation_key
        if report is not None and report.status == 'unreleased':
            return launch_result('not_started', 'not_attempted', 'service_bootstrap_unreleased',
                                 invocation_key=key, unreleased=asdict(report.unreleased))
        if report is not None and report.status in ('started', 'terminal'):
            result = launch_result(report.status, 'dispatched', 'launch_readback_verified',
                                   invocation_key=key, receipt_sha256=report.receipt_sha256)
            if self.registration.service_scope_sha256 is not None:
                service = asdict(report.service)
                if report.service.manager_run_id is None:
                    service.pop('manager_run_id')
                if report.service.lifecycle is None:
                    service.pop('lifecycle')
                if report.service.reaped_process is None:
                    service.pop('reaped_process')
                cleanup = service_cleanup(report.service, report.status, limits=self.registration.service_limits,
                                          clock_id=self.invocation.clock_id, window=self.invocation.service_window)
                result.update(service=service, cleanup=cleanup)
                observer = self.registration.observe_result
                if (observer is not None and self._requested and report.status == 'terminal'
                        and report.service.manager_run_id is not None and cleanup == 'verified'):
                    try:
                        result['observer_result'] = self._call(observer, report, deadline_ns=deadline_ns)
                    except (OSError, EOFError, TypeError, KeyError, ValueError):
                        pass
            return result
        if report is not None and report.status == 'not_started' and not self._requested:
            return launch_result('not_started', 'not_attempted', 'launch_not_started', invocation_key=key)
        return launch_result('unknown', 'unknown', 'launch_readback_unconfirmed', invocation_key=key)

    def read(self, *, deadline_ns=None):
        return self._result(self._read(deadline_ns), deadline_ns=deadline_ns)

    def start(self, *, valid_until_ns, deadline_ns=None, reserve=None, claim_ticket=None):
        # Contention cannot wait past the caller's shared budget.
        if not self._dispatch_lock.acquire(blocking=False):
            return self._result(None)
        try:
            window = self.invocation.service_window
            limits = self.registration.service_limits
            if (limits is not None and window is None or window is not None and (
                    limits is None or window.cleanup_until_ns - window.active_until_ns
                    > limits.cleanup_ms * 1_000_000)):
                return launch_result('refused', 'not_attempted', 'service_window_unverified')
            prior = self._read(deadline_ns)
            if self._requested or prior is None or prior.status != 'not_started':
                return self._result(prior, deadline_ns=deadline_ns)
            if window is not None and not callable(reserve):
                return launch_result('refused', 'not_attempted', 'service_reservation_required')
            if self.registration.require_ticket_claim and (not callable(reserve) or not callable(claim_ticket)):
                return launch_result('refused', 'not_attempted', 'launch_ticket_claim_required')
            if reserve is not None:
                # Persist before contacting a potentially stateful ticket issuer.
                self._requested = True
                if not reserve():
                    return launch_result('unknown', 'unknown', 'launch_reservation_unconfirmed')
                if monotonic_ns() >= valid_until_ns:
                    return launch_result('refused', 'not_attempted', 'launch_deadline_elapsed')
            if window is not None and monotonic_ns() >= window.active_until_ns:
                return launch_result('refused', 'not_attempted', 'launch_deadline_elapsed')
            try:
                approval = self._call(self.registration.authorize, self.invocation, deadline_ns=deadline_ns)
            except LaunchArmingUnconfirmed:
                return launch_result('unknown', 'unknown', 'service_arming_unconfirmed')
            except Exception:
                if self.registration.service_enforcement == GUARDED_SERVICE:
                    return launch_result('unknown', 'unknown', 'service_arming_unconfirmed')
                approval = None
            if (type(approval) is not LaunchAuthorization or approval.invocation != self.invocation
                    or (approval.source, approval.source_sha256) != (
                        self.registration.plan.authority, self.registration.plan.authority_sha256)
                    or (window is not None and approval.guard_sha256 is None)
                    or not monotonic_ns() < approval.expires_ns <= valid_until_ns):
                return launch_result('refused', 'not_attempted', 'launch_authority_unverified')
            dispatch_deadline = None if deadline_ns is None else min(deadline_ns, approval.expires_ns)
            if window is not None:
                dispatch_deadline = min(dispatch_deadline if dispatch_deadline is not None else approval.expires_ns,
                                        window.active_until_ns)
            if dispatch_deadline is not None and monotonic_ns() >= dispatch_deadline:
                return launch_result('refused', 'not_attempted', 'launch_deadline_elapsed')
            if self.registration.require_ticket_claim:
                try:
                    claimed = claim_ticket(approval)
                except Exception:
                    claimed = None
                if claimed is False:
                    return launch_result('refused', 'not_attempted', 'launch_ticket_already_consumed')
                if claimed is not True:
                    return launch_result('unknown', 'unknown', 'launch_ticket_consumption_unconfirmed')
                if not monotonic_ns() < min(valid_until_ns, approval.expires_ns,
                                            dispatch_deadline if dispatch_deadline is not None else approval.expires_ns):
                    return launch_result('refused', 'not_attempted', 'launch_deadline_elapsed')
            self._requested = True
            try:
                self._call(self.registration.dispatch_once, self.invocation, approval, deadline_ns=dispatch_deadline)
            except Exception:
                pass
            # A return or exception from the launcher cannot settle the outcome.
            return self._result(self._read(deadline_ns), deadline_ns=deadline_ns)
        finally:
            self._dispatch_lock.release()
