"""Read a commissioned observer's independent result for one guarded run."""

from dataclasses import asdict, dataclass, replace
import re
from time import monotonic_ns

from .managed_executor import _Authority, authority_pin
from .managed_launch import (GUARDED_SERVICE, LaunchInvocation, LaunchReadback, ServiceProcessIdentity,
                             _digest, _service_cgroup, _unsigned, service_cleanup)
from .recording import _name
from .roles_cli import _fields
from .scope_meter import CgroupIdentity


def _compatible_cuts(left, right):
    """Require a single causal order across observations in this same clock."""
    if left.clock_id != right.clock_id:
        return False
    phases = [(left.start_ns, right.start_ns), (left.terminal_ns, right.terminal_ns),
              (left.empty_ns, right.empty_ns)]
    begin = tuple(sample.observed_ns for sample in (left.meter_begin, right.meter_begin) if sample is not None)
    end = tuple(sample.observed_ns for sample in (left.meter_end, right.meter_end) if sample is not None)
    if begin:
        phases.insert(0, begin)
    if end:
        phases.append(end)
    phases.append((left.retired_ns, right.retired_ns, left.handles_closed_ns, right.handles_closed_ns))
    return all(max(earlier) <= min(later) for earlier, later in zip(phases, phases[1:]))


@dataclass(frozen=True, slots=True)
class EffectCleanupObservation:
    """A witness's own effect and closure observations. No wait status."""

    scope_sha256: str
    manager_run_id: str
    cgroup: CgroupIdentity
    reaped_process: ServiceProcessIdentity
    live_ns: int
    exit_ready_ns: int
    empty_ns: int
    retired_ns: int
    effect_observed_ns: int
    handles_closed_ns: int

    def __post_init__(self):
        _digest(self.scope_sha256)
        if (type(self.manager_run_id) is not str or re.fullmatch(r'[0-9a-f]{32}', self.manager_run_id) is None
                or self.manager_run_id == '0' * 32):
            raise ValueError('service_witness_run_invalid')
        object.__setattr__(self, 'cgroup', _service_cgroup(self.cgroup))
        if type(self.reaped_process) is dict:
            object.__setattr__(self, 'reaped_process', ServiceProcessIdentity(**self.reaped_process))
        if type(self.reaped_process) is not ServiceProcessIdentity:
            raise ValueError('service_witness_process_invalid')
        for tick in (self.live_ns, self.exit_ready_ns, self.empty_ns, self.retired_ns,
                     self.effect_observed_ns, self.handles_closed_ns):
            _unsigned(tick, positive=True)
        if not (self.live_ns < self.exit_ready_ns <= self.empty_ns <= self.retired_ns <= self.handles_closed_ns
                and self.empty_ns <= self.effect_observed_ns <= self.handles_closed_ns):
            raise ValueError('service_witness_cuts_invalid')

    def matches(self, service):
        life = service.lifecycle
        return (life is not None and life.terminal_ns is not None
                and life.retired_ns is not None and self.effect_observed_ns <= life.retired_ns
                and (self.scope_sha256, self.manager_run_id, self.cgroup, self.reaped_process) == (
                    service.scope_sha256, service.manager_run_id, life.cgroup, service.reaped_process)
                and self.live_ns < life.terminal_ns and life.start_ns <= self.exit_ready_ns)


@dataclass(frozen=True, slots=True)
class _WitnessReadback:
    invocation: LaunchInvocation
    source: str
    source_sha256: str
    receipt_sha256: str
    cleanup: EffectCleanupObservation

    def __post_init__(self):
        _name(self.source)
        _digest(self.source_sha256)
        _digest(self.receipt_sha256)
        object.__setattr__(self, 'cleanup', EffectCleanupObservation(**self.cleanup))


def validate_observer(config, policy, guard, limits):
    _fields(config, ('source', 'socket', 'uid'), ('expected_effect_sha256', 'handoff'))
    if (guard.get('enforcement') != GUARDED_SERVICE or limits is None or config['source'] == policy.authority
            or config['uid'] in (0, guard['uid'], policy.principal_uid) or config['socket'] == guard['socket']):
        raise ValueError('service_result_observer_not_independent')
    if 'handoff' in config and (config['handoff'] is not True or 'expected_effect_sha256' not in config):
        raise ValueError('service_witness_registration_invalid')
    if 'expected_effect_sha256' in config:
        _digest(config['expected_effect_sha256'])
    return authority_pin(config['source'], config['socket'], config['uid'])


class ResultObserver:
    """Use the existing authenticated authority transport for a read-only observation."""

    def __init__(self, config, policy, guard, limits):
        self.pin = validate_observer(config, policy, guard, limits)
        self.source = config['source']
        self.endpoint = _Authority(config['socket'], config['uid'], replace(
            policy, authority=self.source, authority_sha256=self.pin))
        self.limits = limits
        self.expected_effect = config.get('expected_effect_sha256')

    def read(self, guard, *, deadline_ns):
        invocation = guard.invocation
        requested_ns = monotonic_ns()
        # The observer looks up the exact invocation from its own evidence.
        # This request deliberately carries no guard report it could echo.
        reply = self.endpoint._exchange('read_result', invocation, deadline_ns)
        _fields(reply, ('observation', 'effect_sha256', 'verified_ns', 'expires_ns'))
        effect = reply['effect_sha256']
        _digest(effect)
        verified, expiry = reply['verified_ns'], reply['expires_ns']
        _unsigned(verified, positive=True)
        _unsigned(expiry, positive=True)
        if (self.expected_effect is not None and effect != self.expected_effect
                or not requested_ns <= verified <= monotonic_ns() < expiry):
            raise ValueError('service_result_observer_unverified')
        fields = reply['observation']
        if type(fields) is dict and 'cleanup' in fields:
            result = self.endpoint._decode(fields, _WitnessReadback)
            evidence = result.cleanup
            if (result.invocation != invocation or (result.source, result.source_sha256) != (self.source, self.pin)
                    or invocation.service_window is None or not evidence.matches(guard.service)
                    or evidence.handles_closed_ns >= invocation.service_window.cleanup_until_ns
                    or evidence.handles_closed_ns > verified):
                raise ValueError('service_result_observer_unverified')
            return {'source': self.source, 'source_sha256': self.pin, 'effect_sha256': effect,
                    'receipt_sha256': result.receipt_sha256, 'verified_ns': verified, 'expires_ns': expiry,
                    'cleanup_observation': asdict(evidence),
                    'terminal_source': {'source': guard.source, 'source_sha256': guard.source_sha256}}
        result = self.endpoint._decode(fields, LaunchReadback)
        service = result.service
        if (result.status != 'terminal' or result.invocation != invocation
                or (result.source, result.source_sha256) != (self.source, self.pin)
                or (result.effective_principal, result.effective_principal_uid,
                    result.effective_executable_sha256, result.effective_scope_sha256) != (
                    guard.effective_principal, guard.effective_principal_uid,
                    guard.effective_executable_sha256, guard.effective_scope_sha256)
                or service is None or service.lifecycle is None):
            raise ValueError('service_result_observer_binding_mismatch')
        life, reported = service.lifecycle, guard.service.lifecycle
        if ((service.unit, service.scope_sha256, service.manager_run_id, life.cgroup,
             life.terminal_disposition, life.terminal_status) != (
                 guard.service.unit, guard.service.scope_sha256, guard.service.manager_run_id,
                 reported.cgroup, reported.terminal_disposition, reported.terminal_status)
                or service_cleanup(service, 'terminal', limits=self.limits,
                                   clock_id=invocation.clock_id, window=invocation.service_window) != 'verified'
                or not _compatible_cuts(reported, life)
                or max(life.retired_ns, life.handles_closed_ns) > verified):
            raise ValueError('service_result_observer_unverified')
        return {'source': self.source, 'source_sha256': self.pin, 'effect_sha256': effect,
                'receipt_sha256': result.receipt_sha256, 'verified_ns': verified, 'expires_ns': expiry,
                'service': asdict(service)}
