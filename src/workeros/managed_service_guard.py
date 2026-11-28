"""Client of an already appointed manager that controls guarded admission.

Every call uses the installed launch authority's authenticated peer. The
manager owns preheld resources, the dormant leaf, and atomic submission.
There is no direct service-start fallback.
"""
from dataclasses import asdict, dataclass
from hashlib import sha256
import os
from time import monotonic_ns

from .managed_launch import (
    GUARDED_SERVICE, LaunchArmingUnconfirmed, LaunchAuthorization, LaunchReadback,
    _digest, _service_cgroup, _unsigned,
)
from .managed_service_parent import PlacementRefusal, ServiceParent, _DIR, _identity, check_unit
from .recording import _name
from .roles_cli import _canonical, _fields
from .scope_meter import CgroupIdentity, _read_metric


@dataclass(frozen=True, slots=True)
class ServiceArm:
    binding_sha256: str
    guard_sha256: str
    armed_ns: int
    leaf: CgroupIdentity

    def __post_init__(self):
        for digest in (self.binding_sha256, self.guard_sha256):
            _digest(digest)
            if digest == '0' * 64:
                raise ValueError('missing guarded service identity')
        _unsigned(self.armed_ns, positive=True)
        object.__setattr__(self, 'leaf', _service_cgroup(self.leaf))


@dataclass(frozen=True, slots=True)
class ServicePhaseObservation:
    """A point sample of the exact leaf after the guard sent its release."""

    invocation_key: str
    clock_id: str
    scope_sha256: str
    cgroup: CgroupIdentity
    released_ns: int
    observed_ns: int
    populated: bool

    def __post_init__(self):
        _digest(self.invocation_key)
        _digest(self.scope_sha256)
        _name(self.clock_id)
        object.__setattr__(self, 'cgroup', _service_cgroup(self.cgroup))
        _unsigned(self.released_ns, positive=True)
        _unsigned(self.observed_ns, positive=True)
        if self.observed_ns < self.released_ns or type(self.populated) is not bool:
            raise ValueError('invalid guarded service phase observation')


def _require_empty_leaf(parent, unit, identity):
    check_unit(unit)
    with parent.directory() as directory:
        leaf = os.open(unit, _DIR, dir_fd=directory)
        try:
            if _identity(leaf) != identity:
                raise PlacementRefusal('armed_service_leaf_changed')
            if _read_metric(leaf, identity.mount_id, 'cgroup.events', b'populated', 1) != 0:
                raise PlacementRefusal('armed_service_leaf_occupied')
        finally:
            os.close(leaf)


class GuardedServiceAuthority:
    """Bind an exact protected scope to the existing authority transport."""

    def __init__(self, authority, scope, *, check_resources):
        if type(scope.parent) is not ServiceParent:
            raise PlacementRefusal('service_parent_registration_required')
        self._authority, self._parent = authority, scope.parent
        self._scope_sha256, self._check_resources = scope.digest, check_resources
        self._armed = None
        self._arm_attempted = False
        self._submitted = False
        self.phase_observation = None

    @property
    def guard_uid(self):
        return self._authority.uid

    def _binding(self, invocation):
        if invocation.service_window is None:
            raise ValueError('missing absolute service bounds')
        unit = f'workeros-{invocation.plan.invocation_key}.service'
        return {'enforcement': GUARDED_SERVICE, 'scope_sha256': self._scope_sha256,
                'parent': asdict(self._parent), 'unit': unit, 'leaf': f'{self._parent.control_group}/{unit}'}

    def _arm_receipt(self, invocation, value):
        guard = ServiceArm(**value)
        binding = self._binding(invocation)
        expected = sha256(_canonical({'invocation': asdict(invocation), 'service': binding})).hexdigest()
        if (guard.binding_sha256 != expected or guard.leaf.mount_id != self._parent.mount_id
                or guard.leaf.device != self._parent.device or guard.leaf == self._parent.identity
                or not guard.armed_ns < invocation.service_window.active_until_ns):
            raise ValueError('armed service binding mismatch')
        return guard

    def _exchange(self, operation, invocation, deadline_ns, **fields):
        return self._authority._exchange(
            operation, invocation, deadline_ns, service=self._binding(invocation), **fields)

    def authorize(self, invocation, *, deadline_ns):
        if self._arm_attempted:
            raise LaunchArmingUnconfirmed('service_arming_already_requested')
        self._arm_attempted = True
        try:
            self._check_resources()
            result = self._exchange('arm_service', invocation, deadline_ns)
            if result is None:
                return None
            _fields(result, ('approval', 'arm'))
            approval = self._authority._decode(result['approval'], LaunchAuthorization)
            arm = self._arm_receipt(invocation, result['arm'])
            now = monotonic_ns()
            if (approval.invocation != invocation
                    or (approval.source, approval.source_sha256) != (
                        invocation.plan.authority, invocation.plan.authority_sha256)
                    or approval.guard_sha256 != arm.guard_sha256
                    or not arm.armed_ns <= now < approval.expires_ns <= invocation.service_window.active_until_ns):
                raise ValueError('guarded approval mismatch')
            _require_empty_leaf(self._parent, self._binding(invocation)['unit'], arm.leaf)
        except (OSError, TypeError, KeyError, ValueError) as exc:
            raise LaunchArmingUnconfirmed('service_arming_unconfirmed') from exc
        self._armed = (approval, arm)
        return approval

    def submit(self, invocation, approval, *, deadline_ns):
        if (self._armed is None or self._submitted or self._armed[0] != approval
                or approval.invocation != invocation or monotonic_ns() >= min(deadline_ns, approval.expires_ns)):
            raise ValueError('guarded service submission refused')
        self._submitted = True
        arm = self._armed[1]
        self._check_resources()
        _require_empty_leaf(self._parent, self._binding(invocation)['unit'], arm.leaf)
        self._exchange('submit_service', invocation, min(deadline_ns, approval.expires_ns),
                       arm=asdict(arm), ticket_sha256=approval.ticket_sha256)
        # Only authenticated readback, corroborated locally where possible,
        # can report effects. A submit reply never proves admission.

    def readback(self, invocation, *, deadline_ns):
        self.phase_observation = None
        result = self._exchange('read_service', invocation, deadline_ns)
        _fields(result, ('observation', 'arm'), ('phase_observation',))
        report = self._authority._decode(result['observation'], LaunchReadback)
        if report.invocation != invocation:
            raise ValueError('guarded service readback invocation mismatch')
        arm = None if result['arm'] is None else self._arm_receipt(invocation, result['arm'])
        if report.status == 'not_started' and arm is not None:
            raise ValueError('armed reservation is not untouched')
        if self._armed is not None and arm != self._armed[1]:
            raise ValueError('guarded service readback arm mismatch')
        if report.status in ('started', 'terminal'):
            life = None if report.service is None else report.service.lifecycle
            if (arm is None or life is None or life.cgroup != arm.leaf
                    or not arm.armed_ns <= life.start_ns < invocation.service_window.active_until_ns):
                raise ValueError('guarded service readback leaf mismatch')
        if report.status == 'unreleased' and (
                arm is None or report.unreleased.cgroup != arm.leaf
                or report.unreleased.placed_ns < arm.armed_ns
                or not report.unreleased.matches(invocation, self._scope_sha256)):
            raise ValueError('guarded unreleased readback leaf mismatch')
        if 'phase_observation' in result:
            phase = ServicePhaseObservation(**result['phase_observation'])
            if (report.status != 'unknown' or arm is None
                    or (report.source, report.source_sha256) != (
                        invocation.plan.authority, invocation.plan.authority_sha256)
                    or (phase.invocation_key, phase.clock_id, phase.scope_sha256, phase.cgroup) != (
                        invocation.plan.invocation_key, invocation.clock_id, self._scope_sha256, arm.leaf)
                    or not arm.armed_ns <= phase.released_ns < invocation.service_window.active_until_ns
                    or not phase.observed_ns <= monotonic_ns() < min(
                        deadline_ns, invocation.service_window.cleanup_until_ns)):
                raise ValueError('guarded service phase observation mismatch')
            self.phase_observation = asdict(phase)
        return report
