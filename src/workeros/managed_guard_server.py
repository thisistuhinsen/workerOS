"""Serve the guarded authority protocol inside an already appointed manager."""

import argparse
from array import array
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing, contextmanager
from dataclasses import asdict, dataclass
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import stat
from subprocess import SubprocessError
from threading import Event
from time import monotonic, monotonic_ns, sleep
from uuid import uuid4

from . import managed_cli, managed_system_bus
from .delegated_service_leaf import DelegatedServiceLeaf
from .managed_executor import _FRAME, _remaining, authority_pin
from .managed_launch import (
    GUARDED_SERVICE, LaunchAuthorization, LaunchInvocation, LaunchPlan, LaunchReadback,
    LaunchRolePolicy, ManagedServiceEvidence, ServiceLifecycle, UnreleasedServiceEvidence, _digest, _uid, _unsigned,
)
from .managed_listeners import ORIGINALS, activation_descriptors, bind_originals, registered_listener
from .managed_service import ServiceScope, limits
from .managed_service_guard import ServiceArm, ServicePhaseObservation
from .managed_service_parent import PlacementRefusal, _DIR, _identity, check_unit
from .managed_service_scope import ServiceBundle, _path
from .recording import EvidenceType, LocalStore, Persistence, RecordError, RecordKey, RecordReceipt, StoragePolicy, _name
from .roles_cli import _canonical, _fields
from .scope_meter import _read_metric
from .verify_install import verify_install


_JOURNAL = StoragePolicy()
_KIND = EvidenceType('guarded-service-authority', 'application/json')
_OPERATIONS = ('read_service', 'arm_service', 'submit_service')
_REGISTRATIONS = ('workeros-guard', 'workeros-setup', 'workeros-executor')


def _hash(value):
    return sha256(_canonical(value)).hexdigest()


@contextmanager
def _guard_request(connection, deadline):
    descriptor_size = array('i').itemsize
    connection.settimeout(_remaining(deadline))
    first, control, flags, _ = connection.recvmsg(
        1, socket.CMSG_SPACE(descriptor_size), socket.MSG_CMSG_CLOEXEC)
    locks = []
    try:
        for level, kind, payload in control:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                descriptors = array('i')
                descriptors.frombytes(payload[:len(payload) - len(payload) % descriptor_size])
                locks.extend(descriptors)
        if (not first or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(locks) != len(control) or len(locks) > 1):
            raise ValueError('guard_request_invalid')
        size, = _FRAME.unpack(first + managed_cli._read_exact(connection, _FRAME.size - 1, deadline))
        if not 0 < size <= managed_cli._LIMIT:
            raise ValueError('guard_request_invalid')
        yield managed_cli.decode_policy(managed_cli._read_exact(connection, size, deadline)), locks
    finally:
        for fd in locks:
            os.close(fd)


def _read(store, key):
    try:
        item = store.read(key, policy=_JOURNAL)
    except RecordError as exc:
        if exc.status is Persistence.MISSING:
            return None
        raise
    if item.receipt.evidence_type != _KIND:
        raise RecordError(Persistence.CONFLICT)
    return managed_cli.decode_policy(store.verify_durable(item.receipt, policy=_JOURNAL))


def _commit(store, key, fields):
    payload = _canonical(fields)
    receipt = RecordReceipt(key, _KIND, sha256(payload).hexdigest(), len(payload), 0)
    return store.commit(receipt, payload, policy=_JOURNAL).state is Persistence.COMMITTED and _read(store, key) == fields


def _require_guard_placement(scope, deadline_ns, *, invocation_id=None):
    if scope.parent is None or not scope.parent.delegated_service:
        raise PlacementRefusal('service_guard_delegated_parent_required')
    observed = managed_system_bus.verify_parent(scope.parent, deadline_ns, guard_uid=os.geteuid(),
                                                metered=limits(scope).metered, guard_pid=os.getpid())
    if invocation_id is not None and observed != invocation_id:
        raise PlacementRefusal('guard_commissioning_incarnation_changed')


def _await_registration(directory, unit, deadline, held):
    path = _path(directory)
    fd = os.open('/', _DIR)
    held.callback(os.close, fd)
    for name in path[1:].split('/'):
        fd = os.open(name, _DIR, dir_fd=fd)
        held.callback(os.close, fd)
        managed_cli._safe_directory(fd)
    try:
        os.stat('registration', dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError('guard_commissioning_registration_already_present')
    parent, invocation = managed_system_bus.discover_guard_parent(
        unit, min(deadline, monotonic_ns() + int(managed_cli._TIMEOUT * 1_000_000_000)),
        guard_uid=os.geteuid(), guard_pid=os.getpid())
    print(json.dumps({'phase': 'guard_parent_pinned', 'parent': asdict(parent),
                      'invocation_id': invocation, 'main_pid': os.getpid(), 'guard_uid': os.geteuid(),
                      'workload_started': False}), flush=True)
    while monotonic_ns() < deadline:
        try:
            incoming = os.open('registration', _DIR, dir_fd=fd)
        except FileNotFoundError:
            sleep(min(0.05, max(0, (deadline - monotonic_ns()) / 1_000_000_000)))
            continue
        held.callback(os.close, incoming)
        managed_cli._safe_directory(incoming)
        registrations = []
        for name in _REGISTRATIONS:
            registration = os.open(name + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=incoming)
            held.callback(os.close, registration)
            registrations.append(registration)
        if monotonic_ns() < deadline:
            return registrations, parent, invocation
        break
    raise TimeoutError('guard_commissioning_deadline_exhausted')


def _open_leaf(invocation, scope, unit):
    if scope.parent is None or not scope.parent.delegated_service:
        raise PlacementRefusal('service_guard_delegated_parent_required')
    check_unit(unit)
    with scope.parent.directory() as parent:
        scope.parent.check_delegated_root(parent, os.geteuid(), metered=limits(scope).metered)
        if monotonic_ns() >= invocation.service_window.active_until_ns:
            raise TimeoutError('guard_arming_deadline_exhausted')
        os.mkdir(unit, mode=0o700, dir_fd=parent)
    identity = scope.parent.child_identity(unit)
    try:
        return identity, DelegatedServiceLeaf(invocation, scope.parent, identity, limits(scope), scope_sha256=scope.digest)
    except (OSError, ValueError):
        # No bootstrap was attempted. Remove only the exact just-created,
        # owned, still-empty leaf. Otherwise keep the durable unknown.
        try:
            with scope.parent.directory() as parent:
                directory = os.open(unit, _DIR, dir_fd=parent)
                try:
                    if (_identity(directory) == identity
                            and os.fstat(directory).st_uid == os.geteuid()
                            and _read_metric(directory, identity.mount_id, 'cgroup.events', b'populated', 1) == 0
                            and scope.parent.child_identity(unit) == identity):
                        os.rmdir(unit, dir_fd=parent)
                finally:
                    os.close(directory)
        except (OSError, ValueError):
            pass
        raise


@dataclass(frozen=True, slots=True)
class GuardEnrollment:
    policy: LaunchRolePolicy
    scope: ServiceScope | ServiceBundle
    profile_identity: str
    clock_id: str
    caller_uid: int

    def __post_init__(self):
        if (type(self.policy) is not LaunchRolePolicy or type(self.scope) not in (ServiceScope, ServiceBundle)
                or self.scope.parent is None or limits(self.scope) is None):
            raise ValueError('guard_enrollment_invalid')
        _digest(self.profile_identity)
        _name(self.clock_id)
        _uid(self.caller_uid)

    def matches(self, invocation, service):
        unit = f'workeros-{invocation.plan.invocation_key}.service'
        plan = asdict(invocation.plan)
        del plan['invocation_key']
        window = invocation.service_window
        bounds = limits(self.scope)
        return (plan == asdict(self.policy) and invocation.profile_identity == self.profile_identity
                and invocation.clock_id == self.clock_id and window is not None
                and window.active_until_ns - monotonic_ns() <= bounds.active_ms * 1_000_000
                and window.cleanup_until_ns - window.active_until_ns <= bounds.cleanup_ms * 1_000_000
                and service == {'enforcement': GUARDED_SERVICE, 'scope_sha256': self.scope.digest,
                                'parent': asdict(self.scope.parent), 'unit': unit,
                                'leaf': self.scope.parent.control_group + '/' + unit})


@dataclass(slots=True)
class _Armed:
    invocation: LaunchInvocation
    leaf: DelegatedServiceLeaf
    arm: ServiceArm
    approval: LaunchAuthorization
    run_id: str


class GuardedManager:
    """Own an armed leaf, exact worker release, and one serial reap.

    The caller supplies its already commissioned enrollment, a protected
    local journal, and a live check of that enrollment. This process owns
    the child through release, reap, and retirement even if its peer leaves.
    """

    def __init__(self, enrollment, store, current, *, role_store_lock, witness=None):
        if type(enrollment) is not GuardEnrollment or type(store) is not LocalStore or not callable(current):
            raise ValueError('guard_enrollment_invalid')
        store.check_policy(_JOURNAL)
        self.enrollment, self.store, self._current = enrollment, store, current
        self._role_store_lock = role_store_lock
        self._witness = witness
        self._armed = None
        self._retirement = None
        self._released = None
        self._worker = None

    @staticmethod
    def _key(invocation, state):
        return RecordKey(invocation.plan.invocation_key, 'guard-' + state)

    def _observation(self, invocation, status, **evidence):
        plan = invocation.plan
        result = asdict(LaunchReadback(invocation, plan.authority, plan.authority_sha256, status, **evidence))
        if result['unreleased'] is None:
            result.pop('unreleased')
        if result['service'] is not None and result['service']['reaped_process'] is None:
            result['service'].pop('reaped_process')
        return result

    def _read(self, invocation, binding):
        intent = _read(self.store, self._key(invocation, 'intent'))
        armed = _read(self.store, self._key(invocation, 'armed'))
        observed = _read(self.store, self._key(invocation, 'terminal'))
        unreleased = _read(self.store, self._key(invocation, 'unreleased'))
        submitted = _read(self.store, self._key(invocation, 'submitted'))
        if intent is None and armed is None and observed is None and unreleased is None and submitted is None:
            return {'observation': self._observation(invocation, 'not_started'), 'arm': None}
        if intent != {'binding': binding} or (armed is not None and armed.get('binding') != binding):
            return {'observation': self._observation(invocation, 'unknown'), 'arm': None}
        arm = armed.get('arm') if armed is not None else None
        if observed is None or unreleased is None:
            final = observed if observed is not None else unreleased
            if (final is not None and arm is not None and final.get('binding') == binding
                    and submitted == {'binding': binding, 'ticket': armed.get('ticket')}):
                return {'observation': final['observation'], 'arm': arm}
        return {'observation': self._observation(invocation, 'unknown'), 'arm': arm}

    def _observe_phase(self, invocation, result, unit, deadline):
        from .managed_bootstrap import setup_clock_id

        release, retirement = self._released, self._retirement
        if (result['observation']['status'] != 'unknown' or result['arm'] is None
                or release is None or release[0] != invocation or retirement is None or retirement.done()):
            return None
        arm = ServiceArm(**result['arm'])
        _, identity, sent_ns = release
        window = invocation.service_window
        scope = self.enrollment.scope
        cutoff = min(int(deadline * 1_000_000_000), window.cleanup_until_ns)
        if (identity != arm.leaf or not arm.armed_ns <= sent_ns < window.active_until_ns
                or monotonic_ns() >= cutoff):
            return None
        try:
            if setup_clock_id() != invocation.clock_id:
                return None
            with scope.parent.directory() as parent, ExitStack() as opened:
                leaf = os.open(unit, _DIR, dir_fd=parent)
                opened.callback(os.close, leaf)
                if _identity(leaf) != identity or os.fstat(leaf).st_uid != os.geteuid():
                    return None
                populated = bool(_read_metric(leaf, identity.mount_id, 'cgroup.events', b'populated', 1))
                # Keep the observation tied to the named leaf, including
                # when retirement is running concurrently with this read.
                current = os.stat(unit, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (identity.device, identity.inode):
                    return None
                sampled_ns = monotonic_ns()
        except (OSError, ValueError):
            return None
        if sampled_ns >= cutoff or retirement.done():
            return None
        return ServicePhaseObservation(invocation.plan.invocation_key, invocation.clock_id, scope.digest,
                                       identity, sent_ns, sampled_ns, populated)

    def _arm(self, invocation, binding, unit):
        prior = self._read(invocation, binding)
        if (self._armed is not None or self._retirement is not None
                or prior['observation']['status'] != 'not_started'
                or self._current() is not True or monotonic_ns() >= invocation.service_window.active_until_ns):
            return None
        self.enrollment.scope.check_original()
        scope = self.enrollment.scope
        _require_guard_placement(scope, invocation.service_window.active_until_ns)
        if not _commit(self.store, self._key(invocation, 'intent'), {'binding': binding}):
            return None
        leaf_id, leaf = _open_leaf(invocation, scope, unit)
        try:
            run_id = uuid4().hex
            guard = _hash({'binding': binding, 'leaf': asdict(leaf_id), 'run': run_id,
                           'armed_ns': leaf.armed_ns})
            arm = ServiceArm(binding, guard, leaf.armed_ns, leaf_id)
            plan = invocation.plan
            ticket = _hash({'guard': guard, 'authority': plan.authority_sha256})
            approval = LaunchAuthorization(invocation, plan.authority, plan.authority_sha256, ticket,
                                           invocation.service_window.active_until_ns, guard)
            recorded = {'binding': binding, 'arm': asdict(arm), 'ticket': ticket}
            if not _commit(self.store, self._key(invocation, 'armed'), recorded):
                return None
            self._armed = _Armed(invocation, leaf, arm, approval, run_id)
            return {'arm': asdict(arm), 'approval': asdict(approval)}
        finally:
            if self._armed is None:
                try:
                    leaf.cancel_unstarted()
                finally:
                    leaf.close()

    def _live_approval_lock(self, locks):
        if len(locks) != 1:
            return False
        try:
            fd, = locks
            info = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_uid != self.enrollment.caller_uid
                    or (info.st_dev, info.st_ino) != self._role_store_lock
                    or flags & (os.O_PATH | os.O_ACCMODE)):
                return False
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _submit(self, invocation, binding, request, locks):
        held = self._armed
        if (held is None or held.invocation != invocation or request['arm'] != asdict(held.arm)
                or request['ticket_sha256'] != held.approval.ticket_sha256):
            return None
        if (not self._live_approval_lock(locks) or self._current() is not True
                or monotonic_ns() >= held.approval.expires_ns):
            self.close()
            return None

        claimed = {'binding': binding, 'ticket': held.approval.ticket_sha256}
        if not _commit(self.store, self._key(invocation, 'submitted'), claimed):
            return None
        self._armed = None
        if self._worker is None:
            return self._finish_submit(held, binding, request['service']['unit'], locks)
        released = Event()
        owned = [locks.pop()]
        try:
            self._retirement = self._worker.submit(
                self._finish_submit, held, binding, request['service']['unit'], owned, released)
        except BaseException:
            os.close(owned.pop())
            with closing(held.leaf):
                held.leaf.cancel_unstarted()
            raise
        # A reply only permits the launcher to drop its copy of the approval
        # lock. The guard retains the exact child and scoped cleanup deadline.
        released.wait(max(0, (held.approval.expires_ns - monotonic_ns()) / 1_000_000_000))
        return None

    def _finish_submit(self, held, binding, unit, locks, released=None):
        try:
            return self._finish_claimed(held, binding, unit, locks, released)
        finally:
            for fd in locks:
                os.close(fd)
            locks.clear()
            if released is not None:
                released.set()

    def _finish_claimed(self, held, binding, unit, locks, released):
        @contextmanager
        def approve_release():
            if (self._current() is not True or not self._live_approval_lock(locks)
                    or monotonic_ns() >= held.approval.expires_ns):
                raise PermissionError('guard_release_approval_unavailable')
            _require_guard_placement(self.enrollment.scope, held.approval.expires_ns)
            try:
                yield
            finally:
                # Leave the worker and its retirement with the existing guard.
                os.close(locks.pop())
                if released is not None:
                    released.set()

        invocation = held.invocation
        unreleased = None
        with closing(held.leaf) as leaf, ExitStack() as resources:
            if self._current() is not True:
                leaf.cancel_unstarted()
                return None
            witness = None
            options = {}
            if released is not None:
                def retain_release_cut(sent_ns):
                    self._released = (invocation, held.arm.leaf, sent_ns)

                options['on_released'] = retain_release_cut
            if self._witness is not None:
                from .managed_witness_activation import WitnessHandoff

                scope = self.enrollment.scope
                service = {'enforcement': GUARDED_SERVICE, 'scope_sha256': scope.digest,
                           'parent': asdict(scope.parent), 'unit': unit,
                           'leaf': scope.parent.control_group + '/' + unit}
                witness = WitnessHandoff(self._witness, invocation, service, held.run_id, resources)
                options['witness'] = witness.activate
            try:
                leaf.release_approved_child(self.enrollment.scope, deadline_ns=held.approval.expires_ns,
                                            approval=approve_release, **options)
            except (OSError, EOFError, ValueError, SubprocessError):
                try:
                    unreleased = leaf.retire_unreleased()
                except (OSError, ValueError):
                    try:
                        leaf.cancel_unstarted()
                    except (OSError, ValueError):
                        pass
                    raise
            else:
                captured = False
                if witness is not None:
                    try:
                        witness.captured()
                        captured = True
                    except (OSError, EOFError, ValueError):
                        # Native cleanup still owns the leaf after an observer failure.
                        pass
                observed = leaf.retire()
                if captured:
                    try:
                        witness.closed()
                    except (OSError, EOFError, ValueError):
                        pass
        if unreleased is not None:
            witness = UnreleasedServiceEvidence(
                unit, self.enrollment.scope.digest, invocation.clock_id, held.run_id,
                unreleased.cgroup, unreleased.placed_ns, unreleased.reaped_ns, unreleased.empty_ns,
                unreleased.retired_ns,
            )
            if witness.cgroup != held.arm.leaf or not held.arm.armed_ns <= witness.placed_ns:
                raise ValueError('guard_unreleased_binding_mismatch')
            report = self._observation(invocation, 'unreleased', unreleased=witness)
            _commit(self.store, self._key(invocation, 'unreleased'), {'binding': binding, 'observation': report})
            return None
        # This is the guard's waitable child, which may have failed before
        # worker exec. Retain its exit and cleanup without assuming an effect.
        closed = monotonic_ns()
        evidence = ServiceLifecycle(
            invocation.clock_id, observed.adopted_ns, observed.cgroup,
            observed.reaped_ns, observed.disposition, observed.exit_status, observed.empty_ns,
            observed.retired_ns, closed, observed.meter_begin, observed.meter_end,
        )
        scope = self.enrollment.scope
        plan = invocation.plan
        service = ManagedServiceEvidence(
            f'workeros-{plan.invocation_key}.service', None, scope.digest, True, True,
            evidence, manager_run_id=held.run_id, reaped_process=observed.reaped_process,
        )
        report = self._observation(
            invocation, 'terminal', effective_principal=plan.principal,
            effective_executable_sha256=plan.executable_sha256, effective_scope_sha256=plan.scope_sha256,
            effective_principal_uid=plan.principal_uid, receipt_sha256=_hash(asdict(service)), service=service,
        )
        _commit(self.store, self._key(invocation, 'terminal'), {'binding': binding, 'observation': report})
        return None

    def close(self):
        held, self._armed = self._armed, None
        if held is not None:
            with closing(held.leaf):
                held.leaf.cancel_unstarted()

    def serve_connection(self, connection, *, deadline):
        from .managed_service_client import _frame_write, _peer

        if _peer(connection) != self.enrollment.caller_uid:
            raise PermissionError('guard_caller_untrusted')
        with _guard_request(connection, deadline) as (request, locks):
            operation, nonce, result = self._handle(request, locks, deadline)
        _frame_write(connection, {'version': 1, 'operation': operation, 'nonce': nonce, 'result': result}, deadline)

    def _handle(self, request, locks, deadline):
        _fields(request, ('version', 'operation', 'nonce', 'invocation', 'service'), ('arm', 'ticket_sha256'))
        operation, nonce = request['operation'], request['nonce']
        if (type(request['version']) is not int or request['version'] != 1 or operation not in _OPERATIONS
                or locks and operation != 'submit_service'
                or type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None
                or (request.keys() & {'arm', 'ticket_sha256'}) != (
                    {'arm', 'ticket_sha256'} if operation == 'submit_service' else set())):
            raise ValueError('guard_request_invalid')
        wire = request['invocation']
        _fields(wire, ('profile_identity', 'clock_id', 'plan', 'service_window'))
        invocation = LaunchInvocation(wire['profile_identity'], wire['clock_id'], LaunchPlan(**wire['plan']),
                                      wire['service_window'])
        service = request['service']
        if not self.enrollment.matches(invocation, service):
            raise PermissionError('guard_enrollment_mismatch')
        if monotonic() >= deadline:
            raise TimeoutError('guard_request_expired')
        binding = _hash({'invocation': asdict(invocation), 'service': service})
        if operation == 'read_service':
            result = self._read(invocation, binding)
            phase = self._observe_phase(invocation, result, service['unit'], deadline)
            if phase is not None:
                result['phase_observation'] = asdict(phase)
        elif operation == 'arm_service':
            result = self._arm(invocation, binding, service['unit'])
        else:
            result = self._submit(invocation, binding, request, locks)
        return operation, nonce, result

    def serve(self, listener, *, detach_retirement=False):
        """Drive the appointed listener until idle, with bounded unstarted cleanup."""
        with ExitStack() as resources:
            if detach_retirement:
                self._worker = resources.enter_context(ThreadPoolExecutor(max_workers=1))
            try:
                self._serve(listener)
            finally:
                self._worker = None

    def _serve(self, listener):
        try:
            while True:
                budget = managed_cli._TIMEOUT
                if self._armed is not None:
                    window = self._armed.invocation.service_window
                    budget = min(budget, (window.active_until_ns - monotonic_ns()) / 1_000_000_000)
                    if budget <= 0:
                        self.close()
                        break
                listener.settimeout(budget)
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    break
                with connection:
                    try:
                        deadline = monotonic() + managed_cli._TIMEOUT
                        if self._armed is not None:
                            deadline = min(deadline, self._armed.invocation.service_window.active_until_ns / 1_000_000_000)
                        self.serve_connection(connection, deadline=deadline)
                    except (OSError, EOFError, ValueError, KeyError, TypeError, RecordError, SubprocessError):
                        # A failed reply never repeats an admitted request.
                        continue
        finally:
            self.close()


def _approved_identity(host, executor, policy):
    from . import managed_bootstrap
    from .managed_host import LocalProfileApproval, _commissioned_identity

    if ((host['version'], host['profile'], host['revision'], host['wheel_path']) != (
            2, executor['profile'], executor['revision'], executor['wheel_path'])):
        raise ValueError('guard_enrollment_mismatch')
    matches = [entry for entry in managed_bootstrap._scope_entries(host, check_only=True)
               if entry['definition']['name'] == policy.workflow]
    if len(matches) != 1:
        raise ValueError('guard_enrollment_mismatch')
    entry, = matches
    definition = managed_bootstrap._definition(entry['definition'])
    from .appointment_registry import definition_sha256

    clock = managed_bootstrap.setup_clock_id()
    if (definition_sha256(definition) != policy.definition_sha256
            or definition.package_sha256 != executor['wheel_sha256'] or definition.clock_id != clock
            or entry['role'] != policy.role or entry['binding_generation'] != policy.generation):
        raise ValueError('guard_enrollment_mismatch')
    approval = LocalProfileApproval(**host['local_approval'])
    requirements = managed_bootstrap._requirements(policy.role, definition)
    identity = _commissioned_identity(executor['profile'], executor['revision'], executor['wheel_sha256'],
                                      (definition,), (requirements,), (policy.generation,), approval, True)
    return definition, clock, identity


def _registration(config_fd, setup_fd, executor_fd, *, originals=None, readback_only=False, held=None, commissioning=None):
    from . import managed_bootstrap
    from .managed_provider import _read_registration

    config = _read_registration(config_fd)
    _fields(config, ('version', 'profile', 'revision', 'workflow', 'managed_setup_sha256',
                     'launch_executor_sha256', 'journal_directory', 'role_store_lock'))
    if type(config['version']) is not int or config['version'] != 1:
        raise ValueError('guard_enrollment_invalid')
    for key in ('profile', 'revision', 'workflow'):
        _name(config[key])
    lock = config['role_store_lock']
    _fields(lock, ('device', 'inode'))
    _unsigned(lock['device'])
    _unsigned(lock['inode'], positive=True)
    host = _read_registration(setup_fd)
    executor = _read_registration(executor_fd)
    pair = (('managed_setup_sha256', host), ('launch_executor_sha256', executor))
    if (any(config[key] != _hash(document) for key, document in pair)
            or any((document['profile'], document['revision'], document['wheel_path']) != (
                config['profile'], config['revision'], executor['wheel_path']) or document['version'] != 2
                for document in (host, executor))):
        raise ValueError('guard_enrollment_mismatch')
    selected = executor['workflows'][config['workflow']]
    _fields(selected, ('policy', 'service', 'authority', 'run_uids', 'result_uids'), ('result_observer', 'holder'))
    policy = LaunchRolePolicy(**selected['policy'])
    descriptor = selected['service']
    scope = ServiceBundle(**descriptor) if 'descriptors' in descriptor else ServiceScope(**descriptor)
    endpoint = selected['authority']
    _fields(endpoint, ('socket', 'uid', 'enforcement'))
    if (policy.workflow != config['workflow'] or policy.principal_uid == 0
            or endpoint['enforcement'] != GUARDED_SERVICE
            or type(endpoint['uid']) is not int or endpoint['uid'] != os.geteuid()
            or os.getresuid() != (endpoint['uid'],) * 3
            or endpoint['uid'] in (managed_cli._TRUSTED_UID, policy.principal_uid)
            or authority_pin(policy.authority, endpoint['socket'], endpoint['uid']) != policy.authority_sha256):
        raise ValueError('guard_authority_untrusted')
    verify_install(executor['wheel_path'], executor['wheel_sha256'])
    definition, clock, identity = _approved_identity(host, executor, policy)
    if not readback_only:
        from .service_bootstrap import _check_worker_identity

        if scope.parent is None or monotonic_ns() >= definition.expires_ns:
            raise ValueError('guard_enrollment_invalid')
        deadline = min(definition.expires_ns, monotonic_ns() + int(managed_cli._TIMEOUT * 1_000_000_000))
        if commissioning is None:
            _require_guard_placement(scope, deadline)
        else:
            parent, invocation_id, activation_deadline = commissioning
            if scope.parent != parent:
                raise ValueError('guard_commissioning_parent_mismatch')
            _require_guard_placement(scope, min(deadline, activation_deadline), invocation_id=invocation_id)
        _check_worker_identity(policy.principal_uid, scope.principal_gid)
    if originals is not None and not readback_only:
        if 'holder' in selected:
            from .managed_holder import receive_originals, validate_holder

            holder = selected['holder']
            validate_holder(holder, policy, scope, endpoint)
            if originals:
                raise ValueError('service_holder_activation_conflict')
            scope = receive_originals(holder, config['profile'], config['revision'], config['workflow'], scope,
                                      held, monotonic() + managed_cli._TIMEOUT)
        else:
            scope = bind_originals(scope, originals)
    if commissioning is not None and monotonic_ns() >= commissioning[2]:
        raise TimeoutError('guard_commissioning_deadline_exhausted')
    enrollment = GuardEnrollment(policy, scope, identity, clock, managed_cli._TRUSTED_UID)
    witness = None
    if not readback_only and selected.get('result_observer', {}).get('handoff') is True:
        from .managed_service_observer import validate_observer
        from .managed_witness_activation import validate_scope

        witness = selected['result_observer']
        validate_observer(witness, policy, endpoint, limits(scope))
        validate_scope(witness, scope)
        if witness['uid'] in selected['run_uids']:
            raise ValueError('service_result_observer_not_independent')
    directory = Path(config['journal_directory'])
    if not directory.is_absolute():
        raise ValueError('guard_enrollment_invalid')

    def current():
        try:
            return (not readback_only and _read_registration(config_fd) == config
                    and _read_registration(setup_fd) == host
                    and _read_registration(executor_fd) == executor
                    and managed_bootstrap.setup_clock_id() == clock
                    and monotonic_ns() < definition.expires_ns)
        except (OSError, ValueError):
            return False

    manager = GuardedManager(enrollment, LocalStore(directory), current,
                            role_store_lock=(lock['device'], lock['inode']), witness=witness)
    detach = witness is not None or (originals is not None and 'holder' in selected and not readback_only)
    return manager, endpoint['socket'], detach


def main(argv):
    from .managed_service_client import _peer

    parser = argparse.ArgumentParser(prog='workeros managed serve-guard',
                                     description='Serve the already appointed guarded manager on its listener.')
    parser.add_argument('--config-fd', type=int, help='preopened administrator authority registration')
    parser.add_argument('--setup-fd', type=int, help='preopened protected managed setup')
    parser.add_argument('--executor-fd', type=int, help='preopened protected executor registration')
    parser.add_argument('--listen-fd', type=int)
    parser.add_argument('--commissioned', action='store_true', help='activate using named manager descriptors')
    parser.add_argument('--commissioning-directory', help='protected directory for one live guard enrollment')
    parser.add_argument('--commissioning-unit', help='systemd service name for live enrollment')
    parser.add_argument('--commissioning-deadline-ns', type=int, help='absolute monotonic deadline in nanoseconds')
    parser.add_argument('--readback-only', action='store_true', help='serve historical reads without reopening originals')
    args = parser.parse_args(argv)
    given = (args.config_fd, args.setup_fd, args.executor_fd, args.listen_fd)
    commissioning = (args.commissioning_directory, args.commissioning_unit, args.commissioning_deadline_ns)
    awaiting = any(value is not None for value in commissioning)
    if awaiting and (not args.commissioned or args.readback_only or any(value is None for value in commissioning)):
        parser.error('live commissioning requires --commissioned and all three --commissioning options')
    if args.commissioned:
        if any(fd is not None for fd in given):
            parser.error('--commissioned cannot be combined with explicit descriptors')
    elif args.readback_only or any(fd is None for fd in given):
        parser.error('use --commissioned or supply all four explicit descriptors')
    serving = False
    held = ExitStack()
    try:
        if args.commissioned:
            required = frozenset() if awaiting else frozenset(_REGISTRATIONS)
            descriptors = activation_descriptors(required, frozenset() if args.readback_only else ORIGINALS)
            registration_pin = None
            if awaiting:
                registrations, parent, invocation = _await_registration(*commissioning, held)
                registration_pin = (parent, invocation, args.commissioning_deadline_ns)
            else:
                registrations = [descriptors.pop(name) for name in _REGISTRATIONS]
            manager, endpoint, detach = _registration(*registrations, originals=descriptors,
                                                      readback_only=args.readback_only, held=held,
                                                      commissioning=registration_pin)
            listener_context = registered_listener(endpoint, os.geteuid())
        else:
            if min(given) < 3 or len(set(given)) != 4:
                raise ValueError('guard_listener_untrusted')
            manager, endpoint, detach = _registration(*given[:3])
            listener_context = socket.socket(fileno=os.dup(args.listen_fd))
        with listener_context as listener:
            if (listener.family != socket.AF_UNIX or listener.getsockname() != endpoint
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                    or _peer(listener) != os.geteuid()):
                raise PermissionError('guard_listener_untrusted')
            serving = True
            manager.serve(listener, detach_retirement=detach)
    except (OSError, ValueError, TypeError, KeyError, RecordError):
        if serving:
            print('{"status":"unknown","effect":"unknown","code":"guard_manager_unconfirmed"}')
        else:
            print('{"status":"refused","effect":"not_attempted","code":"guard_registration_unavailable"}')
        return 1
    finally:
        held.close()
    return 0
