"""Trusted-host adapter for one immutable commissioned setup operation."""
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
import re
from time import monotonic_ns, time

from .aggregate_setup import AggregateSetup, ScopeSetup
from .configuration import ConfigurationError
from .enrollment import _operations, compile_policy, decode_policy
from .managed_launch import LaunchPlan, LaunchRegistration, LaunchRolePolicy, ScopedLaunch, ServiceWindow, launch_result
from .profile_setup import ManagerSelection, ProfileDefinition, SetupResult
from .recording import EvidenceType, Persistence, RecordError, _name
from .verify_install import VerificationError, verify_install

_HASH = re.compile(r'[0-9a-f]{64}')
_LAUNCH_RESERVATION = EvidenceType('managed-launch-reservation', 'application/json')
_LAUNCH_TICKET = EvidenceType('managed-launch-ticket', 'application/json')


def _launch_reservation_key(profile, revision, registration, request_id):
    from .roles_cli import _key

    prefix = ('launch-attempt-' if registration.service_scope_sha256 is None else
              'service-attempt-' + registration.plan.workflow + '-')
    return _key(profile, revision, prefix + request_id)


def _claim_launch_ticket(store, approval):
    """Consume one authority ticket while the existing approval lock is held."""
    from .roles_cli import _canonical, _commit, _key, _read

    # This index is shared by profiles and revisions in the protected store.
    # Key it to the approved authority and the ticket, not a caller request ID.
    key = _key('launch-tickets', approval.source_sha256, approval.ticket_sha256)
    if _read(store, key) is not None:
        return False
    payload = _canonical({'version': 1, 'approval': asdict(approval)})
    if _commit(store, key, payload, kind=_LAUNCH_TICKET) is not Persistence.COMMITTED:
        return None
    return True if _read(store, key) == payload else None


def _launch_record(registration, identity, clock_id, request_id, *, window=None):
    from .appointment_registry import launch_policy_sha256
    from .roles_cli import _canonical

    record = {'version': 1, 'request_id': request_id, 'profile_identity': identity,
              'clock_id': clock_id, 'policy_sha256': launch_policy_sha256(registration.plan)}
    if registration.service_scope_sha256 is not None:
        record['service_scope_sha256'] = registration.service_scope_sha256
    if registration.service_enforcement is not None:
        record['service_enforcement'] = registration.service_enforcement
    if registration.service_limits is not None:
        if type(window) is not ServiceWindow:
            raise ValueError('missing durable service window')
        record['service_window'] = asdict(window)
    invocation_key = sha256(_canonical(record)).hexdigest()
    record['invocation_key'] = invocation_key
    return registration._for_attempt(invocation_key), _canonical(record)


def _recorded_launch(registration, raw, request_id, *, current=None):
    record = decode_policy(raw)
    identity, clock_id = record['profile_identity'], record['clock_id']
    if current is not None and current != (identity, clock_id):
        raise ValueError('different launch registration')
    window = ServiceWindow(**record['service_window']) if registration.service_limits is not None else None
    bound, expected = _launch_record(registration, identity, clock_id, request_id, window=window)
    if raw != expected:
        raise ValueError('different launch registration')
    return ScopedLaunch(bound, identity, clock_id, already_reserved=True, service_window=window)


def _read_historical_launch(registration, profile, revision, request_id, deadline):
    """Resolve one reserved key from the protected store without live role access."""
    from . import roles_cli

    correlation = {'request_id': request_id}
    if type(request_id) is not str or not _HASH.fullmatch(request_id):
        return launch_result('refused', 'not_attempted', 'invalid_launch_request_id')
    key = _launch_reservation_key(profile, revision, registration, request_id)
    try:
        with roles_cli._store(create=False) as store:
            raw = roles_cli._read(store, key)
    except (OSError, RecordError, roles_cli.Refusal):
        return launch_result('unknown', 'unknown', 'launch_reservation_unconfirmed', **correlation)
    if raw is None:
        return launch_result('not_started', 'not_attempted', 'launch_not_reserved', **correlation)
    try:
        launch = _recorded_launch(registration, raw, request_id)
    except (ValueError, TypeError, KeyError):
        return launch_result('unknown', 'unknown', 'launch_reservation_mismatch', **correlation)
    return launch.read(deadline_ns=deadline) | correlation


@dataclass(frozen=True, slots=True)
class LocalProfileApproval:
    """Receipt pins supplied by the trusted host alongside its provider registry."""

    declaration_sha256: str
    intent_sha256: str

    def __post_init__(self):
        if any(type(value) is not str or not _HASH.fullmatch(value)
               for value in (self.declaration_sha256, self.intent_sha256)):
            raise ValueError('expected exact local commission digests')


@dataclass(frozen=True, slots=True)
class RoleAppointment:
    """Current role appointment returned by the trusted manager's verifier."""

    definition: ProfileDefinition
    role: str
    principal: str
    generation: str

    def __post_init__(self):
        if type(self.definition) is not ProfileDefinition:
            raise ValueError('expected an exact appointment definition')
        _name(self.role)
        _name(self.generation)
        if type(self.principal) is not str or not 0 < len(self.principal) <= 128:
            raise ValueError('expected an appointed principal')


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """Trusted durable store's exact operation outcome, not a caller assertion."""
    identity: str
    operation_key: str
    state: str
    results: tuple = ()

    def __post_init__(self):
        if (not _HASH.fullmatch(self.identity) or not _HASH.fullmatch(self.operation_key)
                or self.state not in ('not_started','pending','recorded','not_committed','unavailable')
                or type(self.results) is not tuple):
            raise ValueError('invalid attempt record')
        if self.state != 'recorded' and self.results:
            raise ValueError('unexpected attempt results')


def _commissioned_identity(profile, revision, wheel_sha256, definitions, requirements, generations,
                           local_approval, local_appointments):
    canonical = {'version':1,'profile':profile,'revision':revision,'wheel_sha256':wheel_sha256,
                 'entries':[{'definition':asdict(d),'requirements':asdict(r), 'generation':g}
                            for d,r,g in zip(definitions, requirements, generations, strict=True)]}
    if local_approval is not None:
        canonical['local_approval'] = asdict(local_approval)
    if local_appointments:
        canonical['local_appointments'] = True
    return sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True).encode()).hexdigest()


def _recover_pending(store, identity, operation_key, definitions):
    recover = getattr(store, 'recover_pending', None)
    if not callable(recover):
        return ()
    try:
        results = recover(identity, operation_key)
        if type(results) is not tuple or len(results) != len(definitions):
            return ()
        for definition, (name, result) in zip(definitions, results, strict=True):
            if (name != definition.name or type(result) is not SetupResult
                    or (result.status, result.code, result.effect, result.definition) not in (
                        ('recorded', 'scope_commit_verified', 'committed', definition),
                        ('unknown', 'scope_commit_unconfirmed', 'unknown', None),
                        ('unknown', 'scope_commit_unattributed', 'unknown', None),
                        ('conflict', 'scope_mapping_conflict', 'unknown', None))
                    or result.attempt is not None):
                return ()
    except Exception:
        return ()
    return results


class _PinnedManager:
    def __init__(self, manager, expected, generation):
        self._manager, self._expected, self._generation = manager, expected, generation

    def select(self, name, revision):
        selection = self._manager.select(name, revision)
        if type(selection) is not ManagerSelection or selection.definition != self._expected:
            raise ConfigurationError('commissioned_mapping_mismatch')
        return selection

    def verify_bindings(self, *args):
        generation = self._manager.verify_bindings(*args)
        if generation != self._generation:
            raise ConfigurationError('binding_generation_changed')
        return generation
    def attest(self, *args): return self._manager.attest(*args)
    def readback(self, *args): return self._manager.readback(*args)
    def create(self, *args): return self._manager.create(*args)
    def read_attempt(self, *args): return self._manager.read_attempt(*args)


class ManagedHostAdapter:
    """Bind one fixed operation key to exact approved definitions and requirements.

    The trusted store must atomically and durably reserve a key once, preserve
    uncertain claims across crashes, and authenticate independent readback. It
    may report not_started/not_committed only when it can prove that fact.
    """
    def __init__(self, *, profile, revision, operation_key, scopes, definitions, generations,
                 wheel, wheel_sha256, clock_id, store, local_approval=None, local_appointments=False,
                 launch_registration=None):
        _name(profile); _name(revision)
        if type(operation_key) is not str or not _HASH.fullmatch(operation_key):
            raise ValueError('expected opaque operation key')
        if (type(scopes) is not tuple or not scopes or type(definitions) is not tuple
                or len(scopes) != len(definitions) or type(generations) is not tuple
                or len(scopes) != len(generations) or any(type(s) is not ScopeSetup for s in scopes)
                or any(type(d) is not ProfileDefinition for d in definitions)
                or any(not callable(getattr(store, name, None)) for name in ('read','claim','finish'))):
            raise ValueError('invalid trusted host registration')
        for generation in generations: _name(generation)
        if local_approval is not None and type(local_approval) is not LocalProfileApproval:
            raise ValueError('expected trusted local approval pins')
        if type(local_appointments) is not bool or local_appointments and local_approval is None:
            raise ValueError('local appointments require trusted local approval pins')
        for s, d in zip(scopes, definitions):
            if ((s.name, s.revision, s.requirements.scope) != (d.name, d.revision, d.scope)
                    or d.package_sha256 != wheel_sha256 or d.clock_id != clock_id):
                raise ValueError('commissioned binding mismatch')
        self.profile, self.revision, self.operation_key = profile, revision, operation_key
        self.scopes, self.definitions, self.store = scopes, definitions, store
        self._generations = generations
        self._local_approval = local_approval
        self._local_appointments = local_appointments
        self.wheel, self.wheel_sha256, self.clock_id = wheel, wheel_sha256, clock_id
        self.identity = _commissioned_identity(profile, revision, wheel_sha256, definitions,
            tuple(scope.requirements for scope in scopes), generations, local_approval, local_appointments)
        pinned = tuple(replace(s, manager=_PinnedManager(s.manager,d,g)) for s,d,g in zip(scopes,definitions,generations))
        self.aggregate = AggregateSetup(pinned, wheel=wheel, wheel_sha256=wheel_sha256, clock_id=clock_id)
        if launch_registration is not None and type(launch_registration) is not LaunchRegistration:
            raise ValueError('expected an administrator-supplied launch registration')
        self._launch_registration = launch_registration
        self._launch = None
        if launch_registration is not None:
            if type(launch_registration.plan) is LaunchPlan:
                self._launch = ScopedLaunch(launch_registration, self.identity, clock_id)
            elif not local_appointments or not launch_registration.bounded:
                raise ValueError('reusable launch needs a bounded backend and local appointments')

    @contextmanager
    def _approval(self, *, launch_plan=None):
        """Hold the local role lock across one manager operation."""
        if self._local_approval is None:
            yield None, None, None
            return
        from . import roles_cli
        with ExitStack() as locks:
            registrations = store = None
            try:
                store = locks.enter_context(roles_cli._store(create=False))
                receipt = roles_cli._commission_status_store(store, self.profile, self.revision)
                if receipt['status'] == 'revoked':
                    code = 'profile_revoked'
                elif receipt['status'] != 'configured':
                    code = 'manager_selection_denied'
                elif any(receipt[key] != value for key, value in asdict(self._local_approval).items()):
                    code = 'commissioned_mapping_mismatch'
                elif 'appointments_sha256' in receipt and not self._local_appointments:
                    code = 'role_appointment_unverified'
                elif ('file_acl_plans_sha256' in receipt and
                      roles_cli._inspect_profile_grants(store, receipt)['status'] != 'file_acl_verified'):
                    code = 'file_acl_readback_unverified'
                else:
                    declaration = roles_cli._inspect_store(store, self.profile, self.revision)
                    code, registrations = self._check_declaration(store, receipt, declaration, launch_plan=launch_plan)
            except roles_cli.Refusal as exc:
                code = ('manager_selection_denied' if str(exc) in
                        ('administrator_required', 'profile_store_missing') else 'host_bindings_unavailable')
            except (OSError, ValueError, RecordError):
                code = 'host_bindings_unavailable'
            yield code, registrations, store

    def _check_declaration(self, store, receipt, declaration, *, launch_plan=None):
        registrations = None
        if self._local_appointments:
            from .appointment_registry import read_registry

            document = read_registry(store, self.profile, self.revision, receipt, declaration)
            if document is None:
                return 'role_appointment_unverified', None
            registrations = {entry['workflow']: entry for entry in document['appointments']}
        return self._check_declared_scopes(declaration, registrations, launch_plan=launch_plan), registrations

    def _check_declared_scopes(self, declaration, registrations, *, launch_plan=None):
        from .appointment_registry import launch_plan_sha256, launch_policy_sha256, launch_scope_sha256
        from .roles_cli import _principal

        if declaration['status'] != 'configured':
            return 'manager_selection_denied'
        roles = {role['name']: role for role in declaration['roles']}
        expiry = min(role['expires_at'] for role in roles.values())
        # Capture the monotonic bound first so the conversion cannot add time
        # to the approved role lifetime. The existing final sweep checks the
        # stricter provider and appointment deadlines.
        approval_limit = monotonic_ns() + int((expiry - time()) * 1_000_000_000)
        for scope, definition, expected_generation in zip(self.scopes, self.definitions, self._generations):
            role = roles.get(scope.requirements.role)
            if role is None or scope.requirements.scope not in role['scopes']:
                return 'commissioned_mapping_mismatch'
            aliases = role.get('operation_aliases', {})
            if launch_plan is not None and launch_plan.workflow == definition.name and registrations is not None:
                entry = registrations.get(definition.name, {})
                launch = entry.get('launch')
                scope_sha256 = launch_scope_sha256(role, definition.scope, entry.get('operations', ()))
                pin = ({'policy_sha256': launch_policy_sha256(launch_plan)}
                       if type(launch_plan) is LaunchRolePolicy else {'plan_sha256': launch_plan_sha256(launch_plan)})
                if (launch != {**pin, 'scope_sha256': scope_sha256}
                        or launch_plan.scope_sha256 != scope_sha256
                        or launch_plan.principal != role['principal']
                        or launch_plan.authority == role.get('independent_of')):
                    return 'role_appointment_mismatch'
                principal_uid = _principal(role['principal']).pw_uid
                if launch_plan.principal_uid is not None and principal_uid != launch_plan.principal_uid:
                    return 'role_appointment_mismatch'
                if 'independent_of' in role and principal_uid == _principal(role['independent_of']).pw_uid:
                    return 'role_appointment_mismatch'
                resource = role.get('resources', {}).get(definition.scope)
                verify_scope = getattr(scope.manager, 'verify_launch_scope', None)
                if not callable(verify_scope) or verify_scope(principal_uid, resource) is not True:
                    return 'role_appointment_mismatch'
                verify_role = getattr(scope.manager, 'verify_launch_role', None)
                if (role.get('privileged') or aliases) and not callable(verify_role):
                    return 'role_appointment_mismatch'
                if aliases:
                    provider_pin = self._launch_registration.service_scope_sha256
                    if (any(alias['provider_sha256'] != provider_pin for alias in aliases.values())
                            or not any((binding.kind, binding.capability, binding.reference,
                                        binding.principal, binding.scope) == (
                                            'streams', 'systemd-fd', provider_pin,
                                            launch_plan.launcher, definition.scope)
                                       for binding in definition.providers)):
                        return 'role_appointment_mismatch'
                if callable(verify_role) and verify_role(role) is not True:
                    return 'role_appointment_mismatch'
            elif role.get('resources') or role.get('independent_of') or role.get('privileged') or aliases:
                return 'commissioned_mapping_mismatch'
            if any(binding.scope not in role['scopes'] for binding in definition.providers):
                return 'commissioned_mapping_mismatch'
            if definition.expires_ns > approval_limit:
                return 'manager_selection_denied'
            try:
                selected = scope.manager.select(definition.name, definition.revision)
                if (type(selected) is not ManagerSelection or selected.definition != definition
                        or sha256(selected.policy).hexdigest() != definition.policy_sha256):
                    return 'commissioned_mapping_mismatch'
                policy = decode_policy(selected.policy)
                workflow = policy['workflows'][definition.name]
                operations = _operations(workflow['operations'])
                if workflow['role'] != role['name'] or not operations <= set(role['operations']):
                    return 'commissioned_mapping_mismatch'
            except PermissionError:
                return 'manager_selection_denied'
            except (OSError, ValueError, KeyError, TypeError):
                return 'host_bindings_unavailable'
            code = self._check_role_appointment(scope, selected, policy, role['principal'],
                                                expected_generation, operations, registrations)
            if code is not None:
                return code
        if time() >= expiry:
            return 'manager_selection_denied'
        return None

    @staticmethod
    def _check_role_appointment(scope, selected, policy, principal, expected_generation,
                                operations, registrations):
        try:
            compiled = compile_policy(policy, scope.bindings, workflow=selected.definition.name)
            generation = scope.manager.verify_bindings(selected, compiled, scope.bindings)
        except (OSError, ValueError, KeyError, TypeError):
            return 'host_bindings_unavailable'
        if type(generation) is not str or generation != expected_generation:
            return 'binding_generation_changed'
        if registrations is None:
            verify_appointment = getattr(scope.manager, 'verify_role_appointment', None)
            if not callable(verify_appointment):
                return 'role_appointment_unverified'
            try:
                appointment = verify_appointment(selected, scope.requirements, generation)
            except (OSError, ValueError, KeyError, TypeError):
                return 'role_appointment_unverified'
        else:
            from .appointment_registry import definition_sha256

            definition = selected.definition
            entry = registrations.get(definition.name)
            if entry is None:
                return 'role_appointment_unverified'
            if (entry['workflow_revision'] != definition.revision
                    or entry['scope'] != definition.scope
                    or entry['definition_sha256'] != definition_sha256(definition)
                    or set(entry['operations']) != operations):
                return 'role_appointment_mismatch'
            appointment = RoleAppointment(definition, entry['role'], entry['principal'], entry['generation'])
        if type(appointment) is not RoleAppointment or monotonic_ns() >= selected.expires_ns:
            return 'role_appointment_unverified'
        expected = RoleAppointment(selected.definition, scope.requirements.role, principal, generation)
        if appointment != expected:
            return 'role_appointment_mismatch'
        return None

    def _approval_refusal(self, code):
        scopes = tuple((scope.name, SetupResult('refused', code, 'not_attempted')) for scope in self.scopes)
        return self._output('refused', scopes, effect='not_attempted')

    def _record(self):
        try: record = self.store.read(self.identity, self.operation_key)
        except Exception: return None
        if (type(record) is not AttemptRecord or record.identity != self.identity
                or record.operation_key != self.operation_key): return None
        if record.state == 'recorded':
            if len(record.results) != len(self.scopes): return None
            for scope, definition, item in zip(self.scopes, self.definitions, record.results):
                if (type(item) is not tuple or len(item) != 2 or item[0] != scope.name
                        or type(item[1]) is not SetupResult): return None
                result = item[1]
                if (result.definition is not None and result.definition != definition or
                        result.attempt is not None and result.attempt != definition or
                        result.status == 'accepted' and result.definition != definition): return None
        return record

    def _output(self, status, results=None, final=None, effect='unknown', observed=None):
        # Output has fixed codes and no raw provider metadata or policy content.
        from .managed_cli import _CODES
        results, final = dict(results or ()), dict(final or ())
        entries = []
        for scope in self.scopes:
            original, current = results.get(scope.name), final.get(scope.name)
            state = original.status if original else 'unknown'
            code = current.code if current else original.code if original else 'other'
            entries.append({'name':scope.name,'setup':state,
                            'final':current.status if current else 'not_checked',
                            'effect':original.effect if original else 'unknown',
                            'code':code if code in _CODES else 'other'})
        observation = None
        if observed is not None and observed.valid_until_ns is not None:
            observation = {'clock_id':self.clock_id,'start_ns':str(observed.observed_start_ns),
                           'end_ns':str(observed.observed_end_ns),'valid_until_ns':str(observed.valid_until_ns)}
            if status == 'ready' and monotonic_ns() >= observed.valid_until_ns:
                status = 'incomplete'
        return {'version':1,'profile':self.profile,'identity':self.identity,
                'operation_key':self.operation_key,'status':status,'effect':effect,'scopes':entries,
                'observation':observation}

    def setup(self):
        try: verify_install(self.wheel, self.wheel_sha256)
        except VerificationError: return self._output('refused', effect='not_attempted')
        with self._approval() as (code, _, _):
            if code is not None:
                return self._approval_refusal(code)
            return self._setup()

    def _launch_limit(self, plan, registrations):
        from .appointment_registry import definition_sha256

        for scope, definition, generation in zip(self.scopes, self.definitions, self._generations, strict=True):
            if definition.name == plan.workflow:
                break
        else:
            return None
        if (definition_sha256(definition) != plan.definition_sha256 or generation != plan.generation
                or scope.requirements.role != plan.role or plan.authority == definition.manager):
            return None
        selected = scope.manager.select(definition.name, definition.revision)
        if (type(selected) is not ManagerSelection or selected.definition != definition
                or sha256(selected.policy).hexdigest() != definition.policy_sha256):
            return None
        policy = decode_policy(selected.policy)
        workflow = policy['workflows'][definition.name]
        operations = _operations(workflow['operations'])
        if 'launch' not in operations or workflow['role'] != plan.role:
            return None
        providers = {(binding.kind, binding.name): binding for binding in definition.providers}
        refs = workflow['bindings']
        executable = providers['executable', refs['executable']]
        supervisor = providers['supervisor', refs['supervisor']]
        if (executable.reference != plan.executable_sha256 or supervisor.reference != plan.scope_sha256
                or executable.scope != definition.scope or supervisor.scope != definition.scope
                or supervisor.principal != plan.launcher or supervisor.capability != 'scoped-launch'):
            return None
        if self._check_role_appointment(scope, selected, policy, plan.principal, generation, operations, registrations):
            return None
        if (self._launch_registration.service_scope_sha256 is not None
                and not any(binding.kind in ('observers', 'meters', 'evidence', 'custody')
                            for binding in definition.providers)):
            # Launch authorization and result still pass the separate service
            # authority. No optional setup observation was requested here.
            return selected.expires_ns
        checked = self.aggregate._check_bindings(self.definitions)
        if checked.status != 'bindings_verified' or checked.valid_until_ns is None:
            return None
        return min(selected.expires_ns, checked.valid_until_ns)

    @contextmanager
    def _launch_window(self):
        from .managed_cli import _CHECK_WORK_DEADLINE, _TIMEOUT

        if not self._launch_registration.bounded:
            yield None
            return
        deadline = monotonic_ns() + int(_TIMEOUT * 1_000_000_000)
        enclosing = _CHECK_WORK_DEADLINE.get()
        if enclosing is not None:
            deadline = min(deadline, int(enclosing * 1_000_000_000))
        token = _CHECK_WORK_DEADLINE.set(deadline / 1_000_000_000)
        try:
            yield deadline
        finally:
            _CHECK_WORK_DEADLINE.reset(token)

    def _reusable_attempt(self, request_id, *, window=None):
        bound, payload = _launch_record(self._launch_registration, self.identity, self.clock_id, request_id, window=window)
        key = _launch_reservation_key(self.profile, self.revision, self._launch_registration, request_id)
        return bound, key, payload

    def _launch_request_valid(self, request_id):
        if self._launch is not None:
            return request_id is None
        return type(request_id) is str and _HASH.fullmatch(request_id) is not None

    def launch_approved(self, *, request_id=None):
        """Invoke the current approval once. Retain the request ID for reconciliation."""
        if self._launch_registration is None:
            return launch_result('refused', 'not_attempted', 'launch_backend_unavailable')
        if not self._launch_request_valid(request_id):
            return launch_result('refused', 'not_attempted', 'invalid_launch_request_id')
        try:
            verify_install(self.wheel, self.wheel_sha256)
        except VerificationError:
            return launch_result('refused', 'not_attempted', 'installed_package_unverified')
        plan = self._launch_registration.plan
        with self._launch_window() as deadline, self._approval(launch_plan=plan) as (code, registrations, store):
            if code is not None:
                return launch_result('refused', 'not_attempted', code)
            if self._launch is None:
                return self._launch_reusable(request_id, store, registrations, deadline)
            return self._start_launch(self._launch, plan, registrations, deadline)

    def _start_launch(self, launch, plan, registrations, deadline, *, reserve=None):
        limit = self._checked_launch_limit(plan, registrations)
        if limit is None:
            return launch_result('refused', 'not_attempted', 'launch_scope_unverified')
        return launch.start(valid_until_ns=limit, deadline_ns=deadline, reserve=reserve)

    def _checked_launch_limit(self, plan, registrations):
        try:
            limit = self._launch_limit(plan, registrations)
        except Exception:
            limit = None
        return limit if limit is not None and monotonic_ns() < limit else None

    def _launch_reusable(self, request_id, store, registrations, deadline):
        from . import roles_cli

        configured = self._launch_registration
        key = _launch_reservation_key(self.profile, self.revision, configured, request_id)
        correlation = {'request_id': request_id}
        try:
            prior = roles_cli._read(store, key)
        except (OSError, RecordError):
            return launch_result('unknown', 'unknown', 'launch_reservation_unconfirmed', **correlation)
        if prior is not None:
            try:
                launch = _recorded_launch(configured, prior, request_id, current=(self.identity, self.clock_id))
            except (ValueError, TypeError, KeyError):
                return launch_result('unknown', 'unknown', 'launch_reservation_mismatch', **correlation)
            return launch.read(deadline_ns=deadline) | correlation

        limit = self._checked_launch_limit(configured.plan, registrations)
        if limit is None:
            return launch_result('refused', 'not_attempted', 'launch_scope_unverified') | correlation
        window = None
        if configured.service_limits is not None:
            now = monotonic_ns()
            active = min(limit, deadline, now + configured.service_limits.active_ms * 1_000_000)
            if active <= now:
                return launch_result('refused', 'not_attempted', 'launch_deadline_elapsed') | correlation
            window = ServiceWindow(active, active + configured.service_limits.cleanup_ms * 1_000_000)
            limit = active
        registration, key, payload = self._reusable_attempt(request_id, window=window)
        correlation['invocation_key'] = registration.plan.invocation_key

        def reserve():
            try:
                return (roles_cli._commit(store, key, payload, kind=_LAUNCH_RESERVATION) is Persistence.COMMITTED
                        and roles_cli._read(store, key) == payload)
            except (OSError, RecordError):
                return False

        launch = ScopedLaunch(registration, self.identity, self.clock_id, service_window=window)
        return launch.start(valid_until_ns=limit, deadline_ns=deadline, reserve=reserve,
                            claim_ticket=lambda approval: _claim_launch_ticket(store, approval)) | correlation

    def read_launch(self, *, request_id=None):
        """Read the registered invocation's historical outcome without dispatch."""
        if self._launch_registration is None:
            return launch_result('refused', 'not_attempted', 'launch_backend_unavailable')
        if not self._launch_request_valid(request_id):
            return launch_result('refused', 'not_attempted', 'invalid_launch_request_id')
        try:
            verify_install(self.wheel, self.wheel_sha256)
        except VerificationError:
            return launch_result('refused', 'not_attempted', 'installed_package_unverified')
        with self._launch_window() as deadline:
            if self._launch is not None:
                return self._launch.read(deadline_ns=deadline)
            return self._read_reusable_launch(request_id, deadline)

    def _read_reusable_launch(self, request_id, deadline):
        if self._launch_registration.service_limits is not None:
            return _read_historical_launch(self._launch_registration, self.profile, self.revision,
                                           request_id, deadline)
        from . import roles_cli

        registration, key, payload = self._reusable_attempt(request_id)
        correlation = {'request_id': request_id, 'invocation_key': registration.plan.invocation_key}
        try:
            with roles_cli._store(create=False) as store:
                prior = roles_cli._read(store, key)
        except (OSError, RecordError, roles_cli.Refusal):
            return launch_result('unknown', 'unknown', 'launch_reservation_unconfirmed', **correlation)
        if prior is None:
            return launch_result('not_started', 'not_attempted', 'launch_not_reserved', **correlation)
        if prior != payload:
            return launch_result('unknown', 'unknown', 'launch_reservation_mismatch', **correlation)
        launch = ScopedLaunch(registration, self.identity, self.clock_id, already_reserved=True)
        return launch.read(deadline_ns=deadline) | correlation

    def binding_check_pins(self):
        """Return the fixed revision, clock and definition pins for the client."""
        from .appointment_registry import definition_sha256

        return {'revision': self.revision, 'clock_id': self.clock_id,
                'scope_digests': {definition.name: definition_sha256(definition)
                                  for definition in self.definitions}}

    def check_bindings(self):
        """Verify approved, current bindings without creating or reading an attempt."""
        from .appointment_registry import definition_sha256
        from .managed_cli import _CHECK_BOUNDARY, _CHECK_SCOPE_CODES, _binding_check_time_available

        result = {'profile': self.profile, 'revision': self.revision, 'identity': self.identity,
                  'status': 'refused', **_CHECK_BOUNDARY}
        if not _binding_check_time_available():
            return dict(result, code='host_bindings_unavailable')
        try:
            verify_install(self.wheel, self.wheel_sha256)
        except VerificationError:
            return dict(result, code='installed_package_unverified')
        # Local verification and approval reads are synchronous. Check again
        # before beginning downstream work after either one returns.
        if not _binding_check_time_available():
            return dict(result, code='host_bindings_unavailable')
        with self._approval() as (code, _, _):
            if code is not None:
                return dict(result, code=code)
            if not _binding_check_time_available():
                return dict(result, code='host_bindings_unavailable')
            checked = self.aggregate._check_bindings(self.definitions)
        result['scopes'] = [
            {'name': name, 'status': check.status,
             'code': check.code if check.code in _CHECK_SCOPE_CODES else 'other',
             'definition_sha256': definition_sha256(definition)}
            for definition, (name, check) in zip(self.definitions, checked.scopes, strict=True)
        ]
        result['status'] = checked.status
        if checked.valid_until_ns is not None:
            result['observation'] = {'clock_id': self.clock_id, 'start_ns': str(checked.observed_start_ns),
                                     'end_ns': str(checked.observed_end_ns),
                                     'valid_until_ns': str(checked.valid_until_ns)}
            if monotonic_ns() >= checked.valid_until_ns:
                result.update(status='incomplete', code='binding_evidence_expired')
        if result['status'] == 'incomplete':
            result['next_action'] = 'Check the current approved binding and provider for each unverified scope before setup.'
        return result

    def _setup(self):
        prior = self._record()
        if prior is None or prior.state in ('pending','unavailable'):
            return self._output('unknown')
        if prior.state != 'not_started':
            return self._readback()
        try: claim = self.store.claim(self.identity, self.operation_key)
        except Exception: return self._output('unknown')
        if claim != 'claimed':
            return self._output('unknown')
        result = self.aggregate.setup()
        if not result.scopes:
            return self._output('unknown')
        try: stored = self.store.finish(self.identity, self.operation_key, result.scopes)
        except Exception: return self._output('unknown', result.scopes, result.final_checks)
        if stored is not True:
            return self._output('unknown', result.scopes, result.final_checks)
        # Read through the authority, rather than trusting the write reply.
        return self._readback()

    def readback(self):
        with self._approval() as (code, _, _):
            if code is not None:
                return self._approval_refusal(code)
            return self._readback()

    def _readback(self):
        record = self._record()
        if record is not None and record.state == 'pending':
            results = _recover_pending(self.store, self.identity, self.operation_key, self.definitions)
            status = 'incomplete' if any(result.status != 'unknown' for _, result in results) else 'unknown'
            return self._output(status, results)
        if record is None or record.state in ('not_started','unavailable'):
            return self._output('unknown')
        if record.state == 'not_committed':
            return self._output('incomplete', effect='not_committed')
        observation = self.aggregate.observe(self.definitions)
        final = observation.final_checks
        status = 'ready' if observation.status == 'ready' and all(
            r.status == 'accepted' for _,r in record.results) else 'incomplete'
        return self._output(status, record.results, final, observed=observation)

    def reconcile(self):
        """Exact read-only lookup; never create or replay a setup."""
        return self.readback()
