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
from .profile_setup import ManagerSelection, ProfileDefinition, SetupResult
from .recording import _name
from .verify_install import VerificationError, verify_install

_HASH = re.compile(r'[0-9a-f]{64}')


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
                 wheel, wheel_sha256, clock_id, store, local_approval=None, local_appointments=False):
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

    @contextmanager
    def _approval(self):
        """Hold the local role lock across one bounded, no-start manager operation."""
        if self._local_approval is None:
            yield None
            return
        from . import roles_cli
        from .recording import RecordError

        with ExitStack() as locks:
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
                else:
                    declaration = roles_cli._inspect_store(store, self.profile, self.revision)
                    code = self._check_declaration(store, receipt, declaration)
            except roles_cli.Refusal as exc:
                code = ('manager_selection_denied' if str(exc) in
                        ('administrator_required', 'profile_store_missing') else 'host_bindings_unavailable')
            except (OSError, ValueError, RecordError):
                code = 'host_bindings_unavailable'
            yield code

    def _check_declaration(self, store, receipt, declaration):
        registrations = None
        if self._local_appointments:
            from .appointment_registry import read_registry

            document = read_registry(store, self.profile, self.revision, receipt, declaration)
            if document is None:
                return 'role_appointment_unverified'
            registrations = {entry['workflow']: entry for entry in document['appointments']}
        return self._check_declared_scopes(declaration, registrations)

    def _check_declared_scopes(self, declaration, registrations):
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
            # The existing provider registry cannot compare declaration-side
            # resource identities or OS principal independence to a live binding.
            if (role is None or scope.requirements.scope not in role['scopes']
                    or role.get('resources') or role.get('independent_of') or role.get('privileged')):
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
        with self._approval() as code:
            if code is not None:
                return self._approval_refusal(code)
            return self._setup()

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
        with self._approval() as code:
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
        with self._approval() as code:
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
