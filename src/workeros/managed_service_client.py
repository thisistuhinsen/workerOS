"""Authenticated named-workflow ingress for the stock system service adapter."""
import argparse
from contextlib import ExitStack
from dataclasses import replace
import json
import os
import socket
import sys
from time import monotonic, monotonic_ns
from uuid import uuid4

from . import managed_bootstrap, managed_cli, managed_service
from .appointment_registry import launch_policy_sha256
from .managed_executor import (_Authority, _CREDENTIALS, _FRAME, _read_only_dispatch,
                               _read_registration, _remaining, ExecutorRefusal)
from .managed_host import _read_historical_launch
from .managed_listeners import ORIGINALS, activation_descriptors, bind_originals, registered_listener
from .managed_launch import (
    GUARDED_SERVICE, LaunchRegistration, LaunchRolePolicy, ManagedServiceEvidence, UnreleasedServiceEvidence,
    _digest, _uid, _unsigned, launch_result, service_cleanup,
)
from .managed_service_guard import GuardedServiceAuthority, ServicePhaseObservation
from .managed_service_observer import EffectCleanupObservation, ResultObserver
from .managed_service_scope import ServiceBundle
from .recording import RecordError, _name
from .roles_cli import _canonical, _fields
from .verify_install import VerificationError, verify_install

_CLIENT_CONFIG = 'launch-client.json'
_PUBLIC_CLIENT_CONFIG = 'workeros-launch-client.json'


def _peer(connection):
    pid, uid, _ = _CREDENTIALS.unpack(connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size))
    if pid <= 0:
        raise ExecutorRefusal('service_peer_untrusted')
    return uid


def _frame_read(connection, deadline):
    size, = _FRAME.unpack(managed_cli._read_exact(connection, _FRAME.size, deadline))
    if not 0 < size <= managed_cli._LIMIT:
        raise ExecutorRefusal('service_message_invalid')
    return managed_cli.decode_policy(managed_cli._read_exact(connection, size, deadline))


def _frame_write(connection, payload, deadline):
    data = _canonical(payload)
    if len(data) > managed_cli._LIMIT:
        raise ExecutorRefusal('service_message_invalid')
    connection.settimeout(_remaining(deadline))
    connection.sendall(_FRAME.pack(len(data)) + data)


def _response(result, request):
    _fields(result, ('status', 'effect', 'code'),
            ('request_id', 'invocation_key', 'receipt_sha256', 'service', 'cleanup', 'provider_report', 'unreleased',
             'observer_result', 'terminal_source', 'selection', 'phase_observation', 'activity', 'history', 'summary'))
    if (result['status'], result['effect']) not in (
            ('not_started', 'not_attempted'), ('refused', 'not_attempted'), ('unknown', 'unknown'),
            ('started', 'dispatched'), ('terminal', 'dispatched')) or not _name(result['code']):
        raise ValueError('unexpected service response')
    if 'request_id' in result and result['request_id'] != request['request_id']:
        raise ValueError('different service request')
    for name in ('invocation_key', 'receipt_sha256'):
        if name in result:
            _digest(result[name])
    if 'selection' in result:
        selection = result['selection']
        _fields(selection, ('workflow', 'role', 'scope_sha256', 'resource_scopes'), ('worker',))
        _name(selection['workflow'])
        _name(selection['role'])
        if 'worker' in selection:
            _name(selection['worker'])
        _digest(selection['scope_sha256'])
        scopes = selection['resource_scopes']
        if (selection['workflow'] != request['workflow'] or type(scopes) is not list
                or result['code'] in ('service_caller_denied', 'service_result_not_granted')):
            raise ValueError('unbound or unauthorized service selection')
        for scope in scopes:
            _name(scope)
        if len(scopes) != len(set(scopes)):
            raise ValueError('duplicate service scopes')
    if 'phase_observation' in result:
        phase = ServicePhaseObservation(**result['phase_observation'])
        if (result['status'] != 'unknown' or result.get('request_id') != request['request_id']
                or phase.invocation_key != result.get('invocation_key') or 'provider_report' in result
                or phase.scope_sha256 != result.get('selection', {}).get('scope_sha256')):
            raise ValueError('unbound service phase')
    if 'unreleased' in result or result['code'] == 'service_bootstrap_unreleased':
        proof = UnreleasedServiceEvidence(**result['unreleased'])
        if ((result['status'], result['effect'], result['code']) != (
                'not_started', 'not_attempted', 'service_bootstrap_unreleased')
                or result.get('request_id') != request['request_id']
                or proof.unit != f"workeros-{result['invocation_key']}.service"
                or 'provider_report' in result):
            raise ValueError('unbound service unreleased readback')
    if ('provider_report' in result) != (result['code'] == 'service_terminal_reported'):
        raise ValueError('unexpected service provider report')
    if 'provider_report' in result:
        reported = result['provider_report']
        _fields(reported, ('receipt_sha256', 'service'))
        _digest(reported['receipt_sha256'])
        report = ManagedServiceEvidence(**reported['service'])
        if ((result['status'], result['effect'], result['code']) != ('unknown', 'unknown', 'service_terminal_reported')
                or result.get('request_id') != request['request_id']
                or report.unit != f"workeros-{result['invocation_key']}.service"
                or report.lifecycle is None or report.lifecycle.retired_ns is None):
            raise ValueError('unbound service provider report')
        if 'selection' in result and report.scope_sha256 != result['selection']['scope_sha256']:
            raise ValueError('unbound service provider scope')
        service_cleanup(report, 'terminal')
    observed = result['code'] == 'independent_service_result_verified'
    if observed != ('observer_result' in result):
        raise ValueError('unexpected independent service result')
    if 'history' in result:
        history = result['history']
        _fields(history, ('status', 'profile', 'revision'))
        if ((not observed and 'provider_report' not in result) or history['status'] not in ('recorded', 'unconfirmed')
                or any(history[field] != request[field] for field in ('profile', 'revision'))
                or 'selection' not in result):
            raise ValueError('unbound service history')
    if 'summary' in result:
        summary = result['summary']
        _fields(summary, ('version', 'basis', 'liveness', 'status', 'code', 'verified_count'), ('counts',))
        count = summary['verified_count']
        if ('summary_ids' not in request or result.get('history', {}).get('status') != 'recorded'
                or type(summary['version']) is not int or summary['version'] != 1
                or (summary['basis'], summary['liveness']) != ('verified_archived_requests', 'unavailable')):
            raise ValueError('unbound historical summary')
        requested = len({request['request_id'], *request['summary_ids']})
        if (summary['status'], summary['code']) == ('reported', 'verified_archive_count'):
            if type(count) is not int or not (0 if 'counts' in summary else 1) <= count <= requested:
                raise ValueError('invalid historical count')
        elif (summary['status'], summary['code'], count) != ('unavailable', 'verified_archive_unavailable', None):
            raise ValueError('invalid historical summary')
        if 'counts' in summary:
            coverage = summary['counts']
            _fields(coverage, ('active', 'settling', 'completed', 'refused', 'failed', 'unknown'))
            recorded = tuple(coverage[key] for key in ('completed', 'failed', 'unknown'))
            if any(coverage[key] is not None for key in ('active', 'settling', 'refused')):
                raise ValueError('archive has no current or refused coverage')
            if summary['status'] == 'reported':
                if (any(type(number) is not int or number < 0 for number in recorded)
                        or recorded[0] != count or sum(recorded) != requested):
                    raise ValueError('invalid historical coverage')
            elif any(number is not None for number in recorded):
                raise ValueError('unavailable archive coverage')
    split = 'terminal_source' in result
    if split and not observed:
        raise ValueError('unexpected terminal provenance')
    if observed:
        observer = result['observer_result']
        _fields(observer, ('source', 'source_sha256', 'effect_sha256', 'receipt_sha256', 'verified_ns', 'expires_ns'),
                ('cleanup_observation',))
        _name(observer['source'])
        for field in ('source_sha256', 'effect_sha256', 'receipt_sha256'):
            _digest(observer[field])
        for field in ('verified_ns', 'expires_ns'):
            _unsigned(observer[field], positive=True)
        if ((result['status'], result['effect'], result.get('cleanup')) != ('terminal', 'dispatched', 'verified')
                or split != ('cleanup_observation' in observer)
                or not split and observer['receipt_sha256'] != result.get('receipt_sha256')
                or observer['verified_ns'] >= observer['expires_ns']):
            raise ValueError('unbound independent service result')
        if split:
            terminal = result['terminal_source']
            _fields(terminal, ('source', 'source_sha256'))
            _name(terminal['source'])
            _digest(terminal['source_sha256'])
            if terminal['source'] == observer['source'] or terminal['source_sha256'] == observer['source_sha256']:
                raise ValueError('service terminal and witness sources must be distinct')
    if result['effect'] == 'dispatched':
        report = ManagedServiceEvidence(**result['service'])
        if (report.manager_run_id is not None) != observed:
            raise ValueError('delegated manager report requires separate native verification')
        if observed:
            life = report.lifecycle
            if (life is None or any(tick is None for tick in (life.empty_ns, life.retired_ns, life.handles_closed_ns))
                    or (life.terminal_disposition, life.terminal_status) != ('exited', 0)
                    or not split and max(life.retired_ns, life.handles_closed_ns) > observer['verified_ns']):
                raise ValueError('independent service result has no exact closure')
            if split:
                witness = EffectCleanupObservation(**observer['cleanup_observation'])
                if not witness.matches(report) or witness.handles_closed_ns > observer['verified_ns']:
                    raise ValueError('independent service result names another process or closure')
        expected_cleanup = service_cleanup(report, result['status'])
        cleanup_matches = (result['cleanup'] == expected_cleanup or
                           (result['status'], result['cleanup']) == ('terminal', 'unconfirmed'))
        if (report.unit != f"workeros-{result['invocation_key']}.service" or not cleanup_matches
                or 'receipt_sha256' not in result or result.get('request_id') != request['request_id']):
            raise ValueError('unbound service response')
    elif result.keys() & {'service', 'cleanup', 'receipt_sha256'}:
        raise ValueError('unexpected service evidence')
    if 'activity' in result:
        from .result_summary import scoped_activity

        if 'selection' not in result or result['activity'] != scoped_activity(result):
            raise ValueError('unbound service activity')
    return result


def _validate_client_registration(config):
    _fields(config, ('version', 'profile', 'revision', 'socket', 'peer_uid', 'workflows'))
    _name(config['profile'])
    _name(config['revision'])
    path = config['socket']
    if (type(config['version']) is not int or config['version'] != 1
            or type(config['peer_uid']) is not int or config['peer_uid'] != managed_cli._TRUSTED_UID
            or type(path) is not str or not path.startswith('/') or '\0' in path or len(os.fsencode(path)) > 107):
        raise ValueError('invalid service client registration')
    if type(config['workflows']) is not dict or not 1 <= len(config['workflows']) <= 8:
        raise ValueError('invalid service client registration')
    for workflow, policy in config['workflows'].items():
        _name(workflow)
        _digest(policy)
    return config


def _client_registration():
    try:
        config = managed_cli._read_admin_json(_PUBLIC_CLIENT_CONFIG, public=True)
    except FileNotFoundError:
        config = managed_cli._read_admin_json(_CLIENT_CONFIG)
    return _validate_client_registration(config)


def _service_unavailable(code, request_id, *, readback):
    if readback:
        return launch_result('unknown', 'unknown', code, request_id=request_id)
    return launch_result('refused', 'not_attempted', code)


def request_service(workflow, request_id, *, readback=False, revision=None, summary_ids=None):
    """Request only a pinned name and opaque key, with no live credentials from the caller."""
    try:
        _name(workflow)
        _digest(request_id)
        if revision is not None:
            _name(revision)
            if not readback:
                raise ValueError('history is read-only')
        if summary_ids is not None:
            if revision is None or type(summary_ids) not in (tuple, list):
                raise ValueError('summary needs exact history')
            for identifier in summary_ids:
                _digest(identifier)
    except ValueError:
        return launch_result('refused', 'not_attempted', 'invalid_service_request')
    try:
        config = _client_registration()
        pin = config['workflows'].get(workflow) if revision is None else None
        if revision is None:
            if pin is None:
                return _service_unavailable('service_caller_denied', request_id, readback=readback)
            _digest(pin)
    except (OSError, ValueError, KeyError, TypeError):
        return _service_unavailable('service_client_registration_unavailable', request_id, readback=readback)
    operation = 'history' if revision is not None else 'readback' if readback else 'run'
    request = {'version': 1, 'nonce': uuid4().hex, 'operation': operation,
               'profile': config['profile'], 'revision': revision or config['revision'], 'workflow': workflow,
               'policy_sha256': pin, 'request_id': request_id}
    if summary_ids is not None:
        request['summary_ids'] = list(summary_ids)
    sent = False
    deadline = monotonic() + managed_cli._TIMEOUT
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(_remaining(deadline))
            connection.connect(config['socket'])
            if _peer(connection) != config['peer_uid']:
                return _service_unavailable('service_peer_untrusted', request_id, readback=readback)
            sent = True
            _frame_write(connection, request, deadline)
            reply = _frame_read(connection, deadline)
        _fields(reply, ('version', 'nonce', 'result'))
        if type(reply['version']) is not int or (reply['version'], reply['nonce']) != (1, request['nonce']):
            raise ValueError('different service reply')
        return _response(reply['result'], request)
    except (OSError, EOFError, TypeError, KeyError, ValueError):
        if sent:
            return launch_result('unknown', 'unknown', 'service_reply_unconfirmed', request_id=request_id)
        return _service_unavailable('service_endpoint_unavailable', request_id, readback=readback)


def _selection(request, caller_uid, *, originals=None, resources=None, deadline=None):
    config = _read_registration()
    slots = config.get('workflows')
    entry = slots.get(request['workflow']) if type(slots) is dict else None
    rights = 'run_uids' if request['operation'] == 'run' else 'result_uids'
    if type(entry) is not dict or type(entry.get(rights)) is not list or caller_uid not in entry[rights]:
        raise ExecutorRefusal('service_caller_denied')
    _fields(config, ('version', 'profile', 'revision', 'wheel_path', 'wheel_sha256', 'workflows'))
    if type(config['version']) is not int or config['version'] != 2 or (config['profile'], config['revision']) != (
            request['profile'], request['revision']):
        raise ExecutorRefusal('service_registration_mismatch')
    if not 1 <= len(slots) <= 8:
        raise ExecutorRefusal('service_workflow_unavailable')
    _fields(entry, ('policy', 'authority', 'service', 'run_uids', 'result_uids'), ('result_observer', 'holder'))
    for field in ('run_uids', 'result_uids'):
        allowed = entry[field]
        if type(allowed) is not list or len(allowed) > 64:
            raise ExecutorRefusal('service_caller_registration_invalid')
        for uid in allowed:
            _uid(uid)
    endpoint = entry['authority']
    _fields(endpoint, ('socket', 'uid'), ('enforcement',))
    from .managed_registration import require_pinned_pair

    host = require_pinned_pair(config, required=endpoint.get('enforcement') == GUARDED_SERVICE,
                               readback=request['operation'] == 'readback')
    policy = LaunchRolePolicy(**entry['policy'])
    if policy.workflow != request['workflow'] or launch_policy_sha256(policy) != request['policy_sha256']:
        raise ExecutorRefusal('service_registration_mismatch')
    descriptor = entry['service']
    if type(descriptor) is not dict:
        raise ExecutorRefusal('service_registration_mismatch')
    scope = ServiceBundle(**descriptor) if 'descriptors' in descriptor else managed_service.ServiceScope(**descriptor)
    if (request['operation'] == 'run' and endpoint.get('enforcement') == GUARDED_SERVICE
            and scope.parent is not None and not scope.parent.delegated_service):
        raise ExecutorRefusal('service_guard_delegated_parent_required')
    if (type(scope) is ServiceBundle and scope.elevated_capabilities
            and endpoint.get('enforcement') != GUARDED_SERVICE):
        raise ExecutorRefusal('elevated_service_requires_guarded_enforcement')
    authority = _Authority(endpoint['socket'], endpoint['uid'], policy)
    observer = None
    if 'result_observer' in entry:
        observer = ResultObserver(entry['result_observer'], policy, endpoint, managed_service.limits(scope))
        if observer.endpoint.uid in entry['run_uids']:
            raise ExecutorRefusal('service_result_observer_not_independent')
    _digest(config['wheel_sha256'])
    if 'holder' in entry:
        from .managed_holder import receive_originals, validate_holder

        holder = entry['holder']
        validate_holder(holder, policy, scope, endpoint)
        if request['operation'] == 'run':
            if originals:
                raise ExecutorRefusal('service_holder_activation_conflict')
            scope = receive_originals(holder, config['profile'], config['revision'], policy.workflow,
                                      scope, resources, deadline)
    elif originals is not None and request['operation'] == 'run':
        scope = bind_originals(scope, originals)
    if 'enforcement' in endpoint:
        if endpoint['enforcement'] != GUARDED_SERVICE or managed_service.limits(scope) is None or scope.parent is None:
            raise ExecutorRefusal('service_enforcement_registration_invalid')
        authority = GuardedServiceAuthority(authority, scope, check_resources=scope.check_original)
    may_read = caller_uid in entry['result_uids']
    return (config, policy, scope, authority, may_read, host,
            observer.read if observer and may_read else None, entry['result_uids'])


def _handle(request, caller_uid, deadline, *, originals=None):
    from .service_history import read_history, read_history_summary, retain_history

    if request['operation'] == 'history':
        if 'summary_ids' in request:
            return read_history_summary(request, caller_uid, int(deadline * 1_000_000_000))
        return read_history(request, caller_uid)
    entered = False
    request_id = request['request_id']
    readback = request['operation'] == 'readback'
    holders = ExitStack()
    try:
        config, policy, scope, authority, may_read, host, observe_result, readers = _selection(
            request, caller_uid, originals=originals, resources=holders, deadline=deadline)
        guarded = type(authority) is GuardedServiceAuthority
        if readback:
            verify_install(config['wheel_path'], config['wheel_sha256'])
            if guarded:
                prior = read_history(request, caller_uid, independent_only=True)
                if 'history' in prior:
                    return prior
            enforcement = GUARDED_SERVICE if guarded else None
            registration = LaunchRegistration(policy, authority.authorize, _read_only_dispatch, authority.readback,
                                              bounded=True, service_scope_sha256=scope.digest,
                                              service_limits=managed_service.limits(scope), service_enforcement=enforcement,
                                              require_ticket_claim=enforcement == GUARDED_SERVICE,
                                              observe_result=observe_result)
            native_deadline = int(deadline * 1_000_000_000)
            sampled_after = monotonic_ns()
            report = _read_historical_launch(registration, config['profile'], config['revision'], request_id,
                                             native_deadline)
            outcome = managed_service.verify_native_readback(scope.parent, report, native_deadline,
                                                             guarded=guarded)
            return retain_history(request, caller_uid, readers,
                                  _selected_outcome(outcome, policy, scope, authority, sampled_after))
        if host is None:
            host = managed_cli._read_admin_json(managed_bootstrap._CONFIG_FILE)
        if (host['profile'], host['revision'], host['wheel_path']) != (
                config['profile'], config['revision'], config['wheel_path']) or host['version'] != 2:
            raise ExecutorRefusal('service_registration_mismatch')
        matches = [entry for entry in host['scopes'] if entry['definition']['name'] == policy.workflow]
        if len(matches) != 1 or matches[0]['definition']['package_sha256'] != config['wheel_sha256']:
            raise ExecutorRefusal('service_registration_mismatch')
        with ExitStack() as resources:
            registration = managed_service.prepare(
                scope, policy, authority, resources, deadline_ns=int(deadline * 1_000_000_000))
            if observe_result is not None:
                registration = replace(registration, observe_result=observe_result)
            adapter = resources.enter_context(managed_bootstrap._open_approved_launch(
                {**host, 'scopes': matches}, registration, executable_argv=(scope.executable,),
                require_launch_resource=True, launch_service=scope))
            entered = True
            sampled_after = monotonic_ns()
            outcome = adapter.launch_approved(request_id=request_id)
            if not may_read:
                return launch_result('unknown', 'unknown', 'service_result_not_granted', request_id=request_id)
            if registration.service_enforcement == GUARDED_SERVICE:
                outcome = managed_service.verify_native_readback(
                    scope.parent, outcome, int(deadline * 1_000_000_000), guarded=True)
            return retain_history(request, caller_uid, readers,
                                  _selected_outcome(outcome, policy, scope, authority, sampled_after))
    except (ExecutorRefusal, managed_service.ServiceRefusal) as exc:
        return _service_unavailable(str(exc), request_id, readback=readback)
    except (OSError, KeyError, TypeError, ValueError, VerificationError, RecordError):
        if entered:
            return launch_result('unknown', 'unknown', 'service_reply_unconfirmed', request_id=request_id)
        return _service_unavailable('service_binding_unavailable', request_id, readback=readback)
    finally:
        holders.close()


def _selected_outcome(outcome, policy, scope, authority, sampled_after):
    """Attach the selection only after the caller's result rights are checked."""
    from .result_summary import scoped_activity

    resources = sorted({item.scope for item in scope.descriptors}) if type(scope) is ServiceBundle else []
    result = {**outcome, 'selection': {'workflow': policy.workflow, 'role': policy.role,
                                      'worker': policy.principal,
                                      'scope_sha256': scope.digest, 'resource_scopes': resources}}
    phase = authority.phase_observation if type(authority) is GuardedServiceAuthority else None
    if (phase is not None and result['status'] == 'unknown' and 'provider_report' not in result
            and phase['invocation_key'] == result.get('invocation_key')
            and sampled_after <= phase['observed_ns'] <= monotonic_ns()):
        result['phase_observation'] = phase
    result['activity'] = scoped_activity(result)
    return result


def serve_connection(connection, *, deadline=None, commissioned=None, pending_runs=None, originals=None,
                     history_only=False, accept_deadline=None):
    if os.getresuid() != (managed_cli._TRUSTED_UID,) * 3:
        raise ExecutorRefusal('administrator_required')
    if deadline is None:
        deadline = monotonic() + managed_cli._TIMEOUT
    caller_uid = _peer(connection)
    request = _frame_read(connection, deadline if accept_deadline is None else min(deadline, accept_deadline))
    _fields(request, ('version', 'nonce', 'operation', 'profile', 'revision', 'workflow', 'policy_sha256', 'request_id'),
            ('summary_ids',))
    if (type(request['version']) is not int or request['version'] != 1
            or request['operation'] not in ('run', 'readback', 'history') or type(request['nonce']) is not str
            or len(request['nonce']) != 32 or any(ch not in '0123456789abcdef' for ch in request['nonce'])):
        raise ExecutorRefusal('invalid_service_request')
    for key in ('profile', 'revision', 'workflow'):
        _name(request[key])
    _digest(request['request_id'])
    if request['operation'] == 'history':
        if request['policy_sha256'] is not None:
            raise ExecutorRefusal('invalid_service_request')
    else:
        _digest(request['policy_sha256'])
    if 'summary_ids' in request:
        if request['operation'] != 'history' or type(request['summary_ids']) is not list:
            raise ExecutorRefusal('invalid_service_request')
        for identifier in request['summary_ids']:
            _digest(identifier)
    workflow, operation = request['workflow'], request['operation']
    if accept_deadline is not None and (history_only or operation != 'run'):
        deadline = min(deadline, accept_deadline)
    lookup_answered = False
    token = managed_cli._CHECK_WORK_DEADLINE.set(deadline)
    try:
        _remaining(deadline)
        if history_only and operation != 'history':
            result = launch_result('refused', 'not_attempted', 'service_history_only')
        elif commissioned is not None and workflow not in commissioned:
            if operation == 'history':
                result = launch_result('unknown', 'unknown', 'service_history_unavailable')
            else:
                result = _service_unavailable('service_caller_denied', request['request_id'],
                                              readback=operation == 'readback')
        elif commissioned is not None and operation != 'history':
            admission = commissioned[workflow]
            if caller_uid not in admission[operation]:
                result = _service_unavailable('service_caller_denied', request['request_id'],
                                              readback=operation == 'readback')
            elif any(request[field] != admission[field] for field in ('profile', 'revision', 'policy_sha256')):
                result = _service_unavailable('service_registration_mismatch', request['request_id'],
                                              readback=operation == 'readback')
            elif operation == 'run' and workflow not in pending_runs:
                result = launch_result('refused', 'not_attempted', 'service_workflow_unavailable')
            else:
                if operation == 'run':
                    pending_runs.remove(workflow)
                result = _handle(request, caller_uid, deadline, originals=originals)
                lookup_answered = operation == 'readback' and 'selection' in result
        else:
            result = _handle(request, caller_uid, deadline, originals=originals)
            lookup_answered = operation == 'history' and result.get('history', {}).get('status') == 'recorded'
    finally:
        managed_cli._CHECK_WORK_DEADLINE.reset(token)
    _frame_write(connection, {'version': 1, 'nonce': request['nonce'], 'result': result}, deadline)
    return lookup_answered


def _commissioned_listener(workflows):
    from .managed_registration import _service_registration, require_pinned_pair

    executor = _read_registration()
    config = _client_registration()
    if (executor['version'] != 2 or (config['profile'], config['revision']) != (
            executor['profile'], executor['revision'])):
        raise ValueError('service_registration_mismatch')
    require_pinned_pair(executor, required=True, readback=True)
    originals, endpoints = set(), {config['socket']}
    admissions = {}
    for workflow in workflows:
        _name(workflow)
        selected = executor['workflows'][workflow]
        policy, scope = _service_registration(selected, workflow)
        sockets = {selected[field]['socket'] for field in ('authority', 'result_observer', 'holder')
                   if field in selected}
        if (selected['authority'].get('enforcement') != GUARDED_SERVICE
                or config['workflows'][workflow] != launch_policy_sha256(policy) or sockets & endpoints):
            raise ValueError('service_registration_mismatch')
        if len(workflows) > 1:
            if 'holder' not in selected:
                raise ValueError('service_overlap_requires_holders')
            identities = {item.original for item in scope.descriptors}
            if identities & originals:
                raise ValueError('service_overlap_requires_distinct_originals')
            originals |= identities
        endpoints |= sockets
        admissions[workflow] = {'run': frozenset(selected['run_uids']),
                                'readback': frozenset(selected['result_uids']),
                                'profile': config['profile'], 'revision': config['revision'],
                                'policy_sha256': config['workflows'][workflow]}
    return registered_listener(config['socket'], managed_cli._TRUSTED_UID, public=True), admissions


def serve_main(argv):
    parser = argparse.ArgumentParser(prog='workeros managed serve-launch',
                                     description='Serve a finite batch of explicit requests on a protected listener.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--listen-fd', type=int)
    mode.add_argument('--history', action='store_true',
                      help='Serve one read-only archived lookup on the protected client socket')
    mode.add_argument('--commissioned', action='append', metavar='WORKFLOW',
                      help='add a distinct approved workflow and one run to the finite batch')
    args = parser.parse_args(argv)
    workflows = None if args.commissioned is None else frozenset(args.commissioned)
    if workflows is not None and len(workflows) != len(args.commissioned):
        parser.error('each commissioned workflow must be distinct')
    received = False
    unconfirmed = False
    try:
        if os.getresuid() != (managed_cli._TRUSTED_UID,) * 3 or (args.listen_fd is not None and args.listen_fd < 3):
            raise ExecutorRefusal('administrator_required')
        originals = (activation_descriptors(frozenset(), ORIGINALS) if args.commissioned is not None else None)
        commissioned = None
        pending_runs = None
        if args.commissioned is not None:
            endpoint, commissioned = _commissioned_listener(workflows)
            pending_runs = set(commissioned)
        elif args.history:
            config = _client_registration()
            endpoint = registered_listener(config['socket'], managed_cli._TRUSTED_UID, public=True)
        else:
            endpoint = socket.socket(fileno=os.dup(args.listen_fd))
        with endpoint as listener:
            if (listener.family != socket.AF_UNIX
                    or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                    or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                    or _peer(listener) != managed_cli._TRUSTED_UID):
                raise ExecutorRefusal('service_listener_untrusted')
            accept_deadline = monotonic() + managed_cli._TIMEOUT
            admission_deadline = accept_deadline if commissioned is not None or args.history else None
            lookup_answered = False
            while pending_runs is None or pending_runs:
                try:
                    listener.settimeout(_remaining(accept_deadline))
                    client, _ = listener.accept()
                except TimeoutError:
                    if lookup_answered and not received:
                        break
                    raise
                with client:
                    slots = len(pending_runs) if pending_runs is not None else None
                    reply_failed = False
                    try:
                        lookup_answered |= serve_connection(
                            client, commissioned=commissioned, pending_runs=pending_runs, originals=originals,
                            history_only=args.history, accept_deadline=admission_deadline)
                    except (OSError, ValueError, EOFError, TypeError, KeyError):
                        reply_failed = True
                    if args.history:
                        if lookup_answered:
                            break
                        continue
                    if slots is None or len(pending_runs) < slots:
                        received = True
                        unconfirmed |= reply_failed
                    if commissioned is None:
                        break
            if unconfirmed:
                raise OSError('service_request_unconfirmed')
    except (OSError, ValueError, EOFError, TypeError, KeyError):
        result = (launch_result('unknown', 'unknown', 'service_request_unconfirmed') if received else
                  launch_result('refused', 'not_attempted', 'service_listener_unavailable'))
        print(json.dumps(result))
        return 1
    return 0
