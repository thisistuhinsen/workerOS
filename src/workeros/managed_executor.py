"""Stock bounded launch for one administrator-approved Linux file reader."""
import argparse
from array import array
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import errno
import fcntl
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shlex
import socket
import stat
import struct
import subprocess
import sys
from time import monotonic, monotonic_ns
from uuid import uuid4

from . import managed_bootstrap, managed_cli
from .enrollment import _budget
from .managed_host import _read_historical_launch
from .managed_launch import (
    LaunchAuthorization, LaunchInvocation, LaunchPlan, LaunchReadback, LaunchRegistration,
    LaunchRolePolicy, _digest, _uid, launch_result,
)
from .recording import RecordError, _name
from .roles_cli import _APPROVAL_LOCK, _canonical, _fields
from .supervisor import DirectChildSupervisor, LifecycleStatus
from .verify_install import VerificationError, verify_install

_REGISTRATION = 'launch-executor.json'
_BWRAP = '/usr/bin/bwrap'
_OWNED_BWRAP = Path(__file__).with_name('_runtime') / 'bwrap'
_OWNED_BWRAP_SHA256 = '6865e23c7ac667d87b8805850ec1759aca3fec338eb30fec6a099f31bd8aebbf'
_FRAME = struct.Struct('!I')
_CREDENTIALS = struct.Struct('=iII')
_MAX_EXECUTABLE = 64 * 1024 * 1024
# Linux UAPI values from linux/fcntl.h. A Python build may omit the names.
_ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
_GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
_REQUIRED_SEALS = 0x0f  # SEAL, SHRINK, GROW, WRITE


class ExecutorRefusal(ValueError):
    pass


def authority_pin(name, endpoint, uid):
    """Hash the administrator-approved Unix authority identity."""
    return sha256(_canonical({'version': 1, 'source': name, 'socket': endpoint, 'uid': uid})).hexdigest()


def _remaining(deadline):
    left = deadline - monotonic()
    if left <= 0:
        raise TimeoutError()
    return left


class _Authority:
    def __init__(self, endpoint, uid, policy):
        _uid(uid)
        with open('/proc/sys/kernel/overflowuid', encoding='ascii') as source:
            overflow = int(source.read())
        if (type(endpoint) is not str or not endpoint.startswith('/') or '\0' in endpoint
                or len(os.fsencode(endpoint)) > 107 or uid in (os.geteuid(), policy.principal_uid, overflow)
                or authority_pin(policy.authority, endpoint, uid) != policy.authority_sha256):
            raise ExecutorRefusal('launch_authority_registration_invalid')
        self.endpoint = endpoint
        self.uid = uid

    def _exchange(self, operation, invocation, deadline_ns, **fields):
        deadline = deadline_ns / 1_000_000_000
        nonce = uuid4().hex
        wire = asdict(invocation)
        if wire['service_window'] is None:
            del wire['service_window']
        payload = _canonical({'version': 1, 'operation': operation, 'nonce': nonce,
                              'invocation': wire, **fields})
        if len(payload) > managed_cli._LIMIT:
            raise ExecutorRefusal('launch_authority_request_invalid')
        approval_lock = _APPROVAL_LOCK.get() if operation == 'submit_service' else None
        if operation == 'submit_service' and approval_lock is None:
            raise ExecutorRefusal('service_approval_lock_unavailable')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(_remaining(deadline))
            client.connect(self.endpoint)
            pid, uid, _ = _CREDENTIALS.unpack(client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size))
            if pid <= 0 or uid != self.uid:
                raise ExecutorRefusal('launch_authority_peer_untrusted')
            client.settimeout(_remaining(deadline))
            frame = _FRAME.pack(len(payload)) + payload
            if approval_lock is not None:
                # The guard receives a reference to the existing kernel lock.
                # Closing this client cannot unlock it before guarded release.
                if client.sendmsg([frame[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                array('i', [approval_lock]))]) != 1:
                    raise OSError('service_approval_lock_send_unconfirmed')
                frame = frame[1:]
                client.settimeout(_remaining(deadline))
            client.sendall(frame)
            length, = _FRAME.unpack(managed_cli._read_exact(client, _FRAME.size, deadline))
            if not 0 < length <= managed_cli._LIMIT:
                raise ExecutorRefusal('launch_authority_reply_invalid')
            reply = managed_cli.decode_policy(managed_cli._read_exact(client, length, deadline))
        _fields(reply, ('version', 'operation', 'nonce', 'result'))
        if type(reply['version']) is not int or (reply['version'], reply['operation'], reply['nonce']) != (
                1, operation, nonce):
            raise ExecutorRefusal('launch_authority_reply_invalid')
        return reply['result']

    @staticmethod
    def _decode(result, record):
        if type(result) is not dict:
            raise ExecutorRefusal('launch_authority_reply_invalid')
        fields = dict(result)
        returned = fields.pop('invocation', None)
        _fields(returned, ('profile_identity', 'clock_id', 'plan'), ('service_window',))
        bound = LaunchInvocation(returned['profile_identity'], returned['clock_id'],
                                 LaunchPlan(**returned['plan']), service_window=returned.get('service_window'))
        return record(bound, **fields)

    def authorize(self, invocation, *, deadline_ns):
        result = self._exchange('authorize', invocation, deadline_ns)
        return None if result is None else self._decode(result, LaunchAuthorization)

    def readback(self, invocation, *, deadline_ns):
        result = self._exchange('readback', invocation, deadline_ns)
        return self._decode(result, LaunchReadback)


def _open_protected(path):
    if type(path) is not str or not path.startswith('/') or str(PurePosixPath(path)) != path:
        raise ExecutorRefusal('launch_executable_registration_invalid')
    parts = PurePosixPath(path).parts
    if len(parts) < 2 or '..' in parts:
        raise ExecutorRefusal('launch_executable_registration_invalid')
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as opened:
        parent = os.open('/', directory_flags)
        opened.callback(os.close, parent)
        for part in parts[1:-1]:
            parent = os.open(part, directory_flags, dir_fd=parent)
            opened.callback(os.close, parent)
            managed_cli._safe_directory(parent)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != managed_cli._TRUSTED_UID
            or info.st_mode & 0o6022 or not info.st_mode & 0o111 or info.st_nlink != 1):
        os.close(fd)
        raise ExecutorRefusal('launch_executable_untrusted')
    return fd


def _open_bwrap(resources):
    """Use the exact protected runtime shipped in the platform wheel when present."""
    try:
        _OWNED_BWRAP.lstat()
    except FileNotFoundError:
        if _OWNED_BWRAP.with_name('REQUIRED').exists():
            raise ExecutorRefusal('owned_bubblewrap_unavailable') from None
        program = _open_protected(_BWRAP)
        resources.callback(os.close, program)
    else:
        if sys.platform != 'linux' or os.uname().machine != 'x86_64':
            raise ExecutorRefusal('owned_bubblewrap_platform_unsupported')
        program = _open_protected(str(_OWNED_BWRAP))
        resources.callback(os.close, program)
        with os.fdopen(os.dup(program), 'rb') as payload:
            if file_digest(payload, 'sha256').hexdigest() != _OWNED_BWRAP_SHA256:
                raise ExecutorRefusal('owned_bubblewrap_digest_mismatch')
        os.lseek(program, 0, os.SEEK_SET)
    try:
        os.getxattr(program, 'security.capability')
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
    else:
        raise ExecutorRefusal('launch_executor_bubblewrap_file_capability')
    return program


def _static_elf(fd, size):
    header = os.pread(fd, 64, 0)
    # Linux x86_64 and AArch64 use little-endian ELF64. No interpreter or
    # caller-selectable library mounts are part of this backend.
    if len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01':
        return False
    kind, machine = struct.unpack_from('<HH', header, 16)
    expected_machine = {'x86_64': 62, 'aarch64': 183}.get(os.uname().machine)
    offset, = struct.unpack_from('<Q', header, 32)
    entry_size, count = struct.unpack_from('<HH', header, 54)
    if (kind not in (2, 3) or machine != expected_machine or entry_size != 56
            or not 0 < count < 65535 or not 64 <= offset <= size - entry_size * count):
        return False
    table = os.pread(fd, entry_size * count, offset)
    types = [entry[0] for entry in struct.iter_unpack('<I52x', table)] if len(table) == entry_size * count else []
    return 1 in types and 3 not in types  # PT_LOAD required, PT_INTERP absent.


def _snapshot(path, pin, resources):
    source = _open_protected(path)
    resources.callback(os.close, source)
    worker = os.memfd_create('workeros-approved-worker', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    resources.callback(os.close, worker)
    size = os.fstat(source).st_size
    if not 64 <= size <= _MAX_EXECUTABLE:
        raise ExecutorRefusal('launch_executable_unsupported')
    digest = sha256()
    with os.fdopen(source, 'rb', closefd=False) as input_file, os.fdopen(worker, 'wb', closefd=False) as output:
        remaining = size
        while remaining:
            data = input_file.read(min(remaining, 1024 * 1024))
            if not data:
                raise ExecutorRefusal('launch_executable_changed')
            remaining -= len(data)
            digest.update(data)
            output.write(data)
        if input_file.read(1) or digest.hexdigest() != pin:
            raise ExecutorRefusal('launch_executable_changed')
    fcntl.fcntl(worker, _ADD_SEALS, _REQUIRED_SEALS)
    if fcntl.fcntl(worker, _GET_SEALS) & _REQUIRED_SEALS != _REQUIRED_SEALS:
        raise ExecutorRefusal('launch_executable_sealing_unverified')
    if not _static_elf(worker, size):
        raise ExecutorRefusal('launch_executable_unsupported')
    os.lseek(worker, 0, os.SEEK_SET)
    return worker


def _binding_fd(observer, resources):
    original = observer['original_fd']
    if type(original) is not int or original < 3:
        raise ExecutorRefusal('launch_original_unavailable')
    readable = fcntl.fcntl(original, fcntl.F_GETFL)
    if readable & os.O_PATH or readable & os.O_ACCMODE != os.O_RDONLY:
        raise ExecutorRefusal('launch_original_unavailable')
    held = os.open(f'/proc/self/fd/{original}', os.O_PATH | os.O_CLOEXEC)
    resources.callback(os.close, held)
    info = os.fstat(held)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != managed_cli._TRUSTED_UID
            or info.st_mode & 0o133 or (info.st_dev, info.st_ino) != (observer['device'], observer['inode'])):
        raise ExecutorRefusal('launch_original_unavailable')
    return held


def _sandbox_command(executable, original):
    # These are the entire mount and command surfaces. No host root, procfs,
    # libraries, sockets, caller arguments, or paths are exposed to the worker.
    return [_BWRAP, '--unshare-user', '--unshare-pid', '--unshare-net', '--unshare-ipc',
            '--unshare-uts', '--disable-userns', '--new-session', '--die-with-parent', '--cap-drop', 'ALL',
            '--clearenv', '--chdir', '/', '--perms', '0500', '--ro-bind-data', str(executable),
            '/worker', '--ro-bind-fd', str(original), '/input', '--remount-ro', '/',
            '--', '/worker']


def _read_registration():
    if os.getresuid() != (managed_cli._TRUSTED_UID,) * 3:
        raise ExecutorRefusal('administrator_required')
    try:
        return managed_cli._read_admin_json(_REGISTRATION)
    except FileNotFoundError as exc:
        raise ExecutorRefusal('launch_executor_registration_missing') from exc


def _registration(value=None):
    if value is None:
        value = _read_registration()
    elif os.getresuid() != (managed_cli._TRUSTED_UID,) * 3:
        raise ExecutorRefusal('administrator_required')
    _fields(value, ('version', 'profile', 'revision', 'policy', 'principal_gid', 'executable',
                    'wheel_path', 'wheel_sha256', 'authority'))
    if type(value['version']) is not int or value['version'] != 1:
        raise ExecutorRefusal('launch_executor_registration_invalid')
    _name(value['profile'])
    _name(value['revision'])
    _digest(value['wheel_sha256'])
    raw = value['policy']
    policy = LaunchRolePolicy(**raw)
    _uid(value['principal_gid'])
    if not policy.principal_uid or not value['principal_gid']:
        raise ExecutorRefusal('launch_executor_requires_ordinary_identity')
    peer = value['authority']
    _fields(peer, ('socket', 'uid'))
    return value, policy, _Authority(peer['socket'], peer['uid'], policy)


def _run_pinned_sandbox(command, *, plan, deadline_ns, cleanup_ns, uid, gid, handles):
    """Wait and reap the one owned sandbox child inside an approved budget."""
    active_until = deadline_ns - cleanup_ns
    supervisor = DirectChildSupervisor()
    supervisor.check_available(plan.invocation_key, plan.role)
    if monotonic_ns() >= active_until:
        raise TimeoutError('approved_launch_window_too_short')
    process = subprocess.Popen(
        command, env={}, cwd='/', stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, pass_fds=handles, user=uid, group=gid, extra_groups=[])
    try:
        supervisor.adopt(plan.invocation_key, plan.role, process, uid=uid)
    except BaseException:
        # Before adoption this exact direct child is still our Popen's child.
        if monotonic_ns() < deadline_ns:
            process.kill()
            process.wait(timeout=_remaining(deadline_ns / 1_000_000_000))
        raise
    try:
        result = supervisor.wait(plan.invocation_key, due_ns=active_until, cleanup_due_ns=deadline_ns)
    except BaseException:
        if monotonic_ns() < deadline_ns:
            supervisor.cleanup(plan.invocation_key, due_ns=deadline_ns)
        raise
    if result.lifecycle is not LifecycleStatus.EXITED or monotonic_ns() >= deadline_ns:
        raise TimeoutError('approved_launch_exit_unconfirmed')
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, command)


def _open_sandbox(config, policy, authority, host, resources):
    if (host['profile'], host['revision'], host['wheel_path']) != (
            config['profile'], config['revision'], config['wheel_path']):
        raise ExecutorRefusal('launch_executor_registration_mismatch')
    matching = [item for item in host['scopes'] if item['definition']['name'] == policy.workflow]
    if len(matching) != 1:
        raise ExecutorRefusal('launch_executor_registration_mismatch')
    scope, = matching
    workflow = scope['policy']['workflows'][policy.workflow]
    operations = workflow['operations']
    if (scope['definition']['package_sha256'] != config['wheel_sha256']
            or type(operations) is not list or set(operations) != {'launch', 'observe'}
            or 'observer' not in scope or 'provider' not in scope or 'meter' in scope or 'interval_provider' in scope):
        raise ExecutorRefusal('launch_executor_scope_unsupported')
    account = pwd.getpwnam(policy.principal)
    if (account.pw_uid, account.pw_gid) != (policy.principal_uid, config['principal_gid']):
        raise ExecutorRefusal('launch_executor_principal_changed')
    try:
        program = _open_bwrap(resources)
    except FileNotFoundError as exc:
        raise ExecutorRefusal('launch_executor_bubblewrap_unavailable') from exc
    version = subprocess.run([_BWRAP, '--version'], executable=f'/proc/self/fd/{program}', pass_fds=(program,),
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={},
                             cwd='/', timeout=managed_cli._TIMEOUT, check=True)
    parsed = re.fullmatch(rb'bubblewrap ([0-9]+)\.([0-9]+)\.([0-9]+)\n?', version.stdout)
    if parsed is None or tuple(map(int, parsed.groups())) < (0, 12, 0):
        raise ExecutorRefusal('launch_executor_requires_bubblewrap_0_12')
    executable = _snapshot(config['executable'], policy.executable_sha256, resources)
    original = _binding_fd(scope['observer'], resources)
    cleanup_ns = _budget(workflow['cleanup_ms'], 60_000) if 'cleanup_ms' in workflow else None

    def dispatch(invocation, approval, *, deadline_ns):
        # The locked profile adapter checked the exact role and live bindings
        # and durably reserved this key before requesting the single-use ticket.
        current = pwd.getpwnam(policy.principal)
        if ((current.pw_uid, current.pw_gid) != (account.pw_uid, account.pw_gid)
                or approval.invocation != invocation or invocation.plan.principal_uid != account.pw_uid):
            raise ExecutorRefusal('launch_executor_principal_changed')
        os.lseek(executable, 0, os.SEEK_SET)
        command = _sandbox_command(executable, original)
        command[0] = f'/proc/self/fd/{program}'
        if cleanup_ns is not None:
            _run_pinned_sandbox(command, plan=invocation.plan, deadline_ns=deadline_ns,
                                cleanup_ns=cleanup_ns, uid=account.pw_uid, gid=account.pw_gid,
                                handles=(program, executable, original))
            return
        subprocess.run(command, env={}, cwd='/',
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       pass_fds=(program, executable, original), user=account.pw_uid, group=account.pw_gid,
                       extra_groups=[], timeout=_remaining(deadline_ns / 1_000_000_000), check=True)

    return LaunchRegistration(policy, authority.authorize, dispatch, authority.readback, bounded=True,
                              require_ticket_claim=True)


@contextmanager
def _open_registered_worker(config, policy, authority, host):
    with ExitStack() as resources:
        registration = _open_sandbox(config, policy, authority, host, resources)
        with managed_bootstrap.open_approved_launch(
                registration, executable_argv=('/worker',), config=host, require_launch_resource=True) as adapter:
            yield adapter


@contextmanager
def open_managed_worker(executor_config, *, host_config):
    """Compose the installed ordinary worker with administrator-supplied registrations."""
    from .managed_registration import require_pinned_pair

    if type(executor_config) is not dict or type(host_config) is not dict:
        raise ExecutorRefusal('launch_executor_registration_invalid')
    config, policy, authority = _registration(executor_config)
    pinned = require_pinned_pair(config)
    if pinned is not None:
        if _canonical(host_config) != _canonical(pinned):
            raise ExecutorRefusal('managed_registration_drift')
        host_config = pinned
    with _open_registered_worker(config, policy, authority, host_config) as adapter:
        yield adapter


def _read_only_dispatch(*_args, **_kwargs):
    raise PermissionError('historical_read_only')


def _registered_launch(request_id, workflow, readback):
    try:
        _digest(request_id)
    except ValueError:
        return launch_result('refused', 'not_attempted', 'invalid_launch_request_id')
    if workflow is not None:
        from .managed_service_client import request_service
        return request_service(workflow, request_id, readback=readback)
    from .managed_registration import require_pinned_pair

    entered = False
    try:
        config, policy, authority = _registration()
        host = require_pinned_pair(config, required=not readback, readback=readback)
        if readback:
            verify_install(config['wheel_path'], config['wheel_sha256'])
            registration = LaunchRegistration(policy, authority.authorize, _read_only_dispatch,
                                              authority.readback, bounded=True)
            deadline = monotonic_ns() + int(managed_cli._TIMEOUT * 1_000_000_000)
            return _read_historical_launch(registration, config['profile'], config['revision'], request_id, deadline)
        if host is None:
            raise ExecutorRefusal('managed_registration_unpinned')
        with _open_registered_worker(config, policy, authority, host) as adapter:
            entered = True
            return adapter.launch_approved(request_id=request_id)
    except (OSError, ValueError, TypeError, KeyError, RecordError, VerificationError,
            subprocess.SubprocessError) as exc:
        if entered:
            return launch_result('unknown', 'unknown', 'launch_readback_unconfirmed', request_id=request_id)
        code = 'launch_executor_unavailable'
        if isinstance(exc, ExecutorRefusal) or (
                isinstance(exc, PermissionError) and str(exc) in (
                    'profile_revoked', 'manager_selection_denied', 'role_appointment_unverified',
                    'role_appointment_mismatch', 'commissioned_mapping_mismatch')):
            code = str(exc)
        if readback:
            return launch_result('unknown', 'unknown', code, request_id=request_id)
        return launch_result('refused', 'not_attempted', code)


def registered_launch(request_id, *, workflow=None, readback=False, report=None, revision=None,
                      summary_ids=None, report_default=None, base_dir=None):
    """Resolve one approved invocation and optionally export a caller-owned result copy."""
    from .result_export import RESULT_VERSION, can_export, default_report_path, export_report, report_path

    try:
        _digest(request_id)
    except ValueError:
        return {'version': RESULT_VERSION,
                **launch_result('refused', 'not_attempted', 'invalid_launch_request_id')}
    try:
        if workflow is not None:
            _name(workflow)
        if revision is not None:
            _name(revision)
            if not readback or workflow is None:
                raise ValueError('history needs a named readback')
        if summary_ids is not None:
            if revision is None or type(summary_ids) not in (list, tuple):
                raise ValueError('summary needs exact history')
            for identifier in summary_ids:
                _digest(identifier)
        destination = None
        if report is not None:
            destination = report_path(report)
        elif report_default is not None:
            destination = default_report_path(report_default, base_dir)
    except (TypeError, ValueError) as exc:
        code = ('invalid_report_destination' if str(exc) == 'invalid_report_destination'
                else 'invalid_service_request')
        return {'version': RESULT_VERSION, 'request_id': request_id,
                **launch_result('refused', 'not_attempted', code)}
    result = {'version': RESULT_VERSION, 'request_id': request_id}
    if workflow is not None:
        result['workflow'] = workflow
    if destination is not None and not can_export():
        return {**result, **launch_result('refused', 'not_attempted', 'unprivileged_report_caller_required')}
    if revision is None:
        result.update(_registered_launch(request_id, workflow, readback))
    else:
        from .managed_service_client import request_service

        result.update(request_service(workflow, request_id, readback=True, revision=revision,
                                      summary_ids=summary_ids))
    next_action = {'operation': 'launch-status', 'request_id': request_id}
    if workflow is not None:
        next_action['workflow'] = workflow
    if revision is not None:
        next_action['revision'] = revision
    if summary_ids is not None:
        next_action['summary_ids'] = list(summary_ids)
    if result['status'] == 'unknown':
        result['next_action'] = next_action
    if destination is not None:
        export = export_report(destination, result)
        if export['status'] != 'written':
            export['next_action'] = next_action
        result['export'] = export
    return result


class _LaunchArguments(argparse.ArgumentParser):
    def error(self, message):
        raise ExecutorRefusal('invalid_launch_request')


def main(operation, argv):
    from .result_export import RESULT_VERSION, can_export

    parser = _LaunchArguments(
        prog=f'workeros managed {operation}',
        description='Use one administrator-approved invocation. A report is a caller-owned copy.',
    )
    request = parser.add_mutually_exclusive_group(required=True)
    request.add_argument('--request-id', help='Retained opaque request ID')
    request.add_argument('--format', choices=('json', 'yaml'),
                         help='Read version, request_id and optional workflow and report from standard input')
    parser.add_argument('--workflow', help='Select an approved managed service workflow')
    if operation == 'launch-status':
        parser.add_argument('--revision', help='Read an authorized archived result for this exact revision')
        parser.add_argument('--summary-id', action='append', metavar='ID',
                            help='Count another authorized archived request in the same scope')
    parser.add_argument('--report', metavar='FILE', help='Write a copy to a new file as the unprivileged caller')
    parser.add_argument('--input', metavar='FILE', help='Read the JSON or YAML request from this file')
    workflow = None
    revision = None
    summary_ids = None
    try:
        args = parser.parse_args(argv)
        identifier = args.request_id
        workflow = args.workflow
        revision = getattr(args, 'revision', None)
        summary_ids = getattr(args, 'summary_id', None)
        report = args.report
        report_default = base_dir = None
        if args.input is not None and args.format is None:
            raise ExecutorRefusal('invalid_launch_request')
        if args.format is not None:
            if args.input is not None:
                try:
                    document_path = Path(args.input).absolute()
                    if not can_export():
                        raise PermissionError('caller-owned document required')
                    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                    with os.fdopen(os.open(document_path, flags), 'rb') as source:
                        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                            raise ValueError('regular document required')
                        data = source.read(managed_cli._LIMIT + 1)
                except (OSError, ValueError):
                    raise ExecutorRefusal('launch_document_unavailable') from None
                base_dir = document_path.parent
            else:
                data = sys.stdin.buffer.read(managed_cli._LIMIT + 1)
            if len(data) > managed_cli._LIMIT:
                raise ExecutorRefusal('document_too_large')
            if args.format == 'yaml':
                from .cli import InputError, _yaml_to_json
                try:
                    data = _yaml_to_json(data)
                except InputError as exc:
                    raise ExecutorRefusal(str(exc)) from None
            document = managed_cli.decode_policy(data)
            optional = ('workflow', 'report', 'report_default', 'base_dir')
            if operation == 'launch-status':
                optional += ('revision', 'summary_ids')
            _fields(document, ('version', 'request_id'), optional)
            if type(document['version']) is not int or document['version'] != 1:
                raise ExecutorRefusal('invalid_launch_request')
            if workflow is not None:
                raise ExecutorRefusal('invalid_launch_request')
            identifier = document['request_id']
            workflow = document.get('workflow')
            if 'workflow' in document:
                _name(workflow)
            if 'revision' in document:
                _name(document['revision'])
                if revision is not None:
                    raise ExecutorRefusal('invalid_launch_request')
                revision = document['revision']
            if 'summary_ids' in document:
                if summary_ids is not None or type(document['summary_ids']) is not list:
                    raise ExecutorRefusal('invalid_launch_request')
                summary_ids = document['summary_ids']
            if report is None and 'report' in document:
                if type(document['report']) is not str:
                    raise ExecutorRefusal('invalid_report_destination')
                report = document['report']
            if 'base_dir' in document:
                if base_dir is not None or type(document['base_dir']) is not str:
                    raise ExecutorRefusal('invalid_report_destination')
                base_dir = document['base_dir']
            if 'report_default' in document:
                if type(document['report_default']) is not str:
                    raise ExecutorRefusal('invalid_report_destination')
                report_default = document['report_default']
        result = registered_launch(identifier, workflow=workflow, readback=operation == 'launch-status',
                                   report=report, revision=revision, summary_ids=summary_ids,
                                   report_default=report_default, base_dir=base_dir)
    except ValueError as exc:
        code = str(exc) if isinstance(exc, ExecutorRefusal) else 'invalid_launch_request'
        result = {'version': RESULT_VERSION, **launch_result('refused', 'not_attempted', code)}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    export_failed = result.get('export', {}).get('status') in ('failed', 'unknown')
    if (export_failed or (operation == 'run-approved' and result['status'] == 'unknown')) and 'request_id' in result:
        followup = ['workeros', 'managed', 'launch-status']
        if workflow is not None:
            followup.extend(('--workflow', workflow))
        if revision is not None:
            followup.extend(('--revision', revision))
        for identifier in summary_ids or ():
            followup.extend(('--summary-id', identifier))
        followup.extend(('--request-id', result['request_id']))
        if export_failed:
            print('Report export did not complete. Read the same request and add --report with a new destination: '
                  + shlex.join(followup), file=sys.stderr)
        else:
            print('Launch result unconfirmed. Read this request without resubmitting: '
                  + shlex.join(followup), file=sys.stderr)
    return 0 if not export_failed and result['status'] in ('started', 'terminal', 'not_started') else 1
