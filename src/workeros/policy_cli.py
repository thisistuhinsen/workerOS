"""Local operator bindings for the installed policy controller."""

from contextlib import ExitStack, contextmanager
import ctypes
from dataclasses import asdict
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import stat
from subprocess import TimeoutExpired
from time import monotonic_ns
from uuid import uuid4

from .configuration import ConfigurationError, _clean, _identifier, _require, _serve_isolated, _terminal
from .enrollment import HostBindings, ProjectedEvidence, compile_policy, decode_policy
from .original import observe
from .recording import LocalStore, Persistence, RecordError, RecordKey


_SUPPORTED = frozenset(("launch", "record", "readback", "verify_durable", "recover_receipt", "purge", "sweep"))
_LAUNCH_RECORD = "launch-terminal"
_ATTEMPT_FIELDS = ("attempt_id", "worker_name", "workflow", "policy_sha256")


def _add(registry, name, binding):
    _identifier(name)
    _require(name not in registry, "duplicate_host_binding")
    registry[name] = binding


def _absolute(value):
    path = Path(value)
    _require(path.is_absolute(), "host_binding_requires_absolute_path")
    return path


def _fd(value, owned, *, regular=True):
    _require(re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None, "invalid_host_descriptor")
    fd = int(value)
    _require(3 <= fd < 2**31, "invalid_host_descriptor")
    clone = os.dup(fd)
    owned.callback(os.close, clone)
    if regular:
        info = observe(clone)
        mode = info.flags & os.O_ACCMODE
        _require(stat.S_ISREG(info.mode) and not info.flags & os.O_PATH
                 and mode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR)
                 and (mode == os.O_RDONLY or info.owner_uid == os.getuid()), "invalid_host_descriptor")
    return clone


def _projection(request, result):
    terminal = result.get("terminal")
    if terminal is None:
        raise ValueError("terminal result unavailable")
    value = {"lifecycle": terminal["lifecycle"], "returncode": terminal["returncode"],
             "cleanup": terminal["cleanup"]["status"], **{key: result[key] for key in _ATTEMPT_FIELDS}}
    attempt_id = value["attempt_id"]
    source = "direct-child-supervisor" if request.options.get("supervise") else "owned-child-wait"
    return ProjectedEvidence(RecordKey(attempt_id, _LAUNCH_RECORD), json.dumps(value, sort_keys=True).encode(),
                             source=source, scope=attempt_id)


def _recover(recorder, destination, attempt_id, workflow, policy_sha256):
    _require(re.fullmatch(r"attempt-[0-9a-f]{32}", attempt_id) is not None, "invalid_attempt_id")
    entry = recorder.lookup(destination, RecordKey(attempt_id, _LAUNCH_RECORD))
    if entry.payload is None:
        raise RecordError(Persistence.PURGED)
    try:
        event = json.loads(entry.payload)
        matches = (type(event) is dict and event.get("attempt_id") == attempt_id
                   and event.get("workflow") == workflow and event.get("policy_sha256") == policy_sha256
                   and entry.receipt.scope == attempt_id
                   and entry.receipt.source in ("direct-child-supervisor", "owned-child-wait"))
    except (ValueError, RecursionError):
        matches = False
    if not matches:
        raise RecordError(Persistence.CONFLICT)
    return {"persistence": "verified", "durability": "unconfirmed", "receipt": asdict(entry.receipt)}


class _LocalDestination(LocalStore):
    """Create only the explicitly enrolled ordinary leaf, on first commit."""

    @contextmanager
    def _held_parent(self):
        try:
            if not self.directory.name:
                raise ValueError("store requires an enrolled leaf directory")
            parent = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except (OSError, ValueError) as exc:
            raise RecordError(Persistence.REFUSED) from exc
        try:
            yield parent
        finally:
            os.close(parent)

    def _check_local(self, policy, *, write):
        with self._held_parent() as parent:
            try:
                os.stat(self.directory.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if (policy.group_id is not None or os.geteuid() != self.owner_uid
                        or not os.access(".", os.W_OK | os.X_OK, dir_fd=parent, effective_ids=True)):
                    raise RecordError(Persistence.REFUSED) from None
                return True
            with self._open(policy, write=write, lock=False, _parent_fd=parent) as directory:
                if write and not os.access(".", os.W_OK | os.X_OK, dir_fd=directory, effective_ids=True):
                    raise RecordError(Persistence.REFUSED)
                return True

    def check_policy(self, policy):
        return self._check_local(policy, write=False)

    def check_writable(self, policy):
        return self._check_local(policy, write=True)

    @staticmethod
    def _sync_parent(parent):
        try:
            os.fsync(parent)
        except OSError as exc:
            raise RecordError(Persistence.UNKNOWN) from exc

    def commit(self, receipt, payload, *, policy):
        with self._held_parent() as parent:
            try:
                os.mkdir(self.directory.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            except OSError as exc:
                raise RecordError(Persistence.REFUSED) from exc
            # Sync the same parent used to resolve the leaf before publishing a record.
            # A retry over an already-visible leaf repeats this sync.
            self._sync_parent(parent)
            return super().commit(receipt, payload, policy=policy, _parent_fd=parent)

    def verify_durable(self, expected, *, policy):
        with self._held_parent() as parent:
            payload = super().verify_durable(expected, policy=policy, _parent_fd=parent)
            self._sync_parent(parent)
            return payload


def _bindings(args, owned):
    tools, stores, inherited = {}, {}, {}
    directories, environment, streams = {}, {}, {}

    for name, location in args.executable:
        path = _absolute(location)
        mode = path.stat().st_mode
        _require(stat.S_ISREG(mode) and not mode & (stat.S_ISUID | stat.S_ISGID)
                 and os.access(path, os.X_OK), "invalid_executable_binding")
        _add(tools, name, (str(path),))
    for name, location in args.store:
        _add(stores, name, _LocalDestination(_absolute(location)))
    for name, location, group in args.group_store:
        _require(re.fullmatch(r"0|[1-9][0-9]{0,9}", group) is not None and int(group) <= 2**31 - 1,
                 "invalid_group_binding")
        _add(stores, name, LocalStore(_absolute(location), group_id=int(group)))
    for name, value in args.inherit_fd:
        _add(inherited, name, _fd(value, owned))
    for name, location in args.cwd:
        path = _absolute(location)
        _require(path.is_dir(), "invalid_working_directory_binding")
        _add(directories, name, str(path))
    for name, value in args.env:
        _add(environment, name, value)
    for name, variable in args.secret_env:
        _require(variable in os.environ, "secret_environment_binding_missing")
        _add(environment, name, os.environ[variable])
    for name, value in args.stream_fd:
        _add(streams, name, _fd(value, owned, regular=False))
    settled = frozenset(_identifier(name) for name in args.settled_run)
    return HostBindings(
        executables=tools, stores=stores, inherited=inherited, supervisors=frozenset(("direct-child",)),
        # The trusted operator supplies the policy and the local registrations.
        authorize=lambda request: True,
        settled=(lambda receipt: receipt.key.run_id in settled) if settled else None,
        projectors={"launch-terminal": _projection},
        directories=directories, environment=environment, streams=streams,
    )


def _ordinary_process():
    _require(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(),
             "privileged_policy_cli_unsupported")
    # This process and its children cannot acquire privilege by exec, including via
    # a set-ID executable or file capability used transitively by the enrolled tool.
    try:
        prctl = ctypes.CDLL(None).prctl
        prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
        prctl.restype = ctypes.c_int
        _require(prctl(38, 1, 0, 0, 0) == 0, "ordinary_launch_unavailable")  # PR_SET_NO_NEW_PRIVS
    except AttributeError as exc:
        raise ConfigurationError("ordinary_launch_unavailable") from exc


def _reconcile_unpinned(process, deadline, *, lifecycle="unknown"):
    killed = False
    try:
        if process.poll() is None and monotonic_ns() < deadline:
            process.kill()
            killed = True
        code = process.wait(timeout=max(0, deadline - monotonic_ns()) / 1_000_000_000)
        state = "reaped"
    except TimeoutExpired:
        code, state = None, "pending"
    except OSError:
        code, state = None, "unknown"
    return {"lifecycle": lifecycle, "returncode": code, "error": lifecycle == "unknown",
            "cleanup": {"status": state, "returncode": code,
                        "terminate_sent": False, "kill_sent": killed, "error": state == "unknown"}}


def _wait_basic(process, deadline, cleanup_deadline):
    try:
        code = process.wait(timeout=max(0, deadline - monotonic_ns()) / 1_000_000_000)
    except TimeoutExpired:
        return _reconcile_unpinned(process, cleanup_deadline, lifecycle="timed_out")
    except BaseException:
        _reconcile_unpinned(process, cleanup_deadline)
        raise
    return {"lifecycle": "exited", "returncode": code, "error": False,
            "cleanup": {"status": "reaped", "returncode": code,
                        "terminate_sent": False, "kill_sent": False, "error": False}}


def _finish_launch(policy, request, result, deadline):
    if request.operation != "launch":
        return result
    workflow = policy[request.workflow]
    name = request.options["name"]
    process = workflow.unadopted.get(name)
    if process is not None:
        terminal = _reconcile_unpinned(process, workflow.cleanup_deadline_ns)
    elif not request.options.get("supervise", False):
        terminal = _wait_basic(workflow.roster.owned(name), deadline, workflow.cleanup_deadline_ns)
    else:
        try:
            wait = workflow.supervisor.wait(name, due_ns=deadline, cleanup_due_ns=workflow.cleanup_deadline_ns)
        except BaseException:
            workflow.supervisor.cleanup(name, due_ns=workflow.cleanup_deadline_ns)
            raise
        terminal = _terminal(wait)
        if terminal["cleanup"]["status"] == "not_requested":
            terminal["cleanup"] = _clean(workflow.supervisor.cleanup(name, due_ns=workflow.cleanup_deadline_ns))
    return {**result, "terminal": terminal}


def _invoke(policy, request, digest, events):
    deadline = None
    attempt = None
    if request.operation == "record":
        _require(request.options["record_id"] != _LAUNCH_RECORD, "reserved_launch_record_id")
    if request.operation == "recover_receipt" and request.workflow in policy:
        workflow = policy[request.workflow]
        workflow.recover_receipt = lambda name, key: _recover(workflow.recorder, name, key, request.workflow, digest)
    if request.operation == "launch" and request.workflow in policy:
        workflow = policy[request.workflow]
        attempt = {"attempt_id": "attempt-" + uuid4().hex, "worker_name": request.options["name"],
                   "workflow": request.workflow, "policy_sha256": digest}
        deadline = workflow.deadline_ns
        if "timeout_ms" in request.options:
            deadline = min(deadline, monotonic_ns() + request.options["timeout_ms"] * 1_000_000)
        # One absolute budget spans dispatch and wait, even when clients shorten it.
        cleanup_budget = workflow.cleanup_deadline_ns - workflow.deadline_ns
        workflow.deadline_ns = deadline
        workflow.cleanup_deadline_ns = deadline + cleanup_budget
    def finish(req, result):
        result = _finish_launch(policy, req, result, deadline)
        return {**result, **attempt} if attempt is not None else result

    def announce_capture():
        try:
            message = (json.dumps({"event": "launch_attempt", **attempt}) + "\n").encode()
            if os.write(events, message) != len(message):
                raise OSError("short attempt announcement")
        except OSError as exc:
            raise ConfigurationError("attempt_announcement_unavailable") from exc

    return policy.execute(request, finish=finish, announce_capture=announce_capture)


def run_policy_cli(args):
    try:
        with ExitStack() as owned:
            path = args.check_policy or args.run_policy
            with path.open("rb") as source:
                data = source.read(1_048_577)
            _require(len(data) <= 1_048_576, "policy_too_large")
            digest = sha256(data).hexdigest()
            if args.policy_sha256 is not None:
                expected = args.policy_sha256
                _require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid_policy_digest")
                _require(hmac.compare_digest(digest, expected), "policy_digest_mismatch")
            if args.format == "yaml":
                from .cli import InputError, _yaml_to_json

                # Pin the original policy bytes. Normalize only the compiler input.
                try:
                    data = _yaml_to_json(data)
                except InputError as exc:
                    raise ConfigurationError(str(exc)) from None
            document = decode_policy(data)
            policy = compile_policy(document, _bindings(args, owned), workflow=args.workflow)
            for workflow in policy.values():
                _require(workflow.operations <= _SUPPORTED, "installed_operation_unsupported")
                if "launch" in workflow.operations and workflow.cleanup_deadline_ns is None:
                    workflow.cleanup_deadline_ns = workflow.deadline_ns + 2_000_000_000
            if args.check_policy:
                response = {"status": "checked", "policy_sha256": digest, "workflows": sorted(policy)}
                if args.explain:
                    response["effective"] = {
                        name: {
                            "role": workflow.role, "operations": sorted(workflow.operations),
                            "timeout_ms": document["workflows"][name].get("timeout_ms", 30_000),
                            "cleanup_ms": document["workflows"][name].get(
                                "cleanup_ms", 2000 if "launch" in workflow.operations else None),
                            "require_supervision": workflow.require_supervision,
                            "require_custody": workflow.require_custody,
                            "bindings": document["workflows"][name]["bindings"],
                        }
                        for name, workflow in policy.items()
                    }
                print(json.dumps(response, sort_keys=True))
                return 0
            _require(not args.explain, "explain_requires_check_policy")
            _ordinary_process()
            events = os.dup(2)
            owned.callback(os.close, events)
            return _serve_isolated(lambda request: _invoke(policy, request, digest, events),
                                   reported_exit=_reported_exit, policy_sha256=digest)
    except (OSError, ValueError, OverflowError) as exc:
        code = str(exc) if type(exc) is ConfigurationError else "invalid_host_policy_binding"
        reply = {"status": "refused", "code": code}
        if getattr(exc, "path", None):
            reply["path"] = exc.path
        print(json.dumps(reply))
        return 1


def _reported_exit(request, result):
    operation = request.operation
    if operation == "launch":
        terminal = result["terminal"]
        if (terminal["lifecycle"] != "exited" or terminal["returncode"] != 0
                or terminal["cleanup"]["status"] != "reaped"
                or result.get("capture", {}).get("required_complete") is False):
            return 3
    if operation == "record" and not result["required_complete"]:
        return 3
    if operation in ("readback", "verify_durable", "recover_receipt") and result["persistence"] != "verified":
        return 3
    if operation == "purge" and "persistence" in result:
        return 3
    if operation == "sweep" and any(entry["persistence"] is not None for entry in result.get("sweep", [])):
        return 3
    if operation == "sweep" and "persistence" in result:
        return 3
    return 0
