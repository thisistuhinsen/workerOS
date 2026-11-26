"""One ordinary reader for an administrator-bound serial qualification."""

import argparse
from array import array
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import fcntl
import grp
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import pwd
import re
import select
import shutil
import signal
import socket
from stat import S_ISREG
import struct
import subprocess
import sys
from time import monotonic_ns, sleep
from uuid import uuid4

# The ordinary role processes import the pinned runtime after offline staging.
if __name__ != "__main__" or sys.argv[1:2] != ["commission"]:
    from worker_handoff import (
        CleanupStatus, DeliveryStatus, DirectChildSupervisor, EffectStatus, Identity,
        IndependentCustody, LifecycleStatus, Original, ReleasePlan, observe, release_executable,
    )
    from worker_handoff.evidence import EvidenceScope, EvidenceState, RunBinding, ScopePhase
    from worker_handoff.scope_meter import (
        CgroupSample, CgroupScopeMeter, ScopeMeterUnavailable, cpu_delta_usec, monotonic_clock_id,
    )


FIXTURE = b"workerOS serial fixture\n"
WHEEL = "worker_handoff-0.5.0-py3-none-any.whl"
WHEEL_SHA256 = "04261c977863c4c467856e2696cb470286d2f5c3d87ab9598cfad1f05e1ff1b1"
RUN = re.compile(r"[0-9a-f]{32}")
DIGEST = re.compile(r"[0-9a-f]{64}")
SECOND = 1_000_000_000
MAX_PACKET = 8192
MAX_SCOPE_EVENTS = 4096
MAX_PROVIDER_DIAGNOSTIC = 4096
PROVIDER_REASONS = frozenset({
    "controller_peer_mismatch", "custody_binding_invalid", "custody_recipient_mismatch",
    "custody_request_invalid", "custody_retirement_invalid", "expired_attempt",
    "fixture_packet_eof", "fixture_packet_invalid", "fixture_packet_peer_mismatch",
    "fixture_seed_incomplete", "input_or_execution_unavailable", "meter_phase_invalid",
    "meter_scope_identity_mismatch", "meter_scope_local_view_unavailable",
    "meter_scope_mount_context_unavailable", "meter_scope_mount_not_visible",
    "ordinary_provider_required", "provider_outside_fixture_unit", "reader_role_not_distinct",
})
CREDS = struct.Struct("=iII")
PROTOCOL = "worker-handoff-custody/1"
APPROVAL = b"worker-handoff-custody/1 pregrant provenance grants exclusion "
SYSTEMCTL = "/usr/bin/systemctl"
BUSCTL = "/usr/bin/busctl"
BUS_NAME = "org.freedesktop.systemd1"
BUS_PATH = "/org/freedesktop/systemd1"
UNIT_PATH = re.compile(r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+")
JOB_PATH = re.compile(r"/org/freedesktop/systemd1/job/[1-9][0-9]*")
MANAGER_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
SLICE_PROPERTIES = (
    ("CPUAccounting", "b", "true"), ("MemoryAccounting", "b", "true"),
    ("TasksAccounting", "b", "true"), ("CPUQuotaPerSecUSec", "t", "100000"),
    ("MemoryMax", "t", str(64 * 1024 * 1024)), ("TasksMax", "t", "4"),
    ("CollectMode", "s", "inactive-or-failed"),
)
SERVICE_PROPERTIES = (
    "DynamicUser=yes", "Restart=no", "RuntimeMaxSec=25s", "TimeoutStopSec=2s",
    "KillMode=control-group", "CollectMode=inactive-or-failed", "NoNewPrivileges=yes",
    "CapabilityBoundingSet=", "ProtectHome=yes", "ProtectSystem=strict",
    "ProtectControlGroups=yes", "PrivateTmp=yes", "ProtectProc=invisible",
    "RestrictAddressFamilies=AF_UNIX", "LimitCORE=0", "Nice=10", "CPUQuota=10%",
    "MemoryMax=64M", "TasksMax=4",
)


class Refused(RuntimeError):
    """The fixture did not establish its required input or outcome."""


class ProviderFailure(Refused):
    def __init__(self, role, phase, reason, returncode, child_reason, stderr_present):
        super().__init__(reason)
        self.diagnostic = {
            "status": "fixture_provider_failure", "role": role, "phase": phase,
            "reason": reason, "returncode": returncode, "provider_reason": child_reason,
            "provider_stderr_present": stderr_present,
        }


def expect(condition, reason):
    if not condition:
        raise Refused(reason)


def report(result):
    print(json.dumps(result, sort_keys=True), flush=True)


def slice_name(run_id):
    expect(type(run_id) is str and RUN.fullmatch(run_id), "invalid_run_id")
    return "workerosq" + run_id + ".slice"


def role_unit(run_id, role):
    expect(role in ("reader", "custodian", "meter"), "invalid_role")
    return slice_name(run_id).removesuffix(".slice") + "-" + role + ".service"


def role_user(run_id, role):
    return "wq" + run_id[:24] + role[0]


def role_scope(run_id, role):
    return "/" + role_slice(run_id, role) + "/" + role_unit(run_id, role)


def role_slice(run_id, role):
    return slice_name(run_id) if role == "reader" else "workerosaux" + run_id + ".slice"


def custody_address(run_id):
    return "\0" + slice_name(run_id).removesuffix(".slice") + "-custody"


def plan_for(run_id, device, inode, due_ns):
    expect(RUN.fullmatch(run_id) is not None, "invalid_run_id")
    expect(0 <= device < 1 << 64 and 0 < inode < 1 << 64, "invalid_original_identity")
    expect(0 < due_ns < 1 << 63, "invalid_deadline")
    argv = (sys.executable, "-I", "-B", str(Path(__file__).resolve()), "read", run_id)
    return ReleasePlan(run_id, "serial-reader", argv, Identity(device, inode), due_ns)


def read_original(run_id):
    """A successful child exit requires exact content, EOF and owned FD close."""
    expect(Path("/proc/self/cgroup").read_text().strip() == "0::" + role_scope(run_id, "reader"),
           "worker_outside_fixture_scope")
    expect(os.environ.get("WORKER_HANDOFF_ABI") == "1", "invalid_fd_abi")
    fd = int(os.environ["WORKER_HANDOFF_FD_INPUT"])
    due = int(os.environ["WORKER_HANDOFF_DEADLINE_NS"])
    expect(fd >= 3, "invalid_input_fd")
    # The exec ABI makes the descriptor inheritable at entry. Adopt it before reading.
    os.set_inheritable(fd, False)
    identity = Identity(int(os.environ["WORKER_HANDOFF_DEV_INPUT"]), int(os.environ["WORKER_HANDOFF_INO_INPUT"]))
    with Original(fd, identity) as original:
        sink = BytesIO()
        original.read_and_close(sink, expected_size=len(FIXTURE), due_ns=due)
    expect(sink.getvalue() == FIXTURE, "unexpected_fixture_content")


def run(plan, observer_pid, observer_uid):
    started_ns = monotonic_ns()
    expect(os.getresuid() == (os.getuid(),) * 3 and os.getuid() != 0, "ordinary_release_role_required")
    expect(0 < observer_uid < (1 << 32) - 1 and observer_uid != os.getuid(), "independent_role_required")
    expect(0 < observer_pid < 1 << 31 and observer_pid != os.getpid(), "invalid_observer_pin")
    expect(0 < plan.due_ns - started_ns <= 10 * SECOND, "expired_or_unbounded_attempt")
    expect(Path("/proc/self/cgroup").read_text().strip() == "0::" + role_scope(plan.name, "reader"),
           "release_outside_fixture_scope")
    invocation = os.environ.get("INVOCATION_ID", "")
    expect(RUN.fullmatch(invocation) is not None, "missing_manager_invocation")
    clock = monotonic_clock_id()
    expect(clock is not None, "missing_clock")

    supervisor = DirectChildSupervisor()
    with ExitStack() as stack:
        # The administrator's launcher places only the pre-granted original on stdin.
        fd = fcntl.fcntl(0, fcntl.F_DUPFD_CLOEXEC, 3)
        stack.callback(os.close, fd)
        # The child must not inherit a second copy accidentally on its standard input.
        with open(os.devnull, "rb") as empty:
            os.dup2(empty.fileno(), 0)
        slot = observe(fd)
        expect(slot.identity == plan.identity and slot.size == len(FIXTURE), "wrong_original")
        expect(fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY,
               "original_not_read_only")
        try:
            seals = required_seals()
            observed_seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        except AttributeError:
            raise Refused("kernel_seal_interface_unavailable") from None
        expect(observed_seals & seals == seals, "original_not_sealed")

        channel = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
        remaining = plan.due_ns - monotonic_ns()
        expect(remaining > 0, "expired_attempt")
        report({"status": "reader_ready", "pid": os.getpid(), "uid": os.getuid(),
                "invocation_id": invocation, "plan_digest": plan.custody_scope})
        channel.settimeout(remaining / SECOND)
        channel.connect(custody_address(plan.name))
        with IndependentCustody(channel, observer_pid=observer_pid, observer_uid=observer_uid) as custody:
            result = release_executable(
                plan, input_fd=fd, authorize=lambda candidate: candidate == plan,
                supervisor=supervisor, strict_custody=True, custody=custody,
                cleanup_due_ns=plan.due_ns + 2 * SECOND,
            )
        if result.worker is not None and result.worker.process is not None:
            # This exceptional path returns the actual launch handle without an adopted pin.
            child = result.worker.process
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            raise Refused("launch_reconciled_unknown")
        if result.worker is not None:
            cleanup = supervisor.cleanup(plan.name, due_ns=monotonic_ns() + 2 * SECOND)
        else:
            cleanup = None
        if not (result.delivery is DeliveryStatus.DISPATCHED and result.effect is EffectStatus.NOT_ATTEMPTED
                and result.custody is not None and not result.error and not result.cleanup and result.lifecycle
                and result.lifecycle.lifecycle is LifecycleStatus.EXITED and result.lifecycle.returncode == 0
                and cleanup is not None and cleanup.status is CleanupStatus.REAPED and cleanup.returncode == 0):
            return {"status": "unverified", "reason": "release_or_terminal_evidence_incomplete",
                    "delivery": result.delivery.value}
        reaped_ns = monotonic_ns()
        receipt = asdict(result.custody)

    return {
        "status": "read_reaped_handles_closed", "run_id": plan.name, "plan_digest": plan.custody_scope,
        "invocation_id": invocation, "release_uid": os.getuid(),
        "worker_pid": result.worker.pid,
        "clock_id": clock, "run_started_ns": started_ns, "reaped_ns": reaped_ns,
        "handles_closed_ns": monotonic_ns(), "custody": receipt,
    }


def verify_meter(plan, reader, begin, end, meter_pid, meter_uid):
    """Join authenticated venue inputs structurally, without issuing authority."""
    expect(type(reader) is dict and reader.get("status") == "read_reaped_handles_closed"
           and reader.get("run_id") == plan.name and reader.get("plan_digest") == plan.custody_scope,
           "reader_receipt_mismatch")
    expected = (meter_pid, meter_uid)
    expect(0 < meter_pid < 1 << 31 and 0 < meter_uid < (1 << 32) - 1,
           "invalid_meter_pin")
    expect((begin.meter_pid, begin.meter_uid) == (end.meter_pid, end.meter_uid) == expected,
           "meter_pin_mismatch")
    expect(begin.scope.run.run_id == plan.name and begin.scope.run.artifact_id == plan.custody_scope
           and begin.clock_id == end.clock_id == reader.get("clock_id"),
           "meter_run_or_clock_mismatch")
    custody = reader["custody"]
    expect(custody["scope"] == plan.custody_scope and custody["identity"] == asdict(plan.identity)
           and custody["operation"] == "inherit-input" and custody["recipient"] is None
           and custody["due_ns"] == plan.due_ns and DIGEST.fullmatch(custody["request_digest"])
           and RUN.fullmatch(reader["invocation_id"]), "custody_or_manager_receipt_mismatch")
    roles = (reader["release_uid"], custody["observer_uid"], meter_uid)
    expect(len(set(roles)) == 3 and all(type(uid) is int and 0 < uid < (1 << 32) - 1 for uid in roles),
           "provider_roles_overlap")
    expect(0 <= reader["run_started_ns"] <= reader["reaped_ns"] <= reader["handles_closed_ns"],
           "reader_terminal_order_invalid")
    expect(reader["run_started_ns"] <= custody["attested_ns"] <= reader["reaped_ns"]
           and custody["attested_ns"] < plan.due_ns, "custody_receipt_order_invalid")
    for sample in (begin, end):
        expect(sample.population_state is EvidenceState.OBSERVED and sample.populated is False,
               "scope_emptiness_unavailable")
        expect(sample.memory_current_state is EvidenceState.OBSERVED
               and sample.memory_peak_state is EvidenceState.OBSERVED, "required_memory_unavailable")
    delta = cpu_delta_usec(begin, end, require_meter_for=(reader["run_started_ns"], reader["handles_closed_ns"]))
    expect(end.memory_peak_bytes >= begin.memory_peak_bytes, "memory_peak_regressed")
    return {"status": "serial_receipts_consistent", "cpu_delta_usec": delta,
            "memory_current_bytes": end.memory_current_bytes, "memory_peak_bytes": end.memory_peak_bytes,
            "venue_retirement_required": True}


def required_seals():
    return fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def peer(channel):
    return CREDS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, CREDS.size))[:2]


def send_packet(channel, record, fd=None):
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("ascii")
    expect(len(payload) <= MAX_PACKET, "fixture_packet_too_large")
    ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [fd]))]
    expect(channel.sendmsg([payload], ancillary) == len(payload), "fixture_packet_truncated")


def receive_packet(channel, expected=None, *, with_fd=False):
    payload, messages, flags, _ = channel.recvmsg(
        MAX_PACKET, socket.CMSG_SPACE(CREDS.size) + socket.CMSG_SPACE(array("i").itemsize),
        socket.MSG_CMSG_CLOEXEC,
    )
    if not payload and not messages and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise Refused("fixture_packet_eof")
    fds, credentials = [], []
    valid = True
    try:
        for level, kind, data in messages:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                values = array("i")
                values.frombytes(data[:len(data) // values.itemsize * values.itemsize])
                fds.extend(values)
                valid &= len(data) == values.itemsize
            elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and len(data) == CREDS.size:
                credentials.append(CREDS.unpack(data)[:2])
            else:
                valid = False
        expect(valid and payload and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
               and len(credentials) == 1 and len(fds) == int(with_fd), "fixture_packet_invalid")
        authenticated = credentials[0]
        expect(expected is None or expected == authenticated, "fixture_packet_peer_mismatch")
        record = json.loads(payload)
        expect(type(record) is dict, "fixture_packet_invalid")
        return record, authenticated, fds.pop() if with_fd else None
    finally:
        for fd in fds:
            os.close(fd)


def role_channel(run_id, role, controller_pid):
    expect(os.getuid() != 0 and os.getresuid() == (os.getuid(),) * 3, "ordinary_provider_required")
    expect(Path("/proc/self/cgroup").read_text().strip() == "0::" + role_scope(run_id, role),
           "provider_outside_fixture_unit")
    control = socket.socket(fileno=fcntl.fcntl(0, fcntl.F_DUPFD_CLOEXEC, 3))
    try:
        expect(peer(control) == (controller_pid, 0), "controller_peer_mismatch")
        control.settimeout(18)
        return control
    except BaseException:
        control.close()
        raise


def sealed_fixture():
    """Create one fresh original and retire the only writable open description."""
    writer = os.memfd_create("workeros-serial-fixture", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        expect(os.write(writer, FIXTURE) == len(FIXTURE), "fixture_seed_incomplete")
        fcntl.fcntl(writer, fcntl.F_ADD_SEALS, required_seals())
        return os.open(f"/proc/self/fd/{writer}", os.O_RDONLY | os.O_CLOEXEC)
    finally:
        os.close(writer)


def approve_packet(connection, request, plan, fd):
    detail = json.loads(request)
    nonce = detail.pop("nonce", "")
    expect(type(nonce) is str and DIGEST.fullmatch(nonce) is not None, "invalid_custody_nonce")
    expect(detail == {
        "protocol": PROTOCOL, "device": plan.identity.device, "inode": plan.identity.inode,
        "operation": "inherit-input", "recipient": None, "scope": plan.custody_scope,
        "due_ns": plan.due_ns,
    }, "custody_plan_mismatch")
    seals = required_seals()
    expect(observe(fd).identity == plan.identity
           and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals
           and os.pread(fd, len(FIXTURE) + 1, 0) == FIXTURE
           and monotonic_ns() < plan.due_ns, "custody_original_or_deadline_mismatch")
    digest = sha256(request).hexdigest()
    reply = APPROVAL + digest.encode("ascii")
    expect(connection.send(reply) == len(reply), "custody_approval_incomplete")
    return digest


def custodian(run_id, controller_pid):
    reader = sealed_fixture()
    try:
        with role_channel(run_id, "custodian", controller_pid) as control, \
                socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            info = observe(reader).identity
            listener.bind(custody_address(run_id))
            listener.listen(1)
            listener.settimeout(10)
            send_packet(control, {"event": "original", "identity": asdict(info)}, reader)
            binding, _, _ = receive_packet(control, (controller_pid, 0))
            expect(set(binding) == {"reader_pid", "reader_uid", "due_ns"}, "custody_binding_invalid")
            expected = binding["reader_pid"], binding["reader_uid"]
            expect(expected[0] > 0 and expected[1] not in (0, os.getuid()), "reader_role_not_distinct")
            plan = plan_for(run_id, info.device, info.inode, binding["due_ns"])
            with listener.accept()[0] as connection:
                expect(peer(connection) == expected, "custody_recipient_mismatch")
                remaining = plan.due_ns - monotonic_ns()
                expect(remaining > 0, "expired_attempt")
                connection.settimeout(remaining / SECOND)
                # One request per fresh original. A truncated/invalid request grants nothing.
                request, ancillary, flags, _ = connection.recvmsg(MAX_PACKET, socket.CMSG_SPACE(array("i").itemsize),
                                                                  socket.MSG_CMSG_CLOEXEC)
                for level, kind, data in ancillary:
                    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        values = array("i")
                        values.frombytes(data[:len(data) // values.itemsize * values.itemsize])
                        for fd in values:
                            os.close(fd)
                expect(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
                       "custody_request_invalid")
                digest = approve_packet(connection, request, plan, reader)
            send_packet(control, {"event": "attested", "digest": digest})
            done, _, _ = receive_packet(control, (controller_pid, 0))
            expect(done == {"event": "retire"}, "custody_retirement_invalid")
            os.close(reader)
            reader = None
            send_packet(control, {"event": "original_closed"})
    finally:
        if reader is not None:
            os.close(reader)


@contextmanager
def meter_scope_view(run_id, granted_fd):
    """Open the same scope in the meter's existing read-only mount view."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    grant = os.fstat(granted_fd)
    with ExitStack() as stack:
        try:
            root_fd = os.open("/sys/fs/cgroup", flags)
            stack.callback(os.close, root_fd)
            view_fd = os.open(slice_name(run_id), flags, dir_fd=root_fd)
            stack.callback(os.close, view_fd)
        except OSError as exc:
            raise Refused("meter_scope_local_view_unavailable") from exc
        view = os.fstat(view_fd)
        expect((view.st_dev, view.st_ino) == (grant.st_dev, grant.st_ino),
               "meter_scope_identity_mismatch")
        yield view_fd


def meter(run_id, controller_pid):
    with role_channel(run_id, "meter", controller_pid) as control:
        binding, _, fd = receive_packet(control, (controller_pid, 0), with_fd=True)
        try:
            run = RunBinding(run_id, binding["plan_digest"], binding["clock_id"],
                             binding["started_ns"], binding["finished_ns"])
            scope = EvidenceScope(run, run_id, run.started_ns, run.finished_ns)
            with (
                meter_scope_view(run_id, fd) as local_fd,
                CgroupScopeMeter(
                    scope=scope, provider_id="serial-fixture-meter", directory_fd=local_fd,
                ) as provider,
            ):
                send_packet(control, {"sample": asdict(provider.sample(ScopePhase.METER_BEGIN))})
                done, _, _ = receive_packet(control, (controller_pid, 0))
                expect(done == {"event": "sample_final"}, "meter_phase_invalid")
                send_packet(control, {"sample": asdict(provider.sample(ScopePhase.METER_END))})
        except ScopeMeterUnavailable as exc:
            if str(exc) == "directory is not on a visible cgroup v2 mount":
                raise Refused("meter_scope_mount_not_visible") from exc
            raise Refused("meter_scope_mount_context_unavailable") from exc
        finally:
            os.close(fd)


def command(argv, *, timeout=4, data=None, env=None):
    return subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env=MANAGER_ENV if env is None else env, check=False)


def checked(argv, *, timeout=4, data=None, env=None):
    result = command(argv, timeout=timeout, data=data, env=env)
    expect(result.returncode == 0, "fixed_fixture_command_failed")
    return result.stdout


def bus_command(operation, path, interface, *args):
    return [
        BUSCTL, "--system", "--allow-interactive-authorization=no", "--timeout=3s",
        "--json=short", operation, BUS_NAME, path, BUS_NAME + "." + interface, *args,
    ]


def bus_value(raw, signature):
    message = json.loads(raw)
    expect(type(message) is dict and message.get("type") == signature and "data" in message,
           "fixture_manager_state_unavailable")
    return message["data"]


def unit_path(unit):
    # GetUnit is a lookup. LoadUnit and systemctl show of a name can load an implicit slice.
    result = command(bus_command("call", BUS_PATH, "Manager", "GetUnit", "s", unit))
    if result.returncode:
        missing = f"Call failed: Unit {unit} not loaded.".encode("ascii")
        expect(not result.stdout and result.stderr.strip() == missing, "fixture_manager_lookup_failed")
        return None
    return bus_unit_path(result.stdout)


def bus_unit_path(raw):
    paths = bus_value(raw, "o")
    expect(type(paths) is list and len(paths) == 1 and type(paths[0]) is str
           and UNIT_PATH.fullmatch(paths[0]), "fixture_manager_state_unavailable")
    return paths[0]


def unit_file_exists(unit):
    raw = checked(bus_command("call", BUS_PATH, "Manager",
                              "ListUnitFilesByPatterns", "asas", "0", "1", unit))
    rows = bus_value(raw, "a(ss)")
    expect(type(rows) is list and len(rows) == 1 and type(rows[0]) is list
           and all(type(row) is list and len(row) == 2 and all(type(item) is str for item in row)
                   and Path(row[0]).name == unit for row in rows[0]), "fixture_manager_state_unavailable")
    return bool(rows[0])


def bus_properties(path, interface, **fields):
    raw = checked(bus_command("get-property", path, interface, *fields))
    lines = raw.splitlines()
    expect(len(lines) == len(fields), "fixture_manager_state_unavailable")
    return {name: bus_value(line, signature)
            for (name, signature), line in zip(fields.items(), lines)}


def no_entry(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def slice_empty_or_absent(unit):
    try:
        directory = os.open(Path("/sys/fs/cgroup") / unit,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return True
    try:
        fd = os.open("cgroup.events", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_SCOPE_EVENTS + 1)
        population = [line for line in raw.splitlines() if line.startswith(b"populated ")]
        return len(raw) <= MAX_SCOPE_EVENTS and population == [b"populated 0"]
    finally:
        os.close(directory)


def assert_no_unit_overrides(unit):
    paths = bus_properties(BUS_PATH, "Manager", UnitPath="as")["UnitPath"]
    expect(type(paths) is list and paths and all(type(path) is str and Path(path).is_absolute()
                                                for path in paths), "fixture_manager_state_unavailable")
    stem, kind = unit.rsplit(".", 1)
    suffixes = (unit + ".d", kind + ".d", unit + ".wants", unit + ".requires", unit + ".upholds")
    prefixes = tuple(stem[:index + 1] + "." + kind + ".d"
                     for index, char in enumerate(stem) if char == "-")
    expect(all(no_entry(Path(path) / entry) for path in paths for entry in (*suffixes, *prefixes)),
           "fixture_unit_override_present")


def invocation_path(invocation):
    raw = checked(bus_command("call", BUS_PATH, "Manager", "GetUnitByInvocationID",
                              "ay", str(len(invocation)), *map(str, invocation)))
    return bus_unit_path(raw)


def cancel_start_job(unit, unit_path, job_path):
    job = bus_properties(job_path, "Job", Unit="(so)", JobType="s")
    expect(job == {"Unit": [unit, unit_path], "JobType": "start"}, "fixture_job_ownership_unconfirmed")
    checked(bus_command("call", job_path, "Job", "Cancel"))


def stop_unit(path):
    raw = checked(bus_command("call", path, "Unit", "Stop", "s", "replace"))
    jobs = bus_value(raw, "o")
    expect(type(jobs) is list and len(jobs) == 1 and type(jobs[0]) is str
           and JOB_PATH.fullmatch(jobs[0]), "fixture_stop_job_unknown")


def slice_command(unit, description):
    properties = (*SLICE_PROPERTIES, ("Description", "s", description))
    return bus_command(
        "call", BUS_PATH, "Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
        unit, "fail", str(len(properties)), *(item for entry in properties for item in entry), "0",
    )


def role_command(py, script, run_id, role, args, description):
    return [
        "/usr/bin/systemd-run", "--system", "--no-ask-password", "--quiet", "--pipe", "--wait",
        "--service-type=exec", "--expand-environment=no", "--unit=" + role_unit(run_id, role),
        "--description=" + description, "--slice=" + role_slice(run_id, role),
        "--uid=" + role_user(run_id, role),
        *("--property=" + prop for prop in SERVICE_PROPERTIES),
        "--", str(py), "-I", "-B", str(script), "run" if role == "reader" else role,
        run_id, *(str(arg) for arg in args),
    ]


class Commission:
    """One fixed administrator transaction. No operations on pre-existing units."""

    def __init__(self, run_id, root):
        self.id, self.root = run_id, root
        self.py = root / "venv/bin/python"
        self.script = root / "serial_fixture.py"
        self.units, self.processes = [], []
        self.launch_in_progress = None
        self.owner = uuid4().hex

    def description(self, unit):
        return f"WorkerOS serial fixture {self.owner} {unit}"

    def scope_path(self, unit):
        root = Path("/sys/fs/cgroup")
        if unit.endswith(".slice"):
            return root / unit
        for role in ("custodian", "meter", "reader"):
            if unit == role_unit(self.id, role):
                return root / role_scope(self.id, role).lstrip("/")
        raise Refused("fixture_scope_name_unknown")

    def assert_unused(self, unit):
        expect(unit_path(unit) is None and not unit_file_exists(unit), "fixture_unit_collision")
        assert_no_unit_overrides(unit)
        expect(no_entry(self.scope_path(unit)), "fixture_cgroup_collision")

    def owned_unit(self, unit, path):
        values = bus_properties(path, "Unit", Id="s", Description="s", Transient="b",
                                ActiveState="s", Job="(uo)", InvocationID="ay", DropInPaths="as")
        expect(values["Id"] == unit and values["Description"] == self.description(unit)
               and values["Transient"] is True, "fixture_unit_ownership_unconfirmed")
        # systemd can record the supplied transient properties in its own drop-in directory.
        transient = Path("/run/systemd/transient") / (unit + ".d")
        expect(type(values["DropInPaths"]) is list and all(
            type(item) is str and Path(item).parent == transient for item in values["DropInPaths"]
        ), "fixture_unit_override_present")
        expect(values["ActiveState"] in ("active", "reloading", "inactive", "failed",
                                         "activating", "deactivating", "maintenance"),
               "fixture_manager_state_unavailable")
        job = values["Job"]
        expect(type(job) is list and len(job) == 2 and type(job[0]) is int
               and 0 <= job[0] and job[1] == (f"{BUS_PATH}/job/{job[0]}" if job[0] else "/"),
               "fixture_manager_state_unavailable")
        invocation = values["InvocationID"]
        expect(type(invocation) is list and len(invocation) in (0, 16)
               and all(type(byte) is int and 0 <= byte <= 255 for byte in invocation)
               and (not invocation or any(invocation)), "fixture_manager_state_unavailable")
        return values

    def slice_active(self, unit):
        path = unit_path(unit)
        if path is None or self.owned_unit(unit, path)["ActiveState"] != "active":
            return False
        return bus_properties(path, "Slice", ControlGroup="s")["ControlGroup"] == "/" + unit

    def start_slice(self, name):
        self.assert_unused(name)
        self.units.append(name)
        checked(slice_command(name, self.description(name)))
        for _ in range(12):
            if self.slice_active(name):
                return Path("/sys/fs/cgroup") / name
            sleep(0.05)
        raise Refused("retained_fixture_slice_unavailable")

    def start_role(self, role, stdin, *args):
        unit = role_unit(self.id, role)
        self.assert_unused(unit)
        name = role_user(self.id, role)
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(name)
            except KeyError:
                continue
            raise Refused("fixture_role_collision")
        self.units.append(unit)
        argv = role_command(self.py, self.script, self.id, role, args, self.description(unit))
        self.launch_in_progress = unit
        try:
            proc = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    close_fds=True, env=MANAGER_ENV)
        except OSError:
            self.launch_in_progress = None
            raise
        self.processes.append(proc)
        self.launch_in_progress = None
        return proc

    def pin(self, role, expected):
        unit = role_unit(self.id, role)
        path = unit_path(unit)
        expect(path is not None, "fixture_provider_pin_mismatch")
        invocation = self.owned_unit(unit, path)["InvocationID"]
        values = bus_properties(path, "Service", MainPID="u", User="s", ControlGroup="s")
        pid, uid = expected
        expect(0 < uid < (1 << 32) - 1 and pid > 0 and values["MainPID"] == pid
               and values["User"] == role_user(self.id, role)
               and values["ControlGroup"] == role_scope(self.id, role)
               and len(invocation) == 16, "fixture_provider_pin_mismatch")
        return bytes(invocation).hex()

    def finish_role(self, proc, role):
        try:
            output, error = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise provider_failure(proc, role, "exit", "fixture_role_exit_timeout",
                                   exc.output or b"", exc.stderr or b"") from exc
        if proc.returncode or len(error) > MAX_PACKET or len(output) > MAX_PACKET:
            raise provider_failure(proc, role, "exit", "fixture_role_failed", output, error)
        return output

    def retire_unit(self, unit):
        absent = False
        stop_requested = False
        deadline = monotonic_ns() + 3 * SECOND
        while monotonic_ns() < deadline:
            path = unit_path(unit)
            if path is None and not unit_file_exists(unit) and no_entry(self.scope_path(unit)):
                # Keep observing briefly after quiescing submission clients.
                if absent:
                    return True
                absent = True
            else:
                absent = False
                if path is not None:
                    try:
                        state = self.owned_unit(unit, path)
                    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                        # A collected unit may disappear between the lookup and the property read.
                        if unit_path(unit) is not None:
                            raise
                    else:
                        idle = state["ActiveState"] in ("inactive", "failed") and not state["Job"][0]
                        stopping = state["ActiveState"] == "deactivating"
                        if not (idle or stopping or stop_requested):
                            if unit.endswith(".slice"):
                                cgroup = bus_properties(path, "Slice", ControlGroup="s")["ControlGroup"]
                                known_scope = cgroup == "/" + unit or (
                                    cgroup == "" and state["ActiveState"] in ("activating", "failed", "inactive")
                                )
                                if not known_scope or not slice_empty_or_absent(unit):
                                    return False
                            stop_requested = True
                            try:
                                if state["InvocationID"]:
                                    # A name-based object path could be reused after collection.
                                    stop_unit(invocation_path(state["InvocationID"]))
                                elif state["Job"][0]:
                                    cancel_start_job(unit, path, state["Job"][1])
                            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                                # Observe a possible cleanup effect without replaying the request.
                                pass
            sleep(0.10)
        return False

    def rollback(self):
        pending = [self.launch_in_progress] if self.launch_in_progress is not None else []
        # Quiesce local submission clients before stopping any submitted units.
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pending.append("fixture-manager-client")
        for unit in reversed(self.units):
            if unit == self.launch_in_progress:
                continue
            # An unresolved service could still inhabit its slice. Leave parent units alone
            # when we cannot account for all of our submission clients or intended children.
            if unit.endswith(".slice") and pending:
                pending.append(unit)
                continue
            try:
                if not self.retire_unit(unit):
                    pending.append(unit)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                pending.append(unit)
        for role in ("custodian", "meter", "reader"):
            unit = role_unit(self.id, role)
            if unit not in self.units or unit in pending:
                continue
            for lookup in (pwd.getpwnam, grp.getgrnam):
                try:
                    lookup(role_user(self.id, role))
                except KeyError:
                    continue
                pending.append(unit)
                break
        return pending


def control_pair(stack):
    ends = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    for end in ends:
        stack.enter_context(end)
        end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        end.settimeout(8)
    return ends


def provider_failure(proc, role, phase, reason, output, error):
    child_reason = None
    if len(output) <= MAX_PROVIDER_DIAGNOSTIC:
        for line in output.splitlines():
            try:
                record = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if (type(record) is dict and set(record) == {"status", "reason"}
                    and record["status"] == "unverified" and type(record["reason"]) is str
                    and record["reason"] in PROVIDER_REASONS):
                child_reason = record["reason"]
    return ProviderFailure(role, phase, reason, proc.poll(), child_reason, bool(error))


def read_provider_failure_output(proc):
    # Read bounded diagnostics only from the controller's own pipes.
    streams = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    pending = list(streams)
    deadline = monotonic_ns() + SECOND
    while pending:
        remaining = (deadline - monotonic_ns()) / SECOND
        if remaining <= 0:
            break
        for stream in select.select(pending, [], [], remaining)[0]:
            data = streams[stream]
            chunk = os.read(stream.fileno(), MAX_PROVIDER_DIAGNOSTIC + 1 - len(data))
            data.extend(chunk)
            if not chunk or len(data) > MAX_PROVIDER_DIAGNOSTIC:
                pending.remove(stream)
    # A provider can close both pipes just before the manager client collects its exit.
    remaining = (deadline - monotonic_ns()) / SECOND
    if not pending and remaining > 0:
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            pass
    return bytes(streams[proc.stdout]), bytes(streams[proc.stderr])


@contextmanager
def provider_step(proc, role, phase):
    try:
        yield
    except (Refused, OSError, ValueError) as exc:
        if isinstance(exc, Refused):
            reason = str(exc)
        elif isinstance(exc, TimeoutError):
            reason = "fixture_provider_transport_timeout"
        else:
            reason = "fixture_provider_transport_failed"
        try:
            output, error = read_provider_failure_output(proc)
        except (OSError, ValueError):
            output, error = b"", b""
        raise provider_failure(proc, role, phase, reason, output, error) from exc


def ready_record(proc, timeout=6):
    deadline = monotonic_ns() + timeout * SECOND
    data = bytearray()
    while not data.endswith(b"\n"):
        remaining = (deadline - monotonic_ns()) / SECOND
        expect(remaining > 0 and select.select([proc.stdout], [], [], remaining)[0], "reader_ready_timeout")
        byte = os.read(proc.stdout.fileno(), 1)
        expect(byte and len(data) < MAX_PACKET, "reader_ready_invalid")
        data.extend(byte)
    record = json.loads(data)
    expect(type(record) is dict and record.get("status") == "reader_ready", "reader_ready_invalid")
    return record


def request_final_sample(channel, directory, expected, clock_id, terminal_ns, deadline_ns):
    """Read the retained kernel scope before allowing the meter to take its final sample."""
    started_ns = monotonic_ns()
    expect(terminal_ns <= started_ns < deadline_ns, "scope_empty_check_outside_window")
    identity = expected.st_dev, expected.st_ino
    before = os.fstat(directory)
    expect((before.st_dev, before.st_ino) == identity, "scope_empty_check_identity_mismatch")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open("cgroup.events", flags, dir_fd=directory), "rb") as events:
        metadata = os.fstat(events.fileno())
        expect(S_ISREG(metadata.st_mode) and metadata.st_dev == expected.st_dev, "scope_events_handle_invalid")
        data = events.read(MAX_SCOPE_EVENTS + 1)
    expect(len(data) <= MAX_SCOPE_EVENTS, "scope_events_size_limit")
    fields = [line.split() for line in data.splitlines()]
    populated = [row for row in fields if row and row[0] == b"populated"]
    expect(populated == [[b"populated", b"0"]], "retained_scope_not_observed_empty")
    after = os.fstat(directory)
    expect((after.st_dev, after.st_ino) == identity, "scope_empty_check_identity_mismatch")
    finished_ns = monotonic_ns()
    expect(started_ns <= finished_ns < deadline_ns, "scope_empty_check_outside_window")
    send_packet(channel, {"event": "sample_final"})
    return {"device": expected.st_dev, "inode": expected.st_ino, "populated": False,
            "clock_id": clock_id, "manager_terminal_ns": terminal_ns,
            "started_ns": started_ns, "finished_ns": finished_ns}


def orchestrate(tx):
    with ExitStack() as stack:
        slice_directory = tx.start_slice(slice_name(tx.id))
        tx.start_slice(role_slice(tx.id, "meter"))
        directory = os.open(slice_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        stack.callback(os.close, directory)
        scope_stat = os.fstat(directory)
        custody, custody_end = control_pair(stack)
        custodian_proc = tx.start_role("custodian", custody_end, os.getpid())
        custody_end.close()
        with provider_step(custodian_proc, "custodian", "open_original"):
            opening, custodian_pin, original = receive_packet(custody, with_fd=True)
        try:
            tx.pin("custodian", custodian_pin)
            original_stat = os.fstat(original)
            expect(opening == {"event": "original", "identity": {
                "device": original_stat.st_dev, "inode": original_stat.st_ino,
            }} and S_ISREG(original_stat.st_mode), "fixture_original_mismatch")

            clock = json.loads(checked([str(tx.py), "-I", "-B", "-c",
                                        "import json; from worker_handoff.scope_meter import monotonic_clock_id; "
                                        "print(json.dumps(monotonic_clock_id()))"]))
            expect(type(clock) is str and clock, "common_clock_unavailable")
            started = monotonic_ns()
            due = started + 9 * SECOND
            common = (tx.id, original_stat.st_dev, original_stat.st_ino, due)
            cli = [str(tx.py), "-I", "-B", str(tx.script)]
            plan = json.loads(checked([*cli, "plan", *map(str, common)]))
            measurement, measurement_end = control_pair(stack)
            meter_proc = tx.start_role("meter", measurement_end, os.getpid())
            measurement_end.close()
            with provider_step(meter_proc, "meter", "begin_sample"):
                send_packet(measurement, {
                    "plan_digest": plan["plan_digest"], "clock_id": clock,
                    "started_ns": started, "finished_ns": due + 8 * SECOND,
                }, directory)
                begin, meter_pin, _ = receive_packet(measurement)
            tx.pin("meter", meter_pin)
            sample = begin["sample"]
            expect(sample["identity"]["device"] == scope_stat.st_dev
                   and sample["identity"]["inode"] == scope_stat.st_ino
                   and sample["clock_id"] == clock and sample["phase"] == "meter_begin"
                   and sample["populated"] is False
                   and all(sample[key] == "observed" for key in (
                       "cpu_state", "population_state", "memory_current_state", "memory_peak_state",
                   )) and sample["finished_ns"] <= monotonic_ns() < due,
                   "baseline_scope_or_metrics_unavailable")
            reader = tx.start_role("reader", original, *common[1:], *custodian_pin)
        finally:
            os.close(original)

        with provider_step(reader, "reader", "ready"):
            ready = ready_record(reader)
        reader_pin = ready["pid"], ready["uid"]
        invocation = tx.pin("reader", reader_pin)
        expect(invocation == ready["invocation_id"] and ready["plan_digest"] == plan["plan_digest"]
               and len({reader_pin[1], custodian_pin[1], meter_pin[1]}) == 3,
               "fixture_identities_not_independent")
        with provider_step(custodian_proc, "custodian", "attest"):
            send_packet(custody, {"reader_pid": reader_pin[0], "reader_uid": reader_pin[1], "due_ns": due})
            attested, _, _ = receive_packet(custody, custodian_pin)
        receipt = json.loads(tx.finish_role(reader, "reader"))
        expect(receipt.get("invocation_id") == invocation and receipt.get("release_uid") == reader_pin[1]
               and attested == {"event": "attested", "digest": receipt["custody"]["request_digest"]},
               "fixture_attestation_or_reader_mismatch")
        # The reader unit has exited and its direct child was reaped. Keep the parent slice active.
        terminal_ns = monotonic_ns()
        expect(tx.slice_active(slice_name(tx.id)), "slice_retired_before_final_sample")
        with provider_step(meter_proc, "meter", "end_sample"):
            empty = request_final_sample(measurement, directory, scope_stat, clock, terminal_ns, due + 8 * SECOND)
            end, _, _ = receive_packet(measurement, meter_pin)
        expect(end["sample"]["started_ns"] >= empty["finished_ns"], "final_sample_precedes_scope_empty_check")
        tx.finish_role(meter_proc, "meter")
        joined = json.loads(checked([*cli, "verify", *map(str, (*common, *meter_pin))],
                                    data=json.dumps([receipt, begin, end]).encode()))
        with provider_step(custodian_proc, "custodian", "close_original"):
            send_packet(custody, {"event": "retire"})
            closed, _, _ = receive_packet(custody, custodian_pin)
        expect(closed == {"event": "original_closed"}, "fixture_original_retirement_unknown")
        tx.finish_role(custodian_proc, "custodian")
        return joined, receipt, begin, empty, end


def stage(tx, wheel):
    source = globals().get("VERIFIED_FIXTURE_SOURCE")
    expect(type(source) is bytes and 0 < len(source) <= 65536, "reviewed_source_pin_required")
    fd = os.open(wheel, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        expect(S_ISREG(os.fstat(stream.fileno()).st_mode), "fixture_wheel_not_regular")
        asset = stream.read(48522)
    expect(len(asset) == 48521 and sha256(asset).hexdigest() == WHEEL_SHA256, "fixture_wheel_digest_mismatch")
    tx.script.write_bytes(source)
    staged_wheel = tx.root / WHEEL
    staged_wheel.write_bytes(asset)
    env = {"PATH": "/usr/bin:/bin", "TMPDIR": str(tx.root), "PIP_CONFIG_FILE": "/dev/null",
           "PIP_NO_CACHE_DIR": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    checked(["/usr/bin/python3", "-I", "-B", "-m", "venv", str(tx.root / "venv")], timeout=35, env=env)
    checked([str(tx.py), "-I", "-B", "-m", "pip", "--require-virtualenv", "--disable-pip-version-check",
             "install", "--no-index", "--no-deps", "--no-cache-dir", "--no-compile", str(staged_wheel)],
            timeout=12, env=env)
    # Only the new disposable directory is exposed to the temporary service UIDs.
    tx.root.chmod(0o755)


def commission(wheel):
    expect(os.getresuid() == (0, 0, 0), "administrator_action_required")
    venue = set(Path("/etc/os-release").read_text().splitlines())
    expect("ID=ubuntu" in venue and 'VERSION_ID="24.04"' in venue, "ubuntu_24_04_vm_required")
    expect(wheel.name == WHEEL, "expected_exact_fixture_wheel")
    expect(all(hasattr(fcntl, key) for key in (
        "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL",
    )) and hasattr(os, "memfd_create"), "kernel_seal_interface_unavailable")
    version = checked([SYSTEMCTL, "--system", "--no-ask-password", "show", "--property=Version", "--value"])
    expect(version.decode("ascii").strip().startswith(("255.", "255-")), "reviewed_systemd_255_required")
    enabled = Path("/sys/fs/cgroup/cgroup.subtree_control").read_text().split()
    expect(set(enabled) >= {"cpu", "memory", "pids"}, "root_fixture_controllers_not_already_enabled")
    run_id = uuid4().hex
    root = Path("/run") / ("workerosq" + run_id)
    os.umask(0o022)
    root.mkdir(mode=0o700)
    tx = Commission(run_id, root)
    units = (slice_name(run_id), role_slice(run_id, "meter"),
             *(role_unit(run_id, role) for role in ("custodian", "meter", "reader")))
    print(json.dumps({"fixture": run_id, "fixture_directory": str(root), "planned_units": units,
                      "unit_owner_marker": tx.owner}), file=sys.stderr, flush=True)

    def interrupted(_number, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    result = None
    try:
        for unit in units:
            tx.assert_unused(unit)
        stage(tx, wheel)
        result = orchestrate(tx)
    except ProviderFailure as exc:
        print(json.dumps(exc.diagnostic), file=sys.stderr, flush=True)
        raise
    finally:
        # A second interrupt may require the printed exact cleanup targets.
        print(json.dumps({"fixture": run_id, "cleanup_units": list(reversed(tx.units)),
                          "fixture_directory": str(root)}), file=sys.stderr, flush=True)
        pending = tx.rollback()
        if pending:
            report({"status": "unverified", "reason": "fixture_cleanup_unconfirmed", "units": pending})
            raise Refused("fixture_cleanup_unconfirmed")
        shutil.rmtree(root)
        expect(not root.exists(), "fixture_directory_retirement_unknown")
    joined, reader, baseline, empty, final = result
    report({"status": "synthetic_serial_qualified_and_retired", "run_id": run_id,
            "scope": {"baseline": baseline["sample"], "observed_empty": empty, "final": final["sample"]},
            "reader": reader, "measurements": joined, "retired": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("read").add_argument("run_id")
    sub.add_parser("commission").add_argument("wheel", type=Path)
    for mode in ("custodian", "meter"):
        provider = sub.add_parser(mode)
        provider.add_argument("run_id")
        provider.add_argument("controller_pid", type=int)
    for mode in ("plan", "run", "verify"):
        p = sub.add_parser(mode)
        p.add_argument("run_id")
        for field in ("device", "inode", "due_ns"):
            p.add_argument(field, type=int)
        if mode != "plan":
            for field in ("pid", "uid"):
                p.add_argument(field, type=int)
    args = parser.parse_args()
    try:
        if args.mode == "commission":
            commission(args.wheel)
            return 0
        if args.mode == "read":
            read_original(args.run_id)
            return 0
        if args.mode in ("custodian", "meter"):
            (custodian if args.mode == "custodian" else meter)(args.run_id, args.controller_pid)
            return 0
        plan = plan_for(args.run_id, args.device, args.inode, args.due_ns)
        if args.mode == "plan":
            report({"plan_digest": plan.custody_scope, "operation": "inherit-input",
                    "run_id": plan.name, "original_length": len(FIXTURE)})
        elif args.mode == "run":
            result = run(plan, args.pid, args.uid)
            report(result)
            return 0 if result["status"] == "read_reaped_handles_closed" else 1
        else:
            # Use captured output from the authenticated reader and meter channels.
            data = sys.stdin.buffer.read(65537)
            expect(len(data) <= 65536, "receipt_size_limit")
            reader, begin, end = json.loads(data)
            report(verify_meter(plan, reader, CgroupSample.from_dict(begin["sample"]),
                                CgroupSample.from_dict(end["sample"]), args.pid, args.uid))
        return 0
    except Refused as exc:
        report({"status": "unverified", "reason": str(exc)})
    except KeyboardInterrupt:
        report({"status": "unverified", "reason": "fixture_interrupted"})
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError):
        report({"status": "unverified", "reason": "input_or_execution_unavailable"})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
