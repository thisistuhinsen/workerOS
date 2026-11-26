"""Exercise read-only strict custody against real Linux principals in a disposable VM.

The root controller creates the file, holds the expected plan and observes the
unprivileged release. Irreversible memfd seals enforce exclusion over the entire
grant window. Only the read-only plan for this controlled original can qualify.
"""

import array
from contextlib import closing, contextmanager
import errno
import fcntl
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
from time import monotonic_ns
from unittest.mock import Mock

import worker_handoff
from worker_handoff import (
    CleanupStatus, DeliveryStatus, DirectChildSupervisor, EffectStatus, Identity,
    IndependentCustody, LifecycleStatus, ReleasePlan, release_executable,
)


PROTOCOL = "worker-handoff-custody/1"
APPROVAL = b"worker-handoff-custody/1 pregrant provenance grants exclusion "
CONTENT = b"workerOS strict custody fixture\n"
CREDS = struct.Struct("=iII")
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
SCRIPT = str(Path(__file__).resolve())
TIMEOUT = 12


def peer(channel):
    return CREDS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, CREDS.size))


def endpoint():
    return socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)


def address(name):
    return "\0worker-handoff-strict-" + name


@contextmanager
def listening(name):
    with endpoint() as listener:
        listener.bind(address(name))
        listener.listen(1)
        listener.settimeout(TIMEOUT)
        yield listener


def opened_original(fd):
    info = os.fstat(fd)
    return Identity(info.st_dev, info.st_ino)


@contextmanager
def original(sealed, account):
    writer = os.memfd_create("worker-handoff-strict", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    with os.fdopen(writer, "rb+", buffering=0) as initial_grant:
        identity = opened_original(writer)
        assert os.fstat(writer).st_size == 0
        subprocess.run(
            (sys.executable, "-I", SCRIPT, "seed", str(writer)), env={}, check=True,
            stdin=subprocess.DEVNULL, timeout=TIMEOUT, pass_fds=(writer,),
            user=account.pw_uid, group=account.pw_gid, extra_groups=(),
        )
        # The direct writer has been reaped. Read back the same original in the
        # independent provisioner before retiring its authority.
        assert opened_original(writer) == identity
        assert os.pread(writer, len(CONTENT) + 1, 0) == CONTENT
        if sealed:
            fcntl.fcntl(writer, fcntl.F_ADD_SEALS, SEALS)
            try:
                os.pwrite(writer, b"X", 0)
            except OSError as exc:
                assert exc.errno == errno.EPERM, exc
            else:
                raise AssertionError("sealed original accepted a write")
        reader = os.open(f"/proc/self/fd/{writer}", os.O_RDONLY | os.O_CLOEXEC)
        with os.fdopen(reader, "rb", buffering=0):
            assert opened_original(reader) == identity
            if sealed:
                initial_grant.close()
            # Negatives deliberately keep the original writable description.
            yield reader, None if sealed else writer


def seed(raw_fd):
    fd = int(raw_fd)
    assert os.geteuid() != 0
    with os.fdopen(fd, "wb", buffering=0) as target:
        assert target.write(CONTENT) == len(CONTENT)


def scope_plan(name, audit, identity, due):
    return ReleasePlan(name, "read", (sys.executable, "-I", SCRIPT, "read", audit), identity, due)


def attest(listener, writer, writer_uid, plan, original_fd, previous_grant, approved):
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(TIMEOUT)
        assert peer(connection)[:2] == (writer.pid, writer_uid)
        request = connection.recv(2048)
        expected = {
            "device": plan.identity.device,
            "inode": plan.identity.inode,
            "operation": "inherit-input",
            "protocol": PROTOCOL,
            "recipient": None,
            "scope": plan.custody_scope,
            "due_ns": plan.due_ns,
        }
        details = json.loads(request)
        nonce = details.pop("nonce")
        assert re.fullmatch(r"[0-9a-f]{64}", nonce)
        assert opened_original(original_fd) == plan.identity
        assert os.fstat(original_fd).st_uid == 0
        assert os.pread(original_fd, len(CONTENT) + 1, 0) == CONTENT
        assert monotonic_ns() < plan.due_ns
        eligible = fcntl.fcntl(original_fd, fcntl.F_GET_SEALS) & SEALS == SEALS
        matches = details == expected
        assert (eligible, matches) == approved
        if eligible and matches:
            assert previous_grant is None
            digest = sha256(request).hexdigest()
            reply = APPROVAL + digest.encode("ascii")
            assert connection.send(reply) == len(reply)
            return digest
        if not eligible:
            assert opened_original(previous_grant) == plan.identity
            assert fcntl.fcntl(previous_grant, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR
        assert connection.send(b"denied") == 6
    return None


def audit_child(listener, writer_uid, identity):
    """Observe the consumed FD from the actual worker and pin its lifetime."""
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(TIMEOUT)
        pid, uid, _ = peer(connection)
        assert uid == writer_uid
        fd_array = array.array("i")
        message, ancillary, flags, _ = connection.recvmsg(
            16, socket.CMSG_SPACE(fd_array.itemsize), socket.MSG_CMSG_CLOEXEC,
        )
        for level, kind, data in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                fd_array.frombytes(data[:len(data) // fd_array.itemsize * fd_array.itemsize])
        try:
            assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            assert message == b"read" and len(ancillary) == len(fd_array) == 1
            fd = fd_array[0]
            assert opened_original(fd) == identity
            assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            assert os.pread(fd, len(CONTENT) + 1, 0) == CONTENT
        finally:
            for fd in fd_array:
                os.close(fd)
        pin = os.pidfd_open(pid)
        try:
            assert connection.send(b"observed") == 8
        except BaseException:
            os.close(pin)
            raise
        return pid, pin


def consume(audit):
    assert os.environ["WORKER_HANDOFF_ABI"] == "1"
    fd = int(os.environ["WORKER_HANDOFF_FD_INPUT"])
    with closing(os.fdopen(fd, "rb", buffering=0)), endpoint() as channel:
        assert fd >= 3 and os.pread(fd, len(CONTENT) + 1, 0) == CONTENT
        channel.settimeout(TIMEOUT)
        channel.connect(address(audit))
        assert channel.sendmsg([b"read"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                           array.array("i", [fd]))]) == 4
        assert channel.recv(16) == b"observed"


def original_handles(identity):
    handles = []
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        try:
            candidate = opened_original(fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
            continue
        if candidate == identity:
            handles.append(fd)
    return handles


def release(case, expected_name, audit, custody, raw_fd, observer_pid, due):
    fd = int(raw_fd)
    os.set_inheritable(fd, False)
    identity = opened_original(fd)
    assert original_handles(identity) == [fd]
    name = "unregistered-scope" if case == "wrong-scope" else expected_name
    plan = scope_plan(name, audit, identity, int(due))
    supervisor = DirectChildSupervisor()
    with endpoint() as connection:
        observer = None
        if case == "mock":
            observer = Mock(spec=IndependentCustody)
        elif case != "missing":
            connection.connect(address(custody))
            observer = IndependentCustody(connection, observer_pid=int(observer_pid), observer_uid=0)
        result = release_executable(
            plan, input_fd=fd, authorize=lambda selected: selected == plan,
            strict_custody=True, custody=observer, supervisor=supervisor,
            cleanup_due_ns=plan.due_ns + 2_000_000_000,
        )
    assert result.effect is EffectStatus.NOT_ATTEMPTED and result.cleanup == ()
    assert result.bytes_written is None and original_handles(identity) == [fd]
    os.close(fd)
    assert original_handles(identity) == []
    if case != "positive":
        assert result.delivery is DeliveryStatus.NOT_ATTEMPTED
        assert result.worker is result.custody is result.lifecycle is None
        assert result.error
        supervisor.check_available(name, "read")
        print(json.dumps({"status": "refused"}))
        return
    assert result.error is None and result.delivery is DeliveryStatus.DISPATCHED, result
    assert result.lifecycle.lifecycle is LifecycleStatus.EXITED
    assert result.lifecycle.returncode == 0
    assert result.lifecycle.cleanup.status is CleanupStatus.NOT_REQUESTED
    reaped = supervisor.cleanup(name, due_ns=plan.due_ns + 2_000_000_000)
    assert (reaped.status, reaped.returncode) == (CleanupStatus.REAPED, 0)
    assert not (reaped.terminate_sent or reaped.kill_sent or reaped.error)
    receipt = result.custody
    assert (receipt.identity, receipt.operation, receipt.recipient, receipt.scope) == (
        identity, "inherit-input", None, plan.custody_scope,
    )
    assert (receipt.observer_pid, receipt.observer_uid) == (int(observer_pid), 0)
    assert receipt.attested_ns < receipt.due_ns == plan.due_ns
    print(json.dumps({"status": "dispatched-reaped", "pid": result.worker.pid,
                      "digest": receipt.request_digest}))


def trial(case, account):
    custody, audit = secrets.token_hex(16), secrets.token_hex(16)
    plan_name = "authorized-reader"
    due = monotonic_ns() + TIMEOUT * 1_000_000_000
    with original(case != "prior-writer", account) as (reader, prior):
        plan = scope_plan(plan_name, audit, opened_original(reader), due)
        with listening(custody) as observer, listening(audit) as auditor:
            argv = (sys.executable, "-I", SCRIPT, "release", case, plan_name, audit, custody,
                    str(reader), str(os.getpid()), str(due))
            with subprocess.Popen(argv, env={}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  text=True, user=account.pw_uid, group=account.pw_gid,
                                  extra_groups=(), pass_fds=(reader,)) as writer:
                pin = None
                try:
                    digest = None
                    if case not in ("mock", "missing"):
                        expected = (case != "prior-writer", case != "wrong-scope")
                        digest = attest(observer, writer, account.pw_uid, plan, reader, prior, expected)
                    if case == "positive":
                        pid, pin = audit_child(auditor, account.pw_uid, plan.identity)
                    report, _ = writer.communicate(timeout=TIMEOUT)
                    assert writer.returncode == 0, writer.returncode
                    if case == "positive":
                        assert json.loads(report) == {"status": "dispatched-reaped", "pid": pid,
                                                      "digest": digest}
                        events = select.poll()
                        events.register(pin, select.POLLIN)
                        assert events.poll(0), "the exact audited child is still live"
                        records = Path(f"/proc/self/fdinfo/{pin}").read_text().splitlines()
                        assert "Pid:\t-1" in records, "the exact audited child is still unreaped"
                    else:
                        assert json.loads(report) == {"status": "refused"}
                        assert not select.select([auditor], [], [], 0)[0], "refused reader got the FD"
                    assert os.pread(reader, len(CONTENT) + 1, 0) == CONTENT
                finally:
                    if pin is not None:
                        os.close(pin)
                    if writer.poll() is None:
                        writer.kill()
        print(f"PASS strict custody {case}")


def main(account_name, expected_version):
    assert sys.platform == "linux" and os.getresuid() == (0, 0, 0)
    assert Path(worker_handoff.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    assert version("worker-handoff") == expected_version
    account = pwd.getpwnam(account_name)
    assert account.pw_uid != 0 and account.pw_gid != 0
    for case in ("positive", "missing", "mock", "wrong-scope", "prior-writer"):
        trial(case, account)


if __name__ == "__main__":
    mode, *args = sys.argv[1:]
    {"check": main, "seed": seed, "release": release, "read": consume}[mode](*args)
