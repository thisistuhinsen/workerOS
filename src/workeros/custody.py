"""Opt-in authenticated pre-grant custody attestations on Linux.

The deployment pins a trusted observer PID and UID outside the release caller's
control. The observer owns its policy and measurements. Before approving a
request, it must recognize the exact scope, establish the original's provenance,
account for earlier grants and any required retirements, and enforce applicable
writer exclusion through the grant window. It must decline whenever it cannot
cover those conditions through the deadline in the caller's monotonic clock.
Provision and configure the observer separately.

The endpoint sends one AF_UNIX SOCK_SEQPACKET message, an ASCII JSON object
with a fresh nonce and the requested scope. An approving observer returns one
packet starting with `worker-handoff-custody/1 pregrant provenance grants exclusion `
followed by the lowercase ASCII SHA-256 of the exact request bytes. The
deployment supplies execution plans to the observer by their scope digests.
A receipt records the observer's pre-grant attestation. Release and worker
outcomes require their own evidence.
"""

import array
from dataclasses import KW_ONLY, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
from time import monotonic_ns

from .original import HandoffError, Identity
from .workers import Worker


_PROTOCOL = "worker-handoff-custody/1"
_APPROVAL = b"worker-handoff-custody/1 pregrant provenance grants exclusion "
_CREDENTIALS = struct.Struct("=iII")
_INT_BYTES = array.array("i").itemsize
_OPERATION = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_SCOPE = re.compile(r"[0-9a-f]{64}")
_PRIVILEGES = (
    1 << 1    # CAP_DAC_OVERRIDE
    | 1 << 2  # CAP_DAC_READ_SEARCH
    | 1 << 7  # CAP_SETUID
    | 1 << 19  # CAP_SYS_PTRACE
    | 1 << 21  # CAP_SYS_ADMIN
)


class CustodyRefused(HandoffError):
    """The independent pre-grant evidence required for this action is absent."""


@dataclass(frozen=True, slots=True)
class CustodyReceipt:
    """Evidence of authenticated pre-grant attestation for one release scope."""

    identity: Identity
    operation: str
    recipient: Worker | None
    scope: str
    observer_pid: int
    observer_uid: int
    request_digest: str
    attested_ns: int
    due_ns: int


@dataclass(frozen=True, slots=True)
class IndependentCustody:
    """One caller-supplied connected socket to a deployment-trusted observer.

    Requiring custody consumes the socket, even on refusal. The caller may use
    the context manager to close an unused endpoint on earlier refusal.
    """

    channel: socket.socket
    _: KW_ONLY
    observer_pid: int
    observer_uid: int

    def __post_init__(self):
        if type(self.channel) is not socket.socket:
            raise TypeError("custody requires a real connected Unix socket")
        if (type(self.observer_pid) is not int or not 0 < self.observer_pid < 1 << 31
                or type(self.observer_uid) is not int or not 0 <= self.observer_uid < (1 << 32) - 1):
            raise ValueError("custody requires a pinned observer PID and UID")

    def close(self):
        self.channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _deadline(due_ns):
    if type(due_ns) is not int or not 0 < due_ns < 1 << 63:
        raise CustodyRefused("custody requires an absolute monotonic deadline")
    now = monotonic_ns()
    if now >= due_ns:
        raise CustodyRefused("custody evidence deadline expired")
    return now


def _credentials(observer, recipient):
    rows = Path("/proc/thread-self/status").read_text(encoding="ascii").splitlines()
    status = dict(row.split(":", 1) for row in rows if ":" in row)
    own_uids = status.get("Uid", "").split()
    caps = status.get("CapPrm", "").strip()
    if len(own_uids) != 4 or not caps:
        raise CustodyRefused("kernel evidence for the release caller is unavailable")
    own_uids = {int(uid) for uid in own_uids}
    if 0 in own_uids or int(caps, 16) & _PRIVILEGES:
        raise CustodyRefused("release caller can assume or alter other principals")
    overflow_uid = int(Path("/proc/sys/kernel/overflowuid").read_text(encoding="ascii"))
    excluded_uids = own_uids | {overflow_uid}
    excluded_pids = {os.getpid()}
    if recipient is not None:
        excluded_uids.add(recipient.uid)
        excluded_pids.add(recipient.pid)
    if observer.observer_uid in excluded_uids or observer.observer_pid in excluded_pids:
        raise CustodyRefused("observer must be an independent process and Linux principal")

    channel = observer.channel
    if (channel.family != socket.AF_UNIX or channel.get_inheritable()
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
        raise CustodyRefused("custody requires a private connected Unix sequenced-packet socket")
    channel.getpeername()
    expected = (observer.observer_pid, observer.observer_uid)
    actual = _CREDENTIALS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                   _CREDENTIALS.size))
    if actual[:2] != expected:
        raise CustodyRefused("custody endpoint does not match the pinned observer")
    return expected


def _request(identity, operation, recipient, scope, due_ns):
    if (type(identity) is not Identity or type(operation) is not str
            or _OPERATION.fullmatch(operation) is None
            or type(scope) is not str or _SCOPE.fullmatch(scope) is None):
        raise CustodyRefused("custody requires an exact file, operation and SHA-256 scope")
    if recipient is not None and (type(recipient) is not Worker or recipient.uid is None):
        raise CustodyRefused("an existing custody recipient requires a pinned PID and UID")
    return json.dumps({
        "protocol": _PROTOCOL,
        "nonce": secrets.token_hex(32),
        "device": identity.device,
        "inode": identity.inode,
        "operation": operation,
        "recipient": None if recipient is None else {
            "name": recipient.name, "role": recipient.role, "pid": recipient.pid, "uid": recipient.uid,
        },
        "scope": scope,
        "due_ns": due_ns,
    }, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")


def _approval(channel, expected, digest):
    response = _APPROVAL + digest.encode("ascii")
    packet, ancillary, flags, _ = channel.recvmsg(
        len(response), socket.CMSG_SPACE(_CREDENTIALS.size), socket.MSG_CMSG_CLOEXEC)
    # Unexpected descriptor rights are still owned by us until closed, even
    # when the kernel marks the ancillary data truncated.
    for level, kind, data in ancillary:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            fds = array.array("i")
            fds.frombytes(data[:len(data) // _INT_BYTES * _INT_BYTES])
            for fd in fds:
                os.close(fd)
    if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(ancillary) != 1
            or ancillary[0][:2] != (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
            or len(ancillary[0][2]) != _CREDENTIALS.size
            or _CREDENTIALS.unpack(ancillary[0][2])[:2] != expected
            or packet != response):
        raise CustodyRefused("missing authenticated approval for the exact custody request")


def require_custody(observer: IndependentCustody | None, *, identity: Identity,
                    operation: str, recipient: Worker | None = None,
                    scope: str, due_ns: int) -> CustodyReceipt:
    """Require a fresh, exact-scope independent attestation before FD release."""
    if type(observer) is not IndependentCustody:
        raise CustodyRefused("strict custody requires a dedicated independent observer")
    with observer:
        try:
            _deadline(due_ns)
            request = _request(identity, operation, recipient, scope, due_ns)
            expected = _credentials(observer, recipient)
            digest = hashlib.sha256(request).hexdigest()
            channel = observer.channel
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.settimeout((due_ns - _deadline(due_ns)) / 1_000_000_000)
            if channel.send(request) != len(request):
                raise CustodyRefused("incomplete custody request")
            channel.settimeout((due_ns - _deadline(due_ns)) / 1_000_000_000)
            _approval(channel, expected, digest)
            seen_ns = _deadline(due_ns)
        except CustodyRefused:
            raise
        except (AttributeError, OSError, ValueError, struct.error) as exc:
            raise CustodyRefused("independent custody evidence unavailable") from exc
    return CustodyReceipt(identity, operation, recipient, scope, *expected, digest, seen_ns, due_ns)
