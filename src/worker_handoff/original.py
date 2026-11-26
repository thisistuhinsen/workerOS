"""One caller-owned regular-file descriptor; facts, not custody or authority."""

import array
from dataclasses import dataclass
import fcntl
import os
import socket
import stat
import struct
import sys
from time import monotonic_ns

from .workers import Worker


class HandoffError(ValueError):
    """The observed inputs did not satisfy this capture; do not retry implicitly."""


@dataclass(frozen=True, slots=True)
class Identity:
    device: int
    inode: int

    def __post_init__(self):
        if (type(self.device) is not int or type(self.inode) is not int
                or self.device < 0 or self.inode < 1):
            raise ValueError("expected a device and positive inode")


@dataclass(frozen=True, slots=True)
class Observation:
    identity: Identity
    owner_uid: int
    flags: int
    inheritable: bool
    mode: int
    size: int
    links: int
    modified_ns: int
    changed_ns: int
    observed_ns: int


@dataclass(frozen=True, slots=True)
class ReadResult:
    original: Identity
    bytes_read: int
    eof_observed_ns: int
    closed_ns: int


def _require(value, label):
    if not value:
        raise HandoffError(label)


def _linux():
    _require(sys.platform == "linux" and hasattr(os, "O_PATH"),
             "this descriptor boundary requires supported Linux")


def _fd(fd):
    _require(type(fd) is int and fd >= 0, "expected a caller-owned descriptor")


def _before(due_ns):
    _require(type(due_ns) is int and 0 < due_ns < 1 << 63,
             "expected an absolute monotonic deadline")
    now = monotonic_ns()
    if now >= due_ns:
        raise TimeoutError("worker handoff deadline expired")
    return now


def observe(fd):
    """Sample a *local borrowed* descriptor without reading or changing it.

    An invalid FD raises OSError. A sampled slot is not a process-wide
    exclusion, continuity, provenance or authoritative retirement proof.
    """
    _linux()
    _fd(fd)
    st = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    return Observation(Identity(st.st_dev, st.st_ino), st.st_uid, flags,
                       os.get_inheritable(fd), st.st_mode, st.st_size, st.st_nlink,
                       st.st_mtime_ns, st.st_ctime_ns, monotonic_ns())


def _check(fd, identity, modes):
    sample = observe(fd)
    _require(type(identity) is Identity and sample.identity == identity
             and stat.S_ISREG(sample.mode) and not sample.inheritable
             and not sample.flags & os.O_PATH and sample.flags & os.O_ACCMODE in modes,
             "expected exact non-inheritable regular-file descriptor and access mode")
    return sample


def _content_sample(o):
    return (o.identity, o.owner_uid, o.flags, o.inheritable, o.mode, o.size,
            o.links, o.modified_ns, o.changed_ns)


class _Owned:
    def __init__(self, fd, identity, modes, *, owner_only=False):
        _fd(fd)
        self._fd = fd
        self.identity = identity
        try:
            actual = _check(fd, identity, modes)
            if owner_only:
                _require(actual.owner_uid == os.getuid() == os.geteuid(),
                         "writer must own the original under its actual Linux UID")
        except BaseException:
            self.close()
            raise

    @property
    def closed(self):
        return self._fd is None

    def fileno(self):
        _require(self._fd is not None, "original is already closed or detached")
        return self._fd  # borrowed; no close or rebind by the caller

    def close(self):
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    def __enter__(self):
        self.fileno()
        return self

    def __exit__(self, *_):
        self.close()


class Writer(_Owned):
    """Consume an already open writable file owned by the caller. No path opens."""

    def __init__(self, fd, identity):
        super().__init__(fd, identity, (os.O_WRONLY, os.O_RDWR), owner_only=True)

    def _writable(self):
        fd = self.fileno()
        sample = _check(fd, self.identity, (os.O_WRONLY, os.O_RDWR))
        _require(sample.owner_uid == os.getuid() == os.geteuid(), "original writer ownership changed")
        return fd

    def write(self, data):
        """Write bytes at the existing position/append mode; not a transaction."""
        _require(type(data) is bytes, "write expects bytes")
        fd = self._writable()
        view = memoryview(data)
        while view:
            sent = os.write(fd, view)
            if sent <= 0:
                raise OSError("write made no progress")
            view = view[sent:]
        return len(data)

    def flush(self, *, sync=False):
        """Writes are unbuffered; explicitly request fsync where the app needs it."""
        _require(type(sync) is bool, "sync must be a bool")
        fd = self._writable()
        if sync:
            os.fsync(fd)


class Original(_Owned):
    """Consume an actual preheld RO original. Non-file/unknown inputs close/refuse."""

    def __init__(self, fd, identity):
        super().__init__(fd, identity, (os.O_RDONLY,))

    def detach(self):
        """Transfer actual FD ownership to an existing, separately authorized app."""
        fd = self.fileno()
        self._fd = None
        return fd

    def read_and_close(self, sink, *, due_ns, expected_size=None, block_size=65536):
        """Copy the sampled full file using positional reads, observe EOF and close.

        Callers choose the scope, sink and deadline. A sink can retain partial
        bytes on failure; publish only after success if atomicity matters.
        The syscall may block beyond the deadline: actual stop/kill remain the
        supervisor's responsibility. Equal stat samples are not continuous proof.
        """
        try:
            fd = self.fileno()
            _before(due_ns)
            _require(type(block_size) is int and block_size > 0 and callable(getattr(sink,"write",None)),
                     "expected a binary sink and positive block size")
            _require(expected_size is None or (type(expected_size) is int and expected_size >= 0),
                     "expected size must be nonnegative")
            first = _check(fd, self.identity, (os.O_RDONLY,))
            _require(expected_size is None or first.size == expected_size, "unexpected original length")
            at = 0
            while at < first.size:
                _before(due_ns)
                chunk = os.pread(fd, min(block_size, first.size-at), at)
                _require(bool(chunk), "original truncated before its sampled length")
                n = sink.write(chunk)
                _require(type(n) is int and n == len(chunk), "binary sink did not accept full chunk")
                at += len(chunk)
            _before(due_ns)
            _require(os.pread(fd, 1, at) == b"", "original grew before EOF")
            after = _check(fd, self.identity, (os.O_RDONLY,))
            _require(_content_sample(first) == _content_sample(after), "original changed during read")
            eof = _before(due_ns)
        finally:
            self.close()
        return ReadResult(self.identity, at, eof, _before(due_ns))


_CREDENTIALS = struct.Struct("iII")
_INT = array.array("i").itemsize


def _check_peer(channel, peer):
    _linux()
    _require(isinstance(channel, socket.socket) and channel.family == socket.AF_UNIX
             and channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) == socket.SOCK_STREAM
             and not channel.get_inheritable() and type(peer) is Worker and peer.uid is not None,
             "expected one connected local stream and the pinned peer PID/UID")
    channel.getpeername()
    pid, uid, _ = _CREDENTIALS.unpack(channel.getsockopt(
        socket.SOL_SOCKET,socket.SO_PEERCRED,_CREDENTIALS.size))
    _require((pid, uid) == (peer.pid, peer.uid), "unexpected local peer; no alternate transfer")


def _window(channel, due_ns):
    channel.settimeout((due_ns-_before(due_ns))/1_000_000_000)


def _token(token):
    _require(type(token) is bytes and bool(token), "expected a nonempty caller-pinned frame")


def send_original(channel, fd, *, peer, identity, token, due_ns):
    """Send one borrowed RO FD; consume the socket even on unknown outcome."""
    if not isinstance(channel,socket.socket):
        raise TypeError("expected a caller-owned socket")
    try:
        _check_peer(channel, peer)
        _check(fd, identity, (os.O_RDONLY,))
        _token(token)
        _window(channel, due_ns)
        sent = channel.sendmsg([token], [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])
        _require(sent == len(token), "incomplete handoff, do not retry implicitly")
        _before(due_ns)
    finally:
        channel.close()


def _receive_one(channel, token, due_ns):
    """The narrow exact-frame/ancillary/EOF boundary, without peer authorization."""
    held = []

    def recv(count):
        _window(channel, due_ns)
        raw, messages, flags, _ = channel.recvmsg(count, socket.CMSG_SPACE(2*_INT), socket.MSG_CMSG_CLOEXEC)
        start = len(held)
        valid = True
        for level, kind, data in messages:
            if (level, kind) != (socket.SOL_SOCKET,socket.SCM_RIGHTS):
                valid = False
                continue
            numbers = array.array("i")
            numbers.frombytes(data[:len(data)//_INT*_INT])
            held.extend(numbers)
            valid = valid and len(data) == _INT
        _require(valid and not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC),
                 "unexpected or truncated ancillary original")
        return raw, len(messages), len(held)-start

    try:
        raw, messages, count = recv(len(token))
        _require(raw and messages == count == 1 and token.startswith(raw), "expected exactly one framed file")
        while len(raw) < len(token):
            rest, messages, count = recv(len(token)-len(raw))
            raw += rest
            _require(rest and messages == count == 0 and token.startswith(raw), "incomplete or extra frame")
        extra, messages, count = recv(1)
        _require(extra == b"" and messages == count == 0, "handoff must end at literal EOF")
        _before(due_ns)
        return held.pop()
    finally:
        for fd in held:
            os.close(fd)


def receive_original(channel, *, peer, identity, token, due_ns):
    """Receive and own one exact read-only regular file; consume the socket."""
    if not isinstance(channel,socket.socket):
        raise TypeError("expected a caller-owned socket")
    original = None
    try:
        _check_peer(channel, peer)
        _token(token)
        original = Original(_receive_one(channel,token,due_ns), identity)
        _before(due_ns)
        return original
    except BaseException:
        if original is not None:
            original.close()
        raise
    finally:
        channel.close()
