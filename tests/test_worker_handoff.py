import array
import io
import multiprocessing
import os
from pathlib import Path
import socket
import stat
import tempfile
from time import monotonic_ns
import unittest

from workeros import HandoffError, Identity, Original, WorkerRoster, Writer, observe
from workeros.original import _receive_one

DATA = b"one original, two independent reads\n"


def due():
    return monotonic_ns() + 5_000_000_000  # test only, not a package budget


def write_worker(fd, identity, out):
    with Writer(fd, identity) as w:
        assert w.write(DATA) == len(DATA)
        w.flush(sync=True)
        sampled = observe(w.fileno())
    try:
        observe(fd)
    except OSError:
        out.send((sampled.identity, sampled.flags & os.O_ACCMODE, sampled.size, True))
    else:
        raise AssertionError("local owned write slot still open")
    finally:
        out.close()


def read_worker(fd, identity, out):
    sink = io.BytesIO()
    before = os.lseek(fd, 0, os.SEEK_CUR)
    result = Original(fd, identity).read_and_close(sink, due_ns=due(), block_size=3)
    try:
        observe(fd)
    except OSError:
        out.send((before, result, sink.getvalue(), True))
    else:
        raise AssertionError("local owned read slot still open")
    finally:
        out.close()


def observe_worker(fd, out):
    first = observe(fd)
    os.close(fd)  # fixture owns this inherited descriptor, not observe()
    try:
        observe(fd)
    except OSError:
        out.send((first, True))
    else:
        raise AssertionError("owned observer slot did not close")
    finally:
        out.close()


class AncillaryFixture:
    """An inert recvmsg-fed parser check. Never initializes AF_UNIX here."""
    def __init__(self, rows):
        self.rows = iter(rows)

    def settimeout(self, amount):
        assert amount > 0

    def recvmsg(self, count, ancillary, flags):
        assert count > 0 and ancillary > 0 and flags == socket.MSG_CMSG_CLOEXEC
        payload, rights, flags = next(self.rows)
        messages = ([(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i",rights).tobytes())]
                    if rights else [])
        return payload, messages, flags, None


class LoopTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "original"
        self.fd = os.open(self.path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC, 0o600)
        self.ident = observe(self.fd).identity

    def tearDown(self):
        if self.fd is not None:
            os.close(self.fd)

    def close_setup_fd(self):
        os.close(self.fd)
        self.fd = None

    def expect_closed(self, fd):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def ro(self):
        return os.open(self.path, os.O_RDONLY | os.O_CLOEXEC)

    def test_five_owned_workers_one_writer_two_readers_two_observers(self):
        ctx = multiprocessing.get_context("fork")
        roster = WorkerRoster()
        pipes = {}

        def launch(name, role, handler, *args):
            rx, tx = ctx.Pipe(duplex=False)  # no socket: test owns both ends
            pipes[name] = rx
            try:
                return roster.start(name, role, handler, args=(*args,tx), context=ctx, uid=os.getuid())
            finally:
                tx.close()

        def outcome(name):
            self.assertTrue(pipes[name].poll(3))
            actual = pipes[name].recv()
            self.assertEqual(roster.join(name,due_ns=due()),0)
            return actual

        rd = None
        try:
            launch("compose", "write", write_worker, self.fd,self.ident)
            self.close_setup_fd()
            self.assertEqual(outcome("compose"),(self.ident,os.O_WRONLY,len(DATA),True))
            rd = self.ro()
            os.lseek(rd, 2, os.SEEK_SET)
            for name,role,task,args in (
                ("reader-a","read",read_worker,(rd,self.ident)),
                ("reader-b","read",read_worker,(rd,self.ident)),
                ("watch-a","observe",observe_worker,(rd,)),
                ("watch-b","observe",observe_worker,(rd,)),
            ):
                launch(name,role,task,*args)
            self.assertEqual([w.role for w in roster],["write","read","read","observe","observe"])
            self.assertEqual(len({w.pid for w in roster}),5)
            for name in ("reader-a","reader-b"):
                offset, result, raw, local_closed = outcome(name)
                self.assertEqual((offset,result.original,result.bytes_read,raw,local_closed),
                                 (2,self.ident,len(DATA),DATA,True))
                self.assertLessEqual(result.eof_observed_ns,result.closed_ns)
            # Each reader inherited the very same open file description. Neither read
            # altered its position as seen in the still-open parent's duplicate.
            self.assertEqual(os.lseek(rd,0,os.SEEK_CUR),2)
            for name in ("watch-a","watch-b"):
                snapshot, local_closed = outcome(name)
                self.assertEqual((snapshot.identity,snapshot.flags&os.O_ACCMODE,snapshot.size,local_closed),
                                 (self.ident,os.O_RDONLY,len(DATA),True))
                self.assertTrue(stat.S_ISREG(snapshot.mode))
                self.assertFalse(snapshot.inheritable)
        finally:
            if rd is not None:
                os.close(rd)
                self.expect_closed(rd)
            for rx in pipes.values():
                rx.close()
            for w in roster:
                p=roster.owned(w.name)
                if p.is_alive():
                    p.terminate()  # fixture's own child only, never a package default
                p.join(2)

    def test_external_supervisor_keeps_worker_and_duplicate_names_refuse(self):
        roster = WorkerRoster()
        for i in range(8):
            w=roster.external(f"peer-{i}", "application-capability", pid=os.getpid(),uid=os.getuid())
            self.assertIsNone(w.process)
        self.assertEqual(len(tuple(roster)),8)
        with self.assertRaises(KeyError):
            roster.owned("peer-0")
        with self.assertRaises(ValueError):
            roster.external("peer-0","other",pid=os.getpid())

    def test_adopt_bad_descriptor_refuses_and_closes(self):
        read, write = os.pipe()
        os.close(write)
        for fd,identity in ((os.dup(self.fd),self.ident),
                            (os.open(self.path,os.O_PATH|os.O_CLOEXEC),self.ident),
                            (self.ro(),Identity(self.ident.device,self.ident.inode+1)),
                            (read,observe(read).identity)):
            with self.subTest(fd=fd):
                with self.assertRaises(HandoffError):
                    Original(fd,identity)
                self.expect_closed(fd)
        writer_fd=self.ro()
        with self.assertRaises(HandoffError):
            Writer(writer_fd,self.ident)
        self.expect_closed(writer_fd)

    def test_empty_eof_detach_has_explicit_ownership(self):
        fd=self.ro()
        with Original(fd,self.ident) as r:
            self.assertEqual(r.detach(),fd)
        self.assertEqual(observe(fd).identity,self.ident)
        result=Original(fd,self.ident).read_and_close(io.BytesIO(),expected_size=0,due_ns=due())
        self.assertEqual(result.bytes_read,0)
        self.expect_closed(fd)

    def test_expired_and_wrong_size_consume_no_bytes_and_close(self):
        for expiry,size,kind in ((1,0,TimeoutError),(due(),1,HandoffError)):
            fd=self.ro(); output=io.BytesIO()
            with self.assertRaises(kind):
                Original(fd,self.ident).read_and_close(output,expected_size=size,due_ns=expiry)
            self.assertEqual(output.getvalue(),b"")
            self.expect_closed(fd)

    def test_parser_preserves_one_exact_frame_and_eof(self):
        fd=self.ro()
        channel=AncillaryFixture([(b"a",[fd],0),(b"bc",[],0),(b"",[],0)])
        self.assertEqual(_receive_one(channel,b"abc",due()),fd)
        Original(fd,self.ident).close()
        self.expect_closed(fd)

    def test_parser_refuses_extra_file_wrong_frame_and_truncation(self):
        for shape in ("extra-file","wrong-frame","truncation","after-frame"):
            fd=self.ro(); second=self.ro() if shape=="extra-file" else None
            frame=[(b"token",[fd]+([second] if second is not None else []),0),(b"",[],0)]
            if shape=="wrong-frame": frame[0]=(b"other",[fd],0)
            if shape=="truncation": frame[0]=(b"token",[fd],socket.MSG_CTRUNC)
            if shape=="after-frame": frame[1]=(b"x",[],0)
            with self.subTest(shape=shape):
                with self.assertRaises(HandoffError):
                    _receive_one(AncillaryFixture(frame),b"token",due())
                self.expect_closed(fd)
                if second is not None:
                    self.expect_closed(second)


if __name__ == "__main__":
    unittest.main(verbosity=2)
