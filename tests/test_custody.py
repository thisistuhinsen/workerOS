import array
import hashlib
import json
import os
import socket
import subprocess
import sys
from time import monotonic_ns
import unittest
from unittest.mock import Mock
from uuid import uuid4

from workeros.custody import (
    CustodyReceipt, CustodyRefused, IndependentCustody,
    _APPROVAL, _approval, _request, require_custody,
)
from workeros.original import Identity
from workeros.workers import Worker


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.identity = Identity(1, 23)
        self.scope = "ab" * 32
        self.due_ns = monotonic_ns() + 5_000_000_000

    def require(self, observer, **changes):
        inputs = dict(identity=self.identity, scope=self.scope,
                      operation="write", due_ns=self.due_ns)
        inputs.update(changes)
        return require_custody(observer, **inputs)

    def sockets(self, kind=socket.SOCK_SEQPACKET):
        a, b = socket.socketpair(socket.AF_UNIX, kind)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        return a, b

    def test_missing_mock_and_writer_supplied_receipt_are_refused(self):
        receipt = CustodyReceipt(self.identity, "write", None, self.scope, os.getpid(),
                                 os.getuid(), "0" * 64, monotonic_ns(), self.due_ns)
        for invalid in (None, receipt, Mock(spec=IndependentCustody), lambda **_: receipt):
            with self.subTest(invalid=invalid), self.assertRaises(CustodyRefused):
                self.require(invalid)

    def test_same_principal_endpoint_is_consumed_without_a_request(self):
        client, peer = self.sockets()
        observer = IndependentCustody(client, observer_pid=os.getpid(), observer_uid=os.getuid())
        with self.assertRaises(CustodyRefused):
            self.require(observer)
        self.assertEqual(client.fileno(), -1)
        self.assertEqual(peer.recv(4096), b"")

    def test_substituting_the_expected_principal_does_not_authenticate_the_socket(self):
        client, peer = self.sockets()
        observer = IndependentCustody(client, observer_pid=os.getpid() + 1,
                                      observer_uid=os.getuid() + 1)
        with self.assertRaises(CustodyRefused):
            self.require(observer)
        self.assertEqual(client.fileno(), -1)
        self.assertEqual(peer.recv(4096), b"")

    def test_separate_process_under_the_writer_uid_is_refused(self):
        name = "worker-handoff-custody-" + uuid4().hex
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind("\x00" + name)
            listener.listen()
            listener.settimeout(5)
            program = (
                "import socket, sys\n"
                "with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:\n"
                "    peer.settimeout(5)\n"
                "    peer.connect(chr(0) + sys.argv[1])\n"
                "    sys.exit(peer.recv(4096) != b'')\n"
            )
            with subprocess.Popen([sys.executable, "-c", program, name]) as peer:
                client, _ = listener.accept()
                with IndependentCustody(client, observer_pid=peer.pid,
                                        observer_uid=os.getuid()) as observer:
                    with self.assertRaises(CustodyRefused):
                        self.require(observer)
                self.assertEqual(peer.wait(timeout=5), 0)

    def test_expired_scope_or_invalid_request_consumes_endpoint(self):
        for changes in ({"due_ns": monotonic_ns()}, {"scope": "different"},
                        {"recipient": Worker("other", "read", 1)}, {"operation": "x\n"}):
            with self.subTest(changes=changes):
                client, peer = self.sockets()
                observer = IndependentCustody(client, observer_pid=os.getpid(), observer_uid=os.getuid())
                with self.assertRaises(CustodyRefused):
                    self.require(observer, **changes)
                self.assertEqual(client.fileno(), -1)
                self.assertEqual(peer.recv(4096), b"")

    def test_request_digest_binds_file_operation_recipient_scope_and_deadline(self):
        recipient = Worker("reader", "read", 34, 56)
        inputs = (self.identity, "write", recipient, self.scope, self.due_ns)
        first = _request(*inputs)
        second = _request(*inputs)
        request = json.loads(first)
        self.assertEqual((request["device"], request["inode"]), (1, 23))
        self.assertEqual(request["operation"], "write")
        self.assertEqual(request["recipient"], dict(name="reader", role="read", pid=34, uid=56))
        self.assertEqual(request["scope"], self.scope)
        self.assertEqual(request["due_ns"], self.due_ns)
        self.assertNotEqual(request["nonce"], json.loads(second)["nonce"])
        self.assertNotEqual(hashlib.sha256(first).digest(), hashlib.sha256(second).digest())

    def test_packet_parser_rejects_wrong_origin_and_nonexact_approval(self):
        digest = "a" * 64
        valid = _APPROVAL + digest.encode("ascii")
        credentials = (os.getpid(), os.getuid())
        cases = ((valid, (os.getpid() + 1, os.getuid())), (b"approved", credentials),
                 (_APPROVAL + b"b" * 64, credentials), (valid + b"extra", credentials))
        for packet, expected in cases:
            with self.subTest(packet=packet, expected=expected):
                client, peer = self.sockets()
                client.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                peer.send(packet)
                with self.assertRaises(CustodyRefused):
                    _approval(client, expected, digest)

    def test_packet_parser_accepts_exact_response_without_issuing_a_receipt(self):
        client, peer = self.sockets()
        client.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        digest = "d" * 64
        peer.send(_APPROVAL + digest.encode("ascii"))
        self.assertIsNone(_approval(client, (os.getpid(), os.getuid()), digest))

    def test_ancillary_descriptor_is_refused_without_leaking_it(self):
        client, peer = self.sockets()
        reader, writer = os.pipe()
        with os.fdopen(reader, "rb"), os.fdopen(writer, "wb"):
            fd_list = array.array("i", [reader])
            before = os.listdir("/proc/self/fd")
            digest = "c" * 64
            peer.sendmsg([_APPROVAL + digest.encode("ascii")],
                         [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd_list)])
            with self.assertRaises(CustodyRefused):
                _approval(client, (os.getpid(), os.getuid()), digest)
            self.assertEqual(set(os.listdir("/proc/self/fd")), set(before))


if __name__ == "__main__":
    unittest.main()
