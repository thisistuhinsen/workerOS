import io
import os
import socket
import tempfile
import time
import unittest

from worker_handoff import Worker, observe, receive_original, send_original


class ConnectedOriginal(unittest.TestCase):
    def test_read_only_same_original_over_real_unix_stream(self):
        body = b"test payload\n"
        with tempfile.TemporaryDirectory() as work:
            path = os.path.join(work, "artifact")
            with open(path, "wb") as f:
                f.write(body)
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.lseek(fd, 2, os.SEEK_SET)
                identity = observe(fd).identity
                due = time.monotonic_ns() + 5_000_000_000
                peer = Worker("local-fixture", "test", os.getpid(), os.getuid())
                tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                with tx, rx:
                    send_original(tx, fd, peer=peer, identity=identity, token=b"fixture", due_ns=due)
                    with receive_original(rx, peer=peer, identity=identity, token=b"fixture", due_ns=due) as reader:
                        result = io.BytesIO()
                        self.assertEqual(reader.read_and_close(result, due_ns=due).bytes_read, len(body))
                    self.assertEqual(result.getvalue(), body)
                    self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 2)
            finally:
                os.close(fd)
