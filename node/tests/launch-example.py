"""Run a Node example through a real inherited WorkerRoster descriptor."""

import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns

from workeros import WorkerRoster


def main(node, example):
    with TemporaryDirectory(prefix="workeros-node-fd-") as directory:
        path = Path(directory) / "input"
        path.write_bytes(b"Worker input\n")
        with path.open("rb", buffering=0) as original:
            path.rename(Path(directory) / "renamed-input")
            path.write_bytes(b"Replacement input\n")
            fd = original.fileno()
            os.lseek(fd, 2, os.SEEK_SET)
            deadline = monotonic_ns() + 10_000_000_000
            roster = WorkerRoster()
            worker = roster.start_executable(
                "node-example", "read", [node, example], fds={"INPUT": fd}, due_ns=deadline,
            )
            try:
                status = roster.join(worker.name, due_ns=deadline)
            finally:
                if worker.process.poll() is None:
                    worker.process.kill()
                    worker.process.wait(timeout=5)
            if status != 0:
                raise RuntimeError(f"Node worker failed with status {status}")
            if os.lseek(fd, 0, os.SEEK_CUR) != 2:
                raise RuntimeError("Node worker changed the shared offset")


if __name__ == "__main__":
    main(*sys.argv[1:])
