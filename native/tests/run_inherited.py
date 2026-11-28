"""Run installed Conan C and C++ consumers against the Python launcher."""

from pathlib import Path
import os
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns

from workeros import WorkerRoster


def launch(label, executable, fd):
    roster = WorkerRoster()
    deadline = monotonic_ns() + 5_000_000_000
    os.lseek(fd, 2, os.SEEK_SET)
    worker = roster.start_executable(label, "read", [str(executable)],
                                     fds={"INPUT": fd}, due_ns=deadline, env={})
    status = roster.join(worker.name, due_ns=deadline)
    if status is None:
        worker.process.kill()
        worker.process.wait(timeout=5)
    if status != 0:
        raise RuntimeError(f"{label} consumer failed with exit status {status}")
    if os.lseek(fd, 0, os.SEEK_CUR) != 2:
        raise RuntimeError(f"{label} consumer moved the shared offset")


def refusals(executable, source):
    with source.open("rb", buffering=0) as reader:
        fd = reader.fileno()
        path_fd = os.open(source, os.O_PATH | os.O_CLOEXEC)
        try:
            actual = os.fstat(fd)
            valid = {
                "WORKER_HANDOFF_ABI": "1",
                "WORKER_HANDOFF_FD_INPUT": str(fd),
                "WORKER_HANDOFF_DEV_INPUT": str(actual.st_dev),
                "WORKER_HANDOFF_INO_INPUT": str(actual.st_ino),
                "WORKER_HANDOFF_ACCESS_INPUT": "read",
            }
            for owned_by_fixture, key, value in (
                (fd, "WORKER_HANDOFF_ABI", "2"),
                (fd, "WORKER_HANDOFF_FD_INPUT", f"0{fd}"),
                (fd, "WORKER_HANDOFF_FD_INPUT", "2"),
                (path_fd, "WORKER_HANDOFF_FD_INPUT", str(path_fd)),  # same identity, O_PATH
                (fd, "WORKER_HANDOFF_DEV_INPUT", str(actual.st_dev + 1)),
                (fd, "WORKER_HANDOFF_INO_INPUT", str(actual.st_ino + 1)),
                (fd, "WORKER_HANDOFF_ACCESS_INPUT", "write"),
                (fd, "WORKER_HANDOFF_ACCESS_INPUT", "read-write"),  # kernel says read
            ):
                subprocess.run(
                    [str(executable), str(owned_by_fixture)], env={**valid, key: value},
                    pass_fds=(fd, path_fd), check=True, timeout=5,
                )
        finally:
            os.close(path_fd)


def main(c_executable, cpp_executable):
    with TemporaryDirectory(prefix="workeros-conan-input-") as directory:
        source = Path(directory) / "original"
        contents = b"Worker handoff\n"
        source.write_bytes(contents)
        for label, executable in (("C", c_executable), ("C++", cpp_executable)):
            for access in (os.O_RDONLY, os.O_RDWR):
                fd = os.open(source, access | os.O_CLOEXEC)
                try:
                    launch(label, executable, fd)
                finally:
                    os.close(fd)
            refusals(executable, source)
            print(f"{label}: PASSED (Conan consumer, inherited ABI, offset, ownership, and refusals)")
        if source.read_bytes() != contents:
            raise RuntimeError("consumer changed the original content")


if __name__ == "__main__":
    main(*(Path(value).resolve(strict=True) for value in sys.argv[1:]))
