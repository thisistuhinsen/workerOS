"""Exercise the separately compiled Maven consumer through the installed Python worker roster."""

from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns

from workeros import WorkerRoster


def main(classpath):
    java = shutil.which("java")
    if java is None:
        raise RuntimeError("java is required")
    command = [java, "--enable-native-access=ALL-UNNAMED", "-cp", classpath, "Consume"]
    roster = WorkerRoster()
    with TemporaryDirectory() as work:
        path = Path(work) / "input"
        path.write_bytes(b"Worker")
        for mode in ("rb", "r+b"):
            with path.open(mode, buffering=0) as original:
                fd = original.fileno()
                original.seek(5)
                due = monotonic_ns() + 20_000_000_000
                worker = roster.start_executable(mode, "reader", command, fds={"INPUT": fd}, due_ns=due)
                try:
                    assert roster.join(mode, due_ns=due) == 0
                finally:
                    if worker.process.poll() is None:
                        worker.process.kill()
                        worker.process.wait(timeout=5)
                assert original.tell() == 5

        with path.open("rb") as original:
            fd = original.fileno()
            facts = os.fstat(fd)
            abi = {"WORKER_HANDOFF_ABI": "1", "WORKER_HANDOFF_FD_INPUT": str(fd),
                   "WORKER_HANDOFF_DEV_INPUT": str(facts.st_dev),
                   "WORKER_HANDOFF_INO_INPUT": str(facts.st_ino), "WORKER_HANDOFF_ACCESS_INPUT": "read"}
            for name, field, value in (
                ("bad binding", None, None), ("absent binding", None, None),
                ("wrong ABI", "ABI", "2"), ("standard stream", "FD_INPUT", "1"),
                ("noncanonical FD", "FD_INPUT", f"0{fd}"), ("FD overflow", "FD_INPUT", "2147483648"),
                ("wrong device", "DEV_INPUT", str(facts.st_dev + 1)),
                ("wrong inode", "INO_INPUT", str(facts.st_ino + 1)),
                ("invalid identity", "INO_INPUT", "-1"), ("wrong access", "ACCESS_INPUT", "read-write"),
            ):
                binding = {"bad binding": "Input", "absent binding": "MISSING"}.get(name, "INPUT")
                env = dict(abi)
                if field:
                    env[f"WORKER_HANDOFF_{field}"] = value
                subprocess.run([*command, binding], env=env, pass_fds=(fd,), check=True, timeout=10)
                print(f"PASS Java refusal: {name}")
        with ExitStack() as descriptors:
            pipe, pipe_writer = os.pipe()
            descriptors.callback(os.close, pipe)
            descriptors.callback(os.close, pipe_writer)
            path_fd = os.open(path, os.O_PATH)
            descriptors.callback(os.close, path_fd)
            write_fd = os.open(path, os.O_WRONLY)
            descriptors.callback(os.close, write_fd)
            for label, special in (("pipe", pipe), ("O_PATH", path_fd), ("write-only", write_fd)):
                facts = os.fstat(special)
                env = {**abi, "WORKER_HANDOFF_FD_INPUT": str(special),
                       "WORKER_HANDOFF_DEV_INPUT": str(facts.st_dev),
                       "WORKER_HANDOFF_INO_INPUT": str(facts.st_ino)}
                subprocess.run([*command, "INPUT"], env=env, pass_fds=(special,), check=True, timeout=10)
                print(f"PASS Java refusal: {label}")
    print("PASS Maven consumer: read and read-write originals, shared offset and handle lifetime")


if __name__ == "__main__":
    main(sys.argv[1])
