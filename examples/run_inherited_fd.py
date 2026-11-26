"""Run read-only FD ABI examples against the installed workerOS wheel."""

import argparse
from importlib.metadata import version
import os
from pathlib import Path
import re
from shutil import which
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns


EXAMPLES = Path(__file__).resolve().parent
LANGUAGES = {
    "c": "C",
    "cpp": "C++",
    "go": "Go",
    "java": "Java",
    "node": "Node.js",
    "python": "Python",
    "rust": "Rust",
}


class ToolchainUnavailable(Exception):
    """An executable needed to build or launch a worker is missing or unsuitable."""


def tool(name):
    executable = which(name)
    if executable is None:
        raise ToolchainUnavailable(f"{name} was not found on PATH")
    return executable


def tool_version(executable, flag, expected):
    try:
        probe = subprocess.run(
            [executable, flag], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ToolchainUnavailable(f"{executable} {flag}: {error}") from error
    match = re.search(expected, probe.stdout)
    if probe.returncode or match is None:
        first_line = probe.stdout.strip().splitlines()[:1]
        detail = " ".join(first_line) or f"exit status {probe.returncode}"
        raise ToolchainUnavailable(f"{executable} {flag}: {detail}")
    return match


def build(args, *, env=None):
    subprocess.run(args, timeout=120, check=True, env=env)


def worker_command(language, output):
    if language == "python":
        return [sys.executable, "-I", str(EXAMPLES / "read_worker.py")]
    if language == "node":
        return [tool("node"), str(EXAMPLES / "read_worker.cjs")]
    if language == "java":
        java = tool("java")
        runtime = int(tool_version(java, "-version", r'version "(\d+)').group(1))
        if runtime < 22:
            raise ToolchainUnavailable(f"Java runtime {runtime} found, JDK 22+ is required")
        javac = tool("javac")
        compiler = int(tool_version(javac, "-version", r"\bjavac (\d+)").group(1))
        if compiler < 22:
            raise ToolchainUnavailable(f"javac {compiler} found, JDK 22+ is required")
        classes = output / "java-classes"
        classes.mkdir()
        build([javac, "--release", "22", "-d", str(classes), str(EXAMPLES / "ReadWorker.java")])
        return [java, "--enable-native-access=ALL-UNNAMED", "-cp", str(classes), "ReadWorker"]

    executable = str(output / f"read-worker-{language}")
    if language == "go":
        go = tool("go")
        tool_version(go, "version", r"\bgo version go\d+\.\d+")
        env = dict(os.environ, GOCACHE=str(output / "go-cache"), GOTOOLCHAIN="local", GOPROXY="off")
        build([go, "build", "-o", executable, str(EXAMPLES / "read_worker.go")], env=env)
    elif language == "rust":
        rustc = tool("rustc")
        tool_version(rustc, "--version", r"\brustc \d+\.\d+")
        build([rustc, "--edition=2021", str(EXAMPLES / "read_worker.rs"), "-o", executable])
    else:
        compiler, standard, source = {
            "c": ("cc", "c11", "read_worker.c"),
            "cpp": ("c++", "c++17", "read_worker.cpp"),
        }[language]
        build([tool(compiler), f"-std={standard}", "-Wall", "-Wextra", "-Werror",
               str(EXAMPLES / source), "-o", executable])
    return [executable]


def run_worker(language, argv, fd, roster):
    os.lseek(fd, 2, os.SEEK_SET)
    deadline = monotonic_ns() + 10_000_000_000
    worker = roster.start_executable(language, "read", argv, fds={"INPUT": fd}, due_ns=deadline)
    try:
        status = roster.join(language, due_ns=deadline)
    finally:
        if worker.process.poll() is None:
            worker.process.kill()
            worker.process.wait(timeout=5)
    if status is None:
        raise TimeoutError("worker deadline expired")
    if status != 0:
        raise RuntimeError(f"worker exited with status {status}")
    if os.lseek(fd, 0, os.SEEK_CUR) != 2:
        raise RuntimeError("worker changed the shared file offset")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", action="append", choices=LANGUAGES,
                        help="require this example to pass (repeat to select several, defaults to discovery)")
    args = parser.parse_args()
    selected = set(args.language or LANGUAGES)
    required = args.language is not None
    if sys.platform != "linux":
        for language, label in LANGUAGES.items():
            target = "64-bit Linux" if language == "java" else "Linux"
            reason = f"{target} required" if language in selected else "language was not selected"
            print(f"{label}: SKIPPED ({reason})", flush=True)
        return int(required)

    import worker_handoff

    print(f"workerOS {version('workeros')} from {worker_handoff.__file__}", flush=True)

    failed = False
    with TemporaryDirectory(prefix="workeros-examples-") as directory:
        output = Path(directory)
        original = output / "original.txt"
        original.write_bytes(b"Worker input\n")
        roster = worker_handoff.WorkerRoster()
        with original.open("rb", buffering=0) as file:
            for language, label in LANGUAGES.items():
                if language not in selected:
                    print(f"{label}: SKIPPED (language was not selected)", flush=True)
                    continue
                if language == "java" and struct.calcsize("P") != 8:
                    failed = failed or required
                    print(f"{label}: SKIPPED (64-bit Linux required)", flush=True)
                    continue
                try:
                    command = worker_command(language, output)
                    run_worker(language, command, file.fileno(), roster)
                except ToolchainUnavailable as error:
                    failed = failed or required
                    print(f"{label}: UNAVAILABLE ({error})", flush=True)
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    failed = True
                    print(f"{label}: FAILED ({error})", flush=True)
                else:
                    print(f"{label}: PASSED (worker exited 0 and kept the shared offset)", flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
