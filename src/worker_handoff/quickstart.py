"""Small, installed walkthrough for supervised local jobs."""

import argparse
import subprocess
import sys
from time import monotonic_ns

from .supervisor import CleanupStatus, DirectChildSupervisor, LifecycleStatus, SupervisionStartError


SECOND = 1_000_000_000


def _run(label, command, wait_seconds):
    # A new supervisor owns each invocation, including reuse of a display label.
    jobs = DirectChildSupervisor()
    deadline = monotonic_ns() + wait_seconds * SECOND
    cleanup_deadline = deadline + 2 * SECOND
    try:
        worker = jobs.start_executable(label, "demo", command, due_ns=deadline)
    except SupervisionStartError as exc:
        print(f"{label}: started; checking cleanup after a supervision error", file=sys.stderr)
        try:
            remaining = max(0, cleanup_deadline - monotonic_ns())
            if remaining:
                exc.process.kill()
            exc.process.wait(timeout=remaining / SECOND)
        except (OSError, subprocess.TimeoutExpired):
            print(f"cleanup: unconfirmed (PID {exc.process.pid})", file=sys.stderr)
        else:
            print("cleanup: reaped", file=sys.stderr)
        print("Check any effects before trying again.", file=sys.stderr)
        return None
    except (OSError, RuntimeError) as exc:
        print(f"{label}: could not start: {exc}", file=sys.stderr)
        return None

    result = jobs.wait(label, due_ns=deadline, cleanup_due_ns=cleanup_deadline)
    status = result.lifecycle.value.replace("_", " ")
    cleanup = result.cleanup
    if result.lifecycle is LifecycleStatus.EXITED:
        print(f"{label}: {status} {result.returncode}", flush=True)
    else:
        print(f"{label}: {status}", flush=True)
        if cleanup.status is CleanupStatus.NOT_REQUESTED:
            cleanup = jobs.cleanup(label, due_ns=cleanup_deadline)
        print(f"cleanup: {cleanup.status.value}", flush=True)
        if cleanup.status is not CleanupStatus.REAPED:
            print(f"Child shutdown is unconfirmed (PID {worker.pid}). Check its state and effects before retrying.",
                  file=sys.stderr)
    return result.lifecycle, cleanup.status, result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the WorkerOS report and timeout demo, or one trusted command.")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="use -- COMMAND ARG ... for your own local job")
    command = parser.parse_args(argv).command
    if command:
        if command[0] != "--" or len(command) < 2:
            parser.error("use -- COMMAND ARG ... to run a command")
        result = _run("job", command[1:], 5)
        if result is not None and result[0] is LifecycleStatus.EXITED and result[2] == 0:
            return 0
        print("Check any effects before trying again.", file=sys.stderr)
        return 1

    report = (
        "import shutil; "
        "print('Disk report:', shutil.disk_usage('.').free // 2**30, 'GiB free')"
    )
    result = _run("report", (sys.executable, "-c", report), 5)
    if result is None or result[0] is not LifecycleStatus.EXITED or result[2] != 0:
        return 1
    slow = _run("slow job", (sys.executable, "-c", "import time; time.sleep(10)"), 1)
    return int(slow is None or slow[:2] != (LifecycleStatus.TIMED_OUT, CleanupStatus.REAPED))
