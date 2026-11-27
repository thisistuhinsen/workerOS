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


def run_json(argv, *, wait_seconds=5):
    """Run one direct child and emit one structured, effect-cautious result."""
    import json
    from .configuration import _clean, _terminal, _wire
    from .supervisor import CleanupResult, SupervisionResult

    if not argv or any(type(arg) is not str or "\x00" in arg for arg in argv):
        print(json.dumps({"status": "refused", "effect": "not_attempted",
                          "code": "command_required"}, separators=(",", ":")))
        return 1
    due_ns = monotonic_ns() + wait_seconds * SECOND
    cleanup_due_ns = due_ns + 2 * SECOND
    supervisor = DirectChildSupervisor()
    try:
        supervisor.start_executable(
            "run", "command", argv, due_ns=due_ns, stdout=2, stderr=2)
    except SupervisionStartError as exc:
        process = exc.process
        reaped = False
        try:
            remaining = max(0, cleanup_due_ns - monotonic_ns())
            if process.poll() is None and remaining:
                process.kill()
            process.wait(timeout=max(0, cleanup_due_ns - monotonic_ns()) / SECOND)
            reaped = True
        except (OSError, subprocess.TimeoutExpired):
            pass
        cleanup = CleanupResult(CleanupStatus.REAPED if reaped else CleanupStatus.PENDING,
                                process.returncode)
        terminal = _wire(_terminal(SupervisionResult(
            LifecycleStatus.UNKNOWN, cleanup, process.returncode,
            exc.__cause__ if isinstance(exc.__cause__, OSError) else None)))
        reply = {"status": "unavailable", "effect": "unknown",
                 "code": "supervision_pin_unavailable", "result": {"terminal": terminal}}
        print(json.dumps(reply, separators=(",", ":")))
        return 1
    except (OSError, RuntimeError, ValueError):
        print(json.dumps({"status": "refused", "effect": "not_attempted",
                          "code": "command_start_failed"}, separators=(",", ":")))
        return 1

    try:
        result = supervisor.wait("run", due_ns=due_ns, cleanup_due_ns=cleanup_due_ns)
    except (OSError, RuntimeError, KeyboardInterrupt) as exc:
        try:
            cleanup = supervisor.cleanup("run", due_ns=cleanup_due_ns)
        except (OSError, RuntimeError, KeyboardInterrupt):
            cleanup = CleanupResult(CleanupStatus.PENDING)
        result = SupervisionResult(LifecycleStatus.UNKNOWN, cleanup, error=exc)
    cleanup = result.cleanup
    if cleanup.status is CleanupStatus.NOT_REQUESTED:
        try:
            cleanup = supervisor.cleanup("run", due_ns=cleanup_due_ns)
        except (OSError, ValueError):
            # wait() already observed and reaped an EXITED child; a failure
            # to make the follow-up read does not erase that direct evidence.
            if result.lifecycle is LifecycleStatus.EXITED and result.error is None:
                cleanup = CleanupResult(CleanupStatus.REAPED, result.returncode)
    terminal = _terminal(result)
    terminal["cleanup"] = _clean(cleanup)
    terminal = _wire(terminal)
    lifecycle = result.lifecycle.value
    status = "unavailable" if lifecycle == "unknown" or result.error is not None else "reported"
    reply = {"status": status, "effect": "unknown", "result": {"terminal": terminal}}
    if status == "unavailable":
        reply["code"] = "terminal_result_unavailable"
    print(json.dumps(reply, separators=(",", ":")))
    return int(not (lifecycle == LifecycleStatus.EXITED.value and result.returncode == 0
                    and cleanup.status is CleanupStatus.REAPED and status == "reported"))
