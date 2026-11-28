"""Small, installed walkthrough for supervised local jobs."""

import argparse
from contextlib import ExitStack, contextmanager
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from time import monotonic_ns
from uuid import uuid4

from .supervisor import CleanupStatus, DirectChildSupervisor, LifecycleStatus, SupervisionStartError
from .result_export import RESULT_VERSION, _open_directory, can_export, export_report, report_path


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


def _emit_result(result, *, attempt_id, destination=None):
    receipt = {'version': RESULT_VERSION, 'attempt_id': attempt_id,
               'persistence': 'not_recorded', **result}
    exported = None
    if destination is not None:
        exported = export_report(destination, receipt)
        if exported['status'] != 'written':
            exported['next_action'] = 'save_this_receipt_without_rerunning'
        receipt['export'] = exported
    print(json.dumps(receipt, separators=(',', ':')))
    return exported is None or exported['status'] == 'written'


def run_json_main(args):
    """Parse local machine-mode options before a literal command separator."""
    attempt_id = 'attempt-' + uuid4().hex
    split = args.index('--') if '--' in args else len(args)
    if split >= len(args) - 1:
        _emit_result({"status": "refused", "effect": "not_attempted", "code": "json_command_required"},
                     attempt_id=attempt_id)
        return 1
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False, exit_on_error=False)
    for flag, dest in (('--cwd', 'cwd'), ('--stdout', 'stdout_path'), ('--stderr', 'stderr_path'),
                       ('--report', 'report')):
        parser.add_argument(flag, dest=dest, action='append', default=[])
    try:
        values, unknown = parser.parse_known_args(args[:split])
        if unknown or any(len(entries) > 1 for entries in vars(values).values()):
            raise ValueError('invalid local run options')
    except (argparse.ArgumentError, ValueError):
        _emit_result({"status": "refused", "effect": "not_attempted", "code": "invalid_local_run_options"},
                     attempt_id=attempt_id)
        return 1
    return _run_json(args[split + 1:], attempt_id, **{key: entries[0] if entries else None
                                                     for key, entries in vars(values).items()})


class _LocalDestinationError(ValueError):
    pass


def _close_local_handle(descriptor):
    # A close error on the parent's copy cannot establish that the worker
    # did not start or that its raw capture is complete.
    try:
        os.close(descriptor)
    except OSError:
        pass


def _discard_capture(directory, name, descriptor):
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
            os.unlink(name, dir_fd=directory)
    except OSError:
        pass


def _open_capture(value, handles, discard):
    try:
        path = report_path(value)
    except ValueError as exc:
        raise _LocalDestinationError('invalid_capture_destination') from exc
    try:
        directory = _open_directory(path.parent)
        handles.callback(_close_local_handle, directory)
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        handles.callback(_close_local_handle, descriptor)
        discard.callback(_discard_capture, directory, path.name, descriptor)
        return descriptor
    except OSError as exc:
        code = {
            errno.EEXIST: 'capture_destination_exists',
            errno.ENOENT: 'capture_parent_missing',
            errno.ENOTDIR: 'capture_parent_unavailable',
            errno.ELOOP: 'capture_parent_unavailable',
            errno.EACCES: 'capture_destination_denied',
            errno.EPERM: 'capture_destination_denied',
            errno.ENOSPC: 'capture_storage_exhausted',
            errno.EDQUOT: 'capture_storage_exhausted',
        }.get(exc.errno, 'capture_open_failed')
        raise _LocalDestinationError(code) from exc


@contextmanager
def _start_options(cwd, stdout_path, stderr_path):
    options = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
    with ExitStack() as handles, ExitStack() as discard:
        try:
            if (cwd is not None or stdout_path is not None or stderr_path is not None) and not can_export():
                raise _LocalDestinationError('unprivileged_local_paths_required')
            if cwd is not None:
                try:
                    value = os.fspath(cwd)
                    if not value or '\x00' in value:
                        raise ValueError('invalid working directory')
                    path = Path(value)
                    directory = _open_directory(path if path.is_absolute() else Path.cwd() / path)
                    handles.callback(_close_local_handle, directory)
                    options['cwd'] = f'/proc/self/fd/{directory}'
                except (OSError, TypeError, ValueError) as exc:
                    raise _LocalDestinationError('working_directory_unavailable') from exc
            for stream, value in (('stdout', stdout_path), ('stderr', stderr_path)):
                if value is not None:
                    options[stream] = _open_capture(value, handles, discard)
        except KeyboardInterrupt as exc:
            raise _LocalDestinationError('capture_preparation_interrupted') from exc
        try:
            yield options
        except (SupervisionStartError, KeyboardInterrupt):
            # Child creation may already have happened. Keep the caller's capture files.
            discard.pop_all()
            raise
        else:
            discard.pop_all()


def run_json(argv, *, wait_seconds=5, cwd=None, stdout_path=None, stderr_path=None, report=None):
    """Run one direct child and emit one structured, effect-cautious result."""
    return _run_json(argv, 'attempt-' + uuid4().hex, wait_seconds=wait_seconds, cwd=cwd,
                     stdout_path=stdout_path, stderr_path=stderr_path, report=report)


def _run_json(argv, attempt_id, *, wait_seconds=5, cwd=None, stdout_path=None, stderr_path=None, report=None):
    from .configuration import _clean, _terminal, _wire
    from .supervisor import CleanupResult, SupervisionResult

    try:
        destination = report_path(report) if report is not None else None
    except ValueError:
        _emit_result({"status": "refused", "effect": "not_attempted", "code": "invalid_report_destination"},
                     attempt_id=attempt_id)
        return 1

    def emit(result):
        return _emit_result(result, attempt_id=attempt_id, destination=destination)

    if not argv or any(type(arg) is not str or "\x00" in arg for arg in argv):
        emit({"status": "refused", "effect": "not_attempted",
                      "code": "command_required"})
        return 1
    due_ns = monotonic_ns() + wait_seconds * SECOND
    cleanup_due_ns = due_ns + 2 * SECOND
    supervisor = DirectChildSupervisor()
    interrupted = None
    started = False
    try:
        with _start_options(cwd, stdout_path, stderr_path) as options:
            supervisor.start_executable("run", "command", argv, due_ns=due_ns, **options)
            started = True
    except _LocalDestinationError as exc:
        emit({"status": "refused", "effect": "not_attempted", "code": str(exc)})
        return 1
    except KeyboardInterrupt as exc:
        if not started:
            emit({"status": "unavailable", "effect": "unknown", "code": "launch_interrupted"})
            return 1
        interrupted = exc
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
        emit(reply)
        return 1
    except (OSError, RuntimeError, ValueError):
        emit({"status": "refused", "effect": "not_attempted",
                      "code": "command_start_failed"})
        return 1

    try:
        if interrupted is not None:
            raise interrupted
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
    exported = emit(reply)
    return int(not (lifecycle == LifecycleStatus.EXITED.value and result.returncode == 0
                    and cleanup.status is CleanupStatus.REAPED and status == "reported" and exported))
