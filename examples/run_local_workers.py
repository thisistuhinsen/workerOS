"""Run a finite cohort of trusted local executables without file bindings."""

from subprocess import TimeoutExpired
import sys
from time import monotonic_ns

from worker_handoff import CleanupStatus, DirectChildSupervisor, SupervisionStartError

SECOND = 1_000_000_000


def stop_unpinned_child(child):
    # This is the caller's own direct child. Supervision never accepted it.
    child.terminate()
    try:
        child.wait(timeout=1)
    except TimeoutExpired:
        child.kill()
        child.wait(timeout=1)


def run_cohort(jobs, *, wait_ns=5 * SECOND):
    """jobs = (name, application role, trusted argv) triples.

    A single caller drives this supervisor. Do not wait on its Popen handles
    from elsewhere. The optional cleanup here applies only to these children.
    """
    supervisor = DirectChildSupervisor()
    workers = []
    outcomes = {}
    cleanup = {}
    try:
        for name, role, argv in jobs:
            try:
                worker = supervisor.start_executable(
                    name, role, argv, due_ns=monotonic_ns() + 5 * SECOND, env={},
                )
            except SupervisionStartError as exc:
                # Startup may have had an effect. Reconcile it, don't retry.
                stop_unpinned_child(exc.process)
                raise
            workers.append(worker)

        for worker in workers:
            deadline = monotonic_ns() + wait_ns
            outcomes[worker.name] = supervisor.wait(worker.name, due_ns=deadline)
    finally:
        # Use a fresh bound for each direct child. Even if cleanup is pending,
        # keep or report that outcome rather than claim the child stopped.
        for worker in workers:
            receipt = supervisor.cleanup(worker.name, due_ns=monotonic_ns() + 2 * SECOND)
            cleanup[worker.name] = receipt
            if receipt.status is not CleanupStatus.REAPED:
                print(f"{worker.name}: cleanup {receipt.status.value}", file=sys.stderr)
    return outcomes, cleanup


def main():
    demo = [
        ("thumbnail", "renderer", [sys.executable, "-c", "print('rendered')"]),
        ("catalog", "sync", [sys.executable, "-c", "print('synced')"]),
        ("checks", "auditor", [sys.executable, "-c", "print('audited')"]),
    ]
    outcomes, cleanup = run_cohort(demo)
    for name, result in outcomes.items():
        print(f"{name}: {result.lifecycle.value}; exit {result.returncode}; "
              f"cleanup {cleanup[name].status.value}")
    return int(any(result.returncode != 0 for result in outcomes.values()) or
               any(receipt.status is not CleanupStatus.REAPED for receipt in cleanup.values()))


if __name__ == "__main__":
    raise SystemExit(main())
