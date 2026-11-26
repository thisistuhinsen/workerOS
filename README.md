# workerOS

workerOS is a small Linux library for handing an original file to local workers without copying it by pathname, starting another service, or adopting a queue. A Python application can register existing workers or launch trusted executables written in any language that can use an inherited Linux file descriptor.

## What works today

- **Write:** write and flush a file through an explicit writable descriptor.
- **Read:** pass a read-only descriptor over a connected Unix socket or inherit it at launch. Positional reads preserve a shared file offset.
- **Observe:** sample the local file identity, access mode, owner, and size without reading its contents.
- **Launch:** run a trusted argv without a shell and join for an observed exit status. Multiple workers can have the same role.

The library has no runtime dependencies and requires Linux and Python 3.11 or later. Version 0.3 preserves the v0.2 APIs, Unix-stream descriptor-passing frame, and inherited FD ABI.

## Quick start

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
cc -std=c11 -Wall -Wextra -Werror examples/report_worker.c -o /tmp/workeros-report
python examples/run_local_report.py /tmp/workeros-report
```

The native example runs one writer, two readers and two observers against one disposable file. The parent and launched workers share an open file description; do not close or rebind the parent's descriptor during launch. Child bindings use `WORKER_HANDOFF_FD_<KEY>` with ABI version `WORKER_HANDOFF_ABI=1`. The variable identifies the inherited descriptor; it is not itself authorization. Writers, readers and observers are application roles, not OS accounts.

### Examples from the installed wheel

```sh
python -I "$(python -c 'import sys; print(sys.prefix)')/share/worker-handoff/examples/run_inherited_fd.py"
```

The launcher builds and runs separate C, C++, Go, Java, Node.js, Python and Rust workers. Each worker reads from `WORKER_HANDOFF_FD_INPUT` at offset zero and closes its descriptor. The launcher checks the parent offset and worker exit status. Java requires a JDK version 22 or newer on 64-bit Linux. Use `--language` to select individual examples. The launcher reports missing or incompatible toolchains separately from build and execution failures.

## Managed release

`release_executable` is the managed boundary for handing one read-only `INPUT` to a trusted executable. It takes a frozen `ReleasePlan`, a caller-owned read-only file descriptor and an authorization callback. The callback must return `True` for the exact plan, which includes the file identity, worker name, role, absolute executable argv and deadline. Keep the original descriptors and their status flags stable until the call returns. The child environment contains the ABI fields, and the application is responsible for the executable and its dependencies.

- To write before release, include a `PositionalWrite` and supply a writable descriptor for the same file. The library performs one positional write, refuses append-mode descriptors, and leaves a short or uncertain write for the caller to reconcile. File bytes may already have changed if delivery fails. A complete effect reports the byte count returned by the syscall. Durability requires a separate application policy.
- Set `exclusive_writer=True` for advisory exclusion among cooperating `flock` writers on the same file. The library takes a nonblocking lock on an independent open description of the pinned descriptor through Linux procfs. It holds the lock through dispatch and closes the description on exit from that step. The lock's scope is the actual file and callers using the same locking protocol.
- Set `supervisor=DirectChildSupervisor()` to wait for a direct child to exit, reach the monotonic deadline or receive a cancellation event. Supply a separate `cleanup_due_ns` to request bounded termination and reaping after timeout or cancellation. The supervisor uses Linux pidfds. An observed external process stays under its owner's control. `adopt` explicitly transfers sole wait and signal authority for a caller-owned, waitable direct `Popen` child. Descendants and process groups remain the application's responsibility.
- Set `strict_custody=True` to require independent pre-grant evidence. A deployment can configure `IndependentCustody` with a connected Unix sequenced-packet socket and an observer PID and UID pinned by trusted configuration. The release consumes that endpoint when it checks custody. The trusted observer must cover the exact `plan.custody_scope`, provenance, earlier grants and retirements, and applicable exclusion through the grant window. Review the protocol in `worker_handoff.custody`. Missing, unqualified or untimely evidence stops both the write and the release. Deployments provide their own independent observer.

`ReleaseResult` records delivery, write effect, custody evidence, lifecycle and local descriptor cleanup separately. A successful dispatch records child creation. A custody receipt records authenticated pre-grant attestation. Child cleanup is available separately under `lifecycle.cleanup`. If a child starts and its supervisor cannot pin it, the result returns the live process handle for explicit reconciliation.

## Verify on your system

From the repository root run `bash scripts/check-linux.sh`. It builds a wheel, installs it offline into a fresh virtual environment, runs the tests against the installed package and runs the examples shipped in the wheel. The public CI workflow records its Linux kernels, userspaces, architecture and Python versions. Container jobs check userspace compatibility on the runner kernel. WSL2 requires a separately observed run on an actual WSL2 system.

Use the project only with application-authorized files, workers and peers. It does not create users, grant permissions, auto-retry writes, or take ownership of externally registered processes.
