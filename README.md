# workerOS

workerOS is a small Linux library for handing an original file to local workers without copying it by pathname, starting another service, or adopting a queue. A Python application can register existing workers or launch trusted executables written in any language that can use an inherited Linux file descriptor.

## What works today

- **Write:** write and flush a file through an explicit writable descriptor.
- **Read:** pass a read-only descriptor over a connected Unix socket or inherit it at launch. Positional reads preserve a shared file offset.
- **Observe:** sample the local file identity, access mode, owner, and size without reading its contents.
- **Launch:** run a trusted argv without a shell and join for an observed exit status. Multiple workers can have the same role.

The library has no runtime dependencies and requires Linux and Python 3.11 or later. The default Linux paths require Unix-domain sockets with descriptor passing. Advanced supervision and independent custody verification are not in this baseline. Ordinary same-user observations are not proof of isolation, exclusion of other writers, or an independent audit. A timeout is not proof that a write had no effect.

## Quick start

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
cc -std=c11 -Wall -Wextra -Werror examples/report_worker.c -o /tmp/workeros-report
python examples/run_local_report.py /tmp/workeros-report
```

The native example runs one writer, two readers and two observers against one disposable file. The parent and launched workers share an open file description; do not close or rebind the parent's descriptor during launch. Child bindings use `WORKER_HANDOFF_FD_<KEY>` with ABI version `WORKER_HANDOFF_ABI=1`. The variable identifies the inherited descriptor; it is not itself authorization. Writers, readers and observers are application roles, not OS accounts.

## Verify on your system

From the repository root run `bash scripts/check-linux.sh`. It builds a wheel, installs that wheel into a fresh virtual environment, and runs the tests against the installed package. The public CI workflow records its Linux kernels, userspaces, architecture and Python versions. Container jobs check userspace compatibility on the runner kernel, not a separate kernel. WSL2 requires a separately observed run on an actual WSL2 system.

Use the project only with application-authorized files, workers and peers. It does not create users, grant permissions, auto-retry writes, or take ownership of externally registered processes.
