# WorkerOS 0.8.0 API reference

The v0.8.0 distribution and Python import are both `workeros`. See the
[published v0.7.0 reference](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/api.md)
for the installed v0.7.0 names. Use
Python 3.11+ on Linux. [Install and run an example](../README.md#install-and-run) or
check the [platform and verification matrix](support.md). The Python launcher
can run any trusted executable, including tools that need no file inputs.

Use absolute `time.monotonic_ns()` deadlines where an API accepts `due_ns`.
Create a fresh deadline for a later cleanup attempt. Keep launch, file
effects, child exit, and cleanup results separate when deciding whether to retry.

For the opt-in JSON controller and recorder policy, see [Configure a workerOS
application](configuration.md). The APIs below remain available directly.

## Launch and supervise workers

[Worker roster source](../src/workeros/workers.py) ·
[Direct-child supervisor source](../src/workeros/supervisor.py)

`Worker(name, role, pid, uid=None, process=None)` describes a worker. Names
and roles are application labels. The optional UID is expected or reported
metadata and does not change the child's operating-system identity.

| API | Use |
| --- | --- |
| `WorkerRoster.start(name, role, target, *, args=(), context=None, uid=None)` | Start an importable synchronous Python handler, using multiprocessing spawn by default. Pass arguments as a tuple and guard startup with `if __name__ == "__main__"`. |
| `WorkerRoster.start_executable(name, role, argv, *, due_ns, fds=None, env=None, uid=None, cwd=None, stdin=None, stdout=None, stderr=None)` | Start a trusted argv without a shell and optionally bind file descriptors for [ABI v1](#inherit-a-file-descriptor). |
| `WorkerRoster.external(name, role, *, pid, uid=None)` | Register an endpoint. Registration neither checks liveness nor takes wait or signal ownership. |
| `WorkerRoster.owned(name)` and `join(name, *, due_ns)` | Get the owned process handle and wait for its exit code. `join` returns `None` when a result is unavailable by the deadline. The process can still be running. Unowned names raise `KeyError`. |
| `DirectChildSupervisor.check_available(name, role)` | Check whether a name is free and whether Linux pidfds and `waitid(P_PIDFD)` are usable. |
| `DirectChildSupervisor.start_executable(...)` | Start the same executable ABI through a supervisor that pins the owned child. The parameters match the roster's executable method. |
| `DirectChildSupervisor.external(name, role, *, pid, uid=None)` | Register a process for observation only. A wait reports `OBSERVED`, and a cleanup request reports `OUTSIDE_SCOPE`. |
| `DirectChildSupervisor.adopt(name, role, process, *, uid=None)` | Transfer wait and signal authority for a caller-owned, waitable direct `subprocess.Popen` child. Stop polling or waiting on its handle after successful adoption. |
| `DirectChildSupervisor.wait(name, *, due_ns, cancel=None, cleanup_due_ns=None)` | Read a `SupervisionResult` for exit, timeout, cancellation, external registration, or an unknown outcome. Supply a `threading.Event` for cancellation and a separate deadline to request cleanup after timeout or cancellation. |
| `DirectChildSupervisor.cleanup(name, *, due_ns)` | Attempt bounded SIGTERM, SIGKILL if needed, and reap of the exact owned direct child. Use a fresh budget when an earlier cleanup is still pending. |

Drive each roster or supervisor from one control loop. Keep names unique for
the lifetime of that instance. Both executable launchers accept `cwd`,
`stdin`, `stdout` and `stderr` and pass them to `subprocess.Popen`. The
defaults inherit the parent's working directory and standard streams. Supply
opened streams or descriptors to redirect I/O. Drain output pipes while the
child runs. For a waitable `Popen` child you already own, use `adopt`.
A handler that is recognizable as an async
function or generator is refused at launch. A synchronous handler that
returns an awaitable or async generator fails in the child after running.
Its earlier effects may have happened. Other return values are ignored.

If process creation raises, a roster may retain a reserved name and an owned
process handle or placeholder. Reconcile the attempt before launching again.
`SupervisionStartError.process` is the actual caller-owned child when exec
succeeded but supervisor pinning failed.

`SupervisionResult` provides `lifecycle`, `returncode`, `cleanup`, and
`error`. An exit code may be nonzero or negative for a signal. The bounded
wait can end before process termination. The wait checks the child before
checking the deadline, so an exit it first collects at or after the cutoff
can still return `EXITED`. The return code describes the collected exit.
It supplies no timestamp for when the child physically exited. A `CleanupResult` supplies
`status`, its own `returncode`, signal-attempt flags, and `error`.
`REAPED` is actual direct-child cleanup. Other states are
`NOT_REQUESTED`, `OUTSIDE_SCOPE`, `PENDING`, and `UNKNOWN`. A normal
supervisor wait can reap the child with cleanup marked `NOT_REQUESTED`
because no explicit stop was requested. Calling `cleanup` on that owned
name can confirm the reap. Descendants and process groups remain under
the application's control.

This example starts one trusted local command without file inputs. For several
concurrent children, see [run_local_workers.py](../examples/run_local_workers.py).

```python
import sys
from time import monotonic_ns

from workeros import DirectChildSupervisor, SupervisionStartError

supervisor = DirectChildSupervisor()
deadline = monotonic_ns() + 5_000_000_000
try:
    worker = supervisor.start_executable(
        "hello", "demo", [sys.executable, "-c", "print('hello from the child')"],
        due_ns=deadline,
    )
except SupervisionStartError as exc:
    exc.process.kill()
    exc.process.wait(timeout=2)
    raise
result = supervisor.wait(
    worker.name, due_ns=deadline, cleanup_due_ns=deadline + 2_000_000_000,
)
print(result.lifecycle.value, result.returncode, result.cleanup.status.value)
```

## Inherit a file descriptor

Pass `fds={"INPUT": fd}` to either executable launcher. The caller keeps its
descriptor and must hold it stable through launch. The launcher accepts
non-inheritable regular-file FDs. Writable bindings additionally require a
caller-owned file and matching real and effective UIDs. `O_PATH` is a
metadata-only reference and is refused as a launch binding.

| ABI v1 field | Meaning |
| --- | --- |
| `WORKER_HANDOFF_ABI` | Version `1`. |
| `WORKER_HANDOFF_NAME`, `WORKER_HANDOFF_ROLE` | Application labels. |
| `WORKER_HANDOFF_DEADLINE_NS` | Absolute monotonic deadline provided at launch. |
| `WORKER_HANDOFF_FD_INPUT` | FD number in the child for binding `INPUT`. |
| `WORKER_HANDOFF_DEV_INPUT`, `WORKER_HANDOFF_INO_INPUT` | Device and inode observed by the launcher. |
| `WORKER_HANDOFF_ACCESS_INPUT` | `read`, `write`, or `read-write`. |

Replace `INPUT` with a binding matching `[A-Z][A-Z0-9_]*`. The child
inherits the named FDs. Standard streams are inherited unless redirected.
If `env` is omitted,
the launcher inherits the caller's environment after removing existing
`WORKER_HANDOFF_` entries. A supplied environment provides the base
map and must leave that prefix to the launcher.

An inherited descriptor refers to the same open file description, even if
the pathname changes. Position-based reads leave the shared file offset
unchanged. File contents can still change. The application authorizes access.
If the worker spawns a subprocess, close its binding or make it
non-inheritable first unless passing it on is intentional.

## Work with an open file

[Descriptor and transport source](../src/workeros/original.py)

| API | Ownership and result |
| --- | --- |
| `Identity(device, inode)` and `observe(fd)` | `Identity` names a file by device and inode. `observe` borrows the FD and returns an `Observation` with identity, access flags, owner UID, file mode, size, link count, inheritable flag, and timestamps. It reads metadata only. |
| `Original(fd, identity)` | Takes ownership of an exact non-inheritable read-only regular-file FD. `fileno()` borrows the numeric slot, `close()` releases it, and `detach()` transfers it to the caller. |
| `Original.read_and_close(sink, *, due_ns, expected_size=None, block_size=65536)` | Reads positionally into a binary sink, checks EOF and metadata, and closes the descriptor on completion or failure. Returns `ReadResult(original, bytes_read, eof_observed_ns, closed_ns)` on success. |
| `Writer(fd, identity)` | Takes ownership of an exact non-inheritable writable regular-file FD owned by the caller's actual Linux UID. `write(data)` uses the descriptor's current position and mode. `append(AppendWrite(data), due_ns=deadline)` makes one kernel-selected EOF write. `flush(sync=True)` calls `fsync`. `fileno()` borrows the slot. |

Use context managers to close owned wrappers. The constructors may close a
validly passed FD when validation fails. Pass a duplicate if you need to keep
your own open handle. The duplicate still shares the file offset. In a child,
clear the inherited flag on your owned binding before passing it to
`Original` or `Writer`.

A read can leave bytes in the sink before a later failure, and a write can
partially take effect. Stage data if your application publishes it only after
a successful read. Metadata checks cannot account for every intervening
change. `HandoffError` represents a rejected contract. A syscall can
also raise `OSError`, and a blocking operation can outlast a deadline check.

Keep `Writer` private to the trusted owner. `AppendWrite` exposes no offset.
The append call uses Linux `pwritev(RWF_APPEND)` on the retained inode. A
separately opened read-only handle to that inode can see the new bytes even
after a path rename. Append leaves the descriptor position and status flags
unchanged. The Python build, kernel and filesystem must support the syscall.
Check the returned count and reconcile any short or uncertain result before
another attempt. A live worker append grant and independent custody each need
separate host enforcement and evidence.

### Run an enrolled owner append

The enrolled operation keeps the writer in its existing Linux owner process.
The administrator approves the workflow, role, operation alias, and exact
resource. A separate custody observer holds the same original read-only and
authenticates coverage through the append deadline. A writable stream alias
uses a separate capability and offers different access.

For example, this policy lets the role `report-owner` select `add_entry`.
The enrollment supplies the existing registration named `report-original`.

```yaml
version: 1
roles:
  report-owner:
    operations: [owner_append, owner_append_status]
workflows:
  compile-reports:
    role: report-owner
    operations: [owner_append, owner_append_status]
    bindings:
      owner_appends:
        add_entry: report-original
```

For the installed controller, the administrator places the registration at
`/etc/workeros/owner-append.json` in the protected WorkerOS directory. The
registration contains:

- `version` (1) and `policy_sha256` for the exact policy file bytes.
- `workflow`, `role`, `alias`, `reference`, `scope`, and `generation`.
- The approved non-root `owner_uid`, original `device` and `inode`, absolute
  monotonic `expires_ns`, and existing private `journal_directory`.
- The preheld `writer_fd` and `reader_fd` in the appointed owner process, plus
  `observer_fd` for a connected custody socket with pinned `observer_pid`
  and `observer_uid`.

Use decimal strings for large integer values. The registration must be owned
by the administrator, readable by the appointed owner, and writable only by
the administrator. The owner starts the command with those already-held
slots. A fresh install supplies the loader; enrollment supplies the original,
the observer, and the matching clock.

```sh
workeros config --check-policy append.yaml --format yaml --registered-owner-append
workeros config --run-policy append.yaml --format yaml --registered-owner-append < append.json
```

`--check-policy` checks the protected registration and the local original
handles. The append request itself requires the live custody approval.

```json
{
  "version": 1,
  "workflow": "compile-reports",
  "role": "report-owner",
  "operation": "owner_append",
  "options": {"alias": "add_entry", "attempt_id": "report-202", "data": "bm90ZQo="}
}
```

Trusted Python hosts can supply an `OwnerAppendBinding` from
`workeros.owner_append` in `HostBindings.owner_appends`, keyed by the binding's
`registry_reference`. They can execute the same
request with `compile_policy(document, host).execute(parse_request(request))`
from `workeros.enrollment` and `workeros.configuration`.

To reconcile, use `owner_append_status` with the same alias and attempt ID and
`data_sha256` in place of `data`. This reads the matching owner journal without
another append. A known byte count is separate from completion timing.
`late` means completion was observed at or after the deadline. A short write
reports its known count. An uncertain syscall or missing outcome record stays
unknown on readback. The journal records the reported effect; file durability
requires a separate sync policy.

## Transfer an original over a Unix stream

Use a connected, non-inheritable Unix stream and a `Worker` describing the
pinned peer's PID and UID. Supply the same nonempty bytes token and expected
`Identity` to `send_original(channel, fd, *, peer, identity, token, due_ns)`
and `receive_original(channel, *, peer, identity, token, due_ns)`. The sender
borrows its read-only FD and sends one `SCM_RIGHTS` descriptor. The receiver
validates the exact frame and EOF and owns the result as an `Original`. Each
call consumes its socket. The peer's Linux PID and UID must match the
caller's expectation.

Here a local socket pair lets one process exercise both ends with its actual
PID and UID.

```python
import os
import socket
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns

from workeros import Worker, Writer, observe, receive_original, send_original

with TemporaryDirectory() as directory:
    path = Path(directory) / "input"
    path.touch()
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    with Writer(fd, observe(fd).identity) as writer:
        writer.write(b"report\n")
        writer.flush(sync=True)

    with path.open("rb") as source:
        sender, receiver = socket.socketpair()
        peer = Worker("local-peer", "demo", os.getpid(), os.getuid())
        due = monotonic_ns() + 5_000_000_000
        identity = observe(source.fileno()).identity
        with sender, receiver:
            send_original(sender, source.fileno(), peer=peer, identity=identity,
                          token=b"one-local-transfer", due_ns=due)
            with receive_original(receiver, peer=peer, identity=identity,
                                  token=b"one-local-transfer", due_ns=due) as original:
                sink = BytesIO()
                result = original.read_and_close(sink, due_ns=due, expected_size=7)
                print(result.bytes_read, sink.getvalue().decode().strip())
```

The sender's return records its local send. To know the recipient accepted or
read the original, collect that outcome from the recipient. A send error can
occur after the FD reached the peer. Reconcile uncertain delivery before retrying.

## Authorize a managed release

[Managed release source](../src/workeros/managed.py) ·
[Strict custody source](../src/workeros/custody.py)

`ReleasePlan(name, role, argv, identity, due_ns, write=None, exclusive_writer=False)`
describes a single attempt. Use an argv tuple with an absolute executable path.
`PositionalWrite(offset, data)` specifies the optional nonempty bytes write.

`release_executable(plan, *, input_fd, authorize, writer_fd=None, supervisor=None,
strict_custody=False, custody=None, cancel=None, cleanup_due_ns=None)` stages the
exact read-only input and grants it as `INPUT`. The application policy
`authorize(plan)` must return literal `True`. The input and writer FDs stay with
the caller and must remain stable. Supply `writer_fd` only with a write plan,
for the same original. Managed positional writes reject `O_APPEND`.
`exclusive_writer=True` uses an advisory lock on the actual original through
dispatch to coordinate writers using the same lock. The child's environment
consists of ABI fields.

Inspect the returned `ReleaseResult` field by field.

| Field | Interpretation |
| --- | --- |
| `delivery` | `NOT_ATTEMPTED`, `DISPATCHED`, or `UNKNOWN`. Dispatch reports child creation. |
| `effect`, `bytes_written` | `NOT_ATTEMPTED`, `COMPLETE`, `PARTIAL`, or `UNKNOWN`, with a byte count when available. A completed write records bytes accepted by the syscall. Applications requiring durability need their own sync plan. |
| `custody` | A pre-grant `CustodyReceipt` from the optional strict path. |
| `worker`, `lifecycle` | The launched worker if known, and the supervised wait outcome when a supervisor was supplied. Without supervision, the application owns the returned process handle and must wait for it. A pinning failure can still return a dispatched worker whose handle the application must reconcile. |
| `cleanup`, `error` | Staged descriptor-close diagnostics and the reported release error. Read process cleanup separately from `lifecycle.cleanup`. |

If the caller requests strict custody or supplies `custody`, the
deployment supplies an independent, prequalified observer. Wrap its connected,
non-inheritable Unix `SOCK_SEQPACKET` endpoint in
`IndependentCustody(channel, observer_pid=..., observer_uid=...)`. A strict
refusal stops write and dispatch. The strict path authenticates the pinned
Linux PID and UID on a fresh request bound to `plan.custody_scope`, and
requires a separate principal outside the release caller's control. The observer
supplies policy, provenance, prior grant and retirement evidence, and applicable
writer exclusion. A separate Linux UID alone does not establish independent
administrative control.

Custom pre-grant callers can use
`workeros.custody.require_custody(observer, *, identity, operation,
recipient=None, scope, due_ns)`. It consumes the observer endpoint and
returns a receipt or raises `CustodyRefused`. Close an unused endpoint if an
earlier stage refuses. The receipt contains the scope, identity, operation,
recipient if supplied, observer PID and UID, request digest, and attestation
and deadline timestamps. Reader or meter reports cannot supply this receipt.

A completed or partial write can precede failed dispatch. Check the actual
effect and any live child before retrying, even when the release returned an
error.

## Observe a designated process and file slot

[Observer setup and qualification](regular-file-observer.md) ·
[Observer source](../src/workeros/lifecycle.py)

`RegularFileObserver(scope=..., due_ns=..., original_fd=..., identity=...,
pidfd=..., worker=..., slot=..., directory_fd=None, leaf=None, evidence_scope=None)` borrows and
duplicates already held references to a regular file and a live pidfd.
The caller pins the worker PID and expected UID and supplies the plan's
SHA-256 scope. Use a read-only or metadata-only `O_PATH` original reference.
To observe one directory entry, supply both an already searchable directory
FD and a single relative leaf.

`sample()` returns a raw `Sample` covering one observation interval. It
reports the pinned process state, slot match and flags, optional directory
entry match, expected and sampled UID information, raw clock identifiers,
and reasons for uncertainty. Slot identity, directory identity and pidfd
exit are separate points. Closure of one slot and exit observation leave
other descriptors, reaping, and lifecycle history to other sources.
`close()` releases the observer's duplicates and leaves the caller's FDs
open.

For scoped reports, pre-pin the complete `EvidenceScope` at construction with
`RegularFileObserver(..., evidence_scope=scope)`. Its scope ID must match the
plan digest. `sample_for_scope(scope, *, provider_id, subject="slot")` then
returns `(Sample, ScopeReport)` for `"slot"`, `"name"` or `"process"`. It
compares the entire pinned scope, including its `RunBinding` and interval,
and verifies actual boot and time-namespace identifiers against
`scope.run.clock_id`. Use
`workeros.lifecycle.monotonic_clock_id(boot_id, time_namespace)`
to format those identifiers. It returns `None` if either is unavailable.
The scoped adapter refuses unavailable or incompatible clocks and intervals
outside the scope. Within a compatible interval it distinguishes observed
matches, confirmed absence, unavailable or indeterminate readings, and
observations that were not requested. Raw samples retain the reasons and
the actual flags.

`python -m workeros.observer_cli` accepts the existing one-line
launcher plan with inherited FDs and returns the raw sample by default. To
opt in, declare `scope_report` in the startup plan with `scope` (including
its nested `run`), `provider_id`, and optional `subject`. The CLI pins that
complete scope before sampling and returns `{"sample": ..., "scope_report": ...}`.
The plan still needs the top-level scope digest, deadline, identity, slots,
PID and UID fields.

## Validate run and provider evidence

[Evidence source](../src/workeros/evidence.py)

- `RunBinding(run_id, artifact_id, clock_id, started_ns, finished_ns)`
  declares one child execution. Use a fresh run ID and a clock context
  whose timestamps the application can compare.
- `EvidenceObservation(subject, state, detail=None)` distinguishes
  `OBSERVED`, `CONFIRMED_ABSENT`, `UNAVAILABLE`, `INDETERMINATE`, and
  `NOT_REQUESTED`. An omitted report remains missing.
- `RunEvent(binding, source_id, sequence, started_ns, finished_ns, ...)`
  can carry observations, lifecycle, return code, or cleanup status.
  `RunEvent.from_result(binding, source_id, sequence, started_ns, finished_ns, result)`
  projects a supervision or cleanup result. Associate the result with the
  run when you capture it and retain the raw result for detailed diagnostics.
- `validate_run_evidence(binding, events, *, require_observed=(), require_terminal_from=None)`
  checks exact binding and contiguous sequence numbers beginning at one.
  Intervals must be ordered within the declared run. Require historical
  `(source_id, subject)` observations or one explicit reap and exit code
  from a named terminal source. A nonzero exit can satisfy terminal
  coverage.
- `EvidenceScope(run, scope_id, started_ns, finished_ns)` declares a
  separate report window, which can extend before launch and after
  cleanup. `ScopeReport(scope, provider_id, phase, started_ns, finished_ns,
  observation)` carries one observation or one meter endpoint in that
  window. Set `phase` to `ScopePhase.OBSERVATION`, `METER_BEGIN` or
  `METER_END`.
- `validate_scope_evidence(scope, reports, *, observer_id, meter_id, require_meter_for=None)`
  matches reports to the caller's selected provider labels and scope.
  The tuple may contain overlapping samples from different providers.
  With `require_meter_for=(start, finish)`, require one observed begin
  and end from the meter. The begin must finish before or at `start`,
  and the end must start at or after `finish`. Omit the interval to
  inspect a partial set without requiring both endpoints.

These functions preserve the input tuples on success and raise `ValueError`
on validation failure. Bindings and provider labels establish structural
matching. The caller handles source authentication, meter coverage,
qualification, and cross-call replay. Continuous custody and costs outside a
provider's coverage require their own evidence.

## Measure an already provisioned cgroup v2 scope

[Scope meter source](../src/workeros/scope_meter.py)

`CgroupScopeMeter(scope=..., provider_id=..., directory_fd=...)` borrows
and duplicates a non-inheritable FD for an existing, visible cgroup v2
directory. The caller provisions the cgroup and establishes which workload
it contains. The meter reads `cpu.stat`, `cgroup.events`, `memory.current`, and
`memory.peak` through that directory, where available. It leaves placement,
process control, and cleanup to the caller.
Use the meter as a context manager.

Call `sample(ScopePhase.METER_BEGIN)` before the measured interval and
`sample(ScopePhase.METER_END)` after it on the same meter session. A
`CgroupSample` includes aggregate `usage_usec`, `memory_current_bytes` and
`memory_peak_bytes`, a separate `populated` point, individual evidence
states, scope and interval, cgroup identity,
meter session and credentials, clock context, and diagnostic reasons.
`sample.report` projects the CPU reading as a `ScopeReport` when the
sample's clock and interval can be attributed to the declared scope.
Missing clock context can leave raw readings without a report. A missing
or denied population file leaves population unavailable. Memory values are
separate gauges in bytes with `memory_current_state` and `memory_peak_state`.
The meter reads the kernel's existing peak without resetting it. The peak
can predate the invocation, and missing memory fields leave CPU independent.

`cpu_delta_usec(begin, end, *, require_meter_for=(start, finish))` checks
scope, clock, cgroup identity, meter session, endpoint order, and the
bracket around the requested interval. It returns the nondecreasing
counter difference in microseconds or raises `ValueError`. The difference
covers aggregate activity between the readings, including work unrelated
to the target if the caller shares the cgroup. Keep the raw samples.
Include the observed cleanup interval in the required bracket when
appropriate, and record the actual cleanup result separately.
Retained storage and network or other exterior costs need their own sources.

The meter's `monotonic_clock_id()` reads the current local clock ID or
returns `None`. A missing or unsupported cgroup v2 directory can raise
`ScopeMeterUnavailable`. Basic supervision and raw file observation
remain available independently when their own prerequisites are met.

`python -m workeros.scope_meter` accepts a JSON line with `scope`,
`provider_id`, and the inherited `directory_fd`. Then send JSON string
lines `"meter_begin"` and `"meter_end"` in order to the same process.
Each returns one JSON line with the raw `sample` and its `scope_report`,
which can be `null`. This is an ordinary inherited-FD entry point for a
caller-provisioned meter process.

Use `CgroupSample.from_dict(json.loads(line)["sample"])` to decode each
meter reply for Python consumers. Keep the original lines with the typed
begin and end samples. Use `cpu_delta_usec` to check and compare those
samples, then pass their `.report` values and the observer report to
`validate_scope_evidence` for the declared scope. Decoding reconstructs the
sample's types. The application authenticates the meter and its replies.

## Inherited readers and platform boundaries

| Runtime | Package API and lifetime |
| --- | --- |
| [C and C++ with Conan](../native/README.md) | Linux header-only API for C99+ and C++11+. Initialize `workeros_input`, then use `workeros_open_inherited`, `workeros_read_at`, and `workeros_close` with borrowed or owned semantics. |
| [Node.js](../node/README.md) | Linux x64 or ARM64 with procfs and Node.js 22+. `openInherited`, `readAt`, and `close`. Borrowed is the default. Owned closes the validated inherited slot. |
| [Go](../go/README.md) | Go 1.22+ on Linux amd64 or arm64. `workeros.Open`, `ReadAt`, and `Close` operate on a private duplicate. `ReadAt` checks the deadline before reading. |
| [Rust](../rust/README.md) | Rust 1.85+ on Linux x86-64 or AArch64. `open_read` takes a read-only binding, and `read_at` uses a private duplicate that closes on drop. |
| [Java](../java/README.md) | 64-bit Linux x64 or ARM64 with procfs, JDK 22+, and FFM native access enabled. Use `InheritedReader.open`, `readAt`, and try-with-resources to close its private duplicate. |

These adapters consume the inherited descriptor ABI and perform positional reads.
Allow for short reads and EOF. Go, Rust and Java leave the original inherited
slot to its owner. The Python API provides the controller, supervisor,
Unix-socket transfer and optional custody interfaces. Native Windows has an
installation and import-boundary check. WSL2 uses the Linux APIs, subject to
the guest's kernel and the facilities it exposes. Consult
[the support matrix](support.md) for exactly which combinations were verified.
