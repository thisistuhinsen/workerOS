# Support and verification

workerOS runs local Linux workers and can pass the files your application
already has open. Choose the runtime and check the evidence for your exact
version before deployment. See the [install paths](../README.md#packages) and
[verification links](../README.md#verify-and-contribute).

## Capability matrix

The 0.7.0 wheel installs the Python distribution `workeros` and
provides the `workeros-demo` command. The published
[v0.4.0 release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.4.0)
uses the distribution name `worker-handoff`. Both provide the
`worker_handoff` Python import. Use separate environments for the two
distributions. The controller capabilities below are common to both.

| Need | Python API or worker interface | Boundary |
| --- | --- | --- |
| Run a local tool or callable | `WorkerRoster` starts a trusted executable or a synchronous Python handler and joins owned workers. Its registration method records the name, role, and PID of an existing worker. | Roles are application labels. A join can time out while the worker is still running. An external worker keeps its wait and signal owner. |
| Supervise a direct child | `DirectChildSupervisor` reports exit, timeout, or cancellation. It can terminate and reap a child within a separate cleanup budget. | Linux pidfds and `waitid(P_PIDFD)`. Stop and reap authority covers waitable direct children launched by the supervisor or explicitly adopted by it. The application owns descendant management. |
| Pass an open file on launch | Explicit inherited FD bindings under ABI v1. | The application authorizes each grant and keeps its source slot stable. An inherited slot shares the underlying file description. Positional reads preserve its offset. |
| Pass a read-only file to a running peer | Python `send_original` and `receive_original` over a connected Unix stream. | The caller supplies a pinned peer, matching token, and deadline. Each side consumes its socket. |
| Read, write, and observe a held file | Python `Original`, `Writer`, and `observe(fd)`. | A readable descriptor permits content access. A rename keeps the open file identity. A writer can still change its contents. |
| Authorize a managed handoff | Python `release_executable` with a `ReleasePlan` and authorization callback. Optional positional write, cooperative writer locking, direct-child supervision, and strict custody. | Strict custody requires an independently controlled, qualified Linux observer and exact pre-grant evidence. Dispatch, write effect, exit, and cleanup have separate outcomes. |
| Read from a worker in another language | The reader packages below use the same inherited-FD ABI. | The launcher owns the worker and its grant. The worker-side readers use positional reads. |

### Additional interfaces in 0.7.0

| Need | Interface | Boundary |
| --- | --- | --- |
| Use one workflow from several languages | [`workeros-config`](configuration.md) reads a JSON v1 invocation and writes a JSON response. The local operator selects a policy and enrolls named executables and bindings. | The installed command handles a single invocation. Workflows that retain live processes, protect an original, or require a provider use an application-owned controller with the corresponding trusted adapters. |
| Capture, store and recover evidence | [Recorder policy](configuration.md#choose-recorder-storage) selects a typed projection, named destination, required or optional routes, access and retention. Read back a particular receipt; use `verify_durable` when durability needs confirmation. | Persistence and the underlying operation have separate outcomes. The host owns access and adapter qualification. A retention minimum permits a later purge; an operator runs any expiry sweep. |
| Observe, meter or validate a scope | [Observer and evidence APIs](api.md#observe-a-designated-process-and-file-slot) and [cgroup v2 meter](api.md#measure-an-already-provisioned-cgroup-v2-scope) use previously authorized handles and named sources. | A point sample and two meter readings do not establish continuous custody. A shared cgroup includes other tasks; unavailable counters stay unavailable. Validate run, scope, clock and coverage separately from authenticating the source. |

## Choosing an inherited reader

Use the [package matrix](../README.md#packages) for release URLs and exact
install identifiers. Run the reader inside an executable that already has
an authorized binding.

| Language | Runtime and toolchain | Descriptor ownership and access |
| --- | --- | --- |
| Python | Linux with Python 3.11 or newer. | `Original` takes an existing read-only FD. `Writer` takes an existing caller-owned writable FD. Give either a dedicated duplicate if you need to retain the original slot. |
| Node.js | Linux x64 or ARM64, procfs, and Node.js 22+. [Node reader](../node/README.md) | Borrowed by default, owned if selected. Reads `read` and `read-write` bindings. |
| Go | Linux amd64 or arm64 with Go 1.22+. [Go reader](../go/README.md) | Owns a close-on-exec duplicate. Reads `read` and `read-write` bindings and checks the monotonic deadline before a read. An active syscall can outlast that deadline. |
| Rust | Linux x86-64 or AArch64 with Rust 1.85+. [Rust reader](../rust/README.md) | Owns a close-on-exec duplicate of a read-only descriptor. |
| C | Linux, C99 or newer. The package recipe uses Conan 2. [C and C++ readers](../native/README.md) | Borrowed or owned by the reader, as selected. Reads `read` and `read-write` bindings. |
| C++ | Linux, C++11 or newer. The package recipe uses Conan 2. [C and C++ readers](../native/README.md) | Same ownership choices and readable access modes as C. |
| Java | Linux x64 or ARM64 with procfs, JDK 22+, and native access for FFM. [Java reader](../java/README.md) | Owns a close-on-exec duplicate. Reads `read` and `read-write` bindings. |

With Go, Java, or Rust, closing the reader closes its duplicate. If your
worker owns the inherited FD, close that slot when finished or mark it
close-on-exec before spawning another process. Follow the individual examples
for byte counts and EOF.

## What CI verifies

These rows describe the existing checks. Use a check run tied to an exact
candidate SHA when recording which environments passed that candidate.

| Path | Actual environment and evidence |
| --- | --- |
| Linux compatibility | Ubuntu x64 and ARM64, plus Debian, Fedora, and Alpine userspace on an Ubuntu host kernel. The hosted Linux jobs run the inherited examples across C, C++, Go, Java, Node.js, Python, and Rust. The Python suite exercises connected Unix stream transfer. |
| Independent strict custody | A sealed original granted read-only, a separate Linux writer UID, terminal reaping, and pre-grant refusal cases. A deployment using this mode qualifies its own observer and checks its exact grant conditions. |
| Hosted WSL2 | An Ubuntu 24.04 guest with the Microsoft WSL2 kernel on a hosted Windows runner. The guest builds and installs a wheel offline and runs the Python suite plus C and Python examples. Verify your own WSL2 environment for deployment. |
| Native Windows | Wheel build and installation followed by an expected Linux-only `fcntl` import boundary. Run workerOS in a supported Linux environment. |

The project supports the latest published release. For issue reports, include
the exact version, platform, package-manager path, and check outcome.
[Contribution policy](../CONTRIBUTING.md)

### Windows and macOS

A `py3-none-any` wheel can install successfully on native Windows Python.
Seeing `No module named 'fcntl'` with Windows Python
means you are using the native Windows interpreter. Open your existing Ubuntu
WSL2 guest and run the [Linux install](install.md#python) in a fresh guest
environment. Native macOS also lacks the supported Linux supervision facilities; use a Linux VM.
Keep the original environment intact for rollback.

<a name="troubleshooting"></a>

## When a worker doesn't finish

- A `WorkerRoster.join` deadline can return `None` with the worker still alive.
  Use the owned handle to reconcile it.
- One direct-child supervisor drives one control loop at a time. Use separate
  supervisors for independent wait loops. Python callables run with `spawn`
  by default. Use a synchronous, importable target and protect startup with
  `if __name__ == "__main__"`. Wrap async code inside a synchronous entry
  point.
- Executable starts inherit standard streams by default. In 0.7.0 both
  native launchers accept `cwd`, `stdin`, `stdout` and `stderr`. In
  v0.4.0, configure streams on a waitable `Popen` child and transfer
  supervision with `adopt`. Drain any output pipes while the child runs.
- Cleanup after timeout or cancellation is opt-in. Inspect `result.cleanup`
  for the attempt. If startup raises `SupervisionStartError`, a child can
  already be running. Reconcile through the returned `process` handle.
- In managed release, a successful or partial write can precede failed
  delivery. Reconcile the exact attempt before retrying. Keep timeout,
  cancellation, and pending cleanup visible as distinct outcomes.

## Public main source features

The 0.7.0 wheel includes the observation and validation interfaces below.
Earlier versions of those interfaces are on
[public main](https://github.com/thisistuhinsen/workerOS/tree/f47b7baced77a89c03e35683d77a630fab0dc6bc).
They are absent from the published v0.4.0 wheel. For source and test examples,
use the checkout that matches your candidate.

| Source path | Behavior and limits |
| --- | --- |
| [Regular-file observer](regular-file-observer.md) | `worker_handoff.lifecycle` samples a designated process, regular-file slot, or name under already authorized observation. The 0.7.0 wheel includes `python -m worker_handoff.observer_cli`. Each sample describes its observation window. |
| [v0.7.0 evidence API source](https://github.com/thisistuhinsen/workerOS/blob/339ca866647dc61062227923a3b1d697275977ed/src/worker_handoff/evidence.py) | Validates caller-supplied run observations and scope reports. Authentication, authority, and scope measurement remain with the application and its providers. |

### Installed composition acceptance

The public-main installed suite includes
[three acceptance profiles](../tests/test_acceptance.py) using disposable
files and owned children.

- Readable prebound input, identity refusal, and separate recipient read
  evidence, with a metadata-only reference case when `O_PATH` is available.
- Current-attempt receipt checks before managed write, with an observed
  uncertain write left pending reconciliation.
- A write and sync before read-only handoff, with the writer slot closed
  before or after delivery. The overlap case samples both slots before
  closure, checks recipient EOF, and reports the direct reaps separately.
  Injected lookup and mount failures produce unknown states.

Use `bash scripts/check-linux.sh` from the checkout to build and test its
wheel. With the matching installed wheel, run
`python -I -m unittest discover -s tests -p test_acceptance.py -v`
to select these profiles.

Recipient bytes, sampled slots, and direct-child reaps are separate facts.
For whole-scope coverage, obtain independently qualified begin and end
reports for the same scope. The
[strict sealed-file fixture](../scripts/check-strict-custody-linux.py)
authenticates a separate Linux principal for one sealed read-only grant.
It measures that grant and the relevant terminal reaping. Combined
whole-scope qualification and separate administrative control remain
outside that fixture's measured scope.

### Combining provider reports

For the 0.7.0 `worker_handoff.evidence` API, declare a fresh scope ID
with `EvidenceScope`, bind the child with `RunBinding`, and define the report
window in the run's clock domain. The window can start before launch and
finish after cleanup. Preserve unavailable or indeterminate observations.

```python
from worker_handoff.evidence import validate_scope_evidence

reports = validate_scope_evidence(
    scope, (meter_begin, observation, meter_end),
    observer_id="configured-observer", meter_id="configured-meter",
    require_meter_for=(launch_started_ns, cleanup_finished_ns),
)
```

The requested interval passes when the selected meter reports observed
endpoints that bracket it. Omit `require_meter_for` to inspect a partial set.
Provider IDs are application labels. Keep the raw readings, authenticate
sources, check clock context and coverage, and handle duplicate submissions
across calls. Use the pre-grant custody API for strict custody. The acceptance
fixture combines a real owned-child point sample with synthetic meter readings.
