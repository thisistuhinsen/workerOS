# Support and verification

workerOS launches and supervises local Linux workers, with optional file-descriptor handoff. Use the [release’s checks](../README.md#verify-and-contribute) for the exact source version you are deploying. The table describes what each verification path covers.

| Path | Required environment and evidence |
| --- | --- |
| Python controller and readers | Linux, Python 3.11 or newer. The hosted matrix covers Ubuntu x64 and ARM64, plus Debian, Fedora, and Alpine userspace on an Ubuntu host kernel. The suite includes a real connected Unix stream descriptor transfer and the inherited-FD ABI. |
| Direct-child supervision | Usable Linux pidfds and `waitid(P_PIDFD)`. Only a launched or explicitly adopted, waitable direct child is within the supervisor’s stop and reap authority. A legacy roster join can time out with the child still running. |
| Independent strict custody | An independently controlled, qualified Linux observer with its own credentials and exact release-scope evidence. Hosted CI demonstrates a read-only grant of one sealed original, a separate writer UID, terminal reaping, and refusal cases. A deployment that uses strict custody needs its own qualified observer. |
| Installed worker examples | Inherited descriptor ABI v1 under the Linux controller. The hosted Linux jobs exercise C, C++, Go, Java, Node.js, Python, and Rust. Java FFM requires 64-bit Linux and a JDK 22 or newer. |
| Hosted WSL2 | A real Ubuntu 24.04 guest with the Microsoft WSL2 kernel on a hosted Windows runner. The guest builds the wheel, installs it offline, and exercises the Python suite plus the C and Python examples. Individual PCs need their own verification. |
| Native Windows | Wheel build and offline installation, followed by the expected Linux-only `fcntl` import boundary. |

The connected Unix stream framing and Python controller APIs remain at their existing compatibility boundaries. The native language adapters consume inherited descriptor bindings. Their package metadata and documentation state Linux runtime and minimum toolchain requirements. Runtime support still depends on which kernel facilities the host permits.

An inherited FD and its environment fields describe an application grant. The application must establish authorization and descriptor lifetime. A readable file descriptor permits reading the file, including when the roster labels a worker `observe`. Holding an inode across a rename preserves what the descriptor refers to. It does not freeze bytes another writer can change.

The project supports the latest published release. Report failures against that release and include the exact platform and package-manager path. [Contribution policy](../CONTRIBUTING.md)

## When a worker doesn't finish

- A `WorkerRoster.join` deadline can return `None` while the worker is
  still alive. Registration does not give you wait or signal authority.
- The direct-child supervisor runs one control loop at a time. Use a
  separate supervisor for independent wait loops. A roster starts Python
  callables using `spawn` by default; use a synchronous, importable target and
  protect
  startup with `if __name__ == "__main__"`. If your handler uses async
  code, run it inside a synchronous entry point. Built-in executable starts
  use inherited standard streams. For custom streams, create your own
  waitable `Popen` child and explicitly transfer supervision with `adopt`.
- In a supervised call, cleanup after timeout or cancellation is opt-in.
  The example requests cleanup as soon as a wait times out, with a fresh
  wait budget for each child. Inspect `result.cleanup` for that attempt. A
  `SupervisionStartError.process` means the child may already be running.
- For managed file release, dispatch, write effect, exit and cleanup are
  separate. A successful or partial write can precede failed delivery.
  Reconcile what took effect before retrying.
- Treat deadlines as bounds on the wait or cleanup attempt, not proof of
  when a child exited. A timeout, cancellation, or pending cleanup is not
  a success verdict. Use the returned lifecycle and cleanup fields
  separately.

## Installed composition acceptance

The installed Python suite includes [three acceptance profiles](../tests/test_acceptance.py)
using disposable files and owned children.

- Readable prebound input, identity refusal, and separate recipient read
  evidence, with a metadata-only reference case when `O_PATH` is available.
- Current-attempt receipt checks before managed write, with an observed
  uncertain write that the caller leaves pending reconciliation.
- A completed write and sync before read-only handoff, with writer-slot closure
  exercised both before and after delivery. The overlap variant samples the
  two held slots before writer closure, then checks recipient EOF, closure and
  separate reaps. An injected lookup failure leaves the name unknown, and an
  injected mount mismatch leaves the slot unknown.

Run `bash scripts/check-linux.sh` from the checkout to build and test the
installed wheel. Given a verified wheel installation, use
`python -I -m unittest discover -s tests -p test_acceptance.py -v` from the
checkout to run just these profiles.

The fixtures validate recipient bytes and observe designated slots and direct
children. The samples are point observations. Independent custody, activity
between samples, other descendants, and whole-scope cleanup remain unmeasured.
Native Windows CI checks the installation and import boundary.

The overlap fixture keeps handoff and reap evidence separate from qualification
reports. Missing, unavailable, or wrong-run reports leave the requested
custody or whole-scope coverage unverified. Whole-scope coverage also requires
both meter endpoints. A positive combined qualification would need a qualified
independent custody source and a meter reporting begin and end for the same
declared execution scope. The
[strict sealed-file fixture](../scripts/check-strict-custody-linux.py)
authenticates a separate Linux principal for one sealed, read-only grant.
Separate administrative control and combined whole-scope qualification remain
unmeasured.

## Combining provider reports

The optional `worker_handoff.evidence` API accepts point observations and
start and end readings from providers your application already authorizes.
Declare an `EvidenceScope` with a fresh scope ID, a `RunBinding` for the
child, and the outer report window. Use the run's clock domain for every
timestamp. The report window can start before launch and finish after cleanup.
Preserve each provider's `EvidenceState` when adapting its result to a
`ScopeReport`. Omit a report if the provider supplied none.

```python
from worker_handoff.evidence import validate_scope_evidence

reports = validate_scope_evidence(
    scope, (meter_begin, observation, meter_end),
    observer_id="configured-observer", meter_id="configured-meter",
    require_meter_for=(launch_started_ns, cleanup_finished_ns),
)
```

The requested interval passes when the selected meter reports observed
endpoints that bracket it. Separate providers can report overlapping samples.
Omit `require_meter_for` to inspect a partial set, including unavailable or
indeterminate reports. Inspect the returned observation states and keep the
provider's raw readings for any decision about the scope. A reading marked
`OBSERVED` says the provider obtained a measurement. Your application decides
whether that measurement establishes cleanup or any other outcome.

Provider IDs are caller-supplied labels. Your application authenticates the
sources, checks their authority, clock context and measurement coverage, and
handles duplicate submissions across calls. Strict custody decisions still
use the pre-grant custody path. The acceptance fixture exercises this API with
a real owned-child point sample and synthetic meter readings.

## Producing observation and meter reports

`RegularFileObserver.sample_for_scope(scope, provider_id=..., subject="slot")`
returns the original `Sample` and a bound `ScopeReport`. The subject can also
be `name` or `process`. A slot match concerns the exact prebound original at
the sampled file descriptor. A process report concerns pidfd liveness.

The existing `python -I -m worker_handoff.observer_cli` reads its one-line
plan and returns a raw sample by default. Add a `scope_report` object with
`scope` (the `asdict()` form of the `EvidenceScope`), `provider_id`, and an
optional `subject` to return `sample` and `scope_report` together. The scope
ID must match the plan's bound SHA-256. A separately operated caller still
supplies the already-authorized handles, trusted plan and procfs access.

`CgroupScopeMeter` in `worker_handoff.scope_meter` borrows a non-inheritable
directory FD from one already accessible cgroup v2. Each `sample()` reads
`cpu.stat` and, if present, `cgroup.events` from that directory. It retains the
pinned device, inode, mount ID, meter session, local PID and effective UID,
clock context, and reading interval. `usage_usec` is cumulative CPU time in
microseconds for the cgroup and its descendants. `populated` is a separate
point reading of live-process presence. The reads are sequential. The
population field can be unavailable at the hierarchy root while CPU remains
available. [Linux cgroup v2 interface](https://docs.kernel.org/admin-guide/cgroup-v2.html)

Keep one meter instance for both phases. Build the `EvidenceScope` using
`worker_handoff.scope_meter.monotonic_clock_id()` from a verified common
boot and time namespace. If that context is unavailable, the meter can return
raw values with no bound report. The observer still offers its raw sample path.

```python
from worker_handoff.evidence import ScopePhase, validate_scope_evidence
from worker_handoff.scope_meter import CgroupScopeMeter, cpu_delta_usec

with CgroupScopeMeter(scope=scope, provider_id="meter", directory_fd=cgroup_fd) as meter:
    begin = meter.sample(ScopePhase.METER_BEGIN)
    # Run the application and retain its own launch time, observer receipt,
    # and terminal cleanup evidence before taking the final sample.
    end = meter.sample(ScopePhase.METER_END)

interval = (launch_started_ns, cleanup_finished_ns)
aggregate_cpu_usec = cpu_delta_usec(begin, end, require_meter_for=interval)
validate_scope_evidence(scope, (begin.report, observer_report, end.report),
                        observer_id="observer", meter_id="meter", require_meter_for=interval)
```

`cpu_delta_usec` requires matching raw meter provenance, the same cgroup and
session, comparable clocks, bracketing readings, and a nondecreasing CPU
counter. Keep both raw samples with the result. A caller needs workload
membership and an exclusive scope to attribute the full delta to its run.
An empty population point and an owned-child reap each describe a different
fact. Whole-scope cleanup and continuous custody need separate evidence.

For a separately launched meter, use `python -I -m worker_handoff.scope_meter`
with the already-open directory inherited. Send one JSON plan line with
`scope`, `provider_id`, and `directory_fd`, then a JSON string line
`"meter_begin"`. Wait for the response before launch. After cleanup send
`"meter_end"`. Each response has `sample` and a `scope_report` that may be
null. The caller owns the worker's I/O and termination deadlines.

After installing the wheel, run the disposable owned-child example from the
checkout with `python -I -m unittest discover -v -s tests -p test_scope_meter.py`.
It compares real aggregate kernel counters around launch and reap in the
fixture's existing cgroup. It reports when the clock cannot bind those
readings to the observer. The fixture's shared scope measures compatibility.

## Choosing an inherited reader

The reader packages never launch workers. All use positional reads; none
makes a snapshot of the file. C, C++ and Node can borrow or take ownership
of the inherited descriptor. Go, Java and Rust own a private duplicate and
leave the inherited slot open. Rust accepts read-only inputs only; the
other readers can also read from a read-write binding that matches the
declared access. Go checks the supplied monotonic deadline before starting
a read; it can't cancel an already-started read. Follow each package's
example for byte counts, EOF and cleanup.

Python's `Writer` and `Original` take ownership of the FD you pass. Don't
close that numeric slot separately. If you need to keep a handle, pass a
duplicate you can give up; separate descriptors can still share a file
offset. With Go, Java or Rust, closing the reader closes its duplicate, not
the original inherited slot. Close that slot if your worker owns it and no
longer needs it, or mark it close-on-exec if permitted before spawning other
processes.
