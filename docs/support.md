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
