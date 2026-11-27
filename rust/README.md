# workerOS for Rust

> These are v0.8.0 instructions. Use public downloads only after that release,
> or use a verified offline bundle now. For the published v0.7.0 release, use the [v0.7.0 guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/rust/README.md).

Use Rust 1.85 or later on Linux x86-64 or AArch64. The crate has no Cargo
dependencies. This example builds a reader in a fresh Cargo project and runs
it with a read-only file supplied by the Python launcher.

## Try the public tag

[install the
Python controller](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#python) and activate its environment.
Run this from any directory. Set `WORKEROS_PYTHON` if you want to point to
that environment's Python directly.

```sh
(
    set -eu
    python=$(command -v "${WORKEROS_PYTHON:-python3}")
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    export CARGO_HOME="$work/cargo"
    cd "$work"
    cargo new --bin --vcs none worker-reader
    cd worker-reader
    cargo add workeros --git https://github.com/thisistuhinsen/workerOS --tag v0.8.0
    cat > src/main.rs <<'RUST'
use std::io;
use workeros::open_read;

fn main() -> io::Result<()> {
    let input = open_read("INPUT")?;
    let mut data = [0u8; 64];
    let n = input.read_at(&mut data, 0)?;
    print!("{}", String::from_utf8_lossy(&data[..n]));
    Ok(())
}
RUST
    cargo build --offline --locked
    "$python" -I - "$PWD/target/debug/worker-reader" <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
import sys

from workeros import WorkerRoster

with TemporaryDirectory() as directory:
    path = Path(directory) / "input.txt"
    path.write_bytes(b"Hello from workerOS\n")
    with path.open("rb", buffering=0) as source:
        source.seek(2)
        roster = WorkerRoster()
        deadline = monotonic_ns() + 10_000_000_000
        worker = roster.start_executable("rust", "read", [sys.argv[1]],
                                         fds={"INPUT": source.fileno()}, due_ns=deadline)
        try:
            if roster.join(worker.name, due_ns=deadline) != 0 or source.tell() != 2:
                raise SystemExit("Rust reader failed or moved the shared offset")
        finally:
            if worker.process.poll() is None:
                worker.process.kill()
                worker.process.wait(timeout=5)
PY
)
```

Expect `Hello from workerOS`. Cargo fetches the pinned tag and builds
using the resulting lock.

## Try the private offline bundle

[Install the Python controller](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#python) and set
`WORKEROS_OFFLINE` to the absolute path of the verified
private `workerOS-0.8.0-offline` directory. The block uses the pip environment.
For uv, set `WORKEROS_PYTHON="$WORKEROS_OFFLINE/.venv-0.8.0-uv/bin/python"`
first.

```sh
(
    set -eu
    offline=${WORKEROS_OFFLINE:?set WORKEROS_OFFLINE to the extracted bundle directory}
    python=${WORKEROS_PYTHON:-"$offline/.venv-0.8.0/bin/python"}
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    git clone --quiet --no-checkout "$offline/source/workeros-0.8.0.bundle" "$work/source"
    git -C "$work/source" checkout --quiet --detach refs/tags/v0.8.0
    export CARGO_HOME="$work/cargo"
    export GIT_ALLOW_PROTOCOL=file CARGO_NET_GIT_FETCH_WITH_CLI=true
    cd "$work"
    cargo new --bin --vcs none worker-reader
    cd worker-reader
    cargo add workeros --git "file://$work/source" --tag v0.8.0
    cat > src/main.rs <<'RUST'
use std::io;
use workeros::open_read;

fn main() -> io::Result<()> {
    let input = open_read("INPUT")?;
    let mut data = [0u8; 64];
    let n = input.read_at(&mut data, 0)?;
    print!("{}", String::from_utf8_lossy(&data[..n]));
    Ok(())
}
RUST
    cargo build --offline --locked
    "$python" -I - "$PWD/target/debug/worker-reader" <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
import sys

from workeros import WorkerRoster

with TemporaryDirectory() as directory:
    path = Path(directory) / "input.txt"
    path.write_bytes(b"Hello from workerOS\n")
    with path.open("rb", buffering=0) as source:
        source.seek(2)
        roster = WorkerRoster()
        deadline = monotonic_ns() + 10_000_000_000
        worker = roster.start_executable("rust", "read", [sys.argv[1]],
                                         fds={"INPUT": source.fileno()}, due_ns=deadline)
        try:
            if roster.join(worker.name, due_ns=deadline) != 0 or source.tell() != 2:
                raise SystemExit("Rust reader failed or moved the shared offset")
        finally:
            if worker.process.poll() is None:
                worker.process.kill()
                worker.process.wait(timeout=5)
PY
)
```

Expect `Hello from workerOS`. Cargo fetches the exact tag from a local
clone into the disposable Cargo home and builds from that lock. The
bundle's `checks/Cargo.lock` records the separate private tag check. This
example creates its own lock for its local file URL.

## Use the historical v0.4.0 release

To use the [published v0.4.0 tag](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.4.0),
run this in your own Cargo project:

```sh
cargo add worker-handoff --git https://github.com/thisistuhinsen/workerOS --tag v0.4.0 --rename workeros &&
cargo build --locked
```

## Reader behavior

`open_read` checks the named binding against the live read-only regular file.
The reader owns a close-on-exec duplicate, and positional reads preserve the
shared offset. A read can return fewer bytes than requested. Dropping the
reader closes the duplicate. Keep the inherited slot stable while opening
the reader and close the slot or mark it non-inheritable before starting
further children unless they need it. The launching application remains
responsible for authorization and supervision.
