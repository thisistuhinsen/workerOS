# workerOS for Go

> These commands use v0.8.0. For the previous release, use the [v0.7.0 guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/go/README.md).

Use Go 1.22 or later on Linux amd64 or arm64. This example builds a reader in
a fresh Go module, then starts it with an already-open file.

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
    cd "$work"
    go mod init example.invalid/workeros-reader
    GOTOOLCHAIN=local go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.8.0
    go mod verify
    cat > main.go <<'GO'
package main

import (
    "fmt"
    "io"
    "log"

    "github.com/thisistuhinsen/workerOS/go/workerhandoff"
)

func main() {
    input, err := workerhandoff.Open("INPUT")
    if err != nil {
        log.Fatal(err)
    }

    var data [64]byte
    n, err := input.ReadAt(data[:], 0)
    if closeErr := input.Close(); closeErr != nil {
        log.Fatal(closeErr)
    }
    if err != nil && err != io.EOF {
        log.Fatal(err)
    }
    fmt.Print(string(data[:n]))
}
GO
    GOTOOLCHAIN=local GOPROXY=off go build -buildvcs=false -o "$work/reader" .
    "$python" -I - "$work/reader" <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
import sys

from worker_handoff import WorkerRoster

with TemporaryDirectory() as directory:
    path = Path(directory) / "input.txt"
    path.write_bytes(b"Hello from workerOS\n")
    with path.open("rb", buffering=0) as source:
        source.seek(2)
        roster = WorkerRoster()
        deadline = monotonic_ns() + 10_000_000_000
        worker = roster.start_executable("go", "read", [sys.argv[1]],
                                         fds={"INPUT": source.fileno()}, due_ns=deadline)
        try:
            if roster.join(worker.name, due_ns=deadline) != 0 or source.tell() != 2:
                raise SystemExit("Go reader failed or moved the shared offset")
        finally:
            if worker.process.poll() is None:
                worker.process.kill()
                worker.process.wait(timeout=5)
PY
)
```

Expect `Hello from workerOS`. The Go checksum service must be able to
verify the public tag. Use your usual Go checksum settings.

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
    cd "$work"
    go mod init example.invalid/workeros-reader
    go mod edit -require=github.com/thisistuhinsen/workerOS@v0.8.0 \
        "-replace=github.com/thisistuhinsen/workerOS=$work/source"
    cat > main.go <<'GO'
package main

import (
    "fmt"
    "io"
    "log"

    "github.com/thisistuhinsen/workerOS/go/workerhandoff"
)

func main() {
    input, err := workerhandoff.Open("INPUT")
    if err != nil {
        log.Fatal(err)
    }

    var data [64]byte
    n, err := input.ReadAt(data[:], 0)
    if closeErr := input.Close(); closeErr != nil {
        log.Fatal(closeErr)
    }
    if err != nil && err != io.EOF {
        log.Fatal(err)
    }
    fmt.Print(string(data[:n]))
}
GO
    GOTOOLCHAIN=local GOPROXY=off go build -buildvcs=false -o "$work/reader" .
    "$python" -I - "$work/reader" <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
import sys

from worker_handoff import WorkerRoster

with TemporaryDirectory() as directory:
    path = Path(directory) / "input.txt"
    path.write_bytes(b"Hello from workerOS\n")
    with path.open("rb", buffering=0) as source:
        source.seek(2)
        roster = WorkerRoster()
        deadline = monotonic_ns() + 10_000_000_000
        worker = roster.start_executable("go", "read", [sys.argv[1]],
                                         fds={"INPUT": source.fileno()}, due_ns=deadline)
        try:
            if roster.join(worker.name, due_ns=deadline) != 0 or source.tell() != 2:
                raise SystemExit("Go reader failed or moved the shared offset")
        finally:
            if worker.process.poll() is None:
                worker.process.kill()
                worker.process.wait(timeout=5)
PY
)
```

Expect `Hello from workerOS`. The checkout and replacement are scoped to
this disposable module. The bundle's `checks/go.sum` records checksums from
the private verification of the exact local tag.

## Use the historical v0.4.0 release

To use the [published v0.4.0 tag](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.4.0),
resolve it from your own module with:

```sh
go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.4.0 &&
go mod verify
```

### If the v0.4.0 checksum lookup returns 404

If Go reports that the checksum service could not fetch v0.4.0, confirm the
public tag points to `cd3d621c28247a66b1c6978396335cc97d8c0fa9`.

```sh
git ls-remote --refs https://github.com/thisistuhinsen/workerOS.git refs/tags/v0.4.0
```

In your own Go module, add these two entries to `go.sum`. Keep unrelated entries
and stop if v0.4.0 already has different checksums.

```text
github.com/thisistuhinsen/workerOS v0.4.0 h1:PUaqJ5Q5IoFOE8qGCYLNZmlgzD80UoT2GuvB82PSdis=
github.com/thisistuhinsen/workerOS v0.4.0/go.mod h1:GLxsXbnr8VyBiNpeAm1qFkJDH8XoyQ03m9nZpiImYH8=
```

```sh
GOPROXY=direct go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.4.0
go mod verify
```

Go checks both the downloaded module and its `go.mod` against the pinned hashes.
Keep your checksum settings in place.

## Reader behavior

`Open` checks the launcher metadata against the live descriptor, including
the device, inode and readable access mode. It owns a close-on-exec
duplicate. Keep the inherited slot stable during `Open` and close it or mark
it non-inheritable before starting further children unless they need it.

`ReadAt` preserves the shared file position and checks the Linux monotonic
deadline before reading. An in-progress syscall can outlast that deadline.
Authorization and worker lifecycle remain with the launching application.
