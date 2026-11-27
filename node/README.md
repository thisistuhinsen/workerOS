# WorkerOS for Node.js

> These are v0.8.0 instructions. Use public downloads only after that release,
> or use a verified offline bundle now. For the published v0.7.0 release, use the [v0.7.0 guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/node/README.md).

Read a file that your launcher already opened. The WorkerOS reader for Node.js
uses positional reads on the inherited Linux descriptor, preserving the
launcher's file offset. Its npm install ID is `workeros`.

Use Node.js 22 or newer on Linux x64 or ARM64 with `/proc` mounted. The tarball
declares Linux in its npm metadata. On Windows, run the example from a Linux
guest under WSL2.

## Download from GitHub Releases

Download the npm tarball, the matching Python wheel
for the launcher example, and their release checksums. This prepares a fresh
npm project with a local `vendor/` directory. Use curl and GNU coreutils
(`sha256sum`). The verified local tarball works with stock npm 12, whose
[remote URL policy](https://docs.npmjs.com/cli/v12/using-npm/config/#allow-remote)
denies direct third-party tarball URLs by default.

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
project_dir="$(mktemp -d)/node-worker" &&
mkdir -p "$project_dir/vendor" &&
(
    cd "$project_dir/vendor" || exit 1
    curl -fsSL "$release/SHA256SUMS" -o SHA256SUMS || exit 1
    for asset in workeros-0.8.0.tgz workeros-0.8.0-py3-none-any.whl; do
        curl -fsSL "$release/$asset" -o "$asset" || exit 1
        checksum=$(awk -v asset="$asset" '$2 == asset { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS) || exit 1
        printf '%s\n' "$checksum" | sha256sum --strict -c - || exit 1
    done
) &&
cd "$project_dir" &&
npm init -y >/dev/null
```

## Or prepare from the offline bundle

Start in the extracted private `workerOS-0.8.0-offline` directory. Verify the bundle,
then copy the npm tarball and matching Python wheel from `assets/` into a
fresh project so npm can record a relative tarball dependency.

```sh
bundle_dir=$(pwd -P) &&
(cd assets && sha256sum --strict -c SHA256SUMS) &&
project_dir="$(mktemp -d)/node-worker" &&
mkdir -p "$project_dir/vendor" &&
cp "$bundle_dir/assets/workeros-0.8.0.tgz" "$bundle_dir/assets/workeros-0.8.0-py3-none-any.whl" "$project_dir/vendor/" &&
cd "$project_dir" &&
npm init -y >/dev/null
```

## Install in the npm project

Once either preparation command succeeds, install the tarball from that project
directory.

```sh
npm install --offline --ignore-scripts --no-audit --no-fund ./vendor/workeros-0.8.0.tgz
```

Keep the lockfile and verified tarball together; restore the project with
`npm ci --offline --ignore-scripts --no-audit --no-fund`.

## Read one inherited file

From the project directory above, install the matching Python controller from
the local wheel. Use Python 3.11 or later.

```sh
python3 -m venv .venv &&
.venv/bin/python -I -m pip install --no-index --no-deps ./vendor/workeros-0.8.0-py3-none-any.whl
```

The launcher opens a temporary file, renames it, and creates different
contents at its old path. The Node worker reads through the granted descriptor
and prints `Hello from workerOS`.

```sh
.venv/bin/python -I - <<'PY'
import os
from pathlib import Path
from shutil import which
from tempfile import TemporaryDirectory
from time import monotonic_ns
from workeros import WorkerRoster

node = which("node")
if node is None:
    raise SystemExit("Install Node.js 22+")
example = Path("node_modules/workeros/examples/read-input.cjs").resolve(strict=True)
roster = WorkerRoster()
with TemporaryDirectory() as directory:
    source = Path(directory) / "input"
    source.write_bytes(b"Hello from workerOS\n")
    with source.open("rb", buffering=0) as file:
        source.rename(Path(directory) / "renamed-input")
        source.write_bytes(b"Replacement at the old path\n")
        fd = file.fileno()
        os.lseek(fd, 2, os.SEEK_SET)
        deadline = monotonic_ns() + 10_000_000_000
        worker = roster.start_executable(
            "node-reader", "read", [node, str(example)], fds={"INPUT": fd}, due_ns=deadline,
        )
        try:
            status = roster.join(worker.name, due_ns=deadline)
        finally:
            if worker.process.poll() is None:
                worker.process.kill()
                worker.process.wait(timeout=5)
        if status != 0:
            raise SystemExit(f"reader failed with status {status}")
        assert os.lseek(fd, 0, os.SEEK_CUR) == 2
PY
```

## Write your own reader

To write your own reader, use the same `INPUT` name in the launcher and the worker.

```js
const { openInherited } = require("workeros");

const input = openInherited("INPUT", { ownership: "owned" });
try {
    const buffer = Buffer.alloc(4096);
    const bytesRead = input.readAt(buffer, 0);
    process.stdout.write(buffer.subarray(0, bytesRead));
} finally {
    input.close();
}
```

For ES modules, import the same function with `import { openInherited } from "workeros"`.

## API and descriptor lifetime

- `openInherited(binding, { ownership })` accepts an exact uppercase ASCII ABI binding such as `INPUT` or `REPORT_2`. It checks `WORKER_HANDOFF_ABI=1` and the binding’s `FD`, `DEV`, `INO` and `ACCESS` declarations. The kernel must report a live regular file with matching device and inode and actual `read` or `read-write` access. `O_PATH` and write-only slots are refused. If `/proc/self/fdinfo` is inaccessible, acquisition fails and leaves the descriptor to the caller.
- The handle exposes `binding`, `ownership`, `device` and `inode` as unsigned bigints for the two numeric IDs, and the actual `access` mode. Its operations are `readAt` and `close`.
- `readAt(buffer, position)` fills a Node `Buffer` from its start. Pass a nonnegative safe integer or signed 64-bit bigint for the file position. It returns the actual byte count, including `0` at EOF. A short read is a normal result. A read leaves the shared file offset unchanged.
- `ownership` defaults to `"borrowed"`. Closing a borrowed handle invalidates that handle and leaves the FD open for its owner. With `"owned"`, a successful acquisition transfers responsibility for the child’s FD to the handle. `close()` invalidates the handle and attempts to close the validated slot once. Repeated calls have no effect, including after a close error. Validation failures during acquisition leave the descriptor open.

The environment fields are declarations. Use this API inside a trusted worker launched by an authorized supervisor. Keep the underlying descriptor stable until the handle closes. Within one JavaScript isolate the package refuses a second simultaneous handle for the same slot, even under another binding. Before a read or owned close it checks the kernel facts again and refuses detected replacement. A file opened again under the same slot with the same device, inode and access can appear identical. Keep other code and worker threads from closing or rebinding the slot.

`HandoffError` is exported by both entry points. Errors from metadata checks carry an `ERR_WORKER_HANDOFF_` code. Node filesystem errors from `readAt` or `close` can be handled with their usual error codes.

The [workerOS project guide](https://github.com/thisistuhinsen/workerOS#readme)
covers the Python launcher, process supervision, and Unix socket APIs. For the
original package name and artifacts, see the [historical v0.4.0 release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.4.0).
The earlier private v0.6.0 bundle has its own artifacts and lockfiles.
