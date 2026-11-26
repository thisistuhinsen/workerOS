# worker-handoff for Node.js

Your supervisor already opened the file. `worker-handoff` lets a Node.js worker read the inherited Linux descriptor at a specific byte offset. The supervisor keeps its own descriptor and its place in the file.

## Install

Use Node.js 22 or newer on Linux x64 or ARM64 with procfs mounted at `/proc`. After v0.5.0 is published, install its GitHub Release tarball in your Node project.

```sh
npm install --no-audit --no-fund https://github.com/thisistuhinsen/workerOS/releases/download/v0.5.0/worker-handoff-0.5.0.tgz
```

For an offline install, save the tarball locally and run `npm install --offline --no-audit --no-fund ./worker-handoff-0.5.0.tgz`.
With npm 12's default remote URL policy, pass `--allow-remote=all` for that direct URL install or use the local tarball.

## Read one inherited file

Save this as `worker.cjs`. The launching supervisor supplies the `INPUT` binding.

```js
const { openInherited } = require("worker-handoff");

const input = openInherited("INPUT", { ownership: "owned" });
try {
    const buffer = Buffer.alloc(4096);
    const bytesRead = input.readAt(buffer, 0);
    process.stdout.write(buffer.subarray(0, bytesRead));
} finally {
    input.close();
}
```

For ES modules, import the same function with `import { openInherited } from "worker-handoff"`.

Here is a Python launcher for the example that ships in the tarball. Install the Python `worker-handoff` wheel in the interpreter you use below, and run the command from your Node project.

```sh
printf 'Hello from the supervisor\n' > input.txt
python - <<'PY'
import os
from pathlib import Path
from shutil import which
from time import monotonic_ns
from worker_handoff import WorkerRoster

node = which("node")
if node is None:
    raise SystemExit("Install Node.js 22+")
example = Path("node_modules/worker-handoff/examples/read-input.cjs").resolve()
roster = WorkerRoster()
with Path("input.txt").open("rb", buffering=0) as file:
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

## API and descriptor lifetime

- `openInherited(binding, { ownership })` accepts an exact uppercase ASCII ABI binding such as `INPUT` or `REPORT_2`. It checks `WORKER_HANDOFF_ABI=1` and the binding’s `FD`, `DEV`, `INO` and `ACCESS` declarations. The kernel must report a live regular file with matching device and inode and actual `read` or `read-write` access. `O_PATH` and write-only slots are refused. If `/proc/self/fdinfo` is inaccessible, acquisition fails and leaves the descriptor to the caller.
- The handle exposes `binding`, `ownership`, `device` and `inode` as unsigned bigints for the two numeric IDs, and the actual `access` mode. Its operations are `readAt` and `close`.
- `readAt(buffer, position)` fills a Node `Buffer` from its start. Pass a nonnegative safe integer or signed 64-bit bigint for the file position. It returns the actual byte count, including `0` at EOF. A short read is a normal result. A read leaves the shared file offset unchanged.
- `ownership` defaults to `"borrowed"`. Closing a borrowed handle invalidates that handle and leaves the FD open for its owner. With `"owned"`, a successful acquisition transfers responsibility for the child’s FD to the handle. `close()` invalidates the handle and attempts to close the validated slot once. Repeated calls have no effect, including after a close error. Validation failures during acquisition leave the descriptor open.

The environment fields are declarations. Use this API inside a trusted worker launched by an authorized supervisor. Keep the underlying descriptor stable until the handle closes. Within one JavaScript isolate the package refuses a second simultaneous handle for the same slot, even under another binding. Before a read or owned close it checks the kernel facts again and refuses detected replacement. A file opened again under the same slot with the same device, inode and access can appear identical. Keep other code and worker threads from closing or rebinding the slot.

`HandoffError` is exported by both entry points. Errors from metadata checks carry an `ERR_WORKER_HANDOFF_` code. Node filesystem errors from `readAt` or `close` can be handled with their usual error codes.

The main [workerOS repository](https://github.com/thisistuhinsen/workerOS) documents the Python launcher, process supervision, and the Unix socket APIs.
