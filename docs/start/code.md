# Use WorkerOS in code

Start a job from Python, or add a reader to a worker that needs an open
file. The Node.js, C, C++, Go, Rust and Java packages read inputs a
launcher passes to them. Applications in those languages can also call
the installed `workeros` executable as a separate process.

## Run hello from Python

From the Linux or Ubuntu WSL2 folder where you ran
[the published hello example](../../README.md#install-and-run), paste:

```sh
.venv-0.7.0/bin/python -I - <<'PY'
from time import monotonic_ns
from worker_handoff import DirectChildSupervisor

supervisor = DirectChildSupervisor()
deadline = monotonic_ns() + 5_000_000_000
worker = supervisor.start_executable(
    "hello", "demo", ["/usr/bin/printf", "hello\\n"],
    due_ns=deadline,
)
result = supervisor.wait(
    worker.name, due_ns=deadline,
    cleanup_due_ns=deadline + 2_000_000_000,
)
print(result.lifecycle.value, result.returncode)
PY
```

Look for `hello` followed by `exited 0`. If the import fails, use the
Python executable from the named environment.

<a name="run-hello-from-python-v080"></a>

### Python hello with v0.8.0

After [installing v0.8.0](../install-0.8.0.md#python), paste this from the
directory that contains `.venv-0.8.0`:

```sh
.venv-0.8.0/bin/python -I - <<'PY'
from time import monotonic_ns
from workeros import DirectChildSupervisor

supervisor = DirectChildSupervisor()
deadline = monotonic_ns() + 5_000_000_000
worker = supervisor.start_executable(
    "hello", "demo", ["/usr/bin/printf", "hello\n"],
    due_ns=deadline,
)
result = supervisor.wait(
    worker.name, due_ns=deadline,
    cleanup_due_ns=deadline + 2_000_000_000,
)
print(result.lifecycle.value, result.returncode)
PY
```

Look for `hello` followed by `exited 0`.
The worker text and Python result are separate observations; an exit does not
prove what the command changed. If you lose the result or it is uncertain,
follow the [recovery guide](../support.md#troubleshooting) before retrying.

## Give a worker a file you already opened

A parent app opens a report. Its worker reads that file through the handle
it receives, not by reopening a filename. The parent's read position
stays the same. Try it with the packaged sample, which creates its own file:

```sh
example=.venv-0.7.0/share/worker-handoff/examples/run_inherited_fd.py
.venv-0.7.0/bin/python -I "$example" --language python
```

Look for `Python: PASSED (worker exited 0 and kept the shared offset)`.

<a name="give-a-worker-an-open-file-v080"></a>

### Open-file handoff with v0.8.0

From the directory that contains `.venv-0.8.0`, run the packaged sample:

```sh
example=.venv-0.8.0/share/workeros/examples/run_inherited_fd.py
.venv-0.8.0/bin/python -I "$example" --language python
```

Look for `Python: PASSED (worker exited 0 and kept the shared offset)`.
If either sample is missing, check that you're in the folder where you
installed that version. If the reader reports `FAILED`, see its printed reason
and the [troubleshooting guide](../support.md#troubleshooting).

[Install a v0.7.0 reader](install.md#reader-packages) ·
[Install a v0.8.0 reader](../install-0.8.0.md#package-manager-quick-reference) ·
[Pass a file from your own Python app](../workers.md#python-apis) ·
[Back to first run](../../README.md#install-and-run)

## Call an approved workflow from code

These **v0.8.0 candidate** examples operate as the caller's ordinary OS
account. First follow [managed terminal setup](terminal.md#run-and-check-an-approved-worker)
to get the verified local executable, enrolled workflow, and retained
request ID. For an invocation from another interface, use its original ID.

Each example defaults to readback. Use `run` once, with an ID retained for
that submission, if you intend to launch and have run rights. Keep the
same ID for readback and do not resubmit to recover an unknown result.
Run rights and result rights can be granted separately. The operator may
need to provide a fresh connection to the finite local listener for readback.

Python uses the candidate's API. The other six examples invoke the installed
executable without a shell, preserve its JSON stdout and diagnostic stderr,
and return its exit code. They use only their standard libraries, with no
separate managed client or worker reader package required. Parse stdout even
on nonzero exit and check `status`, `effect`, and `code` before interpreting
the receipt. An unknown or unavailable result supplies no proof of an effect.

### Python

Save as `request.py`. Run with `.venv-0.8.0/bin/python request.py` to check
status or `.venv-0.8.0/bin/python request.py run` for the one submission.

```python
import json
import os
import sys
from workeros.managed_executor import registered_launch

if sys.argv[1:] not in ([], ["run"]):
    raise SystemExit("usage: request.py [run]")
result = registered_launch(
    os.environ["WORKEROS_REQUEST_ID"],
    workflow=os.environ["WORKEROS_WORKFLOW"],
    readback=sys.argv[1:] != ["run"],
)
print(json.dumps(result))
raise SystemExit(0 if result["status"] in ("started", "terminal", "not_started") else 1)
```

### Node.js

Save as `request.cjs`. Use `node request.cjs` or `node request.cjs run`.

```javascript
const { spawnSync } = require("node:child_process");
const args = process.argv.slice(2);
const { WORKEROS_BIN: bin, WORKEROS_WORKFLOW: flow, WORKEROS_REQUEST_ID: id } = process.env;
if (!bin || !flow || !id || args.length > 1 || (args.length && args[0] !== "run")) {
  throw new Error("set WORKEROS_BIN, WORKEROS_WORKFLOW and WORKEROS_REQUEST_ID; use request.cjs [run]");
}
const op = args.length ? "run-approved" : "launch-status";
const child = spawnSync(bin, ["managed", op, "--workflow", flow, "--request-id", id],
                        { stdio: ["ignore", "inherit", "inherit"] });
if (child.error) throw child.error;
process.exitCode = child.status ?? 1;
```

### Go

Save as `request.go`. Build with `go build -o request-go request.go`,
then use `./request-go` or `./request-go run`.

```go
package main

import (
    "fmt"
    "os"
    "os/exec"
)

func main() {
    bin := os.Getenv("WORKEROS_BIN")
    flow := os.Getenv("WORKEROS_WORKFLOW")
    id := os.Getenv("WORKEROS_REQUEST_ID")
    args := os.Args[1:]
    op := "launch-status"
    if len(args) == 1 && args[0] == "run" {
        op = "run-approved"
    } else if len(args) != 0 {
        fmt.Fprintln(os.Stderr, "usage: request-go [run]")
        os.Exit(2)
    }
    cmd := exec.Command(bin, "managed", op, "--workflow", flow, "--request-id", id)
    cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
    if err := cmd.Run(); err != nil {
        if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() >= 0 {
            os.Exit(exit.ExitCode())
        }
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

### Java

Save as `Request.java`. With a JDK that supports source-file launch, use
`java Request.java` or `java Request.java run`.

```java
import java.util.Objects;

class Request {
    public static void main(String[] args) throws Exception {
        String op = "launch-status";
        if (args.length == 1 && args[0].equals("run")) op = "run-approved";
        else if (args.length != 0) throw new IllegalArgumentException("usage: Request.java [run]");
        var child = new ProcessBuilder(
            Objects.requireNonNull(System.getenv("WORKEROS_BIN")), "managed", op,
            "--workflow", Objects.requireNonNull(System.getenv("WORKEROS_WORKFLOW")),
            "--request-id", Objects.requireNonNull(System.getenv("WORKEROS_REQUEST_ID"))
        ).inheritIO().start();
        System.exit(child.waitFor());
    }
}
```

### C and C++

Save as `request.c`. Build with `cc -o request-c request.c` for C or
`c++ -x c++ -o request-cpp request.c` for C++. Use the resulting executable
with no arguments for readback, or with `run` for the submission. The
POSIX `execl` call replaces this short adapter with WorkerOS.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *bin = getenv("WORKEROS_BIN");
    const char *flow = getenv("WORKEROS_WORKFLOW");
    const char *id = getenv("WORKEROS_REQUEST_ID");
    if (!bin || !flow || !id || argc > 2 || (argc == 2 && strcmp(argv[1], "run"))) {
        fputs("set WORKEROS_BIN, WORKEROS_WORKFLOW and WORKEROS_REQUEST_ID; use [run]\n", stderr);
        return 2;
    }
    const char *op = argc == 2 ? "run-approved" : "launch-status";
    execl(bin, bin, "managed", op, "--workflow", flow, "--request-id", id, (char *)NULL);
    perror("workeros");
    return 127;
}
```

### Rust

Save as `request.rs`. Build with `rustc -o request-rust request.rs`,
then use `./request-rust` or `./request-rust run`.

```rust
use std::{env, process::{self, Command}};

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let op = match args.as_slice() {
        [] => "launch-status",
        [arg] if arg == "run" => "run-approved",
        _ => { eprintln!("usage: request-rust [run]"); process::exit(2); }
    };
    let flow = env::var("WORKEROS_WORKFLOW").expect("WORKEROS_WORKFLOW");
    let id = env::var("WORKEROS_REQUEST_ID").expect("WORKEROS_REQUEST_ID");
    let exit = Command::new(env::var_os("WORKEROS_BIN").expect("WORKEROS_BIN"))
        .args(["managed", op, "--workflow", &flow, "--request-id", &id])
        .status().expect("start WorkerOS");
    process::exit(exit.code().unwrap_or(1));
}
```
