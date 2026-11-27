# Use WorkerOS in code

Start a job from Python, or add a reader to a worker that needs an open
file. **Python starts jobs.** Node.js, C, C++, Go, Rust and Java can read
inputs a launcher passes to them; those libraries aren't launchers.

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

[Install a reader for another language](install.md#reader-packages) ·
[Pass a file from your own Python app](../workers.md#python-apis) ·
[Back to first run](../../README.md#install-and-run)
