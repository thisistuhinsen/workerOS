# Run a job from your terminal

Start in the Linux or Ubuntu WSL2 folder where you ran
[hello with the published v0.7.0 release](../../README.md#install-and-run).
If the shell cannot find the command, return to that folder first.

```sh
.venv-0.7.0/bin/workeros-demo -- /usr/bin/printf 'hello\n'
```

Look for `hello` and `job: exited 0`. After `--`, pass your own command
and arguments. WorkerOS starts it as you; this doesn't grant extra rights.
With the [v0.8.0 candidate](../install-0.8.0.md#offline-install), the same
command starts with `.venv-0.8.0/bin/workeros run --` instead.

## See a timeout

```sh
.venv-0.7.0/bin/workeros-demo
```

This runs a disk-space report and a second job that outlasts the wait.
The disk-space figure varies by machine. Look for:

```text
report: exited 0
slow job: timed out
cleanup: reaped
```

`timed out` means the wait ended before WorkerOS saw an exit. `reaped`
means WorkerOS collected the stopped child's exit. A timeout cannot undo
a file write or message the job already made. If cleanup isn't confirmed,
[check what happened before retrying](../support.md#troubleshooting).

[Run a job from JSON](config.md#run-from-json) · [Back to first run](../../README.md#install-and-run)
