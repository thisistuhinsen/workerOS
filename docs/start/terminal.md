# Run a job from your terminal

Start in the Linux or Ubuntu WSL2 folder where you ran
[hello with the published v0.7.0 release](../../README.md#install-and-run).
If the shell cannot find the command, return to that folder first.

```sh
.venv-0.7.0/bin/workeros-demo -- /usr/bin/printf 'hello\n'
```

Look for `hello` and `job: exited 0`. After `--`, pass your own command
and arguments. WorkerOS starts it as you; this doesn't grant extra rights.
For v0.8.0, use a verified offline bundle or wait for publication, then try
the same job with the candidate's structured result:

<a name="run-a-job-from-terminal-v080"></a>

```sh
.venv-0.8.0/bin/workeros run --json -- /usr/bin/printf 'hello\n'
```

Machine mode emits one versioned JSON result on stdout and omits the
child's output by default. Use the ordinary command without `--json` to
see the child's `hello`. In the JSON result, look for
`status: reported` and `result.terminal` with `lifecycle: exited`,
`returncode: "0"`, and `cleanup.status: reaped`. `effect` remains `unknown`: a successful exit does
not prove what a command changed. See the [v0.8.0 install instructions](../install-0.8.0.md#offline-install).
If the reply is unavailable or cleanup is not confirmed, don't replay
automatically; follow the [recovery steps](../support.md#troubleshooting).

For local machine mode, choose a working directory or capture child output
in new files:

```sh
.venv-0.8.0/bin/workeros run --json --cwd . --stdout job.out --stderr job.err -- /usr/bin/printf 'hello\n'
```

Relative capture paths use your current directory, even when the child
runs in a different one. Use an existing directory you own and fresh
filenames. Capture files contain raw workload output. The JSON result
reports the child's outcome and cleanup separately.

## See a timeout

**Published v0.7.0**

```sh
.venv-0.7.0/bin/workeros-demo
```

**Verified v0.8.0 candidate**

```sh
.venv-0.8.0/bin/workeros demo
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

[Run from v0.7.0 JSON](config.md#run-from-json) ·
[Run from v0.8.0 JSON](config.md#run-from-json-v080) or [YAML](config.md#run-from-yaml) ·
[Try the v0.8.0 named-file example](code.md#give-a-worker-an-open-file-v080) ·
[Back to first run](../../README.md#install-and-run)
