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
.venv-0.8.0/bin/workeros run --json --cwd . --stdout job.out --stderr job.err --report job.json -- /usr/bin/printf 'hello\n'
```

Relative capture paths use your current directory, even when the child
runs in a different one. Use an existing directory you own and fresh
filenames. Capture files contain raw workload output. The JSON result
reports the child's outcome and cleanup separately.
The receipt's `attempt_id` identifies the direct run. Save stdout or use
`--report` to keep a caller-owned copy. Direct runs have no stored receipt
to look up later. If export fails, save the receipt from stdout without
rerunning the job.

## Run and check an approved worker

Use this **v0.8.0 candidate** path after your administrator gives your
Linux account a commissioned workflow name and publishes its local client
routing. Ordinary jobs above need no such setup. For a disposable managed
host, follow the [administrator walkthrough](../guarded-walkthrough.md).
It commissions `write-health-record` and shows which account can call it.

The guarded walkthrough uses the approved Linux x86-64 platform wheel
with glibc 2.38 or newer. It needs a supported system-level `systemd`
guard, a delegated cgroup v2 scope and usable Linux namespaces. The
administrator pins the executable, ordinary worker identity, matching file
descriptors and allowed operations. Requests use the registered local Unix
socket and its authorized caller UID. Preview alone grants no authority.

Use the verified caller installation from your ordinary account. Replace
`write-health-record` if your administrator gave you a different name.
Generate a request ID once and keep it before launching. The examples in
the other guides use the same shell variables.

```sh
export WORKEROS_BIN="$PWD/.venv-0.8.0/bin/workeros"
export WORKEROS_WORKFLOW=write-health-record
WORKEROS_REQUEST_ID=$(.venv-0.8.0/bin/python -I -c \
  'from workeros.managed_launch import new_launch_request; print(new_launch_request())') &&
export WORKEROS_REQUEST_ID
```

Choose **one** interface for the launch. This submits the approved workflow
once. There is no per-call command, filename, account or capability override.

```sh
"$WORKEROS_BIN" managed run-approved --workflow "$WORKEROS_WORKFLOW" \
  --request-id "$WORKEROS_REQUEST_ID"
```

An authorized reader checks the **same ID** without submitting another job.
Keep the ID if a reply is lost or the result is unknown. The operator may
need to make the finite local listener available for the status request.

```sh
"$WORKEROS_BIN" managed launch-status --workflow "$WORKEROS_WORKFLOW" \
  --request-id "$WORKEROS_REQUEST_ID"
```

Read the versioned JSON on stdout and handle a nonzero exit. A refused
request carries its reason. An unknown effect stays unknown until supported
readback establishes more. A guarded terminal receipt can describe the
child's exit and cleanup while independent evidence of the effect is still
unavailable. A point observation describes only its sampled moment.
[Host and transport requirements](../host-preflight.md#register-a-named-systemd-workflow) ·
[JSON and YAML](config.md#submit-an-approved-workflow-from-json-or-yaml) ·
[Python and other languages](code.md#call-an-approved-workflow-from-code)

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
