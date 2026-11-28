# Run a job from JSON

For one runnable example with the install steps, start with [Run a job from
JSON](start/config.md). This page is the complete configuration reference.

- **Policy:** Which jobs and inputs your app may use. Save it once.
- **Request:** Which job to run this time. Pass it on standard input.

In a Linux or Ubuntu WSL2 terminal, go to the folder where you installed
with [pip or uv](../README.md#install-and-run), then activate the environment:
`. .venv-0.7.0/bin/activate`. Use `workeros-config` (or its alias
`worker-handoff-config`). The v0.8.0 candidate also accepts the same
arguments through `workeros config`. Requests and results are JSON.
In the v0.8.0 candidate, the saved policy can also be YAML with optional
PyYAML and `--format yaml`. [Run the same job from YAML](start/config.md#run-from-yaml)
or [preview a role profile](start/config.md#preview-with-yaml).

The app can also use the [Python API](api.md). A role is an application
label, not an OS permission. The host grants access to executables, handles,
providers and destinations, with separate checks for independent evidence.
See [authorized host profiles](host-preflight.md) for that deployment path.

## Check and run an installed policy

### Run a fileless worker

`/usr/bin/true` prints nothing and exits successfully. The policy calls it
`sample`; the request tells WorkerOS to launch it.

```sh
root=$(mktemp -d)
policy="$root/minimal-policy.json"
cat > "$policy" <<'JSON'
{
  "version": 1,
  "roles": {"job-role": {"operations": ["launch"]}},
  "workflows": {
    "fileless": {
      "role": "job-role",
      "operations": ["launch"],
      "bindings": {"executable": "sample"}
    }
  }
}
JSON

workeros-config --run-policy "$policy" \
    --executable sample /usr/bin/true <<'JSON'
{"version":1,"workflow":"fileless","role":"job-role","operation":"launch","options":{"name":"sample-01"}}
JSON
```

Read `result.terminal` in the JSON reply. For this job, look for
`lifecycle: "exited"`, `returncode: "0"`, and `cleanup.status: "reaped"`.
Exit and cleanup are reported separately from timeout. This example uses a 30-second
active budget and a 2-second cleanup budget. An exit may first be collected
at or after the cutoff, so it does not establish the physical exit time.
The reply's `policy_sha256` identifies the exact bytes the command read and
validated. For an ordinary local run, the trusted operator chooses the
policy and enrolled paths. Use `--check-policy` with optional `--explain`
for a preview, or supply `--policy-sha256` to require a specific digest.
A policy check covers parsing and registrations. Verify execution authority
and required store writability at run time. The digest identifies the JSON
bytes; host identity and ownership come from the deployment.
A mismatch is refused before the worker or recorder can run. Delegated
authority and protected originals still require their enrolled host adapters.

### Store and verify terminal evidence

With the [v0.8.0 candidate installed](install-0.8.0.md), use the wheel's
[example policy](../examples/workflow_policy.json) to require the
`direct-child` supervisor and capture terminal metadata. The store's parent
directory must already exist. The installed local store creates a missing
final directory with owner-only access when it first commits evidence.
For the published v0.7.0 wheel, follow the
[tagged configuration instructions](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/configuration.md#store-and-verify-terminal-evidence).

```sh
root=$(mktemp -d)
examples=$(python -I -c 'from pathlib import Path; import sys; print(Path(sys.prefix) / "share/workeros/examples")')
policy="$examples/workflow_policy.json"
workeros-config --check-policy "$policy" \
    --executable sample /usr/bin/true --store archive "$root/archive"
```

The check validates the policy and resolves enrolled names without running
the worker or writing records. Add `--explain` to see the resolved role,
operation names, binding names, and budgets. It does not print enrolled
secret values. Pin approved policy bytes when your deployment calls for it.
Keep the executable, store, and their parent directories under trusted
host control.

```sh
digest=$(sha256sum "$policy" | cut -d' ' -f1)
workeros-config --run-policy "$policy" --policy-sha256 "$digest" \
    --executable sample /usr/bin/true --store archive "$root/archive" \
    > "$root/result.json" 2> "$root/attempt.json" <<'JSON'
{"version":1,"workflow":"fileless","role":"job-role","operation":"launch","options":{"name":"sample-01","supervise":true}}
JSON
cat "$root/result.json"
```

The command owns the direct child through its bounded terminal check and
returns one JSON response. Check `result.terminal` for lifecycle, exit code,
and cleanup. Check `result.capture.required_complete` for the required
store's result. Before dispatch, the command checks whether required local
destinations are compatible or can be initialized. An optional store does
not gate launch. A passing check cannot guarantee the later write.

The built-in `launch-terminal` projection stores terminal metadata with a
fresh host-assigned attempt ID, workflow, policy digest, and readable worker
name. The attempt ID is the receipt's run ID. Keep the separate
`launch_attempt` event on stderr to retain that ID even if the final reply
never arrives. The event identifies the planned attempt. Check the terminal
result or recover the receipt to establish what was observed. Worker stdout
and raw file bytes are outside the projection.

Read back the exact receipt in a second process. Python here copies the
receipt between JSON documents. Any client can make the same invocation.

```sh
python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as response:
    result = json.load(response)["result"]
capture = result["capture"]
if not capture["required_complete"]:
    raise SystemExit("required evidence commit is incomplete")
receipt = capture["record"]["destinations"][0]["receipt"]
print(json.dumps(dict(version=1, workflow="fileless", role="job-role",
                      operation="readback", options=dict(destination="archive", receipt=receipt))))
' "$root/result.json" > "$root/readback.json"

workeros-config --run-policy "$policy" --policy-sha256 "$digest" \
    --executable sample /usr/bin/true --store archive "$root/archive" \
    < "$root/readback.json"
```

The response reports whether the receipt and stored bytes match. Its
`durability: "unconfirmed"` is separate from that byte check. A workflow
that enrolls `verify_durable` can request a local durability check using
the same receipt.

If persistence was unknown or no receipt arrived, use the kept attempt ID
to invoke `recover_receipt` with `{"destination":"archive","attempt_id":"..."}`
under the same workflow and exact policy. It can return the matching receipt
for visible, verified bytes. Follow with `verify_durable` if needed. A missing
or unknown record leaves the workload effect unresolved. Recovery never
starts the worker. A new launch, even with the same worker name, starts a
new attempt and produces a distinct receipt.

### Policy and enrollment reference

| Policy key | Meaning |
| --- | --- |
| `version`, `roles` | Version `1`. Each named role declares its allowed `operations`. |
| `workflows.<name>.role`, `operations` | Select a role and a nonempty subset of its operations. The invocation supplies the matching names and one operation. |
| `workflows.<name>.timeout_ms`, `cleanup_ms` | Positive host budgets. For an installed launch, defaults are 30 seconds active and 2 seconds cleanup. Caps are 24 hours active and 60 seconds cleanup. A client timeout can only shorten the active deadline. |
| `workflows.<name>.args`, `cwd`, `env` | Pinned argument strings, an enrolled working-directory name, and a map from child variable names to enrolled value names. Arguments are part of the exact managed release plan when used there. Working directory and environment context are for ordinary launch. Invocation JSON supplies none of these. |
| `require_supervision`, `require_custody` | Require the corresponding enrolled capability and invocation option. A workflow requiring custody uses managed `release` for access to the protected original. Standalone `read`, `write`, or `launch` must be excluded from that workflow. Use a separate explicitly authorized workflow for fileless work. |
| `bindings.executable`, `supervisor`, `inherited` | Select a host-enrolled executable and supervisor. An optional `inherited` map on ordinary `launch` selects held resources by ABI name, for example `{"INPUT":"held-read","OUTPUT":"held-write"}`. Existing descriptor access and ownership checks apply. |
| `bindings.streams` | For ordinary launch, select enrolled descriptors for `stdin`, `stdout`, or `stderr`. Use distinct host-owned streams for child I/O. The protocol keeps its own stdin and stdout. |
| `bindings.descriptors`, `custody` | Select host-enrolled original descriptors and sink, or the independent custody provider. These are available through host adapters. |
| `bindings.observers`, `meters`, `evidence` | Map a workflow's public scope names to named host registrations. The host supplies the actual provider and run binding. |
| `recorders`, `workflows.<name>.recorder` | Name reusable recorder policies and select one for the workflow. Each uses the storage and routing fields below. |
| `capture.<operation>.profile`, `type` | Select an enrolled projector and a routed evidence type. Projection runs after that operation returns a result. Capture failure has its own status and leaves the operation result available for reconciliation. |

The installed command accepts these trusted operator bindings. Configure them
in the command or service that owns the policy. Clients send invocation JSON
on stdin.

| Operator flag | Enrolled resource |
| --- | --- |
| `--executable NAME ABSOLUTE_PATH` | An existing executable. Policy can supply pinned `args`. The invocation cannot change the program or its arguments. |
| `--inherit-fd NAME DECIMAL_FD` | An existing descriptor the operator explicitly passes to the controller. Use its name in `bindings.inherited`. |
| `--stream-fd NAME DECIMAL_FD` | An existing descriptor the operator passes for one of the child's standard streams. Use its name in `bindings.streams`. |
| `--cwd NAME ABS_DIR` | An operator-controlled directory selectable by name. |
| `--env NAME VALUE` | A nonsecret environment value selectable by an enrolled name. |
| `--secret-env NAME VARIABLE` | Enroll the value of an existing host environment variable without putting it in the command arguments or the policy. Give the child access only when its workflow needs it. |
| `--store NAME ABSOLUTE_DIR` | An owner-only local store. First commit can create the final directory under an existing trusted parent. Existing directory modes stay under the operator's control. |
| `--group-store NAME ABSOLUTE_DIR GID` | Owner-side enrollment of a pre-provisioned local store that allows read access to the existing group. An independent group reader can use the native `LocalStore(path, group_id=gid, owner_uid=owner_uid)` with an exact receipt and already granted OS access. |
| `--settled-run NAME` | An operator assertion that a named run is settled, for authorized maintenance. |

The installed path has a `direct-child` supervisor and a `launch-terminal`
projector. It runs one `launch` to a bounded terminal result, using the
default direct-child wait unless the workflow requires supervision, or
runs one enrolled recorder operation. Subsequent wait, cancel, or cleanup
calls require an application controller that keeps the owning supervisor
alive. The installed policy command runs with ordinary, non-root credentials.

For other resources, an application can build a trusted `HostBindings`
catalog and call `compile_policy(document, host)`. Import both from
`worker_handoff.enrollment` on v0.7.0 or `workeros.enrollment` on v0.8.0.
The compiled policy uses the same JSON
invocations through `serve(source, destination)`. The host authorizes each
request and separately authorizes the exact plan for a managed release.
Connected `SCM_RIGHTS`, Python callables, registration of an external
process, and adoption of an owned child use existing native APIs and require
a host adapter. JSON does not create a connection, transfer descriptor
authority, or adopt a process by PID.

## Try the standalone recorder example

Activate the v0.8.0 candidate environment and run the installed example with
two fresh local destinations you own. For v0.7.0, use the
[tagged recorder instructions](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/configuration.md#try-the-standalone-recorder-example).

```sh
store=$(mktemp -d)
mkdir -m 0700 "$store/archive" "$store/review"
config=$(python -I -c 'from pathlib import Path; import sys; print(Path(sys.prefix) / "share/workeros/examples/evidence_config.json")')
export WORKEROS_STORE="$store" WORKEROS_CONFIG="$config"
workeros-config --example-root "$store" < "$config"
workeros-config --schema
```

The [example configuration](../examples/evidence_config.json) is also under
`share/workeros/examples` in the v0.8.0 Python install prefix. It routes one
synthetic JSON receipt to a required archive and an optional review store. Both
are owner-only. The archive has a seven-day minimum retention age and the
review destination uses manual retention. Neither directory has an automatic
purge schedule. Use a new store to try different layouts or deliberately omit
the optional `review` directory to see a partial result.

To verify the record, use the original configuration in a second process.
Change `operation` to `readback` and replace `options` with
`{"destination":"archive","receipt":...}`. Supply the exact archive receipt
from the first response, including its string `committed_ns`. A successful
readback returns the verified digest and size. The local record's header binds
those bytes to the run, record ID, and declared media type.

## Request and response

One UTF-8 JSON object goes to stdin. Close stdin after the object. The
controller writes one newline-terminated JSON object to stdout. Version 1
requires `version: 1`, `workflow`, `role`, and `operation`. Supply `options` as
an object when the operation has arguments. With a compiled policy, recorder
settings come from that policy. The standalone example uses the legacy
top-level `recorder` object to set up its two stores. Identifiers start with an
ASCII letter or digit, followed by at most 127 ASCII letters, digits, dots,
underscores, or hyphens.

Unknown fields, duplicate keys, malformed Base64, invalid combinations, and
requests over 1 MiB are refused. The controller enforces semantic checks in
addition to the installed schema. Counts, offsets and timestamps in requests
allow canonical nonnegative decimal strings up to 2⁶³−1. JSON integers are
accepted through 2⁵³−1. Versions, group IDs, and retention age use bounded JSON
integers. All result integers are decimal strings, including counters,
timestamps, inode numbers, PIDs, and signed return codes. In JavaScript,
convert to `BigInt` only for arithmetic and serialize the decimal string.

A `reported` response means the operation returned a result. Check delivery,
effect, lifecycle, custody, evidence, and storage as applicable. The
installed policy run exits 3 for a reported failure such as a nonzero
child exit, timeout, incomplete cleanup, or failed required evidence. The
standalone example and native controller report these details in the
response.
A `refused` response (exit 1) has a stable request or enrollment error code.
An `unavailable` response (exit 1) may leave the operation's effect unknown.
Resolve an uncertain effect with the actual worker or store owner before
resubmitting. No operation internally replays a request. The console's own
argument errors exit 2.

## Capabilities and options

| Operation | Request options | Host binding and result |
| --- | --- | --- |
| `read` | Optional `expected_size`, positive `block_size` (default 65536), positive `timeout_ms` | Exact preheld readable original and application sink. Result reports bytes, EOF, and close times. The controller closes its duplicate; the application owns its original FD. |
| `write` | Base64 `data`, optional `sync` (false) | Caller-owned, already writable original and authorization. Sequential write uses the borrowed open description's position or append behavior. `sync` requests fsync. A completed byte write and an uncertain fsync can be reported together. |
| `launch` | Worker `name`, optional `supervise` (false) and positive `timeout_ms` | A pre-enrolled executable and optional host-set environment. The roster returns the actual start. Selecting supervision uses an enrolled direct-child supervisor. A timed launch check does not stop the child. |
| `release` | Worker `name`, optional `supervise` and `custody` (both false), positive `timeout_ms` and `cleanup_ms`, optional `write: {offset, data, exclusive}` | Exact managed plan authorized before any usable FD grant. Inherits the read-only original under the existing INPUT ABI. Optional positional write requires nonempty Base64 and an enrolled writer FD on the same file. `exclusive` defaults false and uses a cooperative advisory lock on that original. `cleanup_ms` requires supervision. Strict custody requires the enrolled independent provider and never falls back. |
| `wait`, `cancel` | Worker `name`, optional positive `timeout_ms` for wait, positive `cleanup_ms` | Enrolled supervisor. Wait reports lifecycle. Cancel asks the owner to make a new check with cancellation set. It cannot interrupt an already running wait or request. With no cleanup window, timeout or cancellation leave stop and reap to the owner. |
| `cleanup` | Worker `name`, required positive `cleanup_ms` | Authorized enrolled supervisor attempts bounded stop and reap of its exact child. External processes without ownership are outside scope. A child reap does not certify its descendants, file handles elsewhere, or whole-scope cleanup. |
| `observe` | Named `scope` and optional `subject` (`slot`, `name`, `process`) | Prebound observer. With a subject, return the corresponding scoped point report. Without it, return the raw point sample. |
| `meter` | Named `scope`, `phase` (`meter_begin` or `meter_end`) | Existing read-only meter for a held cgroup v2 scope. Reports CPU, population, and available memory counters with provenance. Shared scope counts include its other activity, and a lifetime peak remains a lifetime peak. |
| `validate` | Named `scope`, optional `require_observed` as pairs of source and subject, `require_terminal_from` as one coherent source, and `require_meter_for` as a comparable `[start_ns,end_ns]` | Checks enrolled run events and scope reports. A requested missing fact returns `incomplete`. Optional unavailable point reports retain their state. Structural coverage can pass while the CPU delta remains unavailable. Delta needs the matching raw meter pair and comparable counters. Use this operation after the required observations exist, including cleanup when requested. |
| `record` | `run_id`, `record_id`, routed evidence `type`, optional Base64 `data` and reported `effect` | Authorized recorder. Missing data reports `missing` per destination. Effect defaults to `unknown`. The explicit effect enumeration is `not-attempted`, `complete`, `partial`, `unknown`. |
| `readback`, `verify_durable`, `purge` | Named `destination`, exact `receipt` | Verify stored bytes and receipt, confirm durability for a supported local store, or request conditional purge. Purge requires explicit host authorization and positive settlement. |
| `recover_receipt` | Named `destination`, `attempt_id` from the launch event | Recover a built-in terminal receipt only within its workflow and exact policy. Report visible byte verification separately from durability. |
| `sweep` | Named `destination`, 1–128 exact `receipts`, optional `limit` (default 32, maximum 128) | Ask the host to process listed records eligible for expiry. Each record requires positive settlement and must pass its applicable retention settings. |

The active and cleanup deadlines are cooperative decision budgets. A client
timeout can only shorten the active deadline. A separate host deadline can
give cleanup time after that cutoff. These budgets guide checks and waits
and provide no hard wall-clock guarantee. A wait can collect an exit at or
after the active cutoff, so an installed policy command's exit `0` can
reflect a successful exit observed late. The result supplies no physical
exit timestamp. Wait and cancel with an explicit cleanup window are subject
to the application's authorization for stopping the child.
Disabled supervision and custody are `not_requested`. These facts can be
reported alongside a successful delivery.

Linux with the appropriate kernel facilities is required. WSL2 can expose
those same facilities depending on its configuration. Native Windows is
outside the Python controller's Linux descriptor boundary. Missing enrolled
providers cause refusal before release when required. Permission and metric
availability can also differ between separate Linux processes. A point
observation is limited to its sample. A cgroup's `populated=0` sample is
limited to that cgroup at that time. The application owns the rules for using
either report as evidence.

## Enroll an application

Set up program, scope and recorder bindings once in the application that owns
those capabilities. Create fresh run/attempt identifiers and live handles
as appropriate. For example, this whole controller can be run as a dedicated
process. It supports the same JSON request with workflow `app`, role
`renderer`, operation `launch`, and options
`{"name":"frame-1","supervise":true}`. The JSON response reports dispatch.
The controller reports the observed terminal and cleanup results separately
on stderr. Its own exit status is nonzero for a failed or timed-out child
or unconfirmed cleanup. Reconcile an uncertain attempt with its owner
before launching again.

If protocol I/O fails, the reply is unknown. The controller attempts the
same bounded reconciliation for any child it already owns and keeps a
nonzero exit status even if it reaps that child. A definite refusal keeps
its original status and skips reconciliation.

This example uses the published v0.7.0 `worker_handoff` import. On v0.8.0,
import the same classes and functions from `workeros` and
`workeros.configuration`.

```python
import os
import sys
from subprocess import TimeoutExpired
from time import monotonic_ns

from worker_handoff import DirectChildSupervisor, LifecycleStatus
from worker_handoff.configuration import Workflow, serve_stdio

supervisor = DirectChildSupervisor()
deadline = monotonic_ns() + 5_000_000_000
cleanup_deadline = deadline + 1_000_000_000
workflow = Workflow(
    role="renderer",
    operations=frozenset({"launch"}),
    deadline_ns=deadline,
    supervisor=supervisor,
    require_supervision=True,
    argv=(sys.executable, "-c", "print('from the enrolled worker')"),
    authorize=lambda request: request.options["name"] == "frame-1",
)
def remaining(until):
    return max(0, until - monotonic_ns()) / 1_000_000_000


def finish(status):
    try:
        result = supervisor.wait("frame-1", due_ns=deadline, cleanup_due_ns=cleanup_deadline)
    except (KeyError, OSError):
        # If a launch could not be pinned, only its saved owned handle may be used.
        process = workflow.unadopted.get("frame-1")
        if process is None:
            print("Terminal state and cleanup unconfirmed", file=status)
            return 3
        timed_out = False
        try:
            try:
                returncode = process.wait(timeout=remaining(deadline))
            except TimeoutExpired:
                timed_out = True
                if remaining(cleanup_deadline) > 0:
                    process.kill()
                returncode = process.wait(timeout=remaining(cleanup_deadline))
        except (OSError, TimeoutExpired):
            print("Owned child cleanup unconfirmed", file=status)
            return 3
        lifecycle = "timed_out" if timed_out else "exited"
        print(f"Wait: {lifecycle}; owned child reaped with code {returncode}", file=status)
        return 3 if timed_out or returncode != 0 else 0

    print(f"Wait: {result.lifecycle.value}; exit code: {result.returncode}; "
          f"cleanup: {result.cleanup.status.value}", file=status)
    return 0 if result.lifecycle is LifecycleStatus.EXITED and result.returncode == 0 else 3


# serve_stdio reserves the protocol descriptors and redirects process stdio.
with os.fdopen(os.dup(2), "w", encoding="utf-8") as status:
    try:
        code = serve_stdio({"app": workflow})
    except OSError:
        code = 1
        finish(status)
        print("Protocol I/O failed; reply unknown", file=status)
    else:
        if code == 0:
            code = finish(status)
raise SystemExit(code)
```

Use `authorize(request)` for writes, launch, cancellation, cleanup, recording,
and purge. A wait requesting cleanup uses the same decision. For managed
release use `authorize_release(plan)` to check the exact `ReleasePlan`. A
host-supplied strict custody provider remains subject to the normal receipt and
effect checks. Set the enrolled workflow's `require_custody` or
`require_supervision` flags when clients must request those features. The
application owns the binding map and keeps it stable while
serving a request. Keep the roster/supervisor in the same owner process for
subsequent waits or cleanup. `serve` accepts separate application streams
for those integrations. Use `serve_stdio` once in a dedicated protocol process
before writing to stdio. It reserves stdin/stdout for the protocol and
redirects process stdio away from the worker and providers. It closes the
protocol copies on return.

Use the direct Python API to start Python callables, adopt an owned
`subprocess.Popen`, register an observed external process, or exchange
`SCM_RIGHTS` over an already connected socket. These require application-held
authority or objects. Existing language packages still read inherited FDs via
the [ABI v1 readers](api.md#inherited-readers-and-platform-boundaries). Common JSON clients do not need
those packages to call an enrolled controller.

## Choose recorder storage

Register destinations with the application before reading run input. For
instance, use `LocalStore(trusted_path)` for `archive`. To add a project's
existing store, register a `StoreAdapter` object under a name such as
`review`, and pass both names to `RecorderPolicy.from_dict(policy, stores=...)`.
The examples show how routes choose named stores and how each store applies
its own access and retention settings.

| Field | What it controls |
| --- | --- |
| `destinations` | Names the registered stores used by the policy. A request never provides a filesystem path, endpoint, or credential. |
| `routes` | Each entry declares `name`, lowercase `media_type` with no parameters, and distinct destination names in `required` or `optional`. The application declares the type and bytes. The recorder does not interpret the payload. |
| `max_age_seconds` | Legacy name for the minimum age before explicit purge. Omitted or null leaves no age floor for an authorized purge of settled evidence. |
| `expire_after_seconds` | Opt in to age-based expiry when the host explicitly invokes a bounded sweep. Omitted or null keeps retention manual. A sweep still requires positive settlement. |
| `group_id` | Omitted or null means owner-only access. An existing group ID selects group read-only access for the correctly provisioned destination. The recorder does not grant membership or alter existing directory permissions. |

On Linux, the local store requires an application-controlled absolute path
under trusted parent directories and a filesystem supporting locks, durable
file/directory fsync and same-directory hard links. An existing directory must
be mode `0700` for the owner-only policy, or `0750`/`2750` for the
configured group. Only the installed owner-only policy binding provisions
a missing final directory on first commit. Group stores and direct
`LocalStore` registrations use already-provisioned directories. The owner writes records with mode `0600` or `0640`,
respectively. POSIX ACL overrides are refused. Keep an existing group's
setup with the system administrator. The supplied group must already own the
directory and the application must be able to create files of that group.

Adapters must enforce the same requested access and retention semantics
at each operation. `check_policy` must explicitly confirm the actual
destination policy, and commit must compare the key and bytes atomically,
acknowledge durability, and preserve the exact receipt. Use one policy per
actual storage location. An adapter remains within your application's trust. A readback made from a separate process
validates the exact record, regardless of how the original evidence was
captured. Capture quality and role independence still depend on the sources
you enroll.

Commits are per destination. Repeating the same record returns the original
receipt. Changes to bytes, type, effect, or source and scope under the same
key can produce a conflict. The local record binds its original retention
settings. New, weaker settings cannot shorten its original protection.
`required_complete` means all required stores acknowledged commits. Each
store reports its own outcome, including refusal, missing bytes or unknown
persistence.

A local commit syncs the file and directory. A lazy local store also syncs
the held parent directory before publishing. Local lock contention reports
`busy` without waiting. After a lost acknowledgement,
`readback` can verify the exact bytes that are visible. Use supported
`verify_durable` to confirm durability by syncing the exact local record and
directory, or reconcile the exact storage commit. Keep the workload result
separate. A leftover staging entry without a final record reports unknown
and requires owner reconciliation.

Only purge a matching receipt after positive settlement and any applicable
minimum age. To expire eligible records, run a bounded sweep of exact
receipts from a host maintenance job. WorkerOS starts no service or timer.
A maintenance operation can report a busy store and defer work to the host.
Legacy records that lack a retained enforcement version can be read. They
are held from destructive maintenance because their original terms are
unavailable. Purge replaces local bytes with a small tombstone that retains
record identity. Backups, open files and storage snapshots have separate
retention.

Use operator flag `--workflow NAME` with check or run to select a single
workflow from a policy shared with other hosts. Only that workflow's live
bindings are resolved; a request cannot switch to a different workflow. With
no selection, check resolves all workflows and reports unavailable bindings.
Automatic and manual receipt origins identify their enrolled producer or
workflow and scope. A manual run ID remains the caller's reported run label.

<a name="run-the-same-configuration-from-seven-languages"></a>

## Run a policy from seven languages

Each example below calls the same installed `workeros-config` v1 interface. The
Python helper interprets its JSON response for this **launch** example; it is
not an SDK, a durable receipt, or a general classifier for every operation.
Install the wheel on Linux or Ubuntu in WSL2 and activate its environment. An
existing executable can be written in any language; these examples use
`/usr/bin/true`. For language-specific inherited-file readers, see the
[installation guide](install.md). Run the following setup once in the directory
where you will save the examples:

```sh
cat > policy.json <<'JSON'
{"version":1,"roles":{"job-role":{"operations":["launch"]}},"workflows":{"fileless":{"role":"job-role","operations":["launch"],"bindings":{"executable":"sample"}}}}
JSON
cat > worker-result.py <<'PYTHON'
import json
import re
import subprocess
import sys
import tempfile

request = {"version": 1, "workflow": "fileless", "role": "job-role",
           "operation": "launch", "options": {"name": "sample-01"}}
# Keep a production launch_attempt stderr event for recovery; this small
# fileless example does not request evidence capture.
try:
    with tempfile.TemporaryFile() as output:
        run = subprocess.run(
            ["workeros-config", "--run-policy", "policy.json",
             "--executable", "sample", "/usr/bin/true"],
            input=json.dumps(request).encode(), stdout=output,
            stderr=subprocess.DEVNULL, timeout=35, check=False)
        output.seek(0)
        raw = output.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("response too large")
    reply = json.loads(raw)
    if not isinstance(reply, dict):
        raise ValueError("not an object")
    if reply.get("status") == "refused" and run.returncode == 1:
        print("refused:", reply.get("code", "unspecified"))
        sys.exit(1)
    if reply.get("status") == "reported" and run.returncode in (0, 3):
        result = reply["result"]
        terminal = result["terminal"]
        lifecycle = terminal["lifecycle"]
        code = terminal["returncode"]
        cleanup = terminal["cleanup"]["status"]
        cleanup_code = terminal["cleanup"]["returncode"]
        def valid_code(value):
            return value is None or (type(value) is str and
                                     re.fullmatch(r"0|-[1-9][0-9]*|[1-9][0-9]*", value) is not None)
        if (lifecycle not in ("exited", "timed_out", "unknown") or
                cleanup not in ("reaped", "pending", "unknown") or
                not valid_code(code) or not valid_code(cleanup_code) or
                (lifecycle == "exited" and code is None) or
                (cleanup == "reaped" and (code is None or cleanup_code != code)) or
                (cleanup != "reaped" and (code is not None or cleanup_code is not None))):
            raise ValueError("invalid terminal result")
        success = lifecycle == "exited" and code == "0" and cleanup == "reaped"
        if (run.returncode == 0) != success:
            raise ValueError("inconsistent exit and terminal result")
        if lifecycle == "unknown" or cleanup == "unknown":
            raise ValueError("terminal state unknown")
        if success:
            print("reported: exited 0; child reaped")
            sys.exit(0)
        print("reported: lifecycle={}, exit={}, cleanup={}".format(
            lifecycle, code, cleanup))
        sys.exit(3)
except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
    pass
print("unknown: reconcile the worker and any effects before retrying", file=sys.stderr)
sys.exit(4)
PYTHON
```

A normal run prints `reported: exited 0; child reaped` and exits 0. A definite
refusal exits 1; a reported non-success exits 3; an unavailable, missing,
invalid, oversized, interrupted or inconsistent reply exits 4 (unknown).
The helper limits the bytes it parses and its wait; the temporary output file
is not a disk quota. Timing out the controller does not prove its child stopped.
A reported reap does not prove a write had no effect. Reconcile uncertain
effects with their owner before any retry. For evidence-backed operations,
retain the attempt event and use the receipt recovery described above. Values
such as return codes in this interface are decimal strings.

Save the desired example alongside `policy.json` and `worker-result.py`. Each
runs the same helper, propagates its four exit classes, and does not replay.
`python3` must resolve to the activated environment. Running these examples
starts one ordinary local child per invocation.

**Python** (`client.py`; run `python3 client.py`)

```python
import subprocess
raise SystemExit(subprocess.call(["python3", "worker-result.py"]))
```

**JavaScript** (`client.cjs`; run `node client.cjs`)

```javascript
const {spawnSync} = require("node:child_process");
const result = spawnSync("python3", ["worker-result.py"], {stdio: "inherit"});
process.exitCode = result.error || result.status === null ? 4 : result.status;
```

**C** (`client.c`; run `cc client.c -o client && ./client`)

```c
#include <stdio.h>
#include <unistd.h>
int main(void) {
    execlp("python3", "python3", "worker-result.py", (char *)0);
    perror("python3");
    return 4;
}
```

**C++** (`client.cpp`; run `c++ client.cpp -o client && ./client`)

```cpp
#include <cstdio>
#include <unistd.h>
int main() {
    execlp("python3", "python3", "worker-result.py", static_cast<char *>(nullptr));
    std::perror("python3");
    return 4;
}
```

**Rust** (`client.rs`; run `rustc client.rs -o client && ./client`)

```rust
use std::process::{Command, ExitCode};
fn main() -> ExitCode {
    let status = Command::new("python3").arg("worker-result.py").status();
    ExitCode::from(status.ok().and_then(|s| s.code())
        .filter(|c| [0, 1, 3, 4].contains(c)).unwrap_or(4) as u8)
}
```

**Go** (`client.go`; run `go build -o client client.go && ./client`)

```go
package main
import ("os"; "os/exec")
func main() {
    cmd := exec.Command("python3", "worker-result.py")
    cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
    err := cmd.Run()
    if err == nil { return }
    if exit, ok := err.(*exec.ExitError); ok {
        switch exit.ExitCode() { case 1, 3, 4: os.Exit(exit.ExitCode()) }
    }
    os.Exit(4)
}
```

**Java** (`Client.java`; run `javac Client.java && java Client`)

```java
class Client {
    public static void main(String[] args) {
        try {
            int code = new ProcessBuilder("python3", "worker-result.py")
                .inheritIO().start().waitFor();
            System.exit(code == 0 || code == 1 || code == 3 || code == 4 ? code : 4);
        } catch (Exception e) {
            System.err.println("unknown: helper did not complete");
            System.exit(4);
        }
    }
}
```

For this launch example, a refusal is an explicit response; `unavailable`
or a missing response is not proof that an operation did not run. Other
operations have their own result and effect fields: inspect the documented
fields for the selected operation instead of treating `reported` as success.
