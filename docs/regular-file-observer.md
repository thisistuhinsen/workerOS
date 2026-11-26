# Observe an ordinary file without turning its observer into a referee

An importer has returned, but did its child still hold the input? Was the
read-only handle actually read-only? Is the original name still there after
cleanup? Use this **optional Linux observer** to answer those specific
questions without opening the file by pathname, reading its contents, or
scanning a process table. It runs in an already authorized observation role.
It never grants, revokes, signs, changes permissions or controls the worker.

```python
import os
from worker_handoff import Worker
from worker_handoff.lifecycle import Match, RegularFileObserver

# Inputs come from the observer's trusted launcher before the action.
# The launcher already holds the original and the pidfd for this worker.
with RegularFileObserver(
    scope=plan_digest, due_ns=absolute_monotonic_deadline,
    original_fd=preheld_reference, identity=expected_identity,
    pidfd=pinned_process_fd, worker=Worker("preview", "reader", child_pid, child_uid),
    slot=expected_slot, directory_fd=preheld_dir, leaf="report",
) as witness:
    result = witness.sample()
    if result.slot_match == Match.ORIGINAL:
        is_data_reader = not (result.flags & os.O_PATH) and (
            result.flags & os.O_ACCMODE == os.O_RDONLY
        )
    # Save result, including reasons and time interval, in the observer's own sink.
```

The reference must be an already-held, non-inheritable regular-file descriptor:
either read-only or metadata-only (`O_PATH`). The observer duplicates the
given reference and pidfd; their originals remain yours. A readable reference
**is** a reader alias for its lifetime. An `O_PATH` reference carries no data
read right and does not qualify as a read grant. You may omit both directory
and leaf. If provided, the directory must already be searchable by the
observer; the directory FD itself confers no extra search permission.

`due_ns` is an observation deadline on the observer's monotonic clock. It
may cover later cleanup observations without extending an earlier grant or
authorizing any action.

**Read results literally:**

| Field | What was measured | What it does not show |
|---|---|---|
| `process` | Pinned pidfd live/exit indication. The expected UID is supplied; sampled real/effective/saved/fs UIDs are separate and must all match to report a matching slot. | Reaping, descendant exit, time of death, or unused resources. Use the actual direct-child supervisor for its own cleanup receipt. |
| `slot_match` / `flags` | One designated slot on that live process: matching regular file and matching mount, a different object, or absent. Actual kernel flag bits for the matching sample. | Close/receive syscall history, same open-file description, content consumption, no other FDs or mappings, durable write, or uninterrupted control. |
| `name_match` | Entry under one pinned directory: original, other (including a substituted symlink), or absent. | An unlink syscall, deletion of the inode, loss of existing references, or complete cleanup. |
| `scope` / `session` / times | Caller-independent plan input to this observer; observer-generated session and local monotonic interval. Boot ID and time namespace if available. | Authentication, attestation, durable one-use authorization, or comparability of clocks from another host/namespace. |

Every field is a point observation within the returned time interval. Fields
are not an atomic cross-process/slot/name snapshot. The slot belongs to the
designated Linux thread-group leader's file table, not all threads. A leader
without an observable table yields unknown, not an empty slot. The pidfd's
live indication is a process fact, not an authenticated UID. A matching
`sampled_worker_uids` tuple is returned only after the matching read was
revalidated; a mismatching tuple is diagnostic only. If credential readback
or revalidation is unavailable, the sampled tuple is absent and
`expected_worker_uid` is still just the trusted configuration. A missing
namespace/boot ID is unknown, not positive evidence of a shared clock.

Unobservable, changed during a sample, denied, expired, or unsupported
evidence must not be treated as absent. A live target's different slot value
does not prove where a previous handle went. `ABSENT` is a point observation;
even an ordered held → absent → exited sequence cannot establish continuous
writer exclusion. The `scope` is an association supplied by a trusted launcher;
this library does not authenticate a caller, serialize trusted claims, or permit
a release. Keep the existing `IndependentCustody` v1 gate for qualified
deployments with enforcement independent of the release caller. A same-UID
demonstration tests functionality, not independence. Do not grant new host
permissions simply to make a sample green.

**Try the disposable profile:** from a checkout, run
`PYTHONPATH=src python -m unittest discover -s tests -p test_lifecycle.py -v`.
It runs a real regular-file descriptor through an exec child that reads bytes;
the observer samples while held, after slot closure and after exit. A separate
test exercises actual Unix socket handoff where local sockets are enabled.
Do not count a skipped profile as executed. To qualify a deployment, run the
observer in its real authorized role with independently supplied handles and
check which facts that environment can actually see.

For an already-provisioned observer executable, `python -m worker_handoff.observer_cli`
takes **one JSON line from its trusted launcher** on stdin, samples once, then
prints that sample as JSON. Pass the actual `original_fd`, `pidfd`, and optionally
`directory_fd` across exec; the script marks its inherited handles non-inheritable.
Fields are `scope`, `due_ns`, `original_fd`, `device`, `inode`, `pidfd`, `pid`, `uid`,
`slot`, and optionally `directory_fd` plus `leaf`. It does not discover actors or
fetch handles. Exit zero means a **sample was returned**, possibly unknown.
This executable does not authenticate its JSON or create independent control.
For a scoped report, pass a `scope_report` object in the same plan with the
full `scope` (including its run), `provider_id` and optional `subject`
(`slot`, `name`, or `process`). The reply contains both `sample` and
`scope_report`. The native provider requires the same full `EvidenceScope`
at construction and at `sample_for_scope`. The plain `sample()` interface
remains available without a reporting scope.
[Observer arguments and clock requirements](api.md#observe-a-designated-process-and-file-slot)
For repeated observations of the same run, keep one provider open rather than
joining independent invocations by filename or PID.

## Disposable installed-package qualification

From the checkout, on hosted Linux or **actual WSL2**, run this as a regular
user on the Linux filesystem with Python 3.11+ and the project's build
requirements available. The test directory contains no checkout, and isolated
Python runs the installed package in both the supervisor and child.

```sh
set -eu
work="$(mktemp -d)"
python3 -m pip wheel --no-deps --no-build-isolation -w "$work/dist" .
python3 -m venv "$work/env"
"$work/env/bin/python" -m pip install --no-index --no-deps "$work"/dist/*.whl
cp tests/test_lifecycle.py "$work/"
cd "$work"
uname -srvm
cat /etc/os-release
"$work/env/bin/python" --version
WORKER_HANDOFF_OBSERVER_QUALIFY=1 "$work/env/bin/python" -I -m unittest discover -s . -v
```

On actual WSL2, also retain the outer Windows `wsl -l -v` result showing this
distro's version. The socket profile binds the process and original **before**
grant, then exercises one real descriptor transfer and byte read. Its JSON
records before grant, after read, after named slot disappears and the entry is
unlinked, and after pidfd-observed exit. A hosted container does not prove
WSL2. The separate-process profile uses the **same UID** and records UNKNOWN
with the actual reason if the host does not permit inspection; it does not
claim independent identity or custody. Test a separately provisioned identity
only on a system that already authorizes that role for those handles and
observations. A denied or unavailable profile stays unqualified. Do not change
permissions or substitute the same-UID result.
