# Use an authorized host profile

## Run the local profile

Install the [v0.7.0 Python wheel](install.md#python) on Linux or in Ubuntu in WSL2.
Use the same directory where you created `.venv-0.7.0`:

```sh
.venv-0.7.0/bin/python -I \
  .venv-0.7.0/share/worker-handoff/examples/run_host_preflight.py --profile local-read
```

The example selects a single named profile and creates one caller-owned
session. WorkerOS hands an already-open file to its own reader and verifies
the terminal metadata in a local recorder. The response separates setup,
operation, evidence, and direct-child cleanup. A successful example exits `0`.
A refused preflight exits `2`, and an incomplete run exits `1`.

Add `--without-archive` to see the `stores.archive` requirement refused
before setup or worker launch. The example measures one local session.
Independent providers, comparable multi-party clocks, and manager retirement
require a venue integration.

## Supply a deployment profile

Use this Python integration when a host manager already provides a named
workflow and authorized bindings. For a local command or recorder that the
current user owns, start with the [v0.8.0 JSON workflow example](start/config.md#run-from-json-v080).

The host selects the profile and creates a fresh session. `HostBindings`
registers the approved executable, original, optional supervisor, independent
custody, observer, meter, and evidence by name. Which registries are required
depends on the approved workflow. The request selects an enrolled operation.
The host keeps ownership and verifies the identity, deadline and authority of
each supplied resource. The usual local `workeros config` flags enroll only
current-user bindings. An authorized venue owner supplies the named profile
selection, fresh attempt identity, approved policy bytes and digest, exact
open handles, and authenticated provider connections through the existing host
manager. Their host adapter owns provider setup, collects required opening and
closure evidence for the retained session, and confirms retirement. Enroll a
separate phase observer when the policy calls for independent observations
alongside a controller and meter. Use the Python integration below for managed
providers.

## Register a managed profile with your existing host manager

The v0.8.0 candidate includes an opt-in Python integration for an existing
manager. It is available after that version is released. The host supplies a `ProfileManager` implementation with
`select(name, revision)`, `readback(name, revision)` and
`create(selection)`. It authenticates the caller, verifies the exact package
and policy, qualifies the selected providers, and reads the effective mapping
from its own authoritative state. It atomically rechecks authority, revocation, expiry and the selected
mapping at creation, and guards concurrent and unresolved creates across
restarts. A profile name or policy file grants no
permissions. The application verifies that it is using its authorized
manager and establishes its clock context before calling. The clock ID must
identify the same boot and time namespace as local monotonic timestamps:

```python
from workeros.profile_setup import ManagedProfileSetup

setup = ManagedProfileSetup(manager, clock_id=manager_clock_id,
                            package_sha256=verified_wheel_sha256)
result = setup.setup("your-profile", "your-revision")
if result.status == "unknown":
    result = setup.reconcile("your-profile", "your-revision")
```

Before opening a managed session, compare the installed WorkerOS package to
the exact wheel selected by your trusted host. The expected SHA-256 must come
from a source your host already trusts.
Activate the trusted WorkerOS environment before running this command.

```sh
python -I -m workeros.verify_install /path/to/workeros.whl --sha256 TRUSTED_SHA256
```

The command checks the wheel digest, package ownership, installed module and
schema bytes, and loaded module paths. It is a point-in-time comparison. It
does not authenticate the supplied digest, inspect in-memory modifications or
prevent later file changes. A host can call `verify_install(wheel, digest)`
and use the returned `wheel_sha256` as the setup's package pin.

The manager supplies the verified values in this example. It must report
unavailable, revoked, pending or conflicting state accurately, and keep an
uncertain create pending until its own durable readback settles it. The manager
must retain the exact originally approved mapping independently. If the client
dies before receiving the result, recover that mapping from the authorized
manager and pass it as `expected` to `reconcile`. Do not reconstruct it from
a newer selection. A `manager_readback_verified` result confirms only the
reported profile mapping. Supply trusted `ProfileRequirements` when the
consumer needs specific role, scope, capability or independence. The manager
must authenticate those provider facts. The host must also compile the policy
with its real authorized bindings before an invocation. To inspect a prior
committed mapping after an appointment expires or is revoked, a manager can
provide `read_history`; `history(expected)` reports a matching historical
record without claiming current readiness.
The host still supplies fresh handles and validates authority for each
invocation. Independent observation, meter coverage, child cleanup and
manager retirement require their own evidence. This API supplies no manager,
service, privilege grant or venue-specific provider. The ordinary
`workeros config` command continues to enroll resources owned by its caller.

## Resolve the selected profile before an effect

This example uses the `workeros` Python package from the
[v0.8.0 install guide](install-0.8.0.md#python).
The host already has the selected workflow, exact approved policy bytes and
pre-authorized bindings when it calls this function. Keep name resolution,
provider shape, execution authority and storage results distinct. A policy
digest pins the JSON bytes. Authenticate the OS principal and verify resource
ownership and authority separately.

```python
from io import BytesIO

from workeros.configuration import ConfigurationError
from workeros.enrollment import compile_policy, decode_policy


def prepare(policy_bytes, workflow_name, bindings):
    try:
        compiled = compile_policy(decode_policy(policy_bytes), bindings, workflow=workflow_name)
    except ConfigurationError as error:
        return {"status": "refused", "code": str(error), "path": getattr(error, "path", None)}, None
    return {"status": "names_resolved"}, compiled


def serve_one(compiled, request_bytes, reply_stream):
    return compiled.serve(BytesIO(request_bytes), reply_stream)
```

Omit an unavailable binding. A required reference to an absent or unsupported
registration refuses compilation. A registered name can resolve even if its
value is null or unusable. `names_resolved` and the CLI's `--check-policy`
result describe parsing and lookup. An operation still needs authorization
at execution. Check the destination independently for required storage and
verify the actual commit afterward.

Populate the application's maps only with actual provider objects:

| Registry | Value for each enrolled name |
| --- | --- |
| `observers` | `(observer, evidence_scope, provider_id)`. Use a prebound `RegularFileObserver` or a trusted implementation of its sample interfaces. A scoped request needs an `EvidenceScope`. |
| `meters` | A prebound `CgroupScopeMeter` or a trusted meter with `sample(phase)` that returns the corresponding sample and report. |
| `evidence` | `EvidenceInputs` with the exact `RunBinding`, typed events, and any matching scope and provider reports. |

The application checks the required shapes and session before use. An
authorized provider can still become unavailable. Keep an unavailable
placeholder in the host's private setup notes and report the exact missing
capability to the operator.

## Bind and reconcile one attempt

1. Use a fresh attempt and comparable clock context. Bind the exact original,
   child, planned scope, provider identities and expected coverage. Keep the
   original handles stable through the operation.
2. Obtain any required opening evidence through the authorized provider.
   Keep one-use custody for the managed release's pre-grant gate. Use
   `serve_one(...)` once for the selected effectful operation. Keep its
   operation result, including delivery and effects where applicable. An
   unexpected error can occur after an effect. `serve` returns
   `operation_result_unavailable` with `effect: unknown` in that case. Keep
   the attempt and reconcile it before deciding on any further operation.
3. Record owned child cleanup and terminal evidence separately. A point
   observer reports a sampled identity and state during its observation window.
   A required live observer needs the host's authorized live access. A
   synchronous supervised release waits before returning, so arranging a new
   observer afterward cannot recover observations from while it ran.
4. Check same-attempt evidence with `validate_run_evidence` and
   `validate_scope_evidence`. When raw meter data is required, check the raw
   sample statuses and measurements as well as report coverage. For CPU deltas,
   `cpu_delta_usec` checks the two raw samples and the claimed interval.
   The host supplies independent final measurement after it has verified the
   scope is empty. Separate directory or interval evidence requires a provider
   that measures it.
5. Keep the manager's retirement result in a different field. An observed child
   reap and a descriptor close each describe one owned resource. The manager
   reports retirement after its own checks. Preserve unavailable and uncertain
   results and the exact attempt ID. Reconcile an uncertain effect before
   starting a new attempt.

Pass the original operation result, verified or unavailable evidence, cleanup
receipt, and manager retirement receipt to the caller separately. The caller's
verifier decides whether its required evidence is present. See the
[file and custody interfaces](workers.md#authorize-a-managed-release) and
[provider and clock limits](api.md).

### Setup several authorized scopes

`workeros.aggregate_setup.AggregateSetup` is a setup-only Python integration
for a host that already operates authenticated profile managers. Construct one
`ScopeSetup` per independently authorized workflow, with its own
`ProfileRequirements`, live `HostBindings`, and manager. Each manager must
implement the existing `select`, `create`, and authoritative `readback` contract.
`verify_bindings(selection, compiled, host)` must authenticate and compare the
actual compiled objects and handles against its authorized registry and return
the accepted opaque generation. It must refuse missing or changed resources.
`attest(selection, requirements, generation)` returns `ScopeEvidence` only after
it has authenticated a separate evidence source and checked the exact selected
profile, role, scope, clock, expiry, generation and provider appointments. The
`verified` field is a report from that trusted manager, not authentication by
WorkerOS. The caller supplies a wheel and its independently trusted SHA-256;
the aggregate checks the installed package against that wheel before setup.

`setup()` returns each scope's original result and a separate final readback
sweep. `ready` means each required scope passed that sweep. Sequential checks do
not establish a simultaneous snapshot, continued validity or exclusivity; the
host must revalidate the same generation and live resources at use. Setup does
not start work or prove continued access, interval coverage,
cleanup, retirement, or a successful native execution. Partial results are not
rolled back. An unknown write must not be repeated: retain the original attempt
and use `reconcile(name, expected=attempt)` for current readiness. A manager
may separately implement `read_attempt(expected)` returning `AttemptHistory`
when its durable, authenticated records establish that exact attempt's
historical outcome; `not_committed` requires proof that it cannot still commit.
The definition has no attempt ID: the manager must guarantee at most one create
attempt per revision for its entire retained lifetime, or report unresolved.
An absent mapping alone is not that proof. `resolve_attempt` reads history only,
never retries a write and does not establish present readiness.

A real deployment must supply the manager implementation and authority. The
installed local configuration command does not enroll one; no standalone setup
command exists without a commissioned trusted host entry. An administrator must
arrange an authenticated entry in the existing host application that constructs
bindings from its own registry, checks actual object identity and generations,
authenticates evidence sources and independently reads durable manager records.
Applicants cannot supply imports, callbacks or raw handles through configuration.
The [installed setup command](#installed-no-start-host-command) can serve one
request through an administrator-provided listener. The host still supplies
the approved registry, appointments, and independent readback. Policy alone
supplies no OS access.

### Invoke an approved launch through an existing host backend

A trusted in-process integrator can optionally construct `ManagedHostAdapter`
with a `workeros.managed_launch.LaunchRegistration`. This registers one
explicit `launch_approved()` invocation. Neither setup, binding checks nor
the managed CLI invoke it. A stock installation has no such registration.

To use the installed administrator profile and appointment store, use
`workeros.managed_bootstrap.open_approved_launch(registration,
executable_argv=approved_argv)` in the trusted administrator process. It opens
the same protected `managed-setup.json` and holds the inherited bindings for
the returned adapter's lifetime. The installed approval store must already
contain the exact active profile and one appointment with a `launch` object
containing `plan_sha256` and `scope_sha256`. Compute these with
`workeros.appointment_registry.launch_plan_sha256(plan)` and
`launch_scope_sha256(role, scope, operations)`. The latter pins the full
approved role and the selected scope and operations. Updating any of those
pins requires a newly approved appointment. If the selected role scopes a
file, the stock observer must hold that exact device and inode. The appointed
worker and the stock evidence providers must use distinct UIDs. The stock
entry rereads the appointment under the approval lock before dispatch. It
does not establish permissions or bypass a pending file ACL cleanup.

#### Approve a reusable role

For repeated explicit requests, register a `LaunchRolePolicy` instead of a
`LaunchPlan`. It pins the existing account name and numeric Linux UID, the
exact definition and generation, the approved executable and scope digests,
and the launcher and independent authority identities. The selected scope
digest includes the whole approved role with its capability selections,
expiry and separation constraints. The appointment's `launch` object uses
`policy_sha256` from `appointment_registry.launch_policy_sha256(policy)`
alongside `scope_sha256`. Approve it through the same appointment registry.
A changed generation, approval, scope or account binding needs new approval.

In trusted deployment code, use `new_launch_request()` from
`workeros.managed_launch` and retain the ID before requesting the launch.
Pass it to `adapter.launch_approved(request_id=request_id)` on the adapter
from `open_approved_launch()`. Each new ID derives a separate invocation
key pinned to this exact profile, policy and clock. WorkerOS rereads the
active approval and commits the reservation in the protected profile
store before requesting a ticket. The enforcing backend must still
atomically consume the exact ticket and enforce scope at dispatch.

If the response is lost, call `adapter.read_launch(request_id=request_id)`
for the same ID. Repeating an already reserved ID can only read that
invocation. Use a new ID only for intentionally new work. Verified
readback must match both account name and numeric UID. An uncertain
reservation or unconfirmed result stays unknown. A still-open adapter can
read the exact historical result after revocation. Reopening the launch
adapter requires active approval and the same live bindings. If those
are gone, use the approved authority's historical store for that key.

#### Register a named systemd workflow

For first use with an approved v0.8.0 candidate, see the
[administrator walkthrough](guarded-walkthrough.md) and the short
[caller example](start/terminal.md#run-and-check-an-approved-worker).
The caller example links to matching JSON, YAML and code calls. Use this
reference to enroll or verify a deployment's role and scope.

An administrator can enroll a named workflow for several preheld
regular files with exact mode `read`, `write` or `read-write`.
Each selected file has its own resource and mapped owner. The
role explicitly permits the operations and names each device and
inode. The selected workflow compiles `launch` and any selected
evidence operations. Its `streams` provider has capability
`systemd-fd` and pins the aggregate service digest. Keep the
executable and scoped-launch supervisor pins. Live descriptor
numbers are excluded from reusable approval.

The version-2 `launch-executor.json` keeps `profile`, `revision`,
`wheel_path` and `wheel_sha256` at the top level. Each entry in its
`workflows` object has:

- `policy`, the existing `LaunchRolePolicy` for that exact named workflow
- `authority`, the pinned Unix socket path and UID of the independent authority
- `service`, the `ServiceScope` fields `root_directory`, `root_device`,
  `root_inode`, `executable` inside that root, `principal_gid`, `mode`,
  `original_device`, `original_inode`, `original_fd` and the protected `parent`
- `run_uids` and `result_uids`, independent lists of authorized caller UIDs

The multi-file `service` form replaces `mode`, `original_device`,
`original_inode` and `original_fd` with `descriptors`. Each entry has
`slot` (`stdin`, `stdout` or `stderr`), `scope`, `owner_uid`,
`mode`, `device`, `inode` and the live `fd`. Repeated slots,
scopes, owners and originals refuse. The same protected object
sets separate `active_ms` and `cleanup_ms`, plus `metered` to
select lifecycle accounting. If the workflow selects a file
observer, `observation_scope` names the corresponding resource.
With aggregate provider name `original`, use
`{"stdin":"original.stdin","stdout":"original.stdout"}`
as the stream binding for those two slots. The `parent` object is
shared by both forms. For `guarded-service-v1`, set `unit` to the appointed
guard's system-level `.service` and pin its exact `control_group`, `device`,
`inode`, and `mount_id`. These five values enter the protected service
digest. WorkerOS authenticates PID 1 on the system bus and checks the active
unit, invocation ID, delegation, exact cgroup v2 directory, and live guard
principal. Existing slice pins remain valid for supported historical
readback. A slice, user manager, or `.scope` cannot admit a new guarded run.

Historic single-file records retain their existing digest and
`{"stdin":"original"}` binding. For a new stock manager launch
registration with that configuration, include a `limits` object with
`active_ms`, `cleanup_ms`, and `metered`, and the named `parent`.
Existing historical records keep their original service digest.

The approved root is a separate administrator-owned runtime directory.
Provision it with only the approved program and its runtime files. Its
device and inode, the executable digest, and the existing non-root
UID and primary GID must match. The service account must have no additional
groups. The system manager enforces a read-only service root and passes
the selected preheld standard descriptors. The worker can use `pread`
or `pwrite` with explicit offsets. The holder supplies the exact
descriptors with matching access flags. This can grant write on a
descriptor while its pathname remains inaccessible. The backend
refuses O_APPEND and confers no ambient Linux capabilities.

Use the existing Linux system manager and system bus. The host must
entitle the existing operator to create the fixed transient service
and provide an administrator-owned inherited Unix stream listener
and the held originals. `workeros managed serve-launch --listen-fd FD`
serves one explicit request. Setup and `serve-setup` remain no-start.
The host-side roles supply their real independent evidence as selected.
For example, a point provider, a meter, or a registered interval and
meter pair can be required. An unselected observer is unnecessary.
Selected observers must bind the same original as the service.

In the caller environment, the administrator's client routing document contains
version `1`, `profile`, `revision`, `socket`, `peer_uid` and a
`workflows` map of workflow names to reusable policy digests. The caller
supplies the enrolled name and retained request ID. An optional report
destination stays in the caller process.
On a clean host, include it as `launch_client` in the approved provisioning
bundle. WorkerOS checks it against the version-2 executor and writes
`/etc/workeros-launch-client.json` for local callers to read. The file contains
only routing and policy identifiers. The protected setup, executor, caller
rights and role-store files keep their private permissions. An earlier
installation can still use `/etc/workeros/launch-client.json` when the new
client routing file is absent.

Generate the request ID once from the trusted WorkerOS environment before
submitting. Keep it for every status request for that invocation.

```sh
id=$(python -I -c 'from workeros.managed_launch import new_launch_request; print(new_launch_request())')
workeros managed run-approved --workflow report-writer --request-id "$id"
workeros managed launch-status --workflow report-writer --request-id "$id"
```

Use the same `workflow` and `request_id` fields with `version: 1` for
JSON or YAML standard input. Application code calls
`registered_launch(request_id, workflow="report-writer")` or passes
`readback=True` for status. A lost reply leaves the effect unknown.
Keep the retained ID and reconcile through the separately authorized
result right, even if the role has since been revoked.
A caller with run rights only receives no effective-state or cleanup
receipt from the run command. An approved result reader retrieves it.

An approved result reader receives the selected workflow, role, and
registered scopes in `selection`. A pending guarded invocation can also
include a `phase_observation` with the invocation, clock, cgroup, monotonic
release and observation times, and population at that observation. Release
means the guard sent its one-way command. Population is a point sample
and by itself establishes neither worker execution nor ongoing activity.
Without a qualifying sample, the field is omitted. A guard's reaped
child status and verified cleanup can appear in `provider_report` while
the workload effect remains unknown.

#### Save a caller-owned copy of the result

Use `--report FILE` on `run-approved` or `launch-status` to save a copy of
the versioned result. For example, use the retained request ID to read and
save the result without launching a worker:

```sh
workeros managed launch-status --workflow report-writer --request-id "$id" \
  --report ./report-result.json
```

For structured input, add `"report": "./report-result.json"` in JSON or
`report: ./report-result.json` in YAML alongside `version`, `workflow`, and
`request_id`. An explicit `--report` overrides the destination in structured
input. In Python, pass `report="./report-result.json"` to `registered_launch`.
Relative paths use the caller's current directory, including for requests
read from standard input. Choose a new filename in an existing directory
you own, with group and other writes disabled.
The destination's directory path cannot contain symbolic links.

For a reusable request document, use `--format json --input request.json`
or the YAML equivalent. A relative `report_default` uses the directory
containing that file. For a document read from standard input, specify an
absolute `base_dir` or an absolute default. Python callers can supply
`report_default` and `base_dir` to `registered_launch`. An explicit
`report` takes precedence over the default and resolves from the caller's
working directory.

The caller writes the copy with its own permissions after getting the result.
WorkerOS refuses an elevated caller's export request before dispatch. Use your
ordinary account. WorkerOS leaves existing files intact and keeps the
destination out of the privileged launch request. The copy has at most
owner read/write permissions and contains only the result that account
may already read. The manager's retained receipt remains authoritative.

The result has `version: 1`. The command's JSON reply or Python return value
adds an `export` disposition. A failed or uncertain export leaves the run's
effect and cleanup as reported. The command exits nonzero if export fails or
its durability is unconfirmed. In the latter case a copy may already exist.
To try another destination, use
`launch-status` with the **same request ID** and a new filename. An unknown
run result means the current evidence is insufficient to confirm its outcome.

#### Read historical results after a revision changes

When a live guarded result is independently verified, the managed listener
records its proof and the exact revision's authorized result-reader UIDs in
protected storage. Check that `history.status` is `recorded`. A result whose
history could not be committed remains usable as a live receipt while the
qualified providers remain available.

The administrator can serve one archived lookup with
`workeros managed serve-launch --history` using the trusted client socket.
Keep that client routing registered for the original profile. From the
ordinary result-reader account, run:

```sh
workeros managed launch-status --workflow report-writer --revision "$revision" --request-id "$id"
```

Use the original revision and ID. JSON and YAML use `revision` with
`workflow` and `request_id`. Python uses `readback=True` and `revision=...`.
Only the archived revision's originally entitled OS user accounts can read
the result. The archived lookup neither connects to the former witness nor
uses the current launch policy. It cannot dispatch a worker. An absent
record and an unauthorized lookup return the same unavailable result.

Add `--summary-id` for each other request to include, or supply
`summary_ids` in JSON/YAML or Python. The count covers that explicit set
and the primary request, once per ID. If any requested record is unavailable
to the caller or belongs to a different role or resource selection, the
count is unavailable. Archived evidence describes an already verified
outcome and carries no current activity claim.

### Verify an independent result for a guarded workflow

To require independently verified results for a guarded workflow, add
`result_observer` to its protected `launch_executor.workflows` entry. Supply
the appointed observer's `source`, Unix `socket`, and `uid`. The observer
must be distinct from the launch authority, worker, administrator endpoint,
and identities with run rights. Set `expected_effect_sha256` when the approved
workflow has a known expected effect digest. Preview shows the selected
observer. Apply pins the complete executor revision. The same run and status
commands use the selected observer without caller-supplied addresses or proofs.

For the installed witness, set `result_observer.handoff` to `true` and pin
the expected effect digest. Start `workeros managed serve-witness --commissioned
WORKFLOW` under the observer's registered UID with the two protected
registration descriptors (`workeros-setup` and `workeros-executor`) and
the exact original output opened read-only as `workeros-observed-output`.
Use the same narrowly scoped socket access as for a commissioned holder.
The guard transfers the placed process and read-only cgroup handles once.
It releases the worker after the witness acknowledges the exact live attempt
and retires the leaf after the witness confirms emptiness and captures output.
The witness closes its handles and serves readbacks of that invocation for
the remainder of the approved evidence window.

The observer uses the same bounded, nonce-matched authority transport. It
answers `read_result` for the exact `invocation` in the request using its own
independently retained evidence. The response `result` is an object with a
terminal `LaunchReadback` as `observation`, the independently observed
`effect_sha256`, and integer monotonic `verified_ns` and `expires_ns`.
The observation's source pin uses `authority_pin(source, socket, uid)`.
The service evidence must identify the same delegated run and cgroup, bind the
effective executable, principal and resource scope, and support terminal,
emptiness, handle closure, retirement, and any selected meter readings within
the approved cuts. A point or setup-binding receipt cannot answer this request.

A verified reply reports `independent_service_result_verified` and the
observer's effect and receipt digests. WorkerOS also checks that the retained
leaf is absent. `effect: dispatched` describes execution. The independently
observed digest records the workflow-specific effect. Missing, stale, invalid,
or unconfirmed evidence leaves the effect unknown. Keep the original request
ID and use `launch-status` to read again. This does not re-arm or re-submit a
worker. The result reader can reconcile after a profile revoke, with the
same protected executor pins and result rights.

An observer that is separate from the reaper can report only its own
effect and closure evidence. In the same `read_result` response, its
`observation` carries `invocation`, `source`, `source_sha256`,
`receipt_sha256`, and `cleanup` instead of a terminal `LaunchReadback`.
The cleanup record binds the guarded reaper's exact sandbox process
incarnation, manager run, service scope and leaf. It records live pinning,
pidfd exit readiness, observed emptiness and retirement, effect observation,
and closure of the observer's own handles. Readiness carries no exit
status. In the combined result `terminal_source` identifies the legitimate
reaper. Its receipt and terminal status remain in the main service result.
The observer's own receipt and closure remain in `observer_result`.
The manager's meter samples, if selected, stay attributed to the manager.

For an already-appointed in-process observer,
`workeros.managed_service_witness.observe_effect_cleanup` consumes preheld
read-only handles for the exact pidfd, leaf, process list, population
counter, and approved output. It compares a live pre-effect baseline with
the expected post-exit digest held under the existing custody agreement.
The authorized scope owner can synchronize release and leaf removal with
the live and empty notifications, within the existing deadlines. A finite
`serve_witness_result` connection uses the retained native observation
after guard retirement. It accepts only the enrolled administrator launcher
and the same invocation. The venue must already supply the distinct witness,
exclusive output custody, and these preheld handles. This path does not
appoint an observer or acquire a new grant.

An already entitled manager can opt in by setting
`authority.enforcement` to `guarded-service-v1` in the protected
workflow entry. Use the existing approved socket, UID and policy pin.
That provider must already own the registered preheld resources and
implement guarded admission. The client passes only the recorded
invocation and service pins. It sends no user-provided path, executable
arguments, or file descriptors. With no opted-in provider, the
stock path returns `service_deadline_guard_provider_unavailable`
before requesting a ticket, creating a launch reservation, or submitting
a unit.

The provider uses the existing bounded, nonce-matched version-1 socket
frames on the authenticated endpoint. The request's `invocation` carries
the fixed invocation key, clock and both absolute deadlines. Its
`service` object carries `enforcement`, `scope_sha256`, the full
`parent` pin, the generated `unit`, and its direct child `leaf` path.
On submit only, the stock administrator launcher also passes its locked
role-store directory descriptor. The verified caller holds this lock from
the durable approval check. The guard pins the same directory and keeps
the kernel lock through the final protected release, including when the
launcher loses the reply. The caller's request supplies no descriptor.

1. `read_service` returns an `observation` using the existing
   launch-readback schema and an `arm` record, or `null` for
   `arm` when there is no armed reservation. Report `not_started`
   only for a key with no arm. A started or terminal observation must
   carry the same arm and bind its lifecycle to the exact cgroup.
2. After WorkerOS durably reserves the invocation, `arm_service`
   returns an `approval` using the existing launch-authorization schema
   plus `arm`. An arm contains `binding_sha256` (SHA-256 of the
   canonical JSON object with keys `invocation` and `service`),
   the matching `guard_sha256`, `armed_ns`, and `leaf` (a
   cgroup identity of device, inode and mount ID). The manager must
   reserve the exact empty leaf and arm both cutoffs before replying.
   Leave the leaf empty through the client's pre-submit check. An
   explicit null result declines the request without an arm.
3. `submit_service` sends the same invocation, service pins and
   arm with `ticket_sha256`. The manager must atomically consume
   the ticket once, recheck active approval and exact resources,
   admit only under the still-armed cutoffs, and enforce bounded
   cleanup independently of the client. WorkerOS checks the
   pinned empty leaf before submit. A submit receipt does not settle
   worker effect. Lost replies reconcile through `read_service`
   on the same key. No direct systemd start or retry follows.

Where policy permits same-parent bootstrap migration, the appointed
manager must consume the ticket in `submit_service` before staging a
child into the leaf. Recheck exact membership and the cutoff before
any protected release. The abort-only bootstrap context retains reaping
ownership, and its pidfd cannot be adopted as a workload for that
invocation.

### Run the installed delegated guarded authority

`workeros managed serve-guard` serves the protocol above inside an already
appointed authority process. It requires the authority's existing Unix stream
listener, protected read-only registration descriptors, and the approved
read-only original. The authority UID is separate from the administrator's
launch client and the worker UID. The host's existing approved credential and
cgroup controls must let the authority place and reap its direct child.

```sh
workeros managed serve-guard --config-fd "$guard_fd" --setup-fd "$setup_fd" \
  --executor-fd "$executor_fd" --listen-fd "$guard_listener_fd"
```

The guard registration contains `version` (1), `profile`, `revision`,
`workflow`, `managed_setup_sha256`, `launch_executor_sha256`, and an
existing authority-owned `journal_directory`. Set `role_store_lock` to the
administrator-verified `device` and `inode` of the exact role-store lock
directory (`/var/lib/workeros` in the installed configuration). Use the canonical configuration
digests from `profile-status --registered-managed`. The other registration
descriptors are the same linked, administrator-owned, read-only files named
by that receipt. They can remain private to the administrator. The holder
supplies the listener from the appointed authority's own UID.

An administrator can also start the existing finite endpoints without writing
a descriptor wrapper. In the already authorized systemd service, use
`workeros managed serve-guard --commissioned` for the guard service and
`workeros managed serve-launch --commissioned WORKFLOW` for the administrator
listener. Launch the guard as the pinned non-root `User=` and service main
process under `Type=simple`. Set `Delegate=` and use `DelegateSubgroup=` (systemd 254 or later)
to place it in an owned direct subgroup before it starts. The service root
must be an empty cgroup v2 domain in the sense of having no direct processes.
WorkerOS checks the delegation marker and performs worker cgroup operations
only on its exact child leaf. If accounting is selected, the administrator's
delegated service must already expose the memory controller to its children.
WorkerOS does not change service-root or slice controllers. The guard must
already be able to switch the child to the worker's registered credentials.
The commands
create their respective registered listeners in existing protected directories.
The guard's directory must be owned by that guard and accessible only to it
and the administrator. The administrator listener checks the calling UID
against the enrolled workflow rights. Each command removes its own listener
on normal exit. There is no automatic restart or worker start.

Use the activation mode that matches the service:

- **The service's exact cgroup identity is already pinned.** Start
  `serve-guard --commissioned` without any `--commissioning-*` options.
  The system service can deliver the three administrator registrations through
  systemd `OpenFile=` entries with `read-only` (systemd 253 or later) and
  descriptor names `workeros-guard`, `workeros-setup`, and
  `workeros-executor`. The guard checks ownership and registered digests
  after delivery.
- **Discover the exact identity of a new service.** Start its main process
  with `serve-guard --commissioned --commissioning-unit UNIT
  --commissioning-directory DIRECTORY --commissioning-deadline-ns DEADLINE`.
  Leave the three registration descriptors out of the service's activation
  inputs in this mode. A direct activation can still supply the approved
  original descriptors. Use the administrator's existing protected
  directory and an absolute deadline on the host monotonic clock. Keep
  `DIRECTORY/registration` absent at start.

In discovery mode, the host operator must already be authorized to run the
appointed guard in a delegated system service. The following steps enroll
that exact service incarnation.
The subprocess reports `guard_parent_pinned` after PID 1 and the actual guard
process and cgroup agree. Use that exact `parent` when you
[prepare the guarded bundle](#prepare-a-guarded-commissioning-bundle).
Once the administrator has applied the approved revision and generated the
guard registration, atomically
publish the completed `registration` subdirectory with the three linked,
administrator-owned JSON files named `workeros-guard.json`,
`workeros-setup.json`, and `workeros-executor.json`. Keep the directories
administrator-owned and protected from group or other writes. The guard needs
directory traversal and read access to those files. The same MainPID rechecks
its native invocation, the approved five-field pin and selected metering before
opening its listener. If the deadline expires or the pins differ, activation
refuses. Use the normal protected appointment and approval procedure.
For direct activation, the approved original owners supply the exact held
descriptors to both services under their named `workeros-original-stdin`,
`workeros-original-stdout`, or `workeros-original-stderr` slots. WorkerOS
verifies each resulting descriptor against the approved identity and access
mode. A [registered holder](#activate-a-live-holder-and-overlap-distinct-workflows)
can supply the originals instead. Use the separately approved owner and witness
bindings for the workflow. For historical readback after the owners close the
originals, start the guard with `--commissioned --readback-only` and supply just its
three administrator registration descriptors. Run the launcher without
original descriptors for that readback. Any new run then refuses.

### Activate a live holder and overlap distinct workflows

For a descriptor bundle, the protected workflow can name `holder` with the
appointed holder's non-root `uid` and dedicated Unix `socket`. The existing
manager supplies the holder's linked read-only `workeros-executor` registration.
Start the finite
holder as that appointed identity using
`workeros managed serve-holder --commissioned WORKFLOW`. Its protected
directory and every initial recorded descriptor must already exist.

The manager can deliver the live `workeros-original-*` descriptors, or the
appointed holder can open the existing approved files with
`--original-stdin`, `--original-stdout`, and `--original-stderr` for exactly
the slots in the registration. Supply absolute paths. This opens with the
holder's own OS permissions and the registered access modes, verifies the
owner, device and inode, and holds the result across both transfers. It
does not create or truncate a file. Use one method per activation.
The appointed witness can similarly use `--observed-output ABSOLUTE_PATH`
instead of its inherited output descriptor. It always opens it read-only.
See the [disposable commissioning walkthrough](guarded-walkthrough.md) for
the systemd commands.

The holder socket needs Linux POSIX ACL support. Its dedicated holder-owned
directory must have owner `rwx`, a single named execute-only entry for the
commissioned guard UID, a matching ACL mask, and zero group and other rights.
Do not set a default ACL there. Existing trusted ancestors must be searchable
and have no extended access ACL. WorkerOS verifies the directory as supplied.
It creates the socket with owner read/write and one named write-only entry for
the same guard UID. It verifies that ACL before listening and removes only its
own socket when the holder exits. The connection still needs the enrolled
kernel peer credentials and request pins. A failed ACL or traversal check returns
`service_holder_access_unverified` before listening.

The guard and launcher request copies from the registered holder. The holder
checks the kernel credentials and exact profile, revision, workflow and scope.
It sends one copy to each entitled consumer without reopening a pathname. The
receiver verifies every descriptor's owner, access mode and device/inode.
When using a holder, pass no original descriptors directly to the guard or
launcher. The independent Observer remains separately enrolled where required.

To serve two distinct scopes in one profile, provision distinct original
identities and dedicated holder and guard endpoints for both workflows. Start
those guards through `serve-guard --commissioned`, then run the launcher with
`--commissioned WORKFLOW_A --commissioned WORKFLOW_B`. The list limits the
batch to two requests. Submit one for each workflow with different
request IDs. The approval lock is held through each release. A guard retains
ownership through the bounded reap and retirement, so a second scope can
start after the first release and before its retirement. A reply can still
be `UNKNOWN` while the guard retires the scope. Use the same request ID for
readback. Each holder-backed guard processes one claimed run per activation.

Setup and guard registrations must be updated together for this installed
guard to accept submit. The guard refuses a missing or different role-store
lock, rechecks the current protected registration immediately before release,
and retires an unstarted arm. A revocation that wins the role-store lock
prevents new submission. Once the guarded release owns that lock, revocation
is ordered after the release. Previously released jobs remain owned by the
guard for drain and historical readback. If an armed operation has no durable
no-effect proof, the same-key readback remains unknown.

This stock release uses the protected Bubblewrap backend. It snapshots the
approved static executable named by the service scope beneath the protected
root. The service can use its approved legacy stdin or a descriptor bundle
selecting stdin, stdout, and stderr. WorkerOS retains the declared access and
owner of each exact file; unused streams stay inert. Scope and role checks
apply before release. Capabilities beyond those held descriptors require
a backend authorized to enforce them.

The manager reserves the empty cgroup and both cutoffs, then persists the
matching submit before passing any worker descriptor to its verified gated
child. The same owner reaps it and retires its exact leaf. The original
abort-only bootstrap remains available for no-start staging. If a placed
gate is reaped before any release attempt and the exact leaf is observed
empty and retired, the same key can report `service_bootstrap_unreleased`
with no worker effect. That terminal result leaves its submit consumed.
An uncertain release stays unknown.

A delegated terminal receipt names its manager run separately from systemd's
InvocationID. The outer client's `provider_report` preserves that authenticated
same-key observation if it can also corroborate leaf removal. The effect
remains `unknown` at the outer boundary until the required independent worker
evidence is available.

The provider must retain the identical leaf through emptiness and
selected final meter sampling before removal. Readback reports terminal,
final counters and removal separately. WorkerOS corroborates the
running or terminal state from the native manager when still available.
When the pinned leaf is already absent, it may preserve authenticated
history under `provider_report` with code `service_terminal_reported`.
Effect and state remain unknown. Local absence only confirms current absence.
It cannot corroborate earlier final sampling or historical termination.
For a retired delegated service, same-key readback checks present absence
on the pinned cgroup mount without requiring a running guard service.
A replacement at the same path with a different cgroup identity leaves
retirement unconfirmed.
Relative runtime limits, an exited unit record and a guard digest by
itself cannot satisfy this contract.

[systemd cgroup delegation](https://systemd.io/CGROUP_DELEGATION/) ·
[systemd D-Bus manager contract](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)

An existing manager can use `workeros.delegated_service_leaf.DelegatedServiceLeaf`
for a pre-existing, exclusively owned cgroup v2 leaf. It checks the exact
registered parent and leaf, opens the scoped kill control, and arms two
absolute monotonic kernel timers. Supply only an owned, waitable direct
child that was already confined and gated before worker effects. The
manager owns the wait and bounded reap independently of the client. Use
`finish()` to collect local terminal and empty-leaf observations and any
required final counters while retaining the leaf. `retire()` then verifies
the pinned empty leaf, removes it, and observes absence. Close local handles
separately. These local observations do not supply independent readback.

When the venue already authorizes migration of a trusted bootstrap within
the same delegated parent, the manager can use `stage_trusted_bootstrap()`
to hold a fixed child on a private gate. It passes only the gate and the
already-armed active timer, with standard streams on `/dev/null`. It moves
only its direct bootstrap child into the exact leaf and verifies membership
before returning the borrowed waitable pidfd. The context exposes no
worker release, executable selection, service readiness or worker data.
The child exits when the gate closes or the active timer expires. Closure
reaps the direct child within the cleanup window or reports unconfirmed.

Stock WorkerOS still needs the appointed manager's authorized pre-effect
admission operation. A venue that requires birth in the leaf still needs
atomic native placement. The bootstrap context does not replace the
authenticated arm or independent evidence path and is unavailable as a
stock launch operation. A later reap or empty-leaf observation leaves the
active cutoff unconfirmed, even when bounded cleanup succeeds.

#### Retain resources from an existing invocation

In a trusted host process, `workeros.incumbent.retain_incumbent(pins,
handles)` checks and retains five preheld descriptors. The protected
`IncumbentPins` includes the selected profile, invocation and clock
window, directory identity, existing writer and reader incarnations,
pinned Unix phase peer, and cgroup meter directory. The
`IncumbentHandles` comes from the existing scope owner. Keep the
context through the owner's use of those handles, then leave the context
or close the retained copies as part of the same outer close. Release
the copies before checking EOF or closure. The invocation pins remain
available after release. Keep descriptor values local.

This check verifies current identities and holds the exact objects. It
cannot appoint an owner, acknowledge a phase, settle the original,
certify process retirement, or supply independent close evidence. The
assigned incumbent owner must supply an authenticated, invocation-scoped
handoff, and the appointed independent evidence source must verify that
invocation's close. The stock authority's authorize and readback
operations do not supply those operations. The terminal, JSON/YAML,
and Python launch front doors continue to use the existing grant
semantics.

#### Register one read-only Bubblewrap worker

The stock executor supports one read-only regular file and one static
ELF64 x86_64 or AArch64 executable. It runs as the approved existing
non-root UID and primary GID with supplementary groups cleared. The
native Linux host or WSL guest must provide trusted non-setuid
`/usr/bin/bwrap` 0.12 or newer and allow unprivileged namespaces.
Verify both on the deployment host. The
[Bubblewrap documentation](https://github.com/containers/bubblewrap#sandbox-security)
describes the namespace mechanism.

Keep the fixed administrator-owned `/etc/workeros/launch-executor.json`
beside the existing `managed-setup.json`. Its version-1 fields are
`profile`, `revision`, `policy` (the approved `LaunchRolePolicy`),
`principal_gid`, `executable`, `wheel_path`, `wheel_sha256` and
`authority` (a Unix `socket` path and numeric `uid`). Pin the authority
using `workeros.managed_executor.authority_pin(name, socket, uid)`.
The authority UID must differ from the host process and worker UID.
The executable and its parent directories must be administrator-owned
and protected from group and other writes. WorkerOS seals the exact
executable bytes after hashing them and accepts files up to 64 MiB.

The selected workflow must approve `launch` and `observe` for the same
scope, with its existing point provider and approved named original.
The existing host retains the pinned readable descriptor. The input
must be administrator-owned, non-executable, protected from group and
other writes, and readable by the worker under existing permissions.
The sandbox exposes it at `/input` and runs `/worker` with no
caller-supplied arguments or environment. It supplies no host root,
network namespace sharing, libraries, procfs or devices. This backend
does not supply privileged capabilities, interval custody or scope retirement.

Use these commands in the entitled host context that already holds
the approved descriptors. Generate and retain one ID before invoking.

```sh
id=$(python -c 'from workeros.managed_launch import new_launch_request; print(new_launch_request())')
workeros managed run-approved --request-id "$id"
workeros managed launch-status --request-id "$id"
```

An equivalent JSON request on standard input uses
`{"version":1,"request_id":"<the retained ID>"}` with `--format json`.
Use the same fields with `--format yaml` and the optional PyYAML
dependency. Application code calls
`workeros.managed_executor.registered_launch(request_id)` or passes
`readback=True` for historical status. Setup and ordinary managed client
actions still start nothing.

An entitled Python manager can pass the same approved executor and
host registrations to `open_managed_worker(executor_config,
host_config=host_config)` and call `adapter.launch_approved(request_id=id)`.
This uses the same installed sandbox and authority socket without looking
up the two configuration files. The existing approval store is still
required. The administrator chooses the role name. Keep both registration
objects inside the trusted manager.

The host commissions an independent authority at the pinned socket.
WorkerOS checks the peer UID before sending framed JSON. A request
contains version `1`, operation `authorize` or `readback`, a fresh
nonce and an exact typed invocation. The reply echoes version, operation
and nonce and carries the typed result as `result`. The authority owns
one-time tickets and independent effective-state observations. It must
authenticate the sending host and bind any authorization or readback
to the invocation key. The stock executor records each ticket durably
under the existing approval lock before dispatch. A second request
cannot reuse that ticket. An approved workflow with `cleanup_ms` uses
that budget within the authorized deadline to stop and reap its exact
direct child. Keep the
protected executor registration and historical authority available
after revocation. `launch-status` reads the exact reserved result
without live approval or inherited worker handles. It cannot issue a
new ticket.

#### Supply the enforcing backend and verify each invocation

The administrator supplies a `LaunchPlan` for the exact workflow definition
digest, role, appointed principal, generation, executable pin, resource
scope pin and fresh durable invocation key for the single-invocation form.
The reusable form derives a plan with the same policy pins and its reserved
key. In either case the enrolled policy must allow
`launch`. Its executable provider reference must equal the executable
SHA-256. Its supervisor provider must name the appointed launcher with
capability `scoped-launch`, and its reference must hash the administrator's
exact resource and allowed-operation manifest. Both providers must belong to
the definition's scope. The manager must support the existing live binding,
scope attestation and role-appointment checks.

Trusted deployment code must authenticate the launcher and an independent
authority before registering callbacks. The authority's name and credential
fingerprint are pinned in the plan. Its `authorize(invocation)` callback
verifies current scope and returns an exact, bounded `LaunchAuthorization`
with a single-use ticket reference. The launcher receives that invocation
and ticket, with no caller-supplied paths, commands or identities. It must
recheck authority and lifetime at dispatch, enforce the executable, principal
and resources, and durably reserve the exact key before any effect. This
requirement applies across restarts. The host provides that backend separately.

The stock entry requires `bounded=True` on the registration. The three
backend callbacks accept the absolute monotonic `deadline_ns` keyword.
The stock path shares the existing five-second managed request budget with
binding evidence, authorization, submission and readback. A shorter enclosing
budget or ticket lifetime limits use. The endpoint implementations must bound
their I/O themselves and durably reserve the invocation before irreversible
work. The argv used to check the compiled policy comes from the trusted host;
the stock adapter never executes it or accepts it from a managed client.

The independently authenticated `readback(invocation)` callback supplies a
`LaunchReadback` from the authoritative record. For a started or terminal
invocation, it returns effective principal, executable and scope pins measured
by the authority, and the receipt digest. The adapter compares these pins
with the approved plan and derives the result from readback. Lost or
inconsistent evidence stays `unknown`. Use `read_launch()` for historical
reconciliation, including after revocation. A terminal launch receipt alone
does not establish successful work, continuous custody or scope retirement.

### Choose a journey

- **Run a job:** `workeros help run` shows the local Python controller. The
  executable can be written in any language.
- **Read an inherited file:** the installed Python API and the shipped
  [Node.js](../node/README.md), [Go](../go/README.md), [Rust](../rust/README.md),
  [Java](../java/README.md), [C and C++](../native/README.md) readers cover
  seven languages. These worker-side readers do not implement the controller.
- **Configure an authorized host:** `workeros help managed` explains setup and
  recovery. Any language can invoke the shared installed CLI and exchange JSON;
  that does not give its native reader the Python controller's APIs or authority.

The candidate's [install guide](install-0.8.0.md) distinguishes package-manager
and platform requirements. A host, not a language binding, supplies actual
appointments and independent evidence.

### Record an administrator-approved role declaration

The candidate wheel uses one front door: `workeros` (or the short alias `wos`).
Run `workeros --help` to find local jobs, role declarations, managed setup and
recovery. The older commands remain available for existing scripts.

After installation, an administrator can record custom names, existing OS
principals, supported operations, named scopes and Unix expiry seconds with a
single no-start command. This illustrative declaration uses the existing
`root` principal; choose the actual approved principal and scope before use:

For an optional no-write guided draft, run `workeros roles guide` in a terminal.
Enter a profile, revision, role, existing principal, scope, expiry, operations
(default `read`) and an optional `independent_of` principal; type
`back` to revisit a field or `cancel` to stop. The JSON draft is printed to
standard output and administrator handoff instructions to standard error.
Give the draft to the administrator, who sets `ADMIN_WORKEROS` in their own
shell to the absolute path of their independently installed, trusted WorkerOS
executable before running the displayed preview. Do not elevate the draft
author's virtual environment. Nothing is saved or granted. For scripts,
`workeros roles draft --help` describes
the noninteractive version using the same validator.

```sh
workeros roles apply <<'JSON'
{"version":1,"profile":"reporting","revision":"v1","roles":[{"name":"report_reader","principal":"root","operations":["read"],"scopes":["reports"],"expires_at":4102444800}]}
JSON
```

Run it in an administrator shell. The first apply creates a private, fixed
`/var/lib/workeros/profiles` store if needed; it does not create principals,
start services, or grant access. The receipt says `configured` and explicitly
reports `enforcement: not_commissioned` and `independence: unverified`. An
optional `independent_of` names another existing principal; distinct UIDs are
checked, but that check does not establish independent provider evidence.
Unsupported operations and missing or identical principals are refused.

JSON is the default and needs no extra package. For YAML, activate the trusted
environment that will read the profile, then install optional PyYAML there:

```sh
python -m pip install 'PyYAML==6.0.3'
```

This command needs network access unless the dependency is already available
locally. For an offline install, supply a compatible PyYAML wheel in your own
wheelhouse and use `--no-index --find-links ./wheelhouse` instead. Then run
`workeros roles preview --format yaml` or `workeros roles apply --format yaml`
with YAML on standard input. Both formats use the same strict profile validator.
YAML anchors, aliases, duplicate keys and multiple documents are refused. If
PyYAML is unavailable, the command reports `yaml_dependency_missing` before any
effect. Command results remain JSON.

An administrator can add a `privileged` array to a role, with entries such as
`{"capability":"special_resource_access","scope":"reports","approved":true}`.
Run `workeros roles preview` with the same JSON on standard input to see the
exact requested principals, operations, scopes and approved capabilities
without writing anything. `roles apply` refuses entries in the `privileged`
array with `unsupported_privileged_enforcement`. A declaration records the
administrator's intent. To grant an existing principal read access to one
approved Linux file, use the separately applied [named-principal file ACL](#grant-read-access-to-one-linux-file).
Other privileged capabilities require an enforcement backend for the
specific capability and scope. Choose role names to match your deployment.

Use `workeros roles show reporting v1` for readback. To change a declaration,
apply a new revision; the same revision cannot be overwritten. Use
`workeros roles revoke reporting v1` to revoke the recorded declaration. This
does not revoke actual OS permissions or an existing provider appointment: the
administrator must use the authority that granted those.

An administrator can apply an approved profile and read back the resulting
local commissioning receipt in one command, including on an empty role store.
Run the first line only if you want to preview the requested profile:

```sh
workeros managed apply-profile --preview < profile.json
workeros managed apply-profile < profile.json
```

For YAML, add `--format yaml` and use the same optional PyYAML installation
described above. `declaration_sha256` identifies the canonical stored declaration.
`intent_sha256` identifies the exact input bytes, including whitespace and
format. Keep the approved input and use those same bytes for an exact repeat.
The same declaration in another format has the same declaration digest. Its
different intent digest conflicts on the same revision. To commission an
existing declaration against a separate intent document, use
`workeros managed commission PROFILE REVISION --declaration-sha256 SHA --intent-sha256 SHA`.

To commission a profile and register its approved appointments together, add
the host-supplied `appointments` array described below to that same version 1
profile document. The same `apply-profile` command computes the declaration
and intent digests, pins the registry in its receipt, and writes and reads
back the appointments under the same administrator lock. The optional preview
shows the pinned appointments without creating any store records.

`configured` means the receipt matches the active declaration. The result
reports `readiness: not_checked` and `independence: unverified`. The operation
records local intent and leaves workloads, ACLs and provider appointments alone.
If the write is interrupted, run `workeros managed profile-status PROFILE REVISION`.
An `unconfigured` result with `declaration_status: configured` confirms the
declaration exists and the receipt is absent. The administrator can complete
that case with the same approved bytes. For a combined request,
`incomplete` with `appointment_status: unregistered` means the commissioning
receipt exists and the pinned registry is absent. After reading that status,
apply the same approved input to complete the registration. For `unknown`, reconcile the store
before another apply. Status also reports `revoked` or `expired` where applicable.
For actual provider appointments and host verification, use the authenticated
host integration below.

### Installed no-start host command

#### Package host for approved point observers and meters

The package host can serve one managed setup or readback request for several
preauthorized workflows. Apply the version 1 profile with its pinned
appointments using `workeros managed apply-profile`.
`profile-status` reads the local approval and registration. The older
`commission-apply` and `commission-status` names remain aliases. `setup`
checks the providers and stores a managed mapping. `readback` checks the
stored mapping and the current providers. `reconcile` uses the same read-only
path after uncertain setup.

If the provider or original handles have retired, the administrator can read
the interrupted attempt from the exact installed wheel and the original
trusted setup configuration:

```sh
workeros managed serve-setup --recover-interrupted
```

Use the administrator's trusted installation. This command needs no listener,
provider or inherited descriptors. It reads the exact operation and scope
records, without replaying setup or checking current readiness. An outcome
such as `scope_commit_verified` confirms only that one mapping was published
by that operation. A missing mapping stays unknown, and a matching older
mapping or one written by a different operation is not attributed to this
attempt. A conflicting definition or generation is reported separately.
Partial evidence, or even evidence for every scope, does not reconstruct a
missing aggregate result. The command returns exit 1 and
`readiness: not_checked` because it supplies historical evidence only.
Use regular readback for a completed attempt with current providers.

The administrator provisions `/etc/workeros/managed-setup.json` through the
same ownership and no-symlink checks as the client configuration. Supply the
following fields in one setup configuration:

| Fields | Purpose |
| --- | --- |
| `version` | Integer `2` for multiple scopes. Version `1` continues to accept the original single point-observer layout. |
| `profile`, `revision`, `local_approval` | Exact approved local profile and revision. `local_approval` contains `declaration_sha256` and `intent_sha256` from the local receipt. |
| `authorized_uids`, `operation_key` | Allowed Linux client UIDs and the retained 64-hex operation correlation key. |
| `wheel_path`, `journal_directory` | Verified wheel and an existing private directory owned by the host for managed mappings and the attempt journal. Use absolute paths with trusted ancestors. |
| `scopes` | Version 2 accepts an array of one to eight entries with distinct workflow names and scope IDs. Version 1 puts the fields for a single entry directly at the top level. |

Each scope entry has the following fields:

| Fields | Purpose |
| --- | --- |
| `definition`, `policy`, `role`, `binding_generation` | Exact `ProfileDefinition` and matching version 1 policy. The policy hash is SHA-256 of compact JSON with sorted keys. A point scope uses `observe` with one `observers` binding of capability `point`. A metered scope uses `meter` and one `meters` binding of capability `cgroup-v2`. |
| `observer` | Required with `provider` for a selected point. Supply inherited `original_fd` and `pidfd`, plus the pinned `device`, `inode`, `pid`, `uid`, `slot` and `scope_sha256`. Use `require_readable: true` to refuse metadata-only handles. An optional `directory` object supplies an inherited `directory_fd`, exact directory `device` and `inode`, and a relative `leaf`. |
| `provider` | Administrator-pinned absolute Unix `socket` and Linux `peer_uid` for the point attester. The peer UID must differ from the host. Its source name is the point binding's `principal`. |
| `meter`, `meter_provider` | Version 2 pair for a selected meter, with or without a selected point. The meter takes the inherited cgroup v2 `directory_fd`, pinned `device`, `inode` and `mount_id`, and an exact `EvidenceScope` in `scope`. The meter's scope ID must match the binding. The meter attester has its own `socket`, `peer_uid` and source, distinct from the host and from the point attester when both are selected. |

A version 2 scope may select a point, a meter, or both. A scope with no
provider can be recorded with `apply-profile`; stock verified setup reports
`independent_attester_unavailable`. An unsupported scope stops the stock
setup before any mapping is written. The result names the affected scopes
and marks the remaining scopes `not_checked`.

For each `ProviderBinding.reference`, hash that binding's compact plan JSON
with sorted keys, excluding inherited descriptor numbers at every level.
Use different inherited descriptor numbers for each registered binding.

`setup_clock_id()` from `workeros.managed_bootstrap` binds the definition
to this Linux boot and monotonic time namespace. `definition.expires_ns` and
provider `valid_until_ns` are absolute monotonic nanoseconds. The declaration's
`expires_at` is Unix seconds. A meter's nested run clock uses the actual Linux
clock context. Each selected attester must validate the exact definition.
If the scope selects both, it stays unverified if either is unavailable,
and its verified expiry is the earlier of the two deadlines.

A trusted launcher supplies the selected provider's resource descriptors and an already listening
Unix stream socket. Run `workeros managed serve-setup --describe` with the
selected resource descriptors to obtain the adapter identity for
the client file. Its `binding_check` field supplies the client pins described
below. To verify the active approval, exact compiled bindings and
current attester responses before recording setup, run
`workeros managed serve-setup --check-bindings` with the same resource
descriptors. This check needs no listener and writes no setup record.
On success it reports `bindings_verified` and the earliest evidence expiry
across scopes. It intentionally reports `readiness: not_checked` and
`runtime_evidence: not_requested`. Revalidate at use. An existing trusted
host with already authorized typed bindings can use
`ManagedHostAdapter.check_bindings()` for the same check.
Then run `workeros managed serve-setup --listen-fd FD` with
those descriptors and the listening socket. The command serves one request using the fixed configuration. A
launcher may invoke it again for the same approved mapping. The package creates
no accounts, grants, listening sockets or workloads.

The external attester uses a four-byte network-order length followed by UTF-8
JSON. For each connection it receives `version`, `request_id`,
`definition_sha256`, `role`, `clock_id` and `generation`. It must authenticate
the requesting host and independently verify the current appointment and
exact scope against its own approved registry and evidence. On success it
returns `request_id`, `definition_sha256`, `role`, `clock_id`, `generation`,
`source`, `status` (`verified`), `evidence_sha256`, and `valid_until_ns` as a
decimal string. A provider unable to verify the request should close the
connection. WorkerOS checks the kernel peer UID, the challenge, exact scope
binding and expiry before handing the evidence to the existing aggregate.
The provider must already be authorized and independently controlled. A local
role or appointment receipt supplies no provider evidence.

#### Serve an approved point observation

The separately operated observer can use the installed provider command in
place of a custom attestation application. The authorized launcher supplies
the ready-to-accept Unix stream socket, the preopened observer descriptors, and
an administrator-owned read-only registration file descriptor. That descriptor
must refer to a regular file with exactly one link; it must be opened read-only,
not with `O_PATH`, and its file mode must not allow group or world writes. Keep
the registration linked in an administrator-protected directory throughout the
provider session and until the launcher has retired it. The provider checks the
descriptor at startup; that check does not prove continuous protection. The listener
must have been placed in the listening state under the observer's UID. A
listener opened by a different UID fails the peer check. Use a separately
operated non-root provider UID and the exact approved host UID.

The registration is a JSON object with `version: 1`, `host_uid`,
`provider_uid`, `definition`, `role`, `binding_generation`,
`binding`, and `observer`. Use the same definition, role, generation,
and observer inputs as the managed host. `binding` names the definition's
point observer binding. The local descriptor numbers in `observer` must
match those passed to this process. For a metered scope, a separate provider
registration selects its commissioned `meters` binding with capability
`cgroup-v2` and supplies `meter` instead of `observer`. Both registrations
use the same exact scope definition. The meter's preopened readable cgroup v2
directory must match its pinned device, inode and mount ID, and its run must
match the authorized scope and clock context. The meter provider must operate
under a distinct Linux UID from both the point attester and the setup host.
The host, observer and meter must use matching pinned boot, monotonic clock,
time and identity namespace contexts; an incompatible view remains unavailable.

From the launcher, run the first command as the provider principal and the
second as the authorized setup host. The client calls the third command after
the host and provider are listening and the client pins are installed.

```sh
workeros managed serve-provider --config-fd "$PROVIDER_PLAN_FD" --listen-fd "$PROVIDER_LISTENER_FD" --max-requests 16
workeros managed serve-setup --listen-fd "$HOST_LISTENER_FD"
workeros managed check-bindings
```

By default the provider handles one request. `--max-requests` permits 1–16
fresh checks in a bounded session: at most 30 seconds in total (or the earlier
registration expiry), with a five-second idle and per-connection limit. It exits
after the limit or an idle timeout; an invalid request stops the session. A
`check-bindings` operation needs one provider check, while normal setup can
need several fresh checks, so provision up to 16 for that one setup operation.
Readback is a separate authorized listener invocation for the exact unchanged
attempt; relaunch the needed providers through the authorized launcher.

For each check the provider authenticates the host UID, verifies the exact
challenge and settings, then samples its preauthorized resource. The observer
samples the file slot and any configured directory entry. The meter checks a
current raw CPU reading and population point; memory fields remain optional and
unavailable values stay explicit. One meter check is not a begin/end pair, a
run-exclusive measurement, expiry or retirement evidence. Missing process
visibility, a wrong original, a missing clock, incompatible meter identity or
expired evidence fails closed. An attestation digest describes only that point
observation. Revalidate independent, exact evidence at use. Any interval or
retirement requirement still needs its own independently qualified provider and
venue evidence.

For a point-only approved launch scope, the selected point observer can
serve a definition that also carries one exact executable pin and one
`scoped-launch` supervisor pin for the same launcher and scope. The observer
must have its own principal and a UID distinct from the observed worker.
Each request and response pins the full definition, including both launch
records. The provider serves the point observer only. The enforcing launcher,
ticket authority and effective invocation readback still belong to the
approved deployment.

This setup checks associations and current provider attestations. A named
directory entry is a point observation. Interval custody, worker-to-worker
handoff, writer state, dedicated-run meter deltas and whole-scope retirement
still require their own provider or native workflow evidence. The bundled
listener refuses non-point observers for setup and exposes no runtime launch,
write or release operation. A visible cgroup alone does not establish
exclusive workload membership.

`serve-setup` refuses a runtime custody binding or a workflow that requires
custody before accepting a request or writing a managed mapping. The separate
read-only [interval registration check](#check-a-registered-interval-provider)
can verify the binding of an already appointed external provider.
`require_custody` authenticates one pre-grant decision for an exact original,
recipient, scope and deadline. A point observation or a pair of meter readings
cannot establish ongoing exclusion or who retained access after delivery.
Child exit and child reap do not establish retirement of the whole scope.
The administrator's no-start listener is also a separate boundary from
release. The pre-grant custody check refuses a release caller that can assume
or alter other principals.

A deployment needs an independently controlled session that can attest
the already-authorized original at admission, enforce or observe the
required exclusion through the run, and report terminal retirement after
cleanup for the same attempt. The narrow existing sealed-file fixture exercises
one read-only grant and direct-child cleanup with real Linux principals. It
does not qualify mutable originals or directory and whole-scope retirement.
Use a disposable Linux venue with a verifiable monotonic clock context,
a separately authorized observer principal, an unprivileged release caller
and explicitly pre-granted handles to qualify the provider.

#### Check a registered interval provider

For an existing provider, the administrator can opt in to a read-only
`serve-setup --check-bindings` in a version 2 configuration. Use one
`observers` binding with capability `interval`, the exact definition scope,
and an explicit `independent_of` principal. The workflow selects only
`observe`. Supply the existing `observer` plan and inherited descriptors with
`require_readable: true`. In place of `provider`, supply
`interval_provider: {"socket":"/approved/provider.sock","peer_uid":1234}`
with the already authorized provider's actual address and UID. The binding
reference hashes compact, sorted JSON containing the `observer` plan
(excluding all descriptor numbers) and the exact `interval_provider` object.
Provision the appointment against that exact definition digest.

This check-only mode also accepts one independently registered
`cgroup-v2` meter alongside the interval observer **in the same definition**.
Include `meter` and `meter_provider` and select both `observe` and `meter`
in the workflow. Both bindings must name the definition's exact scope ID
and specify `independent_of`. Pin distinct provider principal names,
endpoint paths and Linux UIDs. Set the observer's `scope_sha256` to the
SHA-256 of the compact sorted JSON for the entire meter `scope`
(`EvidenceScope`, including its run and clock). A shared name alone cannot
join different runs. Hash the paired meter reference as compact sorted
JSON containing `{"meter": plan, "meter_provider": endpoint}`, where
`plan` is the meter plan without `directory_fd`. The stock meter provider
derives the endpoint from its preopened listener and registered UID.
Ordinary point/meter references keep their existing format.

The separately controlled provider must implement the bounded Unix-stream
attestation exchange above with `version: 2` and `capability: "interval"` in
both request and verified reply. It must independently verify its current
appointment and exact evidence before replying. The bundled point/meter
provider can serve the meter binding but does not implement the external
interval exchange. Both providers must attest the same current definition,
role, generation, and clock, with the earlier valid expiry governing
the check. The host authenticates the pinned
peer before sending the challenge and refuses a mismatched or expired reply.
Success verifies the current binding only. Readiness remains `not_checked`,
independence remains `unverified`, and runtime evidence is `not_requested`.
The check-only mode needs no setup journal. It ignores `journal_directory`
if the configuration includes one.

Run `workeros managed serve-setup --check-bindings` for a local result.
For the ordinary authenticated client, obtain the exact client pins using
`workeros managed serve-setup --check-bindings --describe` with the same
approved resources and inherited handles. This describes the configured
pins without contacting a provider. Enter the pins in the administrator
client configuration below. Then have the authorized host run
`workeros managed serve-setup --check-bindings --listen-fd FD` with its
preopened listener and approved handles, and run
`workeros managed check-bindings` from the enrolled client.

The check-only listener serves one authenticated request. Setup, mapping
readback and reconciliation requests receive `binding_check_only` and
`effect: not_attempted`. A missing role appointment refuses before querying a
provider. A changed generation, expired provider observation, or unconfirmed
reply leaves the binding unverified. It takes fresh verified evidence to
qualify a future use. Bare setup listen, describe and recovery modes continue
to refuse interval registrations.

#### Existing custom host integration

On Linux or Ubuntu WSL2, a commissioned host can expose its existing authorized
manager through a local Unix stream socket. The administrator provisions the
fixed `/etc/workeros/managed-host.json` and the existing host's listener. The
file and `/etc/workeros` must be root-owned, not group- or world-writable, and
not symbolic links. No user-supplied configuration path or import is accepted.
The root-owned JSON has the following required fields and an optional
`binding_check` object. These example values need to come from your own
approved deployment.

```json
{"version":1,"socket":"/run/workeros/managed.sock","peer_uid":1234,
 "profile":"approved-profile","scopes":["scope-one","scope-two"],
 "identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "operation_key":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

For `workeros managed check-bindings`, put the commissioned adapter's
`binding_check_pins()` result in `binding_check`. It includes `revision`,
`clock_id`, and `scope_digests`, which maps every configured scope name to
its exact definition SHA-256. Obtain these pins from the approved configuration
before sending a check request. The command
authenticates the same peer and requires the exact profile, key, revision,
scope digests, and clock context in the reply. It checks bindings without
creating or reading a setup attempt. Exit zero means `bindings_verified`
at the reported observation time, with `readiness: not_checked` and
`runtime_evidence: not_requested`. When a reply cannot be confirmed,
verify the host and its pins before using the bindings. A stock check-only
listener with an independently authorized registered interval provider supports
this command. An existing trusted host can also supply an authorized typed
provider directly.

Use a dedicated authorized host UID where other processes must not impersonate
that service. The command verifies the connected peer's Linux `SO_PEERCRED` UID
before sending the fixed profile, commissioned digest, operation key and operation; UID authentication by itself is
not proof of provider independence. `workeros managed setup`, `readback`, and
`reconcile` send at most one request each, with a five-second total transport
budget and bounded frames. An error after a send is `unknown`; use the host's
readback and reconciliation rather than repeating setup. Exit zero means only
that every configured scope passed the reported final sweep. Outputs contain
fixed status fields, not resource paths or credentials.

Start with `workeros managed preview`. It reads only the fixed configuration and
shows the selected profile, scope names, identity and operation key. `configured`
does not mean that a manager is listening or that appointments are qualified;
the command tells you when an administrator must commission the profile. Preview
neither connects to the endpoint nor attempts setup. The ordinary local
`workeros demo` path requires neither this configuration nor a manager.

The existing trusted host may pass its already-listening Unix stream socket to
`managed_cli.serve_listener_once(listener, authorized_uids=..., adapter=...)`.
It accepts at most one connection with a bounded wait and closes that connection;
the host retains the listener and can call it again. Alternatively, integrate
`managed_cli.serve_connection` with an already accepted socket. Neither helper
creates a listener or commissions a host. The host supplies an explicit authorized UID set and a
`managed_host.ManagedHostAdapter` built from the approved profile and revision,
exact `ProfileDefinition` objects, per-scope `ScopeSetup` requirements,
accepted provider generations, and the independently verified wheel digest.
The adapter's `identity` hashes that canonical mapping; provision that exact
value in the root-owned configuration. Provision a fresh opaque 64-hex
`operation_key` once for this setup, retain it, and never treat either value as
authority by itself. The helper checks the caller's `SO_PEERCRED` and exact
identity and key before dispatch. The package-owned adapter calls
`AggregateSetup` for setup and exact read-only operations for readback and
reconciliation; it never invokes a generic handler from caller input. The
trusted host must provide a durable store with atomic `read`, `claim`, and
`finish` for that exact identity and key. A claim must persist across process
failure, block duplicate writes, and remain pending if its outcome is unknown;
`not_started` or `not_committed` must be backed by authoritative proof. The host
must also provide appointment verification,
resource generation checks and its own bounded callback execution; the helper
creates no daemon, account, permission or independent evidence. Frames are a
four-byte unsigned big-endian length followed by UTF-8 JSON (maximum 65536
bytes); version 1 requests carry `version`, `operation`, `profile`, `identity`
and `operation_key`. Setup, readback and reconcile responses echo the same exact identity and key and include
the observation clock, beginning, end and earliest expiry as decimal strings.
`ready` is refused if the earliest verified expiry has elapsed by response; the
sweep is not atomic and providers must be revalidated at use. Responses also
contain `status`, `effect`, and one fixed
`{name, setup, final, effect, code}` entry per configured scope. Use
`not_checked` for a final check that did not run, preserve each scope's effect,
and map diagnostics outside the fixed code list to `other`. See
`managed_cli.py` for the accepted values and validate each receipt before acting.

An existing trusted host that already has administrator access to the local
role store can also supply
`local_approval=LocalProfileApproval(declaration_sha256, intent_sha256)` to
`ManagedHostAdapter`. Import both from `workeros.managed_host`. The host
provides the pins from its approved deployment configuration and the typed
scope, provider and generation registrations described above. The two local
receipt digests become part of the adapter identity.

Set `local_appointments=True` on the adapter to use WorkerOS's built-in
appointment registry with the administrator role store. Put the trusted host's
approved `appointments` array in the profile document and run
`workeros managed apply-profile < profile.json`. Inspect the registry with
`workeros managed appointment-status PROFILE REVISION`. The separate
registration command remains available for an already commissioned declaration:

```sh
workeros managed appointment-register < appointments.json
workeros managed appointment-status PROFILE REVISION
```

For separate registration, the JSON object contains `version` (1), `profile`,
`revision`, `declaration_sha256`, `intent_sha256`, and an `appointments` array. Each
appointment has `workflow`, `workflow_revision`, `definition_sha256`, `role`,
`principal`, `scope`, `generation`, and `operations` (an array of allowed
workflow operations). For separate registration, use the two digests from
`profile-status`. The host supplies the definition pin using
`workeros.appointment_registry.definition_sha256` on its pinned
`ProfileDefinition`. This includes the provider references and capabilities,
policy digest, scope, clock, expiry and package pin.

WorkerOS verifies the approved declaration and reads the durable registration
under the existing role lock. An exact repeat returns `unchanged`. A different
registration for the same revision conflicts. Use a newly approved revision for
changed mappings and revoke the old declaration to disable its registration.
An unavailable store or uncertain write requires `appointment-status` before
another attempt. `registered` reports local administrator intent and leaves runtime
readiness and independence unverified.

When the administrator already supplied protected `managed-setup.json` and
`launch-executor.json`, compare both to the exact approved profile before
commissioning its role and appointments:

```sh
workeros managed apply-profile --registered-managed --preview < profile.json
workeros managed apply-profile --registered-managed < profile.json
workeros managed profile-status --registered-managed PROFILE REVISION
```

This path compares the approved profile, backend, and installed wheel with
the two current files. Apply records the role and appointments. Status reads
back those records and reports the current matching configuration digests.
The check opens no backend connection and starts no workload. Live provider
authority and execution require separate proof.

On a fresh installation, the administrator supplies an approved
`bundle.json` with `version: 1`, the approved `profile` with its appointments,
`managed_setup`, and `launch_executor`. To provision
the stock named client on a clean host, include its
[`launch_client` routing document](#register-a-named-systemd-workflow) in that
bundle. Once these inputs are ready, run:

```sh
workeros managed apply-profile --provision-managed --preview < bundle.json
workeros managed apply-profile --provision-managed < bundle.json
workeros managed profile-status --registered-managed PROFILE REVISION
```

Preview checks the configuration before writing. First apply installs
absent fixed files and records their canonical digests in the approved
revision. Guarded launch requires those pins. A changed setup or executor requires a new approved
revision, including changes to allowed callers. Historical access uses the
pinned executor and result rights after revocation.

#### Prepare a guarded commissioning bundle

The installed draft example builds the linked JSON objects for a guarded
workflow from administrator-supplied inputs. Run it in the trusted WorkerOS
environment on the target host. Have the approved worker account, exact
originals, executable, endpoints, and cgroup parent ready. For a new service,
get that parent from the running guard's `guard_parent_pinned` reply.

Here is the input shape for one named writer. Replace the example labels and
paths with the approved values. Fill every zero and every angle-bracket
placeholder from the administrator's actual inputs before drafting.

```json
{
  "profile": "reports",
  "revision": "review-1",
  "workflow": "report-writer",
  "workflow_revision": "v1",
  "generation": "review-1",
  "role": "report-editor",
  "principal": "report-worker",
  "launcher": "report-launcher",
  "manager": "report-manager",
  "authority": "report-guard",
  "authority_socket": "/run/workeros/report-guard/guard.sock",
  "authority_uid": 0,
  "client_socket": "/run/workeros/report-client/launch.sock",
  "wheel_path": "/srv/workeros/approved/workeros.whl",
  "wheel_sha256": "<approved wheel SHA-256>",
  "executable_sha256": "<approved executable SHA-256>",
  "expires_at": 0,
  "expires_ns": 0,
  "operation_key": "<retained 64-hex setup key>",
  "run_uids": [0],
  "result_uids": [0],
  "journal_directory": "/var/lib/workeros/managed-journal",
  "service": {
    "root_directory": "/srv/workeros/report-root",
    "root_device": 0,
    "root_inode": 0,
    "executable": "/write-report",
    "principal_gid": 0,
    "active_ms": 0,
    "cleanup_ms": 0,
    "metered": false,
    "parent": {
      "unit": "report-guard.service",
      "control_group": "/system.slice/report-guard.service",
      "mount_id": 0,
      "device": 0,
      "inode": 0
    },
    "descriptors": [
      {"slot": "stdout", "scope": "report-output", "owner_uid": 0,
       "mode": "write", "device": 0, "inode": 0, "fd": 3}
    ],
    "elevated_capabilities": [
      {"name": "write_report", "scope": "report-output", "operation": "write"}
    ]
  }
}
```

Use the role's Unix expiry in seconds for `expires_at` and its approved
cutoff on this host's monotonic clock in nanoseconds for `expires_ns`. The
monotonic cutoff cannot extend the role's lifetime. Keep one `operation_key`
for the exact setup attempt. List the approved caller and reader UIDs
separately. The `descriptors` pin the original owner and exact file identity.
Named activation binds each slot to its delivered original. The `fd`
number is excluded from the reusable scope digest. The optional
`holder` and `result_observer` entries use the protected forms described in
the [holder](#activate-a-live-holder-and-overlap-distinct-workflows) and
[independent result](#verify-an-independent-result-for-a-guarded-workflow)
sections.

For several workflows in one revision, put their draft inputs in a
`{"workflows": [...]}` document. Use the same profile, revision, wheel,
operation key, setup journal, and client socket, with a distinct workflow
and role for each entry. Keep each registered original and guard separate.

```sh
example=$(python -I -c 'import sysconfig; print(sysconfig.get_path("data") + "/share/workeros/examples/draft_guarded_profile.py")')
umask 077
python -I "$example" draft spec.json > bundle.draft.json
```

The draft prints the bundle. The administrator first previews it, then applies
the same reviewed bytes and captures the status. Set `profile`, `revision`,
and `workflow` to the chosen names, and `guard_journal` to the guard's private
journal directory.

For example, when an administrator has placed the verified install at
`/opt/workeros-qual/venv` and the reviewed bundle at
`/etc/workeros/approved-role.json`, the approval command is:

```sh
sudo -- /bin/sh -c 'exec /opt/workeros-qual/venv/bin/workeros managed apply-profile --provision-managed --preview < /etc/workeros/approved-role.json'
sudo -- /bin/sh -c 'exec /opt/workeros-qual/venv/bin/workeros managed apply-profile --provision-managed < /etc/workeros/approved-role.json'
```

The OS handles administrator authentication. Ordinary callers use the
installed client for preauthorized invocations. The grant specifies
admin-defined combinations of operations and exact resources enforced by
the registered backend. A new or increased grant requires administrator
approval. An ordinary caller's inability to open a protected original does
not prevent its approved owner from supplying that exact descriptor to a
scoped worker.

```sh
# Run inside the trusted administrator shell.
workeros managed profile-status --registered-managed "$profile" "$revision" > status.json
python -I "$example" guard bundle.draft.json status.json "$workflow" \
  --journal "$guard_journal" > workeros-guard.json
```

The guard step matches the bundle to the captured status pins and reads the
identity of the administrator's role-store lock at `/var/lib/workeros`.
Run it in the administrator's trusted environment with access to that
store. Deliver `workeros-guard.json` and the matching setup and executor files
through the [guard's selected activation mode](#run-the-installed-delegated-guarded-authority).
The draft and readback do not supply OS authority, live originals, or a
running guard.

For an intentional revision change of the same managed profile, prepare a
complete new bundle and use its top-level `rotate_from` object. Include the
exact old `revision`, `managed_setup_sha256`, `launch_executor_sha256`,
and `launch_client_sha256` from the current registrations. For the draft
example's batch input, put `rotate_from` beside `workflows`. Revoke the old
revision before applying the new one. Preview then verifies the old
revocation and file pins, and apply publishes the new client routing last.
Check `managed_rotation.status` for `verified`. If a cutover is incomplete,
check `profile-status --registered-managed` for the same revision and use only
the exact retained approved bundle to reconcile it. Retained history uses the
original result rights and remains available through the history listener.

New stock v1 launches also require the setup and executor pins from the
approved revision. Status reads can use the pinned executor after revocation
or expiry without reopening live setup. An old unpinned v1 record remains
readable through its exact historical invocation. Only an explicit trusted
in-process host registration can still run an unpinned v1 configuration.

For a managed service with registered file descriptors, an administrator can
name a scoped operation in the role declaration. Include the name in the
role's `operations`, and register it in `operation_aliases`. For example,
`index_inventory` can select `read` on a role resource named `inventory-source`:

```json
{
  "index_inventory": {
    "capability": "read",
    "scope": "inventory-source",
    "provider_sha256": "<approved ServiceBundle digest>"
  }
}
```

The role's `resources` must pin that scope's device and inode. Supply the matching
launch appointment in the same JSON or YAML document to `managed apply-profile`.
The appointment pins the full role, including the alias, and the workflow
definition pins the existing stream provider. The service manager verifies the
same bundle digest, descriptor identity and access mode before requesting an
invocation ticket. Aliases support the bundle's existing `read` and `write`
rights. Adding an alias grants no new access. The workflow and appointment
still use the typed `launch` operation, and Terminal, JSON/YAML requests and
Python select that same approved workflow. Changes require a new approved
revision.

To authorize elevated access through the guarded service, add the exact
admin-named operation to the selected workflow's protected `service`
registration in `launch_executor`:

```json
"elevated_capabilities": [
  {"name": "index_inventory", "scope": "inventory-source", "operation": "read"}
]
```

The role must list `index_inventory` in `operations` and `operation_aliases`,
and include `{"capability":"index_inventory","scope":"inventory-source","approved":true}`
in `privileged`. Pin the new bundle digest in the alias and workflow definition.
The complete capability list must match the role and the read/write access
modes of the exact registered originals. The protected workflow must select
`guarded-service-v1`. The worker receives access through approved descriptors
only. Ambient system capabilities, arbitrary commands, and other unsupported
operations are refused.

Use `workeros managed apply-profile --preview --provision-managed` to show the
effective scope requested by the registration. Apply without `--preview`,
then use `workeros managed profile-status PROFILE REVISION --registered-managed`
to read back the pins. These operations start no workload and show enforcement
as `not_checked`. Explicit `workeros managed run-approved --workflow WORKFLOW
--request-id ID`, equivalent JSON or YAML input, and Python
`workeros.managed_executor.registered_launch(ID, workflow=WORKFLOW)` use the same
guard. Launch still requires the appointed guard, the exact approved executor,
live descriptor owners, and a writable delegated leaf the authority can arm
and retire. `workeros managed revoke-profile PROFILE REVISION` denies new uses
while leaving authenticated historical readback available. Already released
workers remain subject to their existing guard and deadlines. Approving a
new revision does not revoke an older one.

The administrative receipts include `admin_history` for recorded apply,
commission, and revoke actions. Each entry identifies the revision and
disposition. New entries record the kernel-authenticated effective UID
and a decimal Unix nanosecond timestamp. That UID identifies the process
credential, without identifying the human who authorized it. Older receipts
can show an unverified actor and a null time. Repeating an exact operation
preserves the original history.

During managed setup or readback, WorkerOS compiles the pinned policy against live
bindings and compares the registration with the exact workflow definition, declared
principal, operations and current binding generation. Missing or stale records
refuse before journal claim. Hosts using an existing appointment verifier can
continue implementing `verify_role_appointment(selection, requirements, generation)`
without enabling the registry. Both modes require the host to advance binding
generation when appointments change and revalidate live bindings at create.

On setup and current readback, WorkerOS holds the administrator role lock
while checking the exact receipt, declaration expiry, allowed operations,
and scope of each registered binding. Keep host callbacks bounded and avoid
reentering the local role store from those callbacks. This composition refuses
selected roles with explicit resource, privileged or principal-independence
claims. It has no verifier that connects those declaration fields to a live
provider binding. The existing manager must still authenticate the live provider
bindings and obtain `ScopeEvidence` from its independent source. That evidence
must cover the exact definition and role in the approved clock, arrive from a
verified source distinct from the manager, and match the live generation and
expiry. The local registry supplies the role appointment check. The deployment
supplies the actual provider bindings, independent evidence and authoritative
manager readback.

The identity is SHA-256 of the adapter's versioned JSON object encoded as UTF-8
with sorted keys, ASCII escapes and compact separators. It includes the profile,
revision, wheel digest, and ordered per-scope exact definitions, requirements
and accepted generations. Obtain it from the precommissioned adapter, not an
applicant's request. The operation key identifies one durable setup attempt;
unknown or pending history permits only exact read-only lookup. Neither a
receipt nor a past successful sweep replaces live revalidation.

The package provides `managed_journal.ManagedJournal` as a durable store for an
already provisioned private directory. It commits immutable claims and results,
retains pending or uncertain claims, and does not automatically replay them.
It stores status and exact operation identifiers, not provider credentials.
The host must protect and retain that directory; removing records or restoring
an earlier copy can make a later write unsafe. The journal does not authenticate
providers or independently verify manager readback.

Role and scope names in a policy are chosen by the deploying organization; no
particular set of roles is required. Policy validation can reject unsupported
operations, but cannot create an OS principal or authenticate an observer. The
host must verify that the appointed observer is the authorized independent
principal for the requested scope and that its live binding and expiry match.
Changing a policy or an appointment requires a newly approved revision and
operation key. Revocation must be performed and independently read back through
the existing authority; `preview` and a saved prior receipt cannot revoke or
renew an appointment. Declaration apply and revoke do not apply or revoke a
real provider appointment, so they are not a complete commissioning journey
without a separately commissioned host.

### Grant read access to one Linux file

#### Apply a profile and verify a file grant

An administrator can use one approved profile document to record a custom
role and apply one `named_uid_read_acl` without starting a worker. Use
`workeros managed apply-profile --preview < profile.json` to verify the exact
plan without writing. Run `workeros managed apply-profile < profile.json`
to record and apply it. Both accept JSON or `--format yaml` with PyYAML.

Declare the capability under the role's `privileged` field and pin
its enforcement in the top-level `grant` field. Set the expiry to
your approved future Unix timestamp, the principal and numeric UID to the
same existing account, and the device and inode to the exact approved file.
Use only a regular, single-link, administrator-owned `0600` file with no ACL
in a protected administrator-owned `0711` parent directory.

```json
{
  "version": 1,
  "profile": "reports",
  "revision": "review-1",
  "roles": [{
    "name": "report-reviewer",
    "principal": "existing-reviewer",
    "operations": ["read"],
    "scopes": ["final-report"],
    "expires_at": 1796000000,
    "resources": {"final-report": {"device": "100", "inode": "200"}},
    "privileged": [{
      "capability": "named_uid_read_acl", "scope": "final-report", "approved": true
    }]
  }],
  "grant": {
    "capability": "named_uid_read_acl",
    "role": "report-reviewer",
    "scope": "final-report",
    "path": "/approved/reports/final.txt",
    "principal_uid": 1234,
    "exclusive_admin": true
  }
}
```

Preview shows the held file identity, pinned UID and exact mode change.
`file_acl_verified` records an exact ACL and mode readback from the kernel.
Verify path traversal and any other access controls separately as the
appointed principal. This command starts no worker and leaves readiness
`not_checked` and independence `unverified`. A declaration without
`grant` still needs no independent attester to be recorded. Requests for a
different grant capability or an independent observer on this grant must
use an authorized backend and the required separate provider evidence;
WorkerOS refuses those inputs here before applying an ACL.

Keep the original document. An exact apply repeat reads back the previously
recorded grants. A changed input conflicts with that revision. A lost or
incomplete result may leave only some ACLs present. Check
`workeros managed profile-status reports review-1` for the recorded plan and
per-file kernel readback. Resolve any unknown entries before applying a new
revision. Setup attachment, runtime evidence, scope cleanup and manager
retirement have separate fields and require their own checks.

Use `workeros managed revoke-profile reports review-1` to retire the exact
declaration and remove its recorded file ACLs. Run `profile-status` again
to confirm the individual ACLs are absent. The administrator can update a
profile by verifying removal on the old revision, approving the new version's
registrations and applying an explicitly new revision. The steps are separate
and can leave an interval without access. `roles revoke` affects the
declaration only. Earlier standalone grants use the exact saved plan with
`roles grant-check` and `roles grant-revoke`.

The Linux POSIX ACL backend requires manual revocation. Schedule cleanup
before expiry or uninstall. A request for automatic expiry is refused before
apply. Revocation prevents new opens through the removed grant. An already
open descriptor remains usable until its holder closes it.

#### Register a native file capability

The stock CLI can read an administrator-controlled registry with the same
no-start apply entry. The Linux named-user data ACL backend supports read (4),
write (2), and read and write (6). A write entry permits file writes and cannot
limit them to appends. No registration starts a command or creates a principal.

An administrator places the approved registry at
`/etc/workeros/file-acl-registrations.json`. WorkerOS checks that the fixed file
and its directories are root-owned and free of group and world write access.
The file must be a single-link regular file. User-supplied paths and symbolic
links are refused. Use version 1 and a bounded list of exact ceilings. For
example, an entry for an independently approved local account and pinned file
has this shape:

```json
{
  "version": 1,
  "registrations": [{
    "capability": {"name": "report-data-write", "operation": "replace-report-data", "access": 2},
    "profile": "reports", "revision": "review-1", "role": "report-editor", "scope": "final-report",
    "principal_uid": 1234, "path": "/approved/reports/final.txt",
    "device": "2049", "inode": "123456", "maximum_access": 2, "expires_at": 1893456000
  }]
}
```

Use the actual account UID, file path, device and inode, and the approved
expiry. Keep the actual role document and its grant limited to that revision
and scope. Load the registry explicitly for preview and apply:

```sh
workeros managed apply-profile --registered-file-acl --preview < approved-profile.json
workeros managed apply-profile --registered-file-acl < approved-profile.json
```

Confirm the file, account and mask in the preview before applying. With the
flag set, unavailable, untrusted or nonmatching registry entries refuse
before a new declaration or grant. The registry must explicitly cover
every selected grant, including the built-in read capability if selected.
Existing built-in grants without the flag remain available.

An adapter declares the capability name, operation name and access mask. An
administrator supplies a ceiling for that capability with an exact profile,
revision, role, scope, numeric UID, absolute path, device, inode and expiry.
For example, an approved host integration can pass a registration to the
same installed parser:

```python
from workeros.delegated_acl import FileAclCapability, FileAclRegistration
from workeros.managed_cli import main

capability = FileAclCapability("report-data-write", "replace-report-data", 2)
registration = FileAclRegistration(
    capability=capability, profile="reports", revision="review-1",
    role="report-editor", scope="final-report",
    principal_uid=approved_uid, path=approved_path,
    device=approved_device, inode=approved_inode,
    maximum_access=2, expires_at=approved_expiry,
)
exit_code = main(["apply-profile", "--preview"], acl_registrations=(registration,))
```

Take every `approved_*` value from the host's administrator-controlled policy.
The document on standard input selects `report-data-write` in both capability
fields and lists `replace-report-data` as an operation on the single approved
scope. Its pinned values and expiry must fit the registration. Remove
`--preview` only after approval. The profile on standard input can select an
approved capability and cannot create its registration. An in-process
registry and the fixed file flag cannot be combined.
For several grants in one profile, use a top-level `grants` array in place
of `grant`. Each item has the same shape as `grant` and requires an exact
administrator registration. For example, a report reader and an inventory
editor may have separate operations and separate pinned files under one
revision. A role can have multiple registered scopes. Each scope must map to
a distinct file and each grant is checked against its own UID, device,
inode, operation, mask and expiry. An unenforceable entry is refused. An
independent observer or meter can be registered separately under the same
profile. Its provider binding must be verified before use.

Preview checks every proposed file before apply. Apply records the complete
grant plan, then verifies each ACL in order. If a write or its readback is
uncertain, apply stops changing files and reports the observed per-file
state. There is no cross-file atomic transaction. The stored plan allows
profile status and revocation even after the registrations are removed.
Automatic expiry (`"expiry":"automatic"` in a grant) requires a different
host backend. Omit the field or use `"expiry":"manual"` for this backend.

These ACLs govern an existing UID's access. A trusted host can separately
pin the executable in `HostBindings` and launch it under that existing
identity. The ACL also applies to other processes running as the same UID.
Use `"enforcement":"process"` to require executable-bound isolation and get
a pre-apply refusal from this backend. To enforce that boundary, the host
must supply an authorized supervisor or a process-scoped capability backend.
The managed setup commands do not change worker credentials or start a job.

#### Apply an explicitly approved access plan

From a trusted administrator installation, first record a role that names an
existing non-root principal and allows `read` on the chosen scope. Bind that
scope in the role's `resources` map to the file's decimal `device` and `inode`.
For that active revision, prepare one `grant.json` with `version: 1`, `profile`,
`revision`, `role`, `scope`, the absolute `path` and `exclusive_admin: true`.
Run these commands from the administrator's shell:

```sh
"$ADMIN_WORKEROS" roles grant-preview < grant.json
"$ADMIN_WORKEROS" roles grant-apply < grant.json
```

Preview is optional and shows the named principal, exact file identity and
permission change. Apply verifies the ACL and the journal before reporting
`acl_entry_verified`. Save the plan to read back and revoke the same grant.
Use `"$ADMIN_WORKEROS" roles grant-check < grant.json` in a separate process
to read the retained binding and live ACL without applying anything. The
designated principal can confirm access with a fresh read-only open in their
own session. To revoke, use `"$ADMIN_WORKEROS" roles grant-revoke < grant.json`.
A fresh check should report `acl_entry_removed` and `acl_presence: absent`.
Grant and revoke do not start a worker.

The backend accepts only a root-owned `0600`
single-link file without an existing ACL, inside a root-owned `0711` directory
without access or default ACLs. It refuses unmapped or identical principals,
changed identities, unsupported ACLs, and unrelated existing ACL grants.

The administrator must ensure exclusive permission control. Linux ACL
replacement has no compare-and-swap; `flock` coordinates only cooperating
processes. Apply adds a single named-UID read entry under a read-only mask,
verifies the exact ACL and journals the result. Revoke removes only that exact
ACL and verifies the restored mode. Both operate on the held file descriptor.
An uncertain effect must be reconciled with `grant-check`, not retried. The
check separately reports the original UID and inode, exact ACL presence and the
current declaration/account state. Appointment remains `unverified`: a current
declaration and matching UID do not authenticate an independent appointment.
An expired, revoked, missing or reassigned principal
does not turn an existing ACL into an active appointment. A claim-only record
with the exact retained ACL can be removed only by an explicit `grant-revoke`;
an unexpected ACL is left unchanged. Cleanup uses the retained numeric UID,
not a fresh account-name lookup. A missing or damaged original binding remains
unknown; it is not evidence that no earlier change occurred. Grants created
before the retained-binding journal existed need separate administrator review.
A role's
expiry prevents new grants but does **not** automatically remove an existing
ACL; the administrator must revoke it. Host identity administration must also
prevent UID reuse while the ACL remains. ACL readback does not prove a target
process can open the file under all host controls, close already open
descriptors, or qualify an independent observer.

### Verify an owned-file read grant

`workeros owner-access` provides one narrow real backend: the current non-root
file owner can add its own read bit to one regular file, verify a fresh read-only
open, and later remove that bit. It accepts only a single-link `0200` file in an
owner-only `0700` directory with no access or default ACL, and refuses other
principals, root, unexpected ACLs, and changed identity or mode. It never starts
a worker. Role and scope names are labels, not OS appointments.

The caller must control permission changes for that file while the operation
runs and set `exclusive_owner` to true. The descriptor lock is advisory: a
noncooperating same-UID process can race `chmod`, because Linux offers no atomic
compare-and-chmod here. Do not use this backend where that exclusivity cannot be
established. Applying changes the held inode's owner-read bit and creates a
private `.workeros-grants` journal in its parent; preserve that journal for
readback and revocation. The inode and result journal are synced before a
verified receipt; a failed sync is unknown. An uncertain effect requires `check`, not an automatic
retry. Removing the read bit blocks verified future opens by this owner; it does
not close already open descriptors or prove independent observer custody.

The following local fixture can be run as an ordinary non-root user after
installation. It writes only under a new temporary directory:

```sh
( set -eu
demo_dir=$(mktemp -d)
printf W > "$demo_dir/input"
chmod 200 "$demo_dir/input"
python3 - "$demo_dir/input" <<'PY' > "$demo_dir/request.json"
import json, os, pwd, sys
print(json.dumps({'version': 1, 'path': sys.argv[1],
    'principal': pwd.getpwuid(os.geteuid()).pw_name,
    'role': 'example_reader', 'scope': 'example_file', 'exclusive_owner': True}))
PY
workeros owner-access apply < "$demo_dir/request.json" > "$demo_dir/receipt.json"
cat "$demo_dir/receipt.json"
python3 - "$demo_dir/receipt.json" <<'PY' > "$demo_dir/plan.json"
import json, sys
print(json.dumps(json.load(open(sys.argv[1]))['plan']))
PY
workeros owner-access revoke < "$demo_dir/plan.json"
)
```

`preview` may be used with the request before apply; it reports the pinned
device/inode and exact `0200` to `0600` change. `apply` can also perform that
preview and verification in one command, returning the exact plan and attempt
key. `check` and `revoke` consume that returned plan. This backend does not
grant access to a different UID or modify ACLs, and it does not establish that
an independently operated observer is qualified.

If the apply reply is lost, `check` may also take the original request while
the path still names the same file; it binds the current device/inode and looks
up that exact attempt without repeating the change. If the path moved or was
replaced, use the retained original plan; a missing journal or different inode
remains unknown, not proof that no earlier effect occurred.

This is an integration contract, not evidence that a service is configured on a
particular host. Before offering the command for a real deployment, the host
owner must identify the installed listener, authenticate its configured UID,
authorize the caller, bind the exact profile and appointed providers, and prove
independent durable readback. A successful synthetic test does not establish
those facts or a native workload verdict.
