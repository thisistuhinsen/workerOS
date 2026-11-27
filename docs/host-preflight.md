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

The separately controlled provider must implement the bounded Unix-stream
attestation exchange above with `version: 2` and `capability: "interval"` in
both request and verified reply. It must independently verify its current
appointment and exact evidence before replying. The bundled point/meter
provider does not implement this exchange. The host authenticates the pinned
peer before sending the challenge and refuses a mismatched or expired reply.
Success verifies the current binding only. Readiness remains `not_checked`,
independence remains `unverified`, and runtime evidence is `not_requested`.
Registration is unavailable in listen, describe and recovery modes.

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
verify the host and its pins before using the bindings. The stock bootstrap's
interval registration is a local check only. An existing trusted host with
an already authorized typed interval provider can use this client command.

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
