# Use an authorized host profile

## Run the local profile

Install the [Python wheel](install.md#python) on Linux or in Ubuntu in WSL2.
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
current user owns, start with the [configuration guide](configuration.md).

The host selects the profile and creates a fresh session. `HostBindings`
registers the approved executable, original, optional supervisor, independent
custody, observer, meter, and evidence by name. Which registries are required
depends on the approved workflow. The request selects an enrolled operation.
The host keeps ownership and verifies the identity, deadline and authority of
each supplied resource. The usual local `workeros-config` flags enroll only
current-user bindings. An authorized venue owner supplies the named profile
selection, fresh attempt identity, approved policy bytes and digest, exact
open handles, and authenticated provider connections through the existing host
manager. Their host adapter owns provider setup, collects required opening and
closure evidence for the retained session, and confirms retirement. Enroll a
separate phase observer when the policy calls for independent observations
alongside a controller and meter. Use the Python integration below for managed
providers.

## Resolve the selected profile before an effect

The host already has the selected workflow, exact approved policy bytes and
pre-authorized bindings when it calls this function. Keep name resolution,
provider shape, execution authority and storage results distinct. A policy
digest pins the JSON bytes. Authenticate the OS principal and verify resource
ownership and authority separately.

```python
from io import BytesIO

from worker_handoff.configuration import ConfigurationError
from worker_handoff.enrollment import compile_policy, decode_policy


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
