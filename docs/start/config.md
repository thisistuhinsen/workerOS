# Run a job from JSON

Use a **policy** to describe the jobs your app may start. Send a separate
**request** each time you want one of those jobs to run.
[Run from JSON](#run-from-json) with the published release, or
[run the same job from YAML](#run-from-yaml) with the v0.8.0 candidate.
To set up a role instead, [preview a role profile](#preview-with-yaml).

## Run from JSON

Start in the Linux or Ubuntu WSL2 folder where you
[installed the published v0.7.0 release](../../README.md#install-and-run).
This example runs the same hello without passing it a file. Paste the whole block:

```sh
(
  set -eu
  sample=$(mktemp -d)
  trap 'rm -rf -- "$sample"' EXIT
  cat > "$sample/hello" <<'SH'
#!/bin/sh
printf 'hello\n'
SH
  chmod u+x "$sample/hello"
  cat > "$sample/policy.json" <<'JSON'
{
  "version": 1,
  "roles": {"job-role": {"operations": ["launch"]}},
  "workflows": {
    "hello": {
      "role": "job-role",
      "operations": ["launch"],
      "bindings": {"executable": "sample"}
    }
  }
}
JSON
  .venv-0.7.0/bin/workeros-config \
    --run-policy "$sample/policy.json" \
    --executable sample "$sample/hello" <<'JSON'
{
  "version": 1,
  "workflow": "hello",
  "role": "job-role",
  "operation": "launch",
  "options": {"name": "hello-01"}
}
JSON
)
```

This command returns JSON, not the child's text. Look for these fields in
`result.terminal`:

```json
{
  "lifecycle": "exited",
  "returncode": "0",
  "cleanup": {"status": "reaped"}
}
```

If the shell cannot find the command, go back to your hello folder. If
WorkerOS rejects the policy, use the reason it returns or
[check the policy before retrying](../configuration.md#check-and-run-an-installed-policy).
With the separately verified [v0.8.0 candidate](../install-0.8.0.md#offline-install),
use the complete [v0.8.0 JSON example](#run-from-json-v080).

<a name="run-from-json-v080"></a>

### Run from JSON with v0.8.0

From the folder with your [verified v0.8.0 installation](../install-0.8.0.md#offline-install),
paste this block. It works with either pip or uv.

```sh
(
  set -eu
  sample=$(mktemp -d)
  trap 'rm -rf -- "$sample"' EXIT
  cat > "$sample/hello" <<'SH'
#!/bin/sh
printf 'hello\n'
SH
  chmod u+x "$sample/hello"
  cat > "$sample/policy.json" <<'JSON'
{
  "version": 1,
  "roles": {"job-role": {"operations": ["launch"]}},
  "workflows": {
    "hello": {
      "role": "job-role",
      "operations": ["launch"],
      "bindings": {"executable": "sample"}
    }
  }
}
JSON
  .venv-0.8.0/bin/workeros config --run-policy "$sample/policy.json" \
    --executable sample "$sample/hello" <<'JSON'
{"version":1,"workflow":"hello","role":"job-role","operation":"launch","options":{"name":"hello-01"}}
JSON
)
```

Look for `result.terminal.lifecycle: "exited"`, return code `"0"`, and
cleanup `"reaped"`.

## Run from YAML

**v0.8.0 candidate.** Start in the folder with the
[verified v0.8.0 installation](../install-0.8.0.md#offline-install).
Here the policy is YAML, but you send the same kind of JSON request and
read the same JSON result. If you prefer JSON, use the example above.

Install the optional YAML parser into this same environment. Choose the
command for the installer you used. Both use your configured Python
package index.

**pip**

```sh
.venv-0.8.0/bin/python -m pip install 'PyYAML==6.0.3'
```

**uv**

```sh
uv pip install --python .venv-0.8.0/bin/python 'PyYAML==6.0.3'
```

Now paste this block. It first checks the policy without starting a job,
then runs hello. It saves nothing in your project.

```sh
(
  set -eu
  sample=$(mktemp -d)
  trap 'rm -rf -- "$sample"' EXIT
  cat > "$sample/hello" <<'SH'
#!/bin/sh
printf 'hello\n'
SH
  chmod u+x "$sample/hello"
  cat > "$sample/policy.yaml" <<'YAML'
version: 1
roles:
  job-role:
    operations: [launch]
workflows:
  hello:
    role: job-role
    operations: [launch]
    bindings:
      executable: sample
YAML
  wos=.venv-0.8.0/bin/workeros
  "$wos" config --check-policy "$sample/policy.yaml" \
    --format yaml --executable sample "$sample/hello"
  "$wos" config --run-policy "$sample/policy.yaml" \
    --format yaml --executable sample "$sample/hello" <<'JSON'
{
  "version": 1,
  "workflow": "hello",
  "role": "job-role",
  "operation": "launch",
  "options": {"name": "hello-01"}
}
JSON
)
```

Look for `"status": "checked"` first. The second JSON object has the same
`result.terminal` as the JSON example: `exited`, return code `"0"`,
cleanup `reaped`. If a check reports `yaml_dependency_missing`, install
PyYAML in the environment shown above or use JSON. Any pinned policy
checksum covers the exact bytes on disk, not a converted copy.

## Preview with YAML

**v0.8.0 candidate.** A role profile is separate from the job policy
above. This role can be written in YAML or JSON. An administrator can preview either
format without recording a profile, granting access or starting anything.

From your administrator shell, set `ADMIN_WORKEROS` to the full path of
your independently installed, trusted WorkerOS executable. Don't run a
copy from a user's project directory as administrator. This example uses
Linux's `nobody` account and a sample scope named `demo-report`; it reads
no actual report. YAML requires PyYAML in the trusted Python environment.

```sh
"$ADMIN_WORKEROS" roles preview --format yaml <<'YAML'
version: 1
profile: demo-report
revision: preview-1
roles:
  - name: report-reader
    principal: nobody
    operations: [read]
    scopes: [demo-report]
    expires_at: 4102444800
YAML
```

The equivalent JSON needs no YAML parser:

```sh
"$ADMIN_WORKEROS" roles preview <<'JSON'
{
  "version": 1,
  "profile": "demo-report",
  "revision": "preview-1",
  "roles": [{
    "name": "report-reader",
    "principal": "nobody",
    "operations": ["read"],
    "scopes": ["demo-report"],
    "expires_at": 4102444800
  }]
}
JSON
```

Look for `"status": "preview"`, `"effect": "not_attempted"` and
`"enforcement": "not_commissioned"`. If you see `administrator_required`,
ask your administrator to preview the file from their trusted installation.
If you see `yaml_dependency_missing`, use JSON or ask your administrator
to add PyYAML. Use `workeros help roles` for the available role commands.

[Use WorkerOS in code](code.md) · [Back to first run](../../README.md#install-and-run)
