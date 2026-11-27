---
name: workeros
description: Install the workerOS Linux controller or an inherited-file reader. Run a local tool, check a timeout and cleanup, or pass a file to a worker in one of seven languages.
license: MIT
compatibility: Linux or a suitable Ubuntu WSL2 guest. The controller requires Python 3.11+ and usable Linux pidfds for direct-child supervision.
---

# Use workerOS

Choose the task first. A Python controller can launch an ordinary executable;
a program that needs no file can run without a reader package. Use a language
reader when a launcher will actually grant the worker an open regular file.

## Select the 0.7.0 distribution

Use Linux or an existing Ubuntu WSL2 guest, Python 3.11+ and usable pidfds.
Native Windows Python can install the wheel, then fail to import `fcntl`.
Create the application environment in Ubuntu WSL2 on that host. Native macOS
users need a supported Linux VM.

Choose the source the operator is using. A public v0.7.0 installation requires
the published [release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.7.0)
and the [versioned source tag](https://github.com/thisistuhinsen/workerOS/tree/v0.7.0).
The release has six individual assets plus `SHA256SUMS`. Go and Cargo consume
the tag. A separately supplied `workerOS-0.7.0-offline` directory has its own
layout and source; do not infer a public bundle URL from that directory name.

### Public wheel

Run this in a fresh working directory. An unavailable asset, checksum mismatch
or missing manifest entry must stop the install. Report that outcome and use
an existing approved offline bundle only if the operator supplied it.
The commands use curl and GNU coreutils (`sha256sum --strict`).

```sh
(
  set -eu
  release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0
  wheel=workeros-0.7.0-py3-none-any.whl
  test ! -e .venv-0.7.0
  download=$(mktemp -d)
  trap 'rm -rf -- "$download"' EXIT
  curl -fsSL "$release/SHA256SUMS" -o "$download/SHA256SUMS"
  curl -fsSL "$release/$wheel" -o "$download/$wheel"
  (cd "$download" &&
    awk -v f="$wheel" '$2 == f { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
    sha256sum --strict -c wheel.sha256)
  python3 -m venv .venv-0.7.0
  .venv-0.7.0/bin/python -m pip install --no-index --no-deps "$download/$wheel"
  .venv-0.7.0/bin/workeros-demo
)
```

### Offline handoff

Start in the separately supplied `workerOS-0.7.0-offline` directory, beside
`assets/`.

Use the exact bundle provided by the operator; verify its provenance or
independently supplied digest. The following block verifies the listed files,
installs a wheel into a fresh environment and runs a disposable first job.
It needs Python 3.11+, venv, usable Linux pidfds and GNU sha256sum.
If `.venv-0.7.0` already exists, use a fresh directory for this install.

```sh
test ! -e .venv-0.7.0 &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.7\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
python3 -m venv .venv-0.7.0 &&
.venv-0.7.0/bin/python -m pip install --no-index --no-deps ./assets/workeros-0.7.0-py3-none-any.whl &&
.venv-0.7.0/bin/python -I -c 'from importlib.metadata import version; import worker_handoff; assert version("workeros") == "0.7.0"; print(worker_handoff.__file__)' &&
.venv-0.7.0/bin/workeros-demo
```

Look for the installed path inside the new environment, a disk report,
`report: exited 0`, `slow job: timed out` and `cleanup: reaped`. Record the
actual exit status and output. A timeout bounds the wait; the cleanup result
describes what happened to the owned direct child. To try a trusted fileless
command, run `.venv-0.7.0/bin/workeros-demo -- /usr/bin/printf 'hello\n'`.

Before switching an existing application, add its dependencies in this
environment. Use `.venv-0.7.0/bin/python -m pip check` to check the resolver
result, then verify the one distribution that owns the live import:

```sh
.venv-0.7.0/bin/python -I - <<'PY'
from importlib.metadata import distribution, packages_distributions
from pathlib import Path
import sys

pkg = distribution("workeros")
owners = packages_distributions().get("worker_handoff", [])
print(owners, pkg.version)
assert owners == ["workeros"] and pkg.version == "0.7.0"
import worker_handoff

actual = Path(worker_handoff.__file__).resolve()
print(actual)
assert actual == Path(pkg.locate_file("worker_handoff/__init__.py")).resolve()
assert actual.is_relative_to(Path(sys.prefix).resolve())
PY
```

If a helper pulls in `worker-handoff`, update its requirement or select a
compatible version and resolve in another fresh environment. Keep the old
interpreter and lockfile for rollback; if no compatible helper exists,
continue using the intact previous environment.

## Choose an interface

| Task | API or entry point |
| --- | --- |
| Run a trusted local tool or synchronous Python callable | `WorkerRoster` launches and joins. Pass explicit argv for executables and an importable synchronous function for a Python handler. |
| Wait for or clean up an owned child | `DirectChildSupervisor` reports lifecycle and cleanup separately. If startup raises `SupervisionStartError`, reconcile the returned `process`. Registration of an external PID leaves control with its owner. |
| Give a new worker an open input | Bind the live FD when launching. Choose Python, Node.js/npm, Go, Rust/Cargo, C or C++/Conan, or Java/Maven. The reader's documentation describes borrowing, closing or duplicating that FD. |
| Give a running peer a read-only original | Python `send_original` and `receive_original` need the connected Unix stream, correct peer identity, token and deadline. |
| Authorize an exact handoff | `release_executable` uses a trusted policy callback and release plan. Strict custody also needs a qualified, independently operated observer and matching pre-grant evidence. |
| Interpret scoped reports or sample a designated slot | Use the matching 0.7.0 `worker_handoff.evidence` and `worker_handoff.lifecycle` docs and source. Keep missing or indeterminate reports explicit. |
| Use a policy from any language | Run `.venv-0.7.0/bin/workeros-config --schema` for the invocation contract. Follow the bundle's `docs/configuration.md` for `--check-policy` and `--run-policy`. `worker-handoff-config` is the same installed command under its compatibility name. Bind the executable and other resources on the operator side. |
| Retain and read back a result | Choose an enrolled projection and a recorder policy with typed routes, destinations, retention and access. Keep the host-assigned attempt ID when returned on stderr. Recover or verify a receipt for that exact attempt before repeating an operation with unknown effects. |
| Collect real scope measurements | `worker_handoff.scope_meter` samples an already accessible cgroup v2 directory. Keep raw field availability, units, scope and clock context. Verify provider authority and whole-scope coverage separately. |

Use the published v0.7.0 [install guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/install.md),
[capability matrix](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/support.md) and
[JSON policy guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/configuration.md).
With a matching source tree, open `docs/install.md` for installation,
`docs/support.md` for the capability and platform matrix, and `docs/workers.md`
for the API examples. Read `docs/api.md` for method signatures,
`docs/configuration.md` for JSON policy, and `docs/host-preflight.md` when a
task needs an already authorized host profile. The wheel's preflight example is
`share/worker-handoff/examples/run_host_preflight.py` under the environment prefix. Language walkthroughs live in `node/`, `go/`, `rust/`,
`native/` and `java/`; Python also has the installed demo above. Use the
matching tree's docs for the installed version. The [canonical repository](https://github.com/thisistuhinsen/workerOS)
and [published releases](https://github.com/thisistuhinsen/workerOS/releases)
let you verify what's public. For v0.4.0 specifically, follow the
[tagged release guide](https://github.com/thisistuhinsen/workerOS/blob/v0.4.0/README.md).
That older wheel uses distribution name `worker-handoff` and lacks the new demo
and scoped reporting modules. Keep it in its own environment.

## Report only what ran

- For a reader test, supply the inherited FD from an authorized launcher.
  To exercise the wheel's bundled ABI example, run
  `.venv-0.7.0/bin/python -I .venv-0.7.0/share/worker-handoff/examples/run_inherited_fd.py --language python`.
  Report an actual selected toolchain run or its unavailability. The language
  package guide supplies the test for that package's own reader.
- Separate execution and cleanup, delivery and write effect. Reconcile an
  uncertain handoff or write before considering another attempt. A direct-child
  reap describes that child; whole-scope cleanup needs additional evidence.
- Report the distribution version, wheel digest, Linux environment, selected
  language and observed result. Keep unavailable host inputs, unselected
  languages and unverified custody explicit. The deployment supplies authority;
  a role name or an environment field cannot grant it.
