# workerOS

![workerOS wordmark beside its split W mark](docs/brand/workeros-banner.png)

**Did the job stop, or did you just stop waiting?**

Use workerOS to run a build or generate a report on the machine your app
already runs on. See what finished, what timed out, and what still needs
checking before you try again.

[Install and run](#install-and-run) · [Language packages](#language-packages) ·
[Troubleshooting](docs/support.md#troubleshooting) · [Agent skill](skills/workeros/SKILL.md)

<a name="run-one-worker"></a>
<a name="run-a-job"></a>

## Install and run

Run a disk-space report and a second job that deliberately waits too long.
You'll see one finish and the other time out and stop. The free space
will depend on your machine.

```text
Disk report: 42 GiB free
report: exited 0
slow job: timed out
cleanup: reaped
```

Use a **Linux shell or Ubuntu in WSL2**, with Python 3.11+, venv, Linux
pidfds, curl and GNU coreutils (`sha256sum`). Native Windows Python can
install the wheel but cannot import its Linux runtime.
[Windows and macOS help](docs/support.md#windows-and-macos)

### Run a fileless worker

Once the [v0.7.0 GitHub release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.7.0)
is published, paste this in a fresh directory. It downloads the wheel and
its checksums, verifies the wheel, then runs the demo. No checkout required.
For a supplied offline handoff, use the [offline install](docs/install.md#offline-install).

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

[![The dashboard shows every worker in green. Audit never started, so the lead says to promote Audit.](docs/media/one-small-ticket.gif)](docs/media/README.md#everything-is-green)

From the same folder, swap in a command you trust. This one prints `hello`
and reports `job: exited 0`.

```sh
.venv-0.7.0/bin/workeros-demo -- /usr/bin/printf 'hello\n'
```

`timed out` means the wait ended without an exit observation. An `exited`
result reports the exit status the wait collected, including when observed
at the deadline or later. `reaped` confirms the process stopped and the app
collected its exit. A job can change a file before it stops.
If setup fails or shutdown or effects are uncertain, use the
[troubleshooting steps](docs/support.md#troubleshooting) before trying again.

<a name="packages"></a>
<a name="write-a-worker"></a>

## Language packages

Already have a command that does the work? Use it as it is, whichever
language it was written in. The [Python launcher install](docs/install.md#python)
starts and supervises commands. Pick a package below when your worker
needs to read a file the app hands it.

| Language | Install and try an example |
| --- | --- |
| <img src="docs/brand/language-python.png" alt="" width="20" height="20"> Python | [<img src="docs/brand/manager-pip.png" alt="" width="14" height="14"> `pip` or <img src="docs/brand/manager-uv.png" alt="" width="14" height="14"> `uv`](docs/install.md#python) |
| <img src="docs/brand/language-node.png" alt="" width="20" height="20"> Node.js | [<img src="docs/brand/manager-npm.png" alt="" width="14" height="14"> `npm`](docs/install.md#nodejs) |
| <img src="docs/brand/language-c.png" alt="" width="20" height="20"> C | [<img src="docs/brand/manager-conan.png" alt="" width="14" height="14"> `Conan 2`](docs/install.md#c-and-c) |
| <img src="docs/brand/language-cpp.png" alt="" width="20" height="20"> C++ | [<img src="docs/brand/manager-conan.png" alt="" width="14" height="14"> `Conan 2`](docs/install.md#c-and-c) |
| <img src="docs/brand/language-go.png" alt="" width="20" height="20"> Go | [<img src="docs/brand/manager-go.png" alt="" width="14" height="14"> `Go modules`](docs/install.md#go) |
| <img src="docs/brand/language-rust.png" alt="" width="20" height="20"> Rust | [<img src="docs/brand/manager-cargo.png" alt="" width="14" height="14"> `Cargo`](docs/install.md#rust) |
| <img src="docs/brand/language-java.png" alt="" width="20" height="20"> Java | [<img src="docs/brand/manager-maven.png" alt="" width="14" height="14"> `Maven`](docs/install.md#java) |

[Downloads and checksums](docs/install.md#verify-downloads)

## Configure a workflow once

If several tools need to start the same kind of job, give them one JSON
policy. It names the allowed roles, operations and bindings. The operator
supplies the executable and resources; each client sends a short JSON request
to the installed `workeros-config` command. A fileless job needs no recorder.
To keep evidence, choose which result fields to capture, where to store them,
who can read them, and when stored records may be removed.

[Run the first policy](docs/configuration.md#run-a-fileless-worker) ·
[Use the same JSON from seven languages](docs/configuration.md#run-the-same-configuration-from-seven-languages) ·
[Read the API reference](docs/api.md)

[Run the local host profile](docs/host-preflight.md#run-the-local-profile) to
hand an open file to a reader and verify its terminal record in one session
you own. The same guide describes connecting an existing host manager.

## Fit it into your app

Already calling a command with `subprocess.run`? Keep it if its result is
enough. Reach for workerOS when you need a separate cleanup result or want
to hand the worker an open file.

With a queue such as RQ, keep scheduling and retries in the queue. Use
workerOS inside the queued job for the local tools it calls. Leave time for
cleanup before the queue's timeout. Use a fresh supervisor for each finite
job, or distinct worker names when you reuse one. If a tool may have written
something, check before trying it again, even with automatic retries configured.

Use your service manager to keep the app running and workerOS for the local
jobs the app starts.

<a name="run-an-inherited-fd-example"></a>

## Give a worker the file you opened

You open a report and someone renames it. Your worker can still read the
same file you handed over. Anyone who can write to it can still change
what's inside.

From the directory where you installed workerOS, use that Python environment
to try it with a temporary file.

```sh
.venv-0.7.0/bin/python -I .venv-0.7.0/share/worker-handoff/examples/run_inherited_fd.py --language python
```

The example checks that the worker reads the right byte without moving the
app's place in the file. Try the [Node.js walkthrough](node/README.md#read-one-inherited-file)
or see [more ways to pass a file](docs/workers.md).

## For AI agents

Give your agent the [workerOS skill](skills/workeros/SKILL.md). It shows how
to choose an install, run a disposable job, and report what happened.

## Verify and contribute

[![Latest stable GitHub release](https://badgen.net/github/release/thisistuhinsen/workerOS/stable)](https://github.com/thisistuhinsen/workerOS/releases/latest)
[![Linux compatibility on main pushes](https://github.com/thisistuhinsen/workerOS/actions/workflows/linux.yml/badge.svg?branch=main&event=push)](https://github.com/thisistuhinsen/workerOS/actions/workflows/linux.yml?query=branch%3Amain+event%3Apush)
[![Hosted WSL2 on main pushes](https://github.com/thisistuhinsen/workerOS/actions/workflows/wsl2.yml/badge.svg?branch=main&event=push)](https://github.com/thisistuhinsen/workerOS/actions/workflows/wsl2.yml?query=branch%3Amain+event%3Apush)

- [See what works on your setup](docs/support.md), including what's tested
  on Linux and WSL2.
- If a protected file needs an independent check before a worker receives it,
  see [how that works](docs/workers.md#authorize-a-managed-release).
- [Release process](docs/releasing.md) · [Contributing](CONTRIBUTING.md) ·
  [Security reporting](SECURITY.md) · [MIT license](LICENSE)
