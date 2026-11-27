# <img src="docs/brand/workeros-banner.png" alt="WorkerOS" width="440">

**Run a job. Know how it ended.**

Run a local command on Linux or WSL2. See whether it finished, timed out,
or still needs checking before you try again.

<details open>
<summary>Terminal comic</summary>

[![WorkerOS terminal comic: Everything is green. Read the transcript.](docs/media/one-small-ticket.gif)](docs/media/README.md#everything-is-green)

</details>

**[Install and run](#install-and-run)**

<a name="run-one-worker"></a>
<a name="run-a-job"></a>

## Install and run

Open a **Linux or Ubuntu WSL2 terminal** with Python 3.11+ and `venv`.
In a fresh project folder, paste these commands to try the published
**v0.7.0** release. No checkout or administrator access needed.

```sh
release='https://github.com/'\
'thisistuhinsen/workerOS/releases'\
'/download/v0.7.0'
wheel='workeros-0.7.0-py3-none-any.whl'
sha='1a418f20bffcfbed304855edb6663ce3'\
'5c75c818b3f0af1ff51b6dc445e92c3b'
python3 -m venv .venv-0.7.0 &&
.venv-0.7.0/bin/python -m pip \
  install --no-index --no-deps \
  "$release/$wheel#sha256=$sha" &&
.venv-0.7.0/bin/workeros-demo -- \
  /usr/bin/printf 'hello\n'
```

```text
hello
job: exited 0
```

If Python or `venv` is missing, install your distribution's Python 3.11+
and venv package. If you're in PowerShell or Command Prompt, open Ubuntu
in WSL2 first. If the install reports a checksum mismatch, stop; don't
drop the digest to force it. [Other install help](docs/support.md#windows-and-macos)

## What would you like to do next?

| | Start here |
| --- | --- |
| **Terminal** | [Run a job from a terminal](docs/start/terminal.md) |
| **Config** | [Run from JSON](docs/start/config.md#run-from-json) or [run from YAML](docs/start/config.md#run-from-yaml) (v0.8.0 candidate) |
| **Code** | [Run from Python or give a worker a file](docs/start/code.md) |

<a name="packages"></a>
<a name="language-packages"></a>
<a name="write-a-worker"></a>

**Install for your language:** [pip, uv, npm, Conan, Go, Cargo and Maven](docs/start/install.md). Both Python install routes create the same `.venv-0.7.0`; pick one in a fresh folder.

<a name="try-a-timeout"></a>
<a name="configure-a-workflow-once"></a>
<a name="run-an-inherited-fd-example"></a>
<a name="give-a-worker-the-file-you-opened"></a>

## Guides and reference

The [first-use guides above](#what-would-you-like-to-do-next) use v0.7.0.
For production integrations: [Python API](docs/api.md) · [configuration
reference](docs/configuration.md) · [worker API](docs/workers.md) ·
[authorized host setup](docs/host-preflight.md) ·
[agent skill](skills/workeros/SKILL.md).

For upgrades or offline installs, see [installation reference](docs/install.md).
The [v0.8.0 candidate guide](docs/install-0.8.0.md) is separate; it is not the
published install.

## Verify and contribute

[Latest published release](https://github.com/thisistuhinsen/workerOS/releases/latest) ·
[Platform support and troubleshooting](docs/support.md) ·
[Contributing](CONTRIBUTING.md) · [Report a security issue](SECURITY.md) ·
[MIT license](LICENSE)

[![Linux compatibility on main pushes](https://github.com/thisistuhinsen/workerOS/actions/workflows/linux.yml/badge.svg?branch=main&event=push)](https://github.com/thisistuhinsen/workerOS/actions/workflows/linux.yml?query=branch%3Amain+event%3Apush)
[![Hosted WSL2 on main pushes](https://github.com/thisistuhinsen/workerOS/actions/workflows/wsl2.yml/badge.svg?branch=main&event=push)](https://github.com/thisistuhinsen/workerOS/actions/workflows/wsl2.yml?query=branch%3Amain+event%3Apush)
