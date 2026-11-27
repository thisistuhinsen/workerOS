# WorkerOS for Python

Run a local tool and see whether it exited or timed out. The timeout demo
also checks whether its process stopped and was collected.

Use Python 3.11+ on **Linux or Ubuntu in WSL2** with usable Linux pidfds,
curl and GNU coreutils (`sha256sum`).
Native Windows Python can install the wheel, but its runtime lacks `fcntl`.
[Windows and macOS help](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/support.md#windows-and-macos)

For the published v0.7.0 release, start with the
[stable quickstart](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/README.md#install-and-run).
These instructions apply after v0.8.0 is published. Start in a fresh directory. This installs the versioned wheel
after checking its digest and runs a job without a checkout.

```sh
(
  set -eu
  release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
  wheel=workeros-0.8.0-py3-none-any.whl
  test ! -e .venv-0.8.0
  download=$(mktemp -d)
  trap 'rm -rf -- "$download"' EXIT
  curl -fsSL "$release/SHA256SUMS" -o "$download/SHA256SUMS"
  curl -fsSL "$release/$wheel" -o "$download/$wheel"
  (cd "$download" &&
    awk -v f="$wheel" '$2 == f { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
    sha256sum --strict -c wheel.sha256)
  python3 -m venv .venv-0.8.0
  .venv-0.8.0/bin/python -m pip install --no-index --no-deps "$download/$wheel"
  .venv-0.8.0/bin/workeros run -- /usr/bin/printf 'hello\n'
)
```

Look for `hello` and `job: exited 0`.
Run `.venv-0.8.0/bin/workeros help` for the available commands.
See [uv, source and offline installs](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md),
[upgrade and rollback](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#upgrade-and-roll-back),
and [failed or uncertain jobs](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/support.md#troubleshooting).
Use `import workeros` in your code. [Start a job from Python](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/start/code.md#run-hello-from-python-v080)
or [hand a worker an open file](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/start/code.md#give-a-worker-an-open-file-v080).
Keep your previous environment until the new one passes its checks.

JSON policies and role profiles work without an additional package. For
YAML, install PyYAML in the same environment. Choose the command for your
installer. Both need access to your configured Python package index.

**pip**

```sh
.venv-0.8.0/bin/python -m pip install 'PyYAML==6.0.3'
```

**uv**

```sh
uv pip install --python .venv-0.8.0/bin/python 'PyYAML==6.0.3'
```

For offline use, provide a verified compatible PyYAML wheel in `./wheelhouse`
and add `--no-index --find-links ./wheelhouse` to that command. See
`.venv-0.8.0/bin/workeros help formats` for the supported input rules.

Use `.venv-0.8.0/bin/workeros config --schema` for the invocation schema.
The [JSON configuration guide](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/configuration.md)
links to runnable [JSON](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/start/config.md#run-from-json-v080)
and [YAML](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/start/config.md#run-from-yaml) examples. For the historical v0.4.0 package, follow its
[tagged instructions](https://github.com/thisistuhinsen/workerOS/blob/v0.4.0/README.md#install).
