# WorkerOS for Python

Run a local tool and see whether it exited or timed out. The timeout demo
also checks whether its process stopped and was collected.

Use Python 3.11+ on **Linux or Ubuntu in WSL2** with usable Linux pidfds,
curl and GNU coreutils (`sha256sum`).
Native Windows Python can install the wheel, but its runtime lacks `fcntl`.
[Windows and macOS help](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/support.md#windows-and-macos)

Using the [v0.8.0 GitHub release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.8.0),
start in a fresh directory. This installs the versioned wheel
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
  .venv-0.8.0/bin/workeros demo
)
```

Look for `report: exited 0`, `slow job: timed out` and `cleanup: reaped`.
Use the [install guide](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md)
for uv and source installs, migration, or a separately supplied offline handoff.
Keep using `import worker_handoff` in your code. Keep your previous environment
until the new one passes its checks.

JSON role profiles work without an additional package. To use YAML profiles,
install PyYAML in the same environment (this command needs network access):

```sh
.venv-0.8.0/bin/python -m pip install 'PyYAML==6.0.3'
```

For offline use, provide a verified compatible PyYAML wheel in `./wheelhouse`
and add `--no-index --find-links ./wheelhouse` to that command. See
`.venv-0.8.0/bin/workeros help formats` for the supported input rules.

Use `.venv-0.8.0/bin/workeros config --schema` for the invocation schema.
The [JSON configuration guide](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/configuration.md)
includes the first runnable policy, evidence storage examples and operation
reference. For the historical v0.4.0 package, follow its
[tagged instructions](https://github.com/thisistuhinsen/workerOS/blob/v0.4.0/README.md#install).
