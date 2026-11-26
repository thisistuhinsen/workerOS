# Install workerOS

Use **Linux or Ubuntu in WSL2**, Python 3.11+ with venv support, and usable
Linux pidfds for the demo. Native Windows Python can install the wheel;
loading the controller there fails on `fcntl`. On macOS use a supported
Linux VM. [Windows and macOS help](support.md#windows-and-macos)

These instructions use the published [v0.7.0 GitHub release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.7.0).
They use individual release assets. If you already received a directory named
`workerOS-0.7.0-offline`, go straight to [Offline install](#offline-install).
For the published historical v0.4.0 package, use its
[tagged instructions](https://github.com/thisistuhinsen/workerOS/blob/v0.4.0/README.md#install).

## Python

The checksum commands below use GNU coreutils (`sha256sum --strict`).

The distribution is `workeros`, the Python import is `worker_handoff`, and
`workeros-demo` runs two local jobs. Install the controller here if another
language's reader guide needs a launcher.

For the shortest path from install to a running command, use the
[README quickstart](../README.md#install-and-run). To verify downloads
separately or prepare an offline install, download these two files:

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0
wheel=workeros-0.7.0-py3-none-any.whl
mkdir workeros-download-0.7.0 &&
curl -fsSL "$release/SHA256SUMS" -o workeros-download-0.7.0/SHA256SUMS &&
curl -fsSL "$release/$wheel" -o "workeros-download-0.7.0/$wheel"
```

Choose one installer from the same working directory. Each checks the wheel
against its named entry before creating a fresh environment.

**Public wheel with pip**

```sh
test ! -e .venv-0.7.0 &&
(cd workeros-download-0.7.0 &&
  awk '$2 == "workeros-0.7.0-py3-none-any.whl" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
  sha256sum --strict -c wheel.sha256) &&
python3 -m venv .venv-0.7.0 &&
.venv-0.7.0/bin/python -m pip install --no-index --no-deps ./workeros-download-0.7.0/workeros-0.7.0-py3-none-any.whl
```

**Public wheel with uv**

```sh
test ! -e .venv-0.7.0-uv &&
(cd workeros-download-0.7.0 &&
  awk '$2 == "workeros-0.7.0-py3-none-any.whl" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
  sha256sum --strict -c wheel.sha256) &&
uv venv --offline --python "$(command -v python3)" .venv-0.7.0-uv &&
uv pip install --offline --no-index --no-deps --python .venv-0.7.0-uv/bin/python ./workeros-download-0.7.0/workeros-0.7.0-py3-none-any.whl
```

After installation you can run `.venv-0.7.0/bin/workeros-demo` for pip or
`.venv-0.7.0-uv/bin/workeros-demo` for uv, without a checkout. For a uv
application that needs to lock the public URL, run the download block from
its project root, then use this verified wheel digest:

```sh
(
  set -eu
  release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0
  wheel=workeros-0.7.0-py3-none-any.whl
  (cd workeros-download-0.7.0 &&
  awk '$2 == "workeros-0.7.0-py3-none-any.whl" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
  sha256sum --strict -c wheel.sha256)
  digest=$(sha256sum "workeros-download-0.7.0/$wheel" | cut -d' ' -f1)
  uv add --no-index "workeros @ $release/$wheel#sha256=$digest"
  uv sync --no-index --locked
  uv run --no-sync workeros-demo
)
```

### Offline install

Open a Linux shell in the separately supplied `workerOS-0.7.0-offline`
directory, beside `assets/`. Verify its provenance or independently supplied
bundle digest. Choose one of the following install commands.

**pip**

```sh
test ! -e .venv-0.7.0 &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.7\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
python3 -m venv .venv-0.7.0 &&
.venv-0.7.0/bin/python -m pip install --no-index --no-deps ./assets/workeros-0.7.0-py3-none-any.whl
```

**uv**

```sh
test ! -e .venv-0.7.0-uv &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.7\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
uv venv --offline --python "$(command -v python3)" .venv-0.7.0-uv &&
uv pip install --offline --no-index --no-deps --python .venv-0.7.0-uv/bin/python ./assets/workeros-0.7.0-py3-none-any.whl
```

For a language walkthrough that asks for `WORKEROS_OFFLINE`, set
`export WORKEROS_OFFLINE="$PWD"` here before changing directories.

**Try a job (optional).** In the bundle directory, run
`.venv-0.7.0/bin/workeros-demo` for pip or `.venv-0.7.0-uv/bin/workeros-demo`
for uv. The first child reports the free space on your disk and exits. The second
outlasts its wait; the supervisor stops and collects that direct child. Look
for `report: exited 0`, `slow job: timed out`, then `cleanup: reaped`.
A successful demo exits zero. To run a command of your own, use
`.venv-0.7.0/bin/workeros-demo -- /usr/bin/printf 'hello\n'` (or use the binary
under `.venv-0.7.0-uv`). The arguments after `--` go to that executable.

**Upgrade and roll back.** Both distribution names install the
`worker_handoff` import. A helper that still requires `worker-handoff` can
bring the old distribution into the new environment. After installing your
application's dependencies, check which distribution owns the running import.
For the pip environment, run:

```sh
.venv-0.7.0/bin/python -m pip check &&
.venv-0.7.0/bin/python -I - <<'PY'
from importlib.metadata import distribution, packages_distributions
from pathlib import Path
import sys

owners = packages_distributions().get("worker_handoff", [])
package = distribution("workeros")
print("owners:", owners, "version:", package.version)
assert owners == ["workeros"] and package.version == "0.7.0"
import worker_handoff

actual = Path(worker_handoff.__file__).resolve()
print("import:", actual)
assert actual == Path(package.locate_file("worker_handoff/__init__.py")).resolve()
assert actual.is_relative_to(Path(sys.prefix).resolve())
PY
```

For uv, use `uv pip check --python .venv-0.7.0-uv/bin/python` for the
dependency check and `.venv-0.7.0-uv/bin/python -I` for the Python check.
If an editable install or transitive helper brings in the old distribution,
update the project's pins or upgrade to a compatible helper, then resolve in
another clean environment. Switch
the application interpreter after the check and demo pass. To roll back, use
the old environment's interpreter. If the helper cannot migrate yet, keep
running the application in that intact environment.

**Add the local wheel to a uv project.** From the offline bundle directory, this creates a disposable
project, records the relative wheel dependency and checks the lock. Keep the
wheel at that relative location when reusing this project's lockfile.

```sh
test ! -e trial-project &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.7\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
uv init --offline --bare --no-workspace --python "$(command -v python3)" trial-project &&
(cd trial-project && uv add --offline --no-index ../assets/workeros-0.7.0-py3-none-any.whl &&
 uv sync --offline --no-index --locked && uv run --offline --no-sync workeros-demo)
```

**Build from the source distribution.** The supplied wheel is ready to
install. If you need to build it yourself offline, use a Linux build
interpreter with pip, setuptools 61+ and wheel already available:

```sh
test ! -e wheelhouse-0.7.0 &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.7\.0\.tar\.gz$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
mkdir wheelhouse-0.7.0 &&
python3 -m pip wheel --no-index --no-deps --no-build-isolation -w wheelhouse-0.7.0 ./assets/workeros-0.7.0.tar.gz
```

Install the resulting wheel in a fresh application environment. Record its
own SHA-256 if you distribute that build.

[Python first run](package-python.md) · [Python worker API and examples](workers.md#python-apis) ·
[Give a worker an open file](../README.md#run-an-inherited-fd-example)

The same wheel installs `workeros-config` and its compatibility alias
`worker-handoff-config`. To inspect the invocation schema, run
`.venv-0.7.0/bin/workeros-config --schema`. For a complete local run, use
the [JSON workflow quickstart](configuration.md#run-a-fileless-worker).

## Verify downloads

A public v0.7.0 release supplies six individually downloadable files and a
[SHA256SUMS manifest](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/SHA256SUMS).
Use that manifest from the same release.

| Consumer | Files available upon publication |
| --- | --- |
| Python | [Wheel](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-0.7.0-py3-none-any.whl) and [source distribution](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-0.7.0.tar.gz) |
| Node.js | [npm tarball](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-0.7.0.tgz) |
| Java | [JAR](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-0.7.0.jar) and [matching POM](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-0.7.0.pom) |
| C and C++ | [Conan recipe](https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-conan-0.7.0.tar.gz) |

With all six files and the manifest in one directory, run `sha256sum --strict -c SHA256SUMS`
there. Go and Cargo consume the [versioned source tag](https://github.com/thisistuhinsen/workerOS/tree/v0.7.0).
The separately prepared offline handoff has an `assets/` directory and a
local source layout. Those paths only apply when you receive that handoff.

## Node.js

Use Node.js 22+ on Linux x64 or ARM64 with procfs. Install the release npm
tarball, then run the packaged reader from a launcher that grants it the open
file. [Node.js install and first read](../node/README.md)

## C and C++

Use the versioned header-only Conan 2 recipe on Linux. The C and C++ clients
each receive a file from the launcher. [Conan install and first read](../native/README.md)
· [C client](../native/tests/c/) · [C++ client](../native/tests/cpp/)

## Go

Use Go 1.22+ on Linux amd64 or arm64. The Go guide explains how to resolve
the module for this version and launch a compiled reader with an inherited
input. [Go install and first read](../go/README.md)

## Rust

Use Rust 1.85+ on Linux x86-64 or AArch64. Build the reader with Cargo, then
start its binary with a launcher that supplies the named input.
[Rust install and first read](../rust/README.md)

## Java

Use JDK 22+ on 64-bit Linux with procfs. The Java guide installs the release
JAR and matching POM into Maven's local cache and shows the native-access flag
for the FFM reader. [Maven install and first read](../java/README.md)
