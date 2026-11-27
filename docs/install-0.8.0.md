# Install WorkerOS 0.8.0

Start with the [published v0.7.0 quickstart](../README.md#install-and-run) for a new public install.
Use these v0.8.0 instructions only with a verified offline bundle or after that release is published.

Use **Linux or Ubuntu in WSL2**, Python 3.11+ with venv support, and usable
Linux pidfds for the demo. Native Windows Python can install the wheel;
loading the controller there fails on `fcntl`. On macOS use a supported
Linux VM. [Windows and macOS help](support.md#windows-and-macos)

These instructions use the [v0.8.0 GitHub release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.8.0).
They use individual release assets. If you already received a directory named
`workerOS-0.8.0-offline`, go straight to [Offline install](#offline-install).
For the published historical v0.4.0 package, use its
[tagged instructions](https://github.com/thisistuhinsen/workerOS/blob/v0.4.0/README.md#install).

## Package manager quick reference

These commands use the v0.8.0 GitHub release and tag. GitHub hosts the
artifacts; the commands do not imply a package registry listing. Use Linux or
Ubuntu in WSL2. Python starts jobs; the other packages read an input supplied
to a worker. The linked walkthroughs create disposable consumers and run a
first read.

| Manager | Add to your project | First run |
| --- | --- | --- |
| pip | [Download, verify and install the wheel](#python) | [Python first run](package-python.md) |
| uv | [Verify the wheel and install or lock it](#python) | [Python first run](package-python.md) |
| npm | [Download and verify the tarball, then install locally](#nodejs) | [Node.js walkthrough](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/node/README.md) |
| Go modules | [Resolve the v0.8.0 module](#go) | [Go walkthrough](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/go/README.md) |
| Cargo | [Add the v0.8.0 Git dependency](#rust) | [Rust walkthrough](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/rust/README.md) |
| Conan 2 | [Verify and create the local recipe](#c-and-c) | [C and C++ walkthrough](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/native/README.md) |
| Maven | [Verify and install the JAR and POM](#java) | [Java walkthrough](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/java/README.md) |

## Python

The checksum commands below use GNU coreutils (`sha256sum --strict`).

The distribution is `workeros`, the Python import is `workeros`, and
`workeros demo` runs two local jobs. Install the controller here if another
language's reader guide needs a launcher.

For a copy-and-run v0.8.0 demo, start with the [Python first run](package-python.md).
If you already have the wheel in an offline bundle, use [Offline install](#offline-install).
To verify public downloads separately, download these two files:

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
wheel=workeros-0.8.0-py3-none-any.whl
mkdir workeros-download-0.8.0 &&
curl -fsSL "$release/SHA256SUMS" -o workeros-download-0.8.0/SHA256SUMS &&
curl -fsSL "$release/$wheel" -o "workeros-download-0.8.0/$wheel"
```

Choose one installer from the same working directory. Each checks the wheel
against its named entry before creating a fresh environment.

**Public wheel with pip**

```sh
test ! -e .venv-0.8.0 &&
(cd workeros-download-0.8.0 &&
  awk '$2 == "workeros-0.8.0-py3-none-any.whl" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
  sha256sum --strict -c wheel.sha256) &&
python3 -m venv .venv-0.8.0 &&
.venv-0.8.0/bin/python -m pip install --no-index --no-deps ./workeros-download-0.8.0/workeros-0.8.0-py3-none-any.whl
```

**Public wheel with uv**

```sh
test ! -e .venv-0.8.0 &&
(cd workeros-download-0.8.0 &&
  awk '$2 == "workeros-0.8.0-py3-none-any.whl" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
  sha256sum --strict -c wheel.sha256) &&
uv venv --offline --python "$(command -v python3)" .venv-0.8.0 &&
uv pip install --offline --no-index --no-deps --python .venv-0.8.0/bin/python ./workeros-download-0.8.0/workeros-0.8.0-py3-none-any.whl
```

Either installer creates the same environment. Run `.venv-0.8.0/bin/workeros demo` without a checkout. For a uv
application that needs to lock the public URL, run the download block from
its project root, then use this verified wheel digest:

```sh
(
  set -eu
  release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
  wheel=workeros-0.8.0-py3-none-any.whl
  (cd workeros-download-0.8.0 &&
  awk '$2 == "workeros-0.8.0-py3-none-any.whl" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > wheel.sha256 &&
  sha256sum --strict -c wheel.sha256)
  digest=$(sha256sum "workeros-download-0.8.0/$wheel" | cut -d' ' -f1)
  uv add --no-index "workeros @ $release/$wheel#sha256=$digest"
  uv sync --no-index --locked
  uv run --no-sync workeros demo
)
```

### Offline install

Open a Linux shell in the separately supplied `workerOS-0.8.0-offline`
directory, beside `assets/`. Verify its provenance or independently supplied
bundle digest. Choose one of the following install commands.

**pip**

```sh
test ! -e .venv-0.8.0 &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.8\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
python3 -m venv .venv-0.8.0 &&
.venv-0.8.0/bin/python -m pip install --no-index --no-deps ./assets/workeros-0.8.0-py3-none-any.whl
```

**uv**

```sh
test ! -e .venv-0.8.0 &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.8\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
uv venv --offline --python "$(command -v python3)" .venv-0.8.0 &&
uv pip install --offline --no-index --no-deps --python .venv-0.8.0/bin/python ./assets/workeros-0.8.0-py3-none-any.whl
```

For a language walkthrough that asks for `WORKEROS_OFFLINE`, set
`export WORKEROS_OFFLINE="$PWD"` here before changing directories.

**Try a job (optional).** In the bundle directory, run
`.venv-0.8.0/bin/workeros demo` for pip or `.venv-0.8.0/bin/workeros demo`
for uv. The first child reports the free space on your disk and exits. The second
outlasts its wait; the supervisor stops and collects that direct child. Look
for `report: exited 0`, `slow job: timed out`, then `cleanup: reaped`.
A successful demo exits zero. To run a command of your own, use
`.venv-0.8.0/bin/workeros run -- /usr/bin/printf 'hello\n'`. The arguments after `--` go to that executable.

To try the inherited-file example, run `.venv-0.8.0/bin/workeros help file`
or `.venv-0.8.0/bin/workeros help file`. The printed command uses the
interpreter and example from that installation.

<a name="upgrade-and-roll-back"></a>

**Upgrade and roll back.** Keep the working installation intact and create a new application environment.
After installing your
application's dependencies, use the checksum from the trusted release
manifest to compare the running import with the pinned wheel. From the
offline bundle directory, check the pip environment:

```sh
(
  set -eu
  wheel=workeros-0.8.0-py3-none-any.whl
  digest=$(awk -v wheel="$wheel" '$2 == wheel { print $1; n++ } END { if (n != 1) exit 1 }' assets/SHA256SUMS)
  .venv-0.8.0/bin/python -m pip check
  .venv-0.8.0/bin/python -I -m workeros.verify_install "assets/$wheel" --sha256 "$digest"
)
```

Look for `"status": "matched"` and version `0.8.0`. With the public download
steps above, use `workeros-download-0.8.0` in place of `assets` in both paths.
For uv, use `uv pip check --python .venv-0.8.0/bin/python` for the
dependency check and `.venv-0.8.0/bin/python` for verification.
A repeated path to the same install is allowed. Separate installs or another
distribution owning `workeros` refuse with `ambiguous_distribution`.
If verification refuses, resolve the conflicting install in a new environment.
Switch only after verification and a successful run. Roll back by reselecting
the previous environment.

**Add the local wheel to a uv project.** From the offline bundle directory, this creates a disposable
project, records the relative wheel dependency and checks the lock. Keep the
wheel at that relative location when reusing this project's lockfile.

```sh
test ! -e trial-project &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.8\.0-py3-none-any\.whl$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
uv init --offline --bare --no-workspace --python "$(command -v python3)" trial-project &&
(cd trial-project && uv add --offline --no-index ../assets/workeros-0.8.0-py3-none-any.whl &&
 uv sync --offline --no-index --locked && uv run --offline --no-sync workeros demo)
```

**Build from the source distribution.** The supplied wheel is ready to
install. If you need to build it yourself offline, use a Linux build
interpreter with pip, setuptools 61+ and wheel already available:

```sh
test ! -e wheelhouse-0.8.0 &&
(cd assets && grep -Eq '^[0-9a-f]{64}  workeros-0\.8\.0\.tar\.gz$' SHA256SUMS && sha256sum --strict -c SHA256SUMS) &&
mkdir wheelhouse-0.8.0 &&
python3 -m pip wheel --no-index --no-deps --no-build-isolation -w wheelhouse-0.8.0 ./assets/workeros-0.8.0.tar.gz
```

Install the resulting wheel in a fresh application environment. Record its
own SHA-256 if you distribute that build.

[Python first run](package-python.md) · [Python worker API and examples](workers.md#python-apis) ·
[Give a worker an open file](start/code.md#give-a-worker-a-file-you-already-opened)

Run `.venv-0.8.0/bin/workeros config --schema` for the installed JSON schema.
Run the same hello job with a [JSON policy](start/config.md#run-from-json-v080)
or a [YAML policy](start/config.md#run-from-yaml). YAML needs optional
PyYAML; requests and results stay JSON. Role profiles are separate: see
[Preview a role](start/config.md#preview-with-yaml).

## Verify downloads

The v0.8.0 release supplies six individually downloadable files and a
[SHA256SUMS manifest](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/SHA256SUMS).
Use that manifest from the same release.

| Consumer | Published files |
| --- | --- |
| Python | [Wheel](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/workeros-0.8.0-py3-none-any.whl) and [source distribution](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/workeros-0.8.0.tar.gz) |
| Node.js | [npm tarball](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/workeros-0.8.0.tgz) |
| Java | [JAR](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/workeros-0.8.0.jar) and [matching POM](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/workeros-0.8.0.pom) |
| C and C++ | [Conan recipe](https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0/workeros-conan-0.8.0.tar.gz) |

With all six files and the manifest in one directory, run `sha256sum --strict -c SHA256SUMS`
there. Go and Cargo consume the [versioned source tag](https://github.com/thisistuhinsen/workerOS/tree/v0.8.0).
The separately prepared offline handoff has an `assets/` directory and a
local source layout. Those paths only apply when you receive that handoff.

## Node.js

Use Node.js 22+ on Linux x64 or ARM64 with procfs. Install the release npm
tarball, then run the packaged reader from a launcher that grants it the open
file. [Node.js install and first read](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/node/README.md)

From your npm project, download and verify the tarball before adding the
local dependency. This works with npm 12's default remote URL policy. Keep
`vendor/workeros-0.8.0.tgz` with your lockfile for `npm ci`.

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
mkdir -p vendor &&
curl -fsSL "$release/SHA256SUMS" -o vendor/SHA256SUMS &&
curl -fsSL "$release/workeros-0.8.0.tgz" -o vendor/workeros-0.8.0.tgz &&
(cd vendor &&
  awk '$2 == "workeros-0.8.0.tgz" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > npm.sha256 &&
  sha256sum --strict -c npm.sha256) &&
npm install --offline --ignore-scripts --no-audit --no-fund ./vendor/workeros-0.8.0.tgz
```

## C and C++

Use the versioned header-only Conan 2 recipe on Linux. The C and C++ clients
each receive a file from the launcher. [Conan install and first read](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/native/README.md)
· [C client](../native/tests/c/) · [C++ client](../native/tests/cpp/)

With Conan 2, curl and GNU coreutils installed, run this in a directory where
you can create the archive and extracted recipe. Conan may need a default
profile, created with `conan profile detect`.

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
curl -fsSL "$release/SHA256SUMS" -o SHA256SUMS &&
curl -fsSL "$release/workeros-conan-0.8.0.tar.gz" -o workeros-conan-0.8.0.tar.gz &&
awk '$2 == "workeros-conan-0.8.0.tar.gz" { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > conan.sha256 &&
sha256sum --strict -c conan.sha256 &&
tar -xzf workeros-conan-0.8.0.tar.gz &&
conan create ./workeros-conan-0.8.0 --no-remote
```

Add `workeros/0.8.0` to your consumer. The walkthrough builds and
checks separate C and C++ consumers.

## Go

Use Go 1.22+ on Linux amd64 or arm64. The Go guide explains how to resolve
the module for this version and launch a compiled reader with an inherited
input. [Go install and first read](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/go/README.md)

In your Go module, resolve the public tag with your normal checksum settings.
`go.sum` records the verified dependency.

```sh
go get github.com/thisistuhinsen/workerOS/go/workeros@v0.8.0 &&
go mod verify
```

## Rust

Use Rust 1.85+ on Linux x86-64 or AArch64. Build the reader with Cargo, then
start its binary with a launcher that supplies the named input.
[Rust install and first read](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/rust/README.md)

In your Cargo project, add the Git dependency and keep the resulting lockfile.

```sh
cargo add workeros --git https://github.com/thisistuhinsen/workerOS --tag v0.8.0 &&
cargo build --locked
```

## Java

Use JDK 22+ on 64-bit Linux with procfs. The Java guide installs the release
JAR and matching POM into Maven's local cache and shows the native-access flag
for the FFM reader. [Maven install and first read](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/java/README.md)

Download the matching JAR and POM and verify both release checksum entries
before installing them into your Maven local cache. Maven may download its
install plugin on first use. Use JDK 22+ and GNU coreutils.

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
curl -fsSL "$release/SHA256SUMS" -o SHA256SUMS &&
curl -fsSL "$release/workeros-0.8.0.jar" -o workeros-0.8.0.jar &&
curl -fsSL "$release/workeros-0.8.0.pom" -o workeros-0.8.0.pom &&
for asset in workeros-0.8.0.jar workeros-0.8.0.pom; do
  awk -v asset="$asset" '$2 == asset { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > "$asset.sha256" &&
  sha256sum --strict -c "$asset.sha256" || exit 1
done &&
mvn -B -ntp org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
  -Dfile=workeros-0.8.0.jar -DpomFile=workeros-0.8.0.pom
```

The dependency coordinates are `io.github.thisistuhinsen:workeros:0.8.0`.
Pass `--enable-native-access=ALL-UNNAMED` to a classpath worker using the FFM
reader.
