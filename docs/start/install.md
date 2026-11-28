# Install the published WorkerOS release

Use Linux or Ubuntu in WSL2. These commands install **v0.7.0**, not the
v0.8.0 candidate. Choose one Python installer from a fresh folder; you don't
need to install Python and a reader package just to run an existing command.

## Python

[Install with pip and run hello](../../README.md#install-and-run). You can
use uv instead with Python 3.11+, curl and GNU `sha256sum` installed:

```sh
(
  set -eu
  download=$(mktemp -d)
  trap 'rm -rf -- "$download"' EXIT
  wheel="$download/workeros-0.7.0-py3-none-any.whl"
  curl -fsSL 'https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/workeros-0.7.0-py3-none-any.whl' -o "$wheel"
  printf '%s  %s\n' '1a418f20bffcfbed304855edb6663ce35c75c818b3f0af1ff51b6dc445e92c3b' "$wheel" | sha256sum --strict -c -
  uv venv --offline --python "$(command -v python3)" .venv-0.7.0
  uv pip install --offline --no-index --no-deps --python .venv-0.7.0/bin/python "$wheel"
  .venv-0.7.0/bin/workeros-demo -- /usr/bin/printf 'hello\n'
)
```

Look for `hello` and `job: exited 0`. Both installers create
`.venv-0.7.0`. If the checksum does not match, stop and use the
[versioned release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.7.0)
to check the expected asset. Don't substitute a package with a similar name.
Removing a package does not remove operating-system file grants. If an
administrator granted access to a file, ask them to revoke it through the
same authority and confirm removal with a fresh readback before retiring the
trusted admin environment or grant plan. See the
[named-principal file ACL guide](../host-preflight.md#grant-read-access-to-one-linux-file).

## Reader packages

Use a reader package when the worker needs an open file instead of a
pathname. An existing command does not need a language package.

| Language | Install with | Run the first read |
| --- | --- | --- |
| Python | [pip or uv](#python) | [Bundled Python reader](code.md) |
| Node.js | [npm tarball](#nodejs) | [Read a renamed file](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/node/README.md#read-one-inherited-file) |
| C | [Conan 2 recipe](#c-and-c) | [Run the C reader](#first-c-read) |
| C++ | [Conan 2 recipe](#c-and-c) | [Run the C++ reader](#first-cpp-read) |
| Go | [Go module](#go) | [Build and run a Go reader](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/go/README.md#try-the-public-tag) |
| Rust | [Cargo Git tag](#rust) | [Build and run a Rust reader](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/rust/README.md#try-the-public-tag) |
| Java | [Maven JAR and POM](#java) | [Run a Maven consumer](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/java/README.md#try-the-public-release) |

### Get a checked download

Only the npm, Conan and Maven routes need a separate download. In the
project where you want to install, paste this helper once in the same
Linux shell. It downloads one named v0.7.0 asset and checks its published
SHA-256 before the install can continue. You need curl and GNU `sha256sum`.

```sh
worker_asset() (
  set -eu
  release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0
  scratch=$(mktemp -d) || exit 1
  trap 'rm -rf -- "$scratch"' EXIT
  case "$1" in
    workeros-0.7.0.tgz)
      digest=6aeaa37fcae80398cfff41a6fa1728b4010207c8d0a21b7f22b0390e229083bc ;;
    workeros-conan-0.7.0.tar.gz)
      digest=3baacd1a1c0902a7d40fb25fab8dd3afb550dcfc94cf81775ba9f5c09698cbf6 ;;
    workeros-0.7.0.jar)
      digest=6980d17a11253b56be40de94fff44867688c55d6f1e50781642fef0252fb7ae9 ;;
    workeros-0.7.0.pom)
      digest=942517891f399597bc1b540dc0f5acf059ae32ab02597f14da669331c5f1a8a6 ;;
    *) printf 'Unknown WorkerOS release asset: %s\n' "$1" >&2; exit 1 ;;
  esac
  curl -fsSL "$release/$1" -o "$scratch/$1" || exit 1
  printf '%s  %s\n' "$digest" "$scratch/$1" | sha256sum --strict -c - || exit 1
  mkdir -p vendor || exit 1
  mv -- "$scratch/$1" "vendor/$1"
)
```

### Node.js

First paste the [checked-download helper](#get-a-checked-download) in
the same terminal.

Use Node.js 22+ with npm on Linux x64 or ARM64 and procfs. Run these in
your npm project. For a new project, first run `npm init -y`.

```sh
worker_asset workeros-0.7.0.tgz &&
npm install --offline --ignore-scripts --no-audit --no-fund \
  ./vendor/workeros-0.7.0.tgz &&
npm ls workeros --depth=0
```

Look for `workeros@0.7.0`. Keep the lockfile and tarball together.
[Run the installed reader](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/node/README.md#read-one-inherited-file).

### C and C++

First paste the [checked-download helper](#get-a-checked-download) in
the same terminal.

Use Conan 2 and a Linux toolchain with CMake, Make, and C or C++ compilers.
The recipe provides headers for both languages. If Conan has no default
profile yet, run `conan profile detect` first.

```sh
worker_asset workeros-conan-0.7.0.tar.gz &&
tar -xzf vendor/workeros-conan-0.7.0.tar.gz -C vendor &&
conan create ./vendor/workeros-conan-0.7.0 --no-remote
```

Look for `worker-handoff/0.7.0` in Conan's result. To compile and launch
separate C and C++ consumers, see the
[tagged walkthrough](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/native/README.md#try-the-public-release).
To try a reader without Conan, run its example from the folder where you
installed Python WorkerOS.

<a name="first-c-read"></a>

**C (requires a C11 compiler).**

```sh
example=.venv-0.7.0/share/worker-handoff/examples/run_inherited_fd.py
.venv-0.7.0/bin/python -I "$example" --language c
```

Look for `C: PASSED`.

<a name="first-cpp-read"></a>

**C++ (requires a C++17 compiler).**

```sh
example=.venv-0.7.0/share/worker-handoff/examples/run_inherited_fd.py
.venv-0.7.0/bin/python -I "$example" --language cpp
```

Look for `C++: PASSED`.

### Go

Use Go 1.22+ on Linux amd64 or arm64. In a fresh folder with no Go module,
first run `go mod init example.invalid/workeros-reader`. Then paste:

```sh
GOTOOLCHAIN=local go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.7.0 &&
go mod verify
```

Look for `all modules verified`. The first resolution normally uses
network access. [Build and run a reader](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/go/README.md#try-the-public-tag).

### Rust

Use Rust 1.85+ on Linux x86-64 or AArch64. In a fresh folder with no
Cargo project, first run `cargo init --bin`. Then paste:

```sh
cargo add worker-handoff --git https://github.com/thisistuhinsen/workerOS \
  --tag v0.7.0 --rename workeros
```

Look for the `workeros` dependency and commit in your manifest and lockfile.
Cargo fetches the Git tag. [Build and run a reader](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/rust/README.md#try-the-public-tag).

### Java

First paste the [checked-download helper](#get-a-checked-download) in
the same terminal.

Use JDK 22+, Maven 3.9+ and 64-bit Linux with procfs. This installs the
checked JAR/POM pair to Maven's local cache. Maven may fetch its install
plugin on first use.

```sh
worker_asset workeros-0.7.0.jar &&
worker_asset workeros-0.7.0.pom &&
mvn -B -ntp org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
  -Dfile=vendor/workeros-0.7.0.jar -DpomFile=vendor/workeros-0.7.0.pom
```

Look for `BUILD SUCCESS`. Depend on
`io.github.thisistuhinsen:worker-handoff:0.7.0` for this release. The reader
uses Java's Foreign Function & Memory API with
`--enable-native-access=ALL-UNNAMED`.
[Run the Maven example](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/java/README.md#try-the-public-release).

[Offline install or rollback](../install.md) · [Back to first run](../../README.md#install-and-run)
