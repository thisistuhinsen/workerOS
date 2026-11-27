# workerOS for C and C++

> These are v0.8.0 instructions. Use public downloads only after that release,
> or use a verified offline bundle now. For the published v0.7.0 release, use the [v0.7.0 guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/native/README.md).

`workeros/0.8.0` is a header-only Conan 2 package for Linux. Both C and
C++ readers take an already-open regular file from the workerOS launcher.
The release download uses curl and GNU coreutils (`sha256sum`).

## Try the public release

[install the Python controller](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#python) and activate its
environment. Install Conan 2, CMake, Make and C and C++ compilers. Set
`WORKEROS_PYTHON` to use a particular Python interpreter.

```sh
(
    set -eu
    python=$(command -v "${WORKEROS_PYTHON:-python3}")
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    cd "$work"
    release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
    archive=workeros-conan-0.8.0.tar.gz
    for file in "$archive" SHA256SUMS; do
        curl --fail --silent --show-error --location "$release/$file" --output "$file"
    done
    awk -v name="$archive" '$2 == name { print; count++ } END { if (count != 1) exit 1 }' \
        SHA256SUMS > "$archive.sha256"
    sha256sum --strict --check "$archive.sha256"
    tar -xzf "$archive"
    PYTHON="$python" bash "$work/workeros-conan-0.8.0/check-conan.sh"
)
```

Expect `C: PASSED` and `C++: PASSED`. The checked archive contains both
consumer fixtures and the script that launches them with an inherited file.

## Try the private offline bundle

[Install the Python controller](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#python) and set
`WORKEROS_OFFLINE` to the absolute path of the verified
private `workerOS-0.8.0-offline` directory. The block uses the pip environment.
For uv, set `WORKEROS_PYTHON="$WORKEROS_OFFLINE/.venv-0.8.0-uv/bin/python"`
first. Install Conan 2, CMake, Make and the C and C++ compilers before
running this block.

```sh
(
    set -eu
    offline=${WORKEROS_OFFLINE:?set WORKEROS_OFFLINE to the extracted bundle directory}
    python=${WORKEROS_PYTHON:-"$offline/.venv-0.8.0/bin/python"}
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    tar -xzf "$offline/assets/workeros-conan-0.8.0.tar.gz" -C "$work"
    PYTHON="$python" bash "$work/workeros-conan-0.8.0/check-conan.sh"
)
```

The script uses a fresh Conan home, builds separate C and C++ consumers and
gives each a real inherited file. Expect `C: PASSED` and `C++: PASSED`.

## Use the recipe from your own project

Use the verified archive from the release or private bundle. In the
directory containing the archive, extract it and create the package in your
chosen local Conan cache. Run `conan profile detect` first if that cache
needs a default profile.

```sh
tar -xzf workeros-conan-0.8.0.tar.gz &&
conan create ./workeros-conan-0.8.0 --no-remote
```

The [historical v0.4.0 release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.4.0)
has its own recipe archive and checksums.

Use this in your consumer's `conanfile.txt`. With CMake, use
`find_package(workeros CONFIG REQUIRED)` and link to
`workeros::workeros`.

```ini
[requires]
workeros/0.8.0

[generators]
CMakeDeps
CMakeToolchain
```

## Read an inherited input

Use `<workeros/input.h>` from C99 or newer, or C++11 or newer. Strict
POSIX builds should define `_POSIX_C_SOURCE=200809L` before any system
header. On 32-bit systems that need large file support, compile with
`_FILE_OFFSET_BITS=64`.

```c
#define _POSIX_C_SOURCE 200809L
#include <workeros/input.h>

int main(void)
{
    workeros_input input = WORKEROS_INPUT_INIT;
    if (workeros_open_inherited("INPUT", WORKEROS_OWNED, &input) == -1) {
        return 1;
    }
    char byte;
    ssize_t count = workeros_read_at(&input, &byte, 1, 0);
    int closed = workeros_close(&input);
    return count == 1 && byte == 'W' && closed == 0 ? 0 : 1;
}
```

The binding is checked against ABI version 1 and the live descriptor's
file type, device, inode and access mode. Both `read` and `read-write`
bindings can be read. `workeros_read_at` returns a byte count, zero
at EOF, or `-1` with `errno`. Positional reads preserve the shared offset.

Initialize each handle with `WORKEROS_INPUT_INIT`. An owned handle
closes the descriptor once. Closing a borrowed handle invalidates just
that handle. Keep the slot stable and give an owned handle exclusive
close authority. The launcher and caller retain responsibility for
authorization, deadlines and supervision.
