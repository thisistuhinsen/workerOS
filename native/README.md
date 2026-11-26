# worker-handoff for Conan

`worker-handoff/0.5.0` is a header-only Conan 2 package for Linux. Its C and
C++ API reads a regular file already inherited from a workerOS launcher.
Launch a child with `WorkerRoster.start_executable(..., fds={"INPUT": fd})`
to supply the FD and ABI metadata.

After v0.5.0 is published, extract the GitHub Release archive and create the
package in your local Conan cache. Use an existing Linux Conan profile, or run
`conan profile detect` for a new cache.

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.5.0
archive=worker-handoff-conan-0.5.0.tar.gz
curl -fL "$release/$archive" -o "$archive" &&
    curl -fL "$release/SHA256SUMS" -o SHA256SUMS &&
    awk -v f="$archive" '$2 == f { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > "$archive.sha256" &&
    sha256sum --strict --check "$archive.sha256" &&
    tar -xzf "$archive" &&
    conan create ./worker-handoff-conan-0.5.0 --no-remote
```

Add `worker-handoff/0.5.0` to your consumer's `[requires]` in
`conanfile.txt`. With Conan's `CMakeDeps` and `CMakeToolchain`, use
`find_package(worker-handoff CONFIG REQUIRED)` and link your target to
`worker-handoff::worker-handoff`. A source checkout uses
`conan create native --no-remote` for the same recipe.

## Read an inherited input

Use `<worker_handoff/input.h>` from C99 or newer, or C++11 or newer. Strict
POSIX builds should define `_POSIX_C_SOURCE=200809L` before any system
header. On 32-bit systems that need large file support, compile with
`_FILE_OFFSET_BITS=64`.

```c
#define _POSIX_C_SOURCE 200809L
#include <worker_handoff/input.h>

int main(void)
{
    worker_handoff_input input = WORKER_HANDOFF_INPUT_INIT;
    if (worker_handoff_open_inherited("INPUT", WORKER_HANDOFF_OWNED, &input) == -1) {
        return 1;
    }
    char byte;
    ssize_t count = worker_handoff_read_at(&input, &byte, 1, 0);
    int closed = worker_handoff_close(&input);
    return count == 1 && byte == 'W' && closed == 0 ? 0 : 1;
}
```

The binding is validated against ABI version 1 and the live descriptor's
kernel file type, device, inode and access mode. Both `read` and
`read-write` bindings can be read. `worker_handoff_read_at` returns a byte
count, zero at EOF, or `-1` with `errno`, and preserves the shared offset.
The API performs positional reads only.

Initialize each handle with `WORKER_HANDOFF_INPUT_INIT`. An owned handle
closes the descriptor once. Closing a borrowed handle invalidates just that
handle. Keep the slot stable and give an owned handle exclusive close
authority. The functions recheck file metadata and access before reading
or closing an owned handle. Handle copying, concurrent descriptor rebinding
and concurrent mutation of the ABI environment are outside this contract.
The launcher and caller retain responsibility for authorization, deadlines,
supervision and custody.

## Verify both languages

The included check uses a fresh Conan home, installs a separate C and C++
consumer, and launches each executable through the Python workerOS
package. It checks the inherited ABI, positional offset, ownership and
refusals. Install the Python wheel in a venv first and pass that Python
executable to the script. Conan 2, CMake, Make and C/C++ compilers must be
on PATH.

```sh
PYTHON=/path/to/venv/bin/python bash ./worker-handoff-conan-0.5.0/check-conan.sh
```
