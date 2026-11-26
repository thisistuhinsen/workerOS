#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
wheel=$(realpath -- "${1:?usage: check-git-consumers.sh path/to/release-wheel.whl}")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python=$(command -v "${WORKEROS_RELEASE_PYTHON:-python3}")
revision=$(git -C "$root" rev-parse HEAD)
version=$(git -C "$root" show HEAD:pyproject.toml |
    "$python" -I -c 'import sys,tomllib; print(tomllib.loads(sys.stdin.read())["project"]["version"])')
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$(basename -- "$wheel")" == "worker_handoff-$version-py3-none-any.whl" ]]

# Use the exact committed source. The local tag exercises Git package resolution
# without requiring a public tag, registry credentials, or package proxy.
mirror="$work/mirror"
git init -q "$mirror"
git -C "$mirror" fetch -q "$root" "$revision"
git -C "$mirror" tag "v$version" "$revision"
git -C "$mirror" checkout -q --detach "$revision"
"$python" -I -m venv "$work/python"
"$work/python/bin/python" -I -m pip --disable-pip-version-check install --no-index --no-deps "$wheel"

export GIT_CONFIG_GLOBAL="$work/git.config" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
git config --file "$GIT_CONFIG_GLOBAL" "url.file://$mirror.insteadOf" https://github.com/thisistuhinsen/workerOS
export GIT_ALLOW_PROTOCOL=file GOTOOLCHAIN=local GOPATH="$work/gopath" GOCACHE="$work/gocache"
export GOENV=off GOWORK=off GOFLAGS=-modcacherw
export GOPROXY=direct GOSUMDB=off  # This test resolves only the local mirror.
export CARGO_HOME="$work/cargo-home" CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TARGET_DIR="$work/cargo-target"
(cd -- "$mirror" && go test ./...)
cargo test --offline --manifest-path "$mirror/rust/Cargo.toml"

mkdir -- "$work/go" "$work/rust" "$work/rust/src"
cat > "$work/go/main.go" <<'GO'
package main

import (
    "fmt"
    "github.com/thisistuhinsen/workerOS/go/workerhandoff"
)

func main() {
    input, err := workerhandoff.Open("INPUT")
    if err != nil { panic(err) }
    var data [1]byte
    count, err := input.ReadAt(data[:], 0)
    closeErr := input.Close()
    if err != nil || closeErr != nil || count != 1 || data[0] != 'W' {
        panic(fmt.Sprintf("unexpected inherited input: %q, %d, %v, %v", data, count, err, closeErr))
    }
}
GO
(
    cd -- "$work/go"
    go mod init example.invalid/worker-reader
    go get "github.com/thisistuhinsen/workerOS/go/workerhandoff@v$version"
    [[ "$(go list -m -f '{{.Version}}' github.com/thisistuhinsen/workerOS)" == "v$version" ]]
    GOPROXY=off go build -buildvcs=false -o "$work/go-reader" .
)
cat > "$work/rust/Cargo.toml" <<EOF
[package]
name = "worker-reader"
version = "0.1.0"
edition = "2021"

[dependencies]
worker-handoff = { git = "https://github.com/thisistuhinsen/workerOS", tag = "v$version" }
EOF
cat > "$work/rust/src/main.rs" <<'RUST'
fn main() -> std::io::Result<()> {
    let reader = worker_handoff::open_read("INPUT")?;
    let mut data = [0_u8; 1];
    assert_eq!(reader.read_at(&mut data, 0)?, 1);
    assert_eq!(data[0], b'W');
    Ok(())
}
RUST
cargo fetch --manifest-path "$work/rust/Cargo.toml"
grep -Fq "#$revision" "$work/rust/Cargo.lock"
cargo build --offline --locked --manifest-path "$work/rust/Cargo.toml"

"$work/python/bin/python" -I - "$work/go-reader" "$CARGO_TARGET_DIR/debug/worker-reader" <<'PY'
from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from worker_handoff import WorkerRoster

with TemporaryDirectory() as directory:
    path = Path(directory) / "input"
    path.write_bytes(b"Worker input\n")
    roster = WorkerRoster()
    with path.open("rb", buffering=0) as source:
        fd = source.fileno()
        os.lseek(fd, 2, os.SEEK_SET)
        for name, executable in zip(("Go module", "Cargo Git dependency"), sys.argv[1:], strict=True):
            deadline = monotonic_ns() + 10_000_000_000
            worker = roster.start_executable(name, "read", [executable], fds={"INPUT": fd}, due_ns=deadline)
            try:
                assert roster.join(name, due_ns=deadline) == 0
                assert os.lseek(fd, 0, os.SEEK_CUR) == 2
            finally:
                if worker.process.poll() is None:
                    worker.process.kill()
                    worker.process.wait(timeout=5)
            print(f"{name}: PASSED (exact source tag and inherited positional read)")
PY
