#!/usr/bin/env bash
set -euo pipefail
mode=local
if [[ "${1:-}" == --public ]]; then
    mode=public
    shift
fi
if [[ $# != 1 || "${1:-}" == -* ]]; then
    printf 'Usage: %s [--public] path/to/release-wheel.whl\n' "${0##*/}" >&2
    exit 2
fi
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
wheel=$(realpath -- "$1")
if [[ ! -f "$wheel" ]]; then
    printf 'Wheel file not found: %s\n' "$wheel" >&2
    exit 2
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python=$(command -v "${WORKEROS_RELEASE_PYTHON:-python3}")
module=github.com/thisistuhinsen/workerOS
repository="https://$module"

# Use fresh configuration and caches. Keep the caller's installed Rust toolchain.
export XDG_CONFIG_HOME="$work/xdg"
mkdir -- "$XDG_CONFIG_HOME"
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
unset GIT_ASKPASS SSH_ASKPASS GIT_SSL_NO_VERIFY GIT_SSL_CERT GIT_SSL_KEY NETRC
export GIT_CONFIG_GLOBAL="$work/git.config" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_CEILING_DIRECTORIES="$(dirname -- "$work")"
export GOTOOLCHAIN=local GOPATH="$work/gopath" GOCACHE="$work/gocache" GOMODCACHE="$work/go-mod"
export GOENV=off GOWORK=off GOFLAGS=-modcacherw GOAUTH=off
unset GOPRIVATE GONOPROXY GONOSUMDB GOINSECURE
export CARGO_HOME="$work/cargo-home" CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TARGET_DIR="$work/cargo-target"

revision=$(git -C "$root" rev-parse HEAD)
version=$(git -C "$root" show HEAD:pyproject.toml |
    "$python" -I -c 'import sys,tomllib; print(tomllib.loads(sys.stdin.read())["project"]["version"])')
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$(basename -- "$wheel")" == "worker_handoff-$version-py3-none-any.whl" ]]

if [[ "$mode" == public ]]; then
    for name in .netrc _netrc; do
        if [[ -e "$HOME/$name" || -L "$HOME/$name" ]]; then
            printf 'Public checks require an environment without a user netrc file.\n' >&2
            exit 1
        fi
    done
    export GIT_ALLOW_PROTOCOL=https CARGO_HTTP_SSL_VERIFY=true CARGO_NET_OFFLINE=false
    export GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org
    tag="refs/tags/v$version"
    if ! refs=$(git -C "$work" ls-remote --exit-code --tags "$repository" "$tag" "$tag^{}"); then
        printf 'Could not verify public tag %s at %s\n' "$tag" "$repository" >&2
        exit 1
    fi
    tag_commit=$(awk -v tag="$tag" '
        $2 == tag { ref = $1 }
        $2 == tag "^{}" { peeled = $1 }
        END { print peeled ? peeled : ref }
    ' <<<"$refs")
    if [[ "$tag_commit" != "$revision" ]]; then
        printf 'Public v%s resolves to %s, expected %s\n' "$version" "$tag_commit" "$revision" >&2
        exit 1
    fi
    printf 'Public v%s resolves to %s\n' "$version" "$revision"
else
    # The local tag exercises resolution without a public tag or package proxy.
    export GIT_ALLOW_PROTOCOL=file GOPROXY=direct GOSUMDB=off
    mirror="$work/mirror"
    git init -q "$mirror"
    git -C "$mirror" fetch -q "$root" "$revision"
    git -C "$mirror" tag "v$version" "$revision"
    git -C "$mirror" checkout -q --detach "$revision"
    git config --file "$GIT_CONFIG_GLOBAL" "url.file://$mirror.insteadOf" "$repository"
    (cd -- "$mirror" && go test ./...)
    (cd -- "$mirror" && cargo test --offline --manifest-path rust/Cargo.toml)
fi
"$python" -I -m venv "$work/python"
"$work/python/bin/python" -I -m pip --disable-pip-version-check install --no-index --no-deps "$wheel"

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
    go get "$module/go/workerhandoff@v$version"
    [[ "$(go list -m -f '{{.Version}}' "$module")" == "v$version" ]]
    if [[ "$mode" == public ]]; then
        # The normal fetch provided the sums. Check that the exact Git origin
        # satisfies those same sums in a separate, empty download cache.
        GOPROXY=direct GOMODCACHE="$work/go-direct" go mod download -json "$module@v$version" |
            "$python" -I -c '
import json
import sys

download = json.load(sys.stdin)
if download.get("Origin", {}).get("Hash") != sys.argv[1]:
    raise SystemExit("Go direct module origin did not match the checked-out release revision")
' "$revision"
        go mod verify
    fi
    GOPROXY=off go build -buildvcs=false -o "$work/go-reader" .
)
cat > "$work/rust/Cargo.toml" <<EOF
[package]
name = "worker-reader"
version = "0.1.0"
edition = "2021"

[dependencies]
worker-handoff = { git = "$repository", tag = "v$version" }
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
(
    cd -- "$work/rust"
    cargo fetch
    grep -Fxq "source = \"git+$repository?tag=v$version#$revision\"" Cargo.lock
    cargo build --offline --locked
)

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
