#!/usr/bin/env bash
set -euo pipefail
umask 022

usage() {
    printf 'Usage: %s [--build-only|--verify-only] [OUTPUT_DIR]\n' "$0"
}

mode=all
case "${1:-}" in
    --build-only) mode=build; shift ;;
    --verify-only) mode=verify; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then
    usage >&2
    exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-"$root/dist"}
python=$(command -v "${WORKEROS_RELEASE_PYTHON:-python3}")
inspector="$root/scripts/verify-release.py"
version=$("$python" -I "$inspector" version)
wheel="worker_handoff-$version-py3-none-any.whl"
sdist="worker_handoff-$version.tar.gz"
npm_archive="worker-handoff-$version.tgz"
jar="worker-handoff-$version.jar"
pom="worker-handoff-$version.pom"
native="worker-handoff-conan-$version.tar.gz"
assets=("$wheel" "$sdist" "$npm_archive" "$jar" "$pom" "$native")

# November 26, 2026 at 00:00:00 UTC. Set a shared epoch explicitly to override it.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1795651200}
export TZ=UTC
export LC_ALL=C
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
    printf 'SOURCE_DATE_EPOCH must be a nonnegative integer\n' >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

inspect() {
    "$python" -I "$inspector" "$@"
}

build_one() {
    local destination=$1
    local staging=$2
    mkdir -p -- "$destination" "$staging/python" "$staging/extracted" "$staging/java"
    cp -R -- "$root/pyproject.toml" "$root/README.md" "$root/LICENSE" \
        "$root/CONTRIBUTING.md" "$root/SECURITY.md" "$root/MANIFEST.in" \
        "$root/src" "$root/examples" "$root/tests" "$root/docs" "$staging/python/"
    find "$staging/python" -type d \( -name '*.egg-info' -o -name __pycache__ \) \
        -prune -exec rm -rf -- {} +

    "$python" -I -m build --sdist --no-isolation --outdir "$destination" "$staging/python"
    inspect normalize "$destination/$sdist"
    inspect sdist "$destination/$sdist" "$staging/extracted"
    local source="$staging/extracted/worker_handoff-$version"
    "$python" -I -m build --wheel --no-isolation --outdir "$destination" "$source"
    inspect wheel "$destination/$wheel" "$source"

    (cd -- "$staging" && npm pack "$root/node" --offline --ignore-scripts --loglevel error \
        --cache "$staging/npm-cache" --pack-destination "$destination")
    inspect normalize "$destination/$npm_archive"
    inspect npm "$destination/$npm_archive"

    cp -R -- "$root/java/pom.xml" "$root/java/src" "$staging/java/"
    mvn -B -ntp -Dmaven.repo.local="$work/maven-cache" \
        -Dproject.build.outputTimestamp="$SOURCE_DATE_EPOCH" \
        -f "$staging/java/pom.xml" clean package
    cp -- "$staging/java/target/$jar" "$destination/$jar"
    cp -- "$staging/java/pom.xml" "$destination/$pom"
    inspect maven "$destination/$jar" "$destination/$pom"

    inspect pack-native "$destination/$native" "$root/native"
    inspect native "$destination/$native" "$staging/extracted"
}

hashes() {
    (cd -- "$1" && sha256sum -- "${assets[@]}")
}

build_release() {
    if [[ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        printf 'Release output directory must be empty: %s\n' "$output" >&2
        exit 1
    fi
    build_one "$work/first" "$work/stage-first"
    build_one "$work/second" "$work/stage-second"
    for asset in "${assets[@]}"; do
        cmp -- "$work/first/$asset" "$work/second/$asset"
        cp -- "$work/first/$asset" "$output/$asset"
    done
    hashes "$output" > "$output/SHA256SUMS"
    printf 'Release assets reproduced byte-for-byte.\n'
    cat -- "$output/SHA256SUMS"
}

installed_python() {
    local interpreter=$1
    local target=${2:-}
    (cd -- "$work" && "$interpreter" -I -c '
from importlib.metadata import distribution
from pathlib import Path
import sys

root = Path(sys.argv[1] or sys.prefix).resolve()
if sys.argv[1]:
    sys.path.insert(0, str(root))
import worker_handoff

package = distribution("worker-handoff")
assert package.version == sys.argv[2]
assert not package.requires
assert Path(worker_handoff.__file__).resolve().is_relative_to(root)
print("Installed worker-handoff", package.version, "using", sys.executable)
' "$target" "$version")
}

pip_offline() {
    local interpreter=$1
    shift
    "$interpreter" -I -m pip --isolated --disable-pip-version-check --no-cache-dir \
        "$@" --no-index --no-deps
}

verify_release() {
    local asset
    for asset in "${assets[@]}" SHA256SUMS; do
        if [[ ! -f "$output/$asset" || -L "$output/$asset" ]]; then
            printf 'Missing regular release file: %s\n' "$output/$asset" >&2
            exit 1
        fi
    done
    diff -u -- "$output/SHA256SUMS" <(hashes "$output")
    local extracted="$work/verification"
    mkdir -p -- "$extracted"
    inspect sdist "$output/$sdist" "$extracted"
    local source="$extracted/worker_handoff-$version"
    inspect wheel "$output/$wheel" "$source"
    inspect npm "$output/$npm_archive"
    inspect maven "$output/$jar" "$output/$pom"
    inspect native "$output/$native" "$extracted"

    pip_offline "$python" wheel --no-build-isolation --wheel-dir "$work/sdist-wheel" "$output/$sdist"
    cmp -- "$work/sdist-wheel/$wheel" "$output/$wheel"
    uv --offline --no-config --no-cache pip install --no-index --no-deps --no-build-isolation \
        --python "$python" --target "$work/uv-sdist" "$output/$sdist"
    installed_python "$python" "$work/uv-sdist"

    local pip_env="$work/pip-wheel"
    local uv_env="$work/uv-wheel"
    "$python" -I -m venv "$pip_env"
    pip_offline "$pip_env/bin/python" install "$output/$wheel"
    installed_python "$pip_env/bin/python"
    "$python" -I -m venv --without-pip "$uv_env"
    uv --offline --no-config --no-cache pip install --no-index --no-deps \
        --python "$uv_env/bin/python" "$output/$wheel"
    installed_python "$uv_env/bin/python"

    (cd -- "$work" && "$pip_env/bin/python" -I -m unittest discover -v -s "$source/tests") \
        2>&1 | tee "$work/tests.log"
    if ! awk '
        /^Ran [0-9]+ tests in / && $2 >= 39 { count++ }
        NF { last = $0 }
        END { exit count != 1 || last != "OK" }
    ' "$work/tests.log"; then
        printf 'Expected at least 39 installed-wheel tests and zero skips.\n' >&2
        exit 1
    fi

    local launcher="$pip_env/share/worker-handoff/examples/run_inherited_fd.py"
    (cd -- "$work" && "$pip_env/bin/python" -I "$launcher") 2>&1 | tee "$work/examples.log"
    for language in C C++ Go Java Node.js Python Rust; do
        if ! awk -v prefix="$language: PASSED (" \
            'index($0, prefix) == 1 { count++ } END { exit count != 1 }' "$work/examples.log"; then
            printf '%s example did not pass exactly once.\n' "$language" >&2
            exit 1
        fi
    done

    PATH="$pip_env/bin:$PATH" npm --prefix "$root/node" --ignore-scripts \
        --cache "$work/npm-test-cache" test
    local consumer="$work/node-consumer"
    mkdir -p -- "$consumer"
    (
        cd -- "$consumer"
        npm install --offline --ignore-scripts --no-audit --no-fund --no-save --no-package-lock \
            --cache "$work/npm-install-cache" "$output/$npm_archive"
        node -e 'const {strictEqual} = require("node:assert");
            strictEqual(typeof require("worker-handoff").openInherited, "function");'
        node --input-type=module -e 'import {strictEqual} from "node:assert";
            import {openInherited} from "worker-handoff";
            strictEqual(typeof openInherited, "function");'
        "$pip_env/bin/python" -I "$root/node/tests/launch-example.py" "$(command -v node)" \
            "$consumer/node_modules/worker-handoff/examples/read-input.cjs"
    )

    PATH="$pip_env/bin:$PATH" bash "$root/java/test-package.sh" "$output/$jar" "$output/$pom"
    PYTHON="$pip_env/bin/python" bash "$extracted/worker-handoff-conan-$version/check-conan.sh"
    printf 'Release candidate verified.\n'
}

if [[ "$mode" != verify ]]; then
    mkdir -p -- "$output"
fi
output=$(cd -- "$output" && pwd)
if [[ "$mode" != verify ]]; then
    build_release
fi
if [[ "$mode" != build ]]; then
    verify_release
fi
