#!/usr/bin/env bash
set -euo pipefail
umask 022

usage() {
    printf 'Usage: %s [--build-only|--verify-only] [OUTPUT_DIR]\n' "$0"
    printf '       %s --verify-public OUTPUT_DIR\n' "$0"
    printf 'The public check expects independently fetched release assets in OUTPUT_DIR.\n'
}

mode=all
case "${1:-}" in
    --build-only) mode=build; shift ;;
    --verify-only) mode=verify; shift ;;
    --verify-public) mode=public; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
esac
if (( $# > 1 )) || [[ "$mode" == public && $# -ne 1 ]]; then
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

pip_without_index() {
    local interpreter=$1
    shift
    "$interpreter" -I -m pip --isolated --disable-pip-version-check --no-cache-dir \
        "$@" --no-index --no-deps
}

verify_manifest() {
    local asset
    if [[ $(find "$output" -mindepth 1 -maxdepth 1 -printf '.' | wc -c) != "$(( ${#assets[@]} + 1 ))" ]]; then
        printf 'Unexpected release asset set: %s\n' "$output" >&2
        return 1
    fi
    for asset in "${assets[@]}" SHA256SUMS; do
        if [[ ! -f "$output/$asset" || -L "$output/$asset" ]]; then
            printf 'Missing regular release file: %s\n' "$output/$asset" >&2
            exit 1
        fi
    done
    hashes "$output" > "$work/verified-SHA256SUMS"
    diff -u -- "$output/SHA256SUMS" "$work/verified-SHA256SUMS"
}

asset_hash() {
    awk -v asset="$1" '$2 == asset { print $1 }' "$work/verified-SHA256SUMS"
}

verify_uv_project() (
    local source=$1 digest=$2 project=$3
    local -a uv_options=(--no-config --no-cache)
    if [[ "$source" != https://* ]]; then
        uv_options+=(--offline)
    fi
    mkdir -- "$project"
    cd -- "$project"
    unset VIRTUAL_ENV UV_NO_VERIFY_HASHES UV_INSECURE_HOST
    export UV_PROJECT_ENVIRONMENT="$project/.venv"
    cat > pyproject.toml <<'EOF'
[project]
name = "worker-handoff-lock-consumer"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = []
EOF
    uv "${uv_options[@]}" add --no-sync --no-index --python "$python" --project "$project" "$source"
    cp -- uv.lock verified.lock
    "$python" -I - "$source" "$digest" "$wheel" "$version" <<'PY' || exit 1
from pathlib import Path
import sys
import tomllib

source, digest, filename, version = sys.argv[1:]
with open("verified.lock", "rb") as stream:
    packages = tomllib.load(stream)["package"]
assert sorted(entry["name"] for entry in packages) == ["worker-handoff", "worker-handoff-lock-consumer"]
package, = [entry for entry in packages if entry["name"] == "worker-handoff"]
assert package["version"] == version
asset, = package["wheels"]
assert asset["hash"] == f"sha256:{digest}"
if source.startswith("https://"):
    url = source.split("#", 1)[0]
    assert package["source"] == {"url": url}
    assert asset["url"] == url
else:
    assert Path(package["source"]["path"]).resolve() == Path(source).resolve()
    assert asset["filename"] == filename
PY
    cmp -- verified.lock uv.lock || exit 1
    uv "${uv_options[@]}" lock --check --no-index --python "$python" --project "$project" || exit 1
    test ! -e .venv || exit 1
    cmp -- verified.lock uv.lock || exit 1
    uv "${uv_options[@]}" sync --locked --no-index --python "$python" --project "$project" || exit 1
    cmp -- verified.lock uv.lock || exit 1
    installed_python "$project/.venv/bin/python"
)

verify_node_consumer() (
    local consumer=$1 interpreter=$2
    cd -- "$consumer"
    node -e 'const {strictEqual} = require("node:assert");
        strictEqual(typeof require("worker-handoff").openInherited, "function");'
    node --input-type=module -e 'import {strictEqual} from "node:assert";
        import {openInherited} from "worker-handoff";
        strictEqual(typeof openInherited, "function");'
    "$interpreter" -I "$root/node/tests/launch-example.py" "$(command -v node)" \
        "$consumer/node_modules/worker-handoff/examples/read-input.cjs"
)

verify_release() {
    verify_manifest || exit 1
    local extracted="$work/verification"
    mkdir -p -- "$extracted"
    inspect sdist "$output/$sdist" "$extracted"
    local source="$extracted/worker_handoff-$version"
    inspect wheel "$output/$wheel" "$source"
    inspect npm "$output/$npm_archive"
    inspect maven "$output/$jar" "$output/$pom"
    inspect native "$output/$native" "$extracted"

    pip_without_index "$python" wheel --no-build-isolation --wheel-dir "$work/sdist-wheel" "$output/$sdist"
    cmp -- "$work/sdist-wheel/$wheel" "$output/$wheel"
    uv --offline --no-config --no-cache pip install --no-index --no-deps --no-build-isolation \
        --python "$python" --target "$work/uv-sdist" "$output/$sdist"
    installed_python "$python" "$work/uv-sdist"

    local pip_env="$work/pip-wheel"
    local uv_env="$work/uv-wheel"
    "$python" -I -m venv "$pip_env"
    pip_without_index "$pip_env/bin/python" install "$output/$wheel"
    installed_python "$pip_env/bin/python"
    "$python" -I -m venv --without-pip "$uv_env"
    uv --offline --no-config --no-cache pip install --no-index --no-deps \
        --python "$uv_env/bin/python" "$output/$wheel"
    installed_python "$uv_env/bin/python"
    verify_uv_project "$output/$wheel" "$(asset_hash "$wheel")" "$work/uv-lock-consumer"

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
    )
    verify_node_consumer "$consumer" "$pip_env/bin/python"

    PATH="$pip_env/bin:$PATH" bash "$root/java/test-package.sh" "$output/$jar" "$output/$pom"
    PYTHON="$pip_env/bin/python" bash "$extracted/worker-handoff-conan-$version/check-conan.sh"
    printf 'Release candidate verified.\n'
}

verify_public() (
    verify_manifest || exit 1
    # Keep package-manager defaults for TLS verification, independent of user configuration.
    unset UV_INSECURE_HOST UV_NO_VERIFY_HASHES NODE_TLS_REJECT_UNAUTHORIZED NETRC
    for name in .netrc _netrc; do
        if [[ -e "$HOME/$name" || -L "$HOME/$name" ]]; then
            printf 'Public checks require an environment without a user netrc file.\n' >&2
            exit 1
        fi
    done
    export PIP_CONFIG_FILE=/dev/null
    local base="https://github.com/thisistuhinsen/workerOS/releases/download/v$version"

    local wheel_hash wheel_url sdist_url
    wheel_hash=$(asset_hash "$wheel")
    wheel_url="$base/$wheel#sha256=$wheel_hash"
    sdist_url="$base/$sdist#sha256=$(asset_hash "$sdist")"
    local pip_env="$work/public-pip-wheel" uv_env="$work/public-uv-wheel"
    "$python" -I -m venv "$pip_env"
    pip_without_index "$pip_env/bin/python" install --require-hashes "$wheel_url"
    installed_python "$pip_env/bin/python"
    "$pip_env/bin/python" -I "$pip_env/share/worker-handoff/examples/run_inherited_fd.py" --language python
    "$python" -I -m venv --without-pip "$uv_env"
    uv --no-config --no-cache pip install --no-index --no-deps --require-hashes \
        --python "$uv_env/bin/python" "$wheel_url"
    installed_python "$uv_env/bin/python"
    verify_uv_project "$wheel_url" "$wheel_hash" "$work/public-uv-lock-consumer"

    pip_without_index "$python" install --require-hashes --no-build-isolation \
        --target "$work/public-pip-sdist" "$sdist_url"
    installed_python "$python" "$work/public-pip-sdist"
    uv --no-config --no-cache pip install --no-index --no-deps --require-hashes --no-build-isolation \
        --python "$python" --target "$work/public-uv-sdist" "$sdist_url"
    installed_python "$python" "$work/public-uv-sdist"

    local consumer="$work/public-node-consumer" npm_url="$base/$npm_archive"
    mkdir -- "$consumer"
    touch -- "$work/npmrc-user" "$work/npmrc-global"
    local -a npm_options=(--ignore-scripts --no-audit --no-fund --strict-ssl=true
        --userconfig="$work/npmrc-user" --globalconfig="$work/npmrc-global")
    (
        cd -- "$consumer"
        printf '{"name":"worker-handoff-consumer","version":"0.0.0","private":true}\n' > package.json
        npm install "${npm_options[@]}" --package-lock-only --lockfile-version=3 \
            --cache "$work/public-npm-resolve" "$npm_url"
        cp -- package-lock.json verified-package-lock.json
        node - "$output/$npm_archive" "$(asset_hash "$npm_archive")" "$npm_url" "$version" <<'JS' || exit 1
const assert = require("node:assert/strict");
const {createHash} = require("node:crypto");
const {readFileSync} = require("node:fs");
const [path, sha256, url, version] = process.argv.slice(2);
const archive = readFileSync(path);
assert.equal(createHash("sha256").update(archive).digest("hex"), sha256);
const {lockfileVersion, packages} = JSON.parse(readFileSync("verified-package-lock.json", "utf8"));
assert.equal(lockfileVersion, 3);
assert.deepEqual(Object.keys(packages).sort(), ["", "node_modules/worker-handoff"]);
assert.equal(packages[""].dependencies["worker-handoff"], url);
const installed = packages["node_modules/worker-handoff"];
assert.equal(installed.version, version);
assert.equal(installed.resolved, url);
assert.equal(installed.integrity, `sha512-${createHash("sha512").update(archive).digest("base64")}`);
JS
        test ! -e node_modules || exit 1
        cmp -- verified-package-lock.json package-lock.json || exit 1
        npm ci "${npm_options[@]}" --cache "$work/public-npm-install" || exit 1
        cmp -- verified-package-lock.json package-lock.json
    )
    verify_node_consumer "$consumer" "$pip_env/bin/python"

    # OUTPUT_DIR was fetched and independently checked before this consumer run.
    local extracted="$work/public-extracted"
    mkdir -- "$extracted"
    inspect maven "$output/$jar" "$output/$pom"
    inspect native "$output/$native" "$extracted"
    PATH="$pip_env/bin:$PATH" bash "$root/java/test-package.sh" "$output/$jar" "$output/$pom"
    PYTHON="$pip_env/bin/python" bash "$extracted/worker-handoff-conan-$version/check-conan.sh"
    printf 'Public release artifact consumers verified.\n'
)

if [[ "$mode" != verify && "$mode" != public ]]; then
    mkdir -p -- "$output"
fi
output=$(cd -- "$output" && pwd)
if [[ "$mode" != verify && "$mode" != public ]]; then
    build_release
fi
if [[ "$mode" == public ]]; then
    verify_public
elif [[ "$mode" != build ]]; then
    verify_release
fi
