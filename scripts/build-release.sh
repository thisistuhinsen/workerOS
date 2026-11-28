#!/usr/bin/env bash
set -euo pipefail
umask 022

usage() {
    printf 'Usage: %s [--build-only] [--owned-runtime-dir DIRECTORY] [OUTPUT_DIR]\n' "$0"
    printf '       %s --verify-only [OUTPUT_DIR]\n' "$0"
    printf '       %s --verify-public OUTPUT_DIR\n' "$0"
    printf 'The optional Linux x86-64 wheel takes reviewed bwrap and COPYING files from DIRECTORY.\n'
    printf 'The public check expects independently fetched release assets in OUTPUT_DIR.\n'
}

mode=all
case "${1:-}" in
    --build-only) mode=build; shift ;;
    --verify-only) mode=verify; shift ;;
    --verify-public) mode=public; shift ;;
    --owned-runtime-dir) ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
esac
runtime_dir=
if [[ "${1:-}" == --owned-runtime-dir ]]; then
    if [[ "$mode" == verify || "$mode" == public || $# -lt 2 || -z "$2" ]]; then
        usage >&2
        exit 2
    fi
    runtime_dir=$2
    shift 2
fi
if (( $# > 1 )) || [[ "$mode" == public && $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-"$root/dist"}
python=$(command -v "${WORKEROS_RELEASE_PYTHON:-python3}")
inspector="$root/scripts/verify-release.py"
version=$("$python" -I "$inspector" version)
wheel="workeros-$version-py3-none-any.whl"
sdist="workeros-$version.tar.gz"
npm_archive="workeros-$version.tgz"
jar="workeros-$version.jar"
pom="workeros-$version.pom"
native="workeros-conan-$version.tar.gz"
platform_wheel="workeros-$version-py3-none-linux_x86_64.whl"
runtime_packer="$root/scripts/package-owned-bwrap.py"
assets=("$wheel" "$sdist" "$npm_archive" "$jar" "$pom" "$native")
if [[ -n "$runtime_dir" ]]; then
    for input in "$runtime_dir/bwrap" "$runtime_dir/COPYING"; do
        if [[ ! -f "$input" || -L "$input" ]]; then
            printf 'Missing reviewed regular managed runtime file: %s\n' "$input" >&2
            exit 1
        fi
    done
    "$python" -I "$runtime_packer" --verify-ingress "$root/src/workeros/managed_executor.py" "$runtime_dir"
    runtime_dir=$(cd -- "$runtime_dir" && pwd)
    assets+=("$platform_wheel")
elif [[ "$mode" == verify || "$mode" == public ]]; then
    if [[ -e "$output/$platform_wheel" || -L "$output/$platform_wheel" ]]; then
        assets+=("$platform_wheel")
    fi
fi

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
        "$root/src" "$root/examples" "$root/tests" "$root/docs" "$root/skills" "$staging/python/"
    local guide
    for guide in go java native node rust; do
        mkdir -p -- "$staging/python/$guide"
        cp -- "$root/$guide/README.md" "$staging/python/$guide/"
    done
    mkdir -p -- "$staging/python/native/tests" "$staging/python/scripts"
    cp -R -- "$root/native/tests/c" "$root/native/tests/cpp" "$staging/python/native/tests/"
    cp -- "$root/scripts/check-strict-custody-linux.py" "$staging/python/scripts/"
    find "$staging/python" -type d \( -name '*.egg-info' -o -name __pycache__ \) \
        -prune -exec rm -rf -- {} +

    "$python" -I -m build --sdist --no-isolation --outdir "$destination" "$staging/python"
    inspect normalize "$destination/$sdist"
    inspect sdist "$destination/$sdist" "$staging/extracted"
    local source="$staging/extracted/workeros-$version"
    "$python" -I -m build --wheel --no-isolation --outdir "$destination" "$source"
    inspect wheel "$destination/$wheel" "$source"
    if [[ -n "$runtime_dir" ]]; then
        "$python" -I "$runtime_packer" "$destination/$wheel" "$runtime_dir/bwrap" "$runtime_dir/COPYING" "$destination"
        "$python" -I "$runtime_packer" --verify "$destination/$wheel" "$destination/$platform_wheel"
    fi

    (cd -- "$staging" && npm pack "$root/node" --offline --ignore-scripts --loglevel error \
        --cache "$staging/npm-cache" --pack-destination "$destination")
    inspect normalize "$destination/$npm_archive"
    inspect npm "$destination/$npm_archive"

    cp -R -- "$root/java/pom.xml" "$root/java/src" "$staging/java/"
    mvn -B -ntp -Dmaven.repo.local="$work/maven-cache" \
        -Dproject.build.outputTimestamp="$SOURCE_DATE_EPOCH" \
        -f "$staging/java/pom.xml" clean package
    cp -- "$staging/java/target/workeros-$version.jar" "$destination/$jar"
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
import workeros

package = distribution("workeros")
assert package.version == sys.argv[2]
assert not package.requires
assert Path(workeros.__file__).resolve().is_relative_to(root)
print("Installed workeros", package.version, "using", sys.executable)
' "$target" "$version")
}

pip_offline() {
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
name = "workeros-lock-consumer"
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
assert sorted(entry["name"] for entry in packages) == ["workeros", "workeros-lock-consumer"]
package, = [entry for entry in packages if entry["name"] == "workeros"]
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
        strictEqual(typeof require("workeros").openInherited, "function");'
    node --input-type=module -e 'import {strictEqual} from "node:assert";
        import {openInherited} from "workeros";
        strictEqual(typeof openInherited, "function");'
    "$interpreter" -I "$root/node/tests/launch-example.py" "$(command -v node)" \
        "$consumer/node_modules/workeros/examples/read-input.cjs"
)

verify_owned_runtime() {
    local source=$1
    local environment="$work/owned-runtime"
    [[ -f "$output/$platform_wheel" ]] || return 0
    "$python" -I "$runtime_packer" --verify "$output/$wheel" "$output/$platform_wheel"
    "$python" -I -m venv "$environment"
    pip_offline "$environment/bin/python" install --require-hashes "$source#sha256=$(asset_hash "$platform_wheel")"
    installed_python "$environment/bin/python"
    "$environment/bin/python" -I -m workeros.verify_install \
        "$output/$platform_wheel" --sha256 "$(asset_hash "$platform_wheel")"
    "$environment/bin/python" -I - <<'PY'
import subprocess

from workeros.managed_executor import _OWNED_BWRAP

result = subprocess.run([str(_OWNED_BWRAP), "--version"], env={}, capture_output=True,
                        check=True, timeout=5)
if result.stdout != b"bubblewrap 0.12.0\n":
    raise SystemExit("Installed managed runtime did not report the approved version.")
print("Installed owned runtime starts on the release host and reports Bubblewrap 0.12.0.")
PY
}

verify_release() {
    verify_manifest || exit 1
    local extracted="$work/verification"
    mkdir -p -- "$extracted"
    inspect sdist "$output/$sdist" "$extracted"
    local source="$extracted/workeros-$version"
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
    if [[ -f "$output/$platform_wheel" ]]; then
        verify_owned_runtime "$("$python" -I -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).as_uri())' "$output/$platform_wheel")"
    fi
    "$python" -I -m venv --without-pip "$uv_env"
    uv --offline --no-config --no-cache pip install --no-index --no-deps \
        --python "$uv_env/bin/python" "$output/$wheel"
    installed_python "$uv_env/bin/python"
    verify_uv_project "$output/$wheel" "$(asset_hash "$wheel")" "$work/uv-lock-consumer"

    "$python" -I "$root/scripts/check-release-layout.py" "$output" "$source" "$work" "$version"

    (
        cd -- "$work/wheel-demo"
        demo=".venv-$version/bin/workeros-demo"
        "$demo" -- /usr/bin/printf 'hello\n' | tee custom.log
        grep -x 'hello' custom.log
        grep -x 'job: exited 0' custom.log
        if "$demo" -- ".venv-$version/bin/python" -c \
            'from pathlib import Path; import time; Path("effect").write_text("changed\n"); time.sleep(10)' \
            > effect.log 2>&1; then
            printf 'A job that times out must fail the demo command.\n' >&2
            exit 1
        fi
        grep -x 'job: timed out' effect.log
        grep -x 'cleanup: reaped' effect.log
        grep -x 'Check any effects before trying again.' effect.log
        grep -x 'changed' effect
    )

    "$pip_env/bin/workeros-config" --schema > "$work/schema.json"
    "$pip_env/bin/workeros" config --schema > "$work/canonical-schema.json"
    cmp -- "$source/src/workeros/configuration.schema.json" "$work/schema.json"
    cmp -- "$work/schema.json" "$work/canonical-schema.json"

    local profile="$pip_env/share/workeros/examples/run_host_preflight.py"
    local refusal=0
    mkdir -- "$work/profile-temp"
    TMPDIR="$work/profile-temp" "$pip_env/bin/python" -I "$profile" --profile local-read > "$work/profile.json"
    TMPDIR="$work/profile-temp" "$pip_env/bin/python" -I "$profile" --profile local-read --without-archive \
        > "$work/profile-refused.json" || refusal=$?
    [[ "$refusal" == 2 && -z "$(ls -A -- "$work/profile-temp")" ]]
    "$python" -I - "$work/profile.json" "$work/profile-refused.json" <<'PY'
import json
from pathlib import Path
import sys

success, refusal = [json.loads(Path(path).read_text()) for path in sys.argv[1:]]
assert success["operation"]["delivery"] == "dispatched"
assert success["operation"]["returncode"] == 0
assert success["evidence"]["status"] == "local_readback_verified"
assert success["evidence"]["attempt_id"] == success["attempt_id"]
assert success["cleanup"]["child"]["status"] == "reaped"
assert success["cleanup"]["local_resources"] == "removed"
assert refusal["preflight"]["binding"] == "stores.archive"
assert refusal["operation"]["delivery"] == "not-attempted"
assert refusal["evidence"]["status"] == "not_requested"
assert refusal["cleanup"]["local_resources"] == "not_created"
print("Installed local host profile and pre-effect refusal passed")
PY

    local yaml_env="$work/yaml-wheel"
    "$python" -I -m venv "$yaml_env"
    "$yaml_env/bin/python" -m pip install --no-deps 'PyYAML==6.0.3'
    pip_offline "$yaml_env/bin/python" install "$output/$wheel"
    (cd -- "$work" && WORKEROS_TEST_WHEEL="$output/$wheel" WORKEROS_YAML_PYTHON="$yaml_env/bin/python" \
        "$pip_env/bin/python" -I -m unittest discover -v -s "$source/tests") \
        2>&1 | tee "$work/tests.log"
    if ! awk '
        /^Ran [0-9]+ tests in / && $2 >= 126 { count++ }
        NF { last = $0 }
        END { exit count != 1 || last != "OK" }
    ' "$work/tests.log"; then
        printf 'Expected at least 126 installed-wheel tests and zero skips.\n' >&2
        exit 1
    fi

    local launcher="$pip_env/share/workeros/examples/run_inherited_fd.py"
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
    PYTHON="$pip_env/bin/python" bash "$extracted/workeros-conan-$version/check-conan.sh"
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
    pip_offline "$pip_env/bin/python" install --require-hashes "$wheel_url"
    installed_python "$pip_env/bin/python"
    verify_owned_runtime "$base/$platform_wheel"
    "$pip_env/bin/workeros-config" --schema > "$work/public-schema.json"
    cmp -- "$root/src/workeros/configuration.schema.json" "$work/public-schema.json"
    "$pip_env/bin/python" -I "$pip_env/share/workeros/examples/run_inherited_fd.py" --language python
    "$python" -I -m venv --without-pip "$uv_env"
    uv --no-config --no-cache pip install --no-index --no-deps --require-hashes \
        --python "$uv_env/bin/python" "$wheel_url"
    installed_python "$uv_env/bin/python"
    verify_uv_project "$wheel_url" "$wheel_hash" "$work/public-uv-lock-consumer"

    pip_offline "$python" install --require-hashes --no-build-isolation \
        --target "$work/public-pip-sdist" "$sdist_url"
    installed_python "$python" "$work/public-pip-sdist"
    uv --no-config --no-cache pip install --no-index --no-deps --require-hashes --no-build-isolation \
        --python "$python" --target "$work/public-uv-sdist" "$sdist_url"
    installed_python "$python" "$work/public-uv-sdist"

    local consumer="$work/public-node-consumer" npm_dep="file:vendor/$npm_archive"
    mkdir -p -- "$consumer/vendor"
    cp -- "$output/$npm_archive" "$consumer/vendor/"
    touch -- "$work/npmrc-user" "$work/npmrc-global"
    local -a npm_options=(--offline --ignore-scripts --no-audit --no-fund --strict-ssl=true
        --userconfig="$work/npmrc-user" --globalconfig="$work/npmrc-global")
    (
        cd -- "$consumer"
        printf '{"name":"workeros-consumer","version":"0.0.0","private":true}\n' > package.json
        npm install "${npm_options[@]}" --package-lock-only --lockfile-version=3 \
            --cache "$work/public-npm-resolve" "$npm_dep"
        cp -- package-lock.json verified-package-lock.json
        node - "vendor/$npm_archive" "$(asset_hash "$npm_archive")" "$npm_dep" "$version" <<'JS' || exit 1
const assert = require("node:assert/strict");
const {createHash} = require("node:crypto");
const {readFileSync} = require("node:fs");
const [path, sha256, dependency, version] = process.argv.slice(2);
const archive = readFileSync(path);
assert.equal(createHash("sha256").update(archive).digest("hex"), sha256);
const {lockfileVersion, packages} = JSON.parse(readFileSync("verified-package-lock.json", "utf8"));
assert.equal(lockfileVersion, 3);
assert.deepEqual(Object.keys(packages).sort(), ["", "node_modules/workeros"]);
assert.equal(packages[""].dependencies["workeros"], dependency);
const installed = packages["node_modules/workeros"];
assert.equal(installed.version, version);
assert.equal(installed.resolved, dependency);
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
    PYTHON="$pip_env/bin/python" bash "$extracted/workeros-conan-$version/check-conan.sh"
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
