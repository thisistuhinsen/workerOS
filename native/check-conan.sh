#!/usr/bin/env bash
set -euo pipefail

native="$(cd "$(dirname "$0")" && pwd)"
python="${PYTHON:-python3}"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export CONAN_HOME="$work/conan"

conan --version
cmake --version
conan profile detect
conan create "$native" --no-remote
for language in c cpp; do
    source="$work/source-$language"
    build="$work/build-$language"
    cp -R "$native/tests/$language" "$source"
    conan install "$source" --output-folder "$build" --no-remote \
        -c "tools.cmake.cmaketoolchain:generator=Unix Makefiles"
    cmake -G "Unix Makefiles" -S "$source" -B "$build" \
        -DCMAKE_TOOLCHAIN_FILE="$build/conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$build"
done
"$python" -I "$native/tests/run_inherited.py" "$work/build-c/read-worker-c" "$work/build-cpp/read-worker-cpp"
