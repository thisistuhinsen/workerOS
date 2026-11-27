#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
uname -srm
cat /etc/os-release
python3 --version
python3 -m venv "$work/build"
"$work/build/bin/python" -m pip wheel --no-deps . -w "$work/dist"
wheel=("$work"/dist/*.whl)
test "${#wheel[@]}" -eq 1 && test -f "${wheel[0]}" || exit 1
python3 -m venv "$work/test"
"$work/test/bin/python" -m pip install --no-index --no-deps "${wheel[0]}"
# Keep the default installation free of optional dependencies.
python3 -m venv "$work/yaml"
"$work/yaml/bin/python" -m pip install --no-deps 'PyYAML==6.0.3'
"$work/yaml/bin/python" -m pip install --no-index --no-deps "${wheel[0]}"
WORKEROS_TEST_WHEEL="${wheel[0]}" WORKEROS_YAML_PYTHON="$work/yaml/bin/python" \
    "$work/test/bin/python" -I -m unittest discover -v -s tests
"$work/test/bin/python" -I "$work/test/share/worker-handoff/examples/run_inherited_fd.py"
