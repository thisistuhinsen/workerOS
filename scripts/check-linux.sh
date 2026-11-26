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
python3 -m venv "$work/test"
"$work/test/bin/python" -m pip install --no-index --no-deps "$work"/dist/*.whl
"$work/test/bin/python" -I -m unittest discover -v -s tests
"$work/test/bin/python" -I "$work/test/share/worker-handoff/examples/run_inherited_fd.py"
