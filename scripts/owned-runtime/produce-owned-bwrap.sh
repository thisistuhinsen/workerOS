#!/bin/bash
set -euo pipefail
umask 077
recipe=$(cd -- "$(dirname -- "$0")" && pwd -P)
if (($# != 1)); then
  printf 'usage: bash produce-owned-bwrap.sh NEW_OUTPUT_DIRECTORY\n' >&2
  exit 2
fi
[[ ! -e "$1" && ! -L "$1" ]]
mkdir -m 0700 -- "$1"
out=$(cd -- "$1" && pwd -P)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/inputs"
python3 -I "$recipe/fetch-pinned-inputs.py" "$recipe/inputs.lock.tsv" "$stage/inputs"
image=ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker pull --platform linux/amd64 "$image"
fi
docker run --rm --pull never --network none --platform linux/amd64 \
  --volume "$stage/inputs:/inputs:ro" --volume "$recipe:/recipe:ro" \
  --volume "$out:/outputs" "$image" bash /recipe/build-in-container.sh
