#!/usr/bin/env bash
set -euo pipefail

# Run from the exact checkout. This gate only reads Git and writes job outputs.
[[ "$GITHUB_REPOSITORY" == thisistuhinsen/workerOS && "$GITHUB_REF" == refs/heads/main && "$DEFAULT_BRANCH" == main ]]
[[ "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ && "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]]
read -r live_sha live_ref < <(git ls-remote --exit-code origin refs/heads/main)
[[ "$live_sha" == "$GITHUB_SHA" && "$live_ref" == refs/heads/main ]] || {
    echo 'The release SHA must still be the public default-branch tip.' >&2
    exit 1
}
version=$(git show HEAD:pyproject.toml |
    python -I -c 'import sys,tomllib; print(tomllib.load(sys.stdin.buffer)["project"]["version"])')
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]

case "$GITHUB_EVENT_NAME" in
    push) publish=true ;;
    workflow_dispatch)
        [[ "$REQUESTED_REVISION" == "$GITHUB_SHA" && "$REQUESTED_VERSION" == "$version" ]] || {
            echo 'Dispatch must name the exact checked-out SHA and version.' >&2
            exit 1
        }
        [[ "$REQUESTED_PUBLISH" == true || "$REQUESTED_PUBLISH" == false ]]
        publish=$REQUESTED_PUBLISH ;;
    *) exit 1 ;;
esac

if [[ "$publish" == true ]]; then
    [[ "$REF_PROTECTED" == true ]] || {
        echo 'Release blocked: GitHub reports the default main ref is unprotected.' >&2
        exit 1
    }
    parent=$(git rev-parse HEAD^)
    [[ $(git rev-list --parents -1 HEAD | wc -w) == 2 ]]
    [[ "$(git diff --no-ext-diff --no-renames --name-only "$parent" HEAD)" == .github/release-version ]] || {
        echo 'Release authorization requires a standalone version-marker commit.' >&2
        exit 1
    }
    if [[ "$GITHUB_EVENT_NAME" == push ]]; then
        [[ "$BEFORE_SHA" == "$parent" ]]
    fi
    read -r marker_mode marker_kind _ < <(git ls-tree HEAD -- .github/release-version)
    [[ "$marker_mode" == 100644 && "$marker_kind" == blob ]]
    git show HEAD:.github/release-version | cmp - <(printf '%s\n' "$version")
fi

printf 'version=%s\npublish=%s\n' "$version" "$publish" >> "$GITHUB_OUTPUT"
