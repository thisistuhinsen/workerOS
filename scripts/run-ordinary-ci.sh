#!/usr/bin/env bash
set -euo pipefail

uid=$(id -u)
gid=$(id -g)
test "$uid" -ne 0
if [[ "$(id -G)" == "$gid" ]]; then
    exec "$@"
fi

# Preserve the hosted job's existing UID/GID and remove supplementary groups.
# Only the system credential tool runs before the privilege drop.
exec sudo -n -- /usr/bin/setpriv --reuid="$uid" --regid="$gid" --clear-groups \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
    /usr/bin/env "HOME=$HOME" "PATH=$PATH" "JAVA_HOME=${JAVA_HOME:-}" "$@"
