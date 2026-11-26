#!/usr/bin/env bash
set -euo pipefail

jar=$(realpath "${1:?usage: test-package.sh JAR POM}")
pom=$(realpath "${2:?usage: test-package.sh JAR POM}")
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
repo="$work/repo"
cp -R "$source_dir/consumer" "$work/consumer"
cd "$work"
mvn -B -ntp -Dmaven.repo.local="$repo" org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile="$jar" -DpomFile="$pom"
mvn -B -ntp -Dmaven.repo.local="$repo" -f consumer/pom.xml clean compile
installed="$repo/io/github/thisistuhinsen/worker-handoff/0.4.0/worker-handoff-0.4.0"
cmp "$jar" "$installed.jar"
cmp "$pom" "$installed.pom"
python3 -I consumer/test_handoff.py "$work/consumer/target/classes:$installed.jar"
