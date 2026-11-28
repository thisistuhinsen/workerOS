#!/usr/bin/env bash
set -euo pipefail

jar=$(realpath "${1:?usage: test-package.sh JAR POM}")
pom=$(realpath "${2:?usage: test-package.sh JAR POM}")
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
version=$(python3 -I - "$jar" "$pom" "$source_dir/consumer/pom.xml" <<'PY'
import re
import sys
from xml.etree import ElementTree as ET
from zipfile import ZipFile

jar, pom, consumer = sys.argv[1:]
ns = {"m": "http://maven.apache.org/POM/4.0.0"}
group, artifact = "io.github.thisistuhinsen", "workeros"


def coordinates(project):
    return tuple(project.findtext(f"m:{field}", namespaces=ns) for field in (
        "groupId", "artifactId", "version",
    ))


package = coordinates(ET.parse(pom).getroot())
version = package[2]
if package[:2] != (group, artifact) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version or ""):
    raise SystemExit("Unexpected Maven package coordinates")
with ZipFile(jar) as archive:
    embedded = ET.fromstring(archive.read(f"META-INF/maven/{group}/{artifact}/pom.xml"))
if coordinates(embedded) != package:
    raise SystemExit("JAR and supplied POM have different Maven coordinates")
dependencies = ET.parse(consumer).findall("m:dependencies/m:dependency", ns)
if [coordinates(item) for item in dependencies] != [package]:
    raise SystemExit("Maven consumer dependency does not match the package coordinates")
print(version)
PY
)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
repo="$work/repo"
cp -R "$source_dir/consumer" "$work/consumer"
cd "$work"
mvn -B -ntp -Dmaven.repo.local="$repo" org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile="$jar" -DpomFile="$pom"
mvn -B -ntp -Dmaven.repo.local="$repo" -f consumer/pom.xml clean compile
installed="$repo/io/github/thisistuhinsen/workeros/$version/workeros-$version"
cmp "$jar" "$installed.jar"
cmp "$pom" "$installed.pom"
python3 -I consumer/test_handoff.py "$work/consumer/target/classes:$installed.jar"
