# workerOS for Java

> These commands use v0.8.0. For the previous release, use the [v0.7.0 guide](https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/java/README.md).

Use JDK 22 or later on 64-bit Linux with procfs and Maven 3.9 or newer. The
JAR has no runtime dependencies. It reads a file descriptor inherited
from a workerOS launcher using Java's Foreign Function & Memory API.
The release download uses curl and GNU coreutils (`sha256sum`).

## Try the public release

[install the Python controller](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#python) and activate its
environment. Run this from any directory. Set `WORKEROS_PYTHON` to use a
particular Python interpreter.

```sh
(
    set -eu
    python=$(command -v "${WORKEROS_PYTHON:-python3}")
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    cd "$work"
    release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.8.0
    jar=workeros-0.8.0.jar
    pom=workeros-0.8.0.pom
    for file in "$jar" "$pom" SHA256SUMS; do
        curl --fail --silent --show-error --location "$release/$file" --output "$file"
    done
    for file in "$jar" "$pom"; do
        awk -v name="$file" '$2 == name { print; count++ } END { if (count != 1) exit 1 }' \
            SHA256SUMS > "$file.sha256"
        sha256sum --strict --check "$file.sha256"
    done
    git clone --quiet --no-checkout https://github.com/thisistuhinsen/workerOS "$work/source"
    git -C "$work/source" checkout --quiet --detach refs/tags/v0.8.0
    PATH="${python%/*}:$PATH" bash "$work/source/java/test-package.sh" "$work/$jar" "$work/$pom"
)
```

Expect `PASS Maven consumer`. The test installs the checked pair in a fresh
Maven repository, compiles a separate consumer, and launches it with an open
file. Maven may need to fetch its build plugins.

## Try the private offline bundle

[Install the Python controller](https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#python) and set
`WORKEROS_OFFLINE` to the absolute path of the verified
private `workerOS-0.8.0-offline` directory. The block uses the pip environment.
For uv, set `WORKEROS_PYTHON="$WORKEROS_OFFLINE/.venv-0.8.0-uv/bin/python"`
first.

```sh
(
    set -eu
    offline=${WORKEROS_OFFLINE:?set WORKEROS_OFFLINE to the extracted bundle directory}
    python=${WORKEROS_PYTHON:-"$offline/.venv-0.8.0/bin/python"}
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    git clone --quiet --no-checkout "$offline/source/workeros-0.8.0.bundle" "$work/source"
    git -C "$work/source" checkout --quiet --detach refs/tags/v0.8.0
    PATH="${python%/*}:$PATH" bash "$work/source/java/test-package.sh" \
        "$offline/assets/workeros-0.8.0.jar" "$offline/assets/workeros-0.8.0.pom"
)
```

The verifier installs the supplied JAR and POM in a fresh Maven repository,
then builds a separate consumer and gives it a real inherited file. Expect a
Maven consumer pass. Maven needs access to its own build plugins on first
use; the workerOS artifacts come from the bundle.

## Use the JAR and POM in your own project

Use the verified pair from the matching release or private bundle. In the
directory containing those two files, install them into your Maven cache.
Maven may need to fetch the install plugin on first use.

```sh
mvn -B -ntp org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile=workeros-0.8.0.jar -DpomFile=workeros-0.8.0.pom
```

Use the installed coordinates in your own Maven project.

```xml
<dependency>
  <groupId>io.github.thisistuhinsen</groupId>
  <artifactId>worker-handoff</artifactId>
  <version>0.8.0</version>
</dependency>
```

The [historical v0.4.0 release](https://github.com/thisistuhinsen/workerOS/releases/tag/v0.4.0)
has its own JAR, POM, and checksums.

## Read an inherited binding

Pass `--enable-native-access=ALL-UNNAMED` when starting a Java worker on
the classpath. The launcher supplies the regular file under the name `INPUT`.

```java
import io.github.thisistuhinsen.workerhandoff.InheritedReader;

// In the launched worker:
try (var input = InheritedReader.open("INPUT")) {
    byte[] bytes = new byte[4096];
    int count = input.readAt(0, bytes);
    // Process bytes[0..count) when count > 0. EOF returns -1.
}
```

Binding names match `[A-Z][A-Z0-9_]*`. The reader checks the launcher
metadata against the live regular file, including device, inode and access
mode. Each reader owns a close-on-exec duplicate and preserves the shared
file offset using `pread`. Use try-with-resources to close the duplicate.
Keep the inherited slot stable until `open` returns. Close that slot or
mark it non-inheritable before starting further children unless they need it.
