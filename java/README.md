# workerOS for Java

Use `io.github.thisistuhinsen:worker-handoff:0.5.0` to read a file descriptor inherited from a
workerOS ABI v1 launcher. The JAR has no runtime dependencies. It requires Linux x64 or ARM64 with
procfs, a JDK 22+ runtime, and native access for the Java Foreign Function & Memory API.

## Install the release

Once v0.5.0 is published, download the JAR, POM and checksums from the public GitHub Release.
The downloads use public GitHub URLs.

```sh
release=https://github.com/thisistuhinsen/workerOS/releases/download/v0.5.0
jar=worker-handoff-0.5.0.jar
pom=worker-handoff-0.5.0.pom
for file in "$jar" "$pom" SHA256SUMS; do
  curl --fail --silent --show-error --location "$release/$file" --output "$file" || exit 1
done
for file in "$jar" "$pom"; do
  awk -v f="$file" '$2 == f { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > "$file.sha256" &&
    sha256sum --check "$file.sha256" || exit 1
done
mvn -B -ntp org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
  -Dfile="$jar" -DpomFile="$pom"
```

Then add the dependency to your application's POM.

```xml
<dependency>
  <groupId>io.github.thisistuhinsen</groupId>
  <artifactId>worker-handoff</artifactId>
  <version>0.5.0</version>
</dependency>
```

## Read an inherited binding

Start your Java process through a launcher that explicitly transfers a regular file as `INPUT`.
When running on the classpath, include `--enable-native-access=ALL-UNNAMED` in your Java command.

```java
import io.github.thisistuhinsen.workerhandoff.InheritedReader;

// In the launched worker:
try (var input = InheritedReader.open("INPUT")) {
    byte[] bytes = new byte[4096];
    int count = input.readAt(0, bytes);
    // Process bytes[0..count) when count > 0. EOF returns -1.
}
```

The launcher supplies `WORKER_HANDOFF_ABI=1` and the `FD_`, `DEV_`, `INO_` and `ACCESS_` fields
under the `WORKER_HANDOFF_` prefix for the exact binding. Binding names match `[A-Z][A-Z0-9_]*`.
The reader checks canonical unsigned decimal fields, the kernel device and inode, the regular-file
type and the declared readable access mode. Keep the original descriptor stable until `open`
returns. Each reader owns a close-on-exec duplicate and preserves the shared file offset using
`pread`. Close each reader with try-with-resources. The launcher's original remains caller-owned.
The package provides only the worker-side read interface.

## Build and test the release files

From the checkout root, with Maven 3.9+, JDK 22+ and a Python environment containing the workerOS
wheel on PATH, run the following. Maven needs access to its build plugins on first use.

```sh
mvn -B -ntp -f java/pom.xml clean package
mkdir -p dist
cp java/target/worker-handoff-0.5.0.jar dist/
cp java/pom.xml dist/worker-handoff-0.5.0.pom
bash java/test-package.sh dist/worker-handoff-0.5.0.jar dist/worker-handoff-0.5.0.pom
```

The test installs those two files into a fresh local Maven repository, builds a separate
consumer against its coordinates, and transfers real descriptors using Python's `WorkerRoster`.
It checks positional reads, EOF, handle closure, shared offsets, and rejection of invalid metadata.
