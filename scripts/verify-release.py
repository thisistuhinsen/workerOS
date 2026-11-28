"""Canonicalize and inspect the workerOS release candidate archives."""

import argparse
from email.parser import BytesParser
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
from tempfile import NamedTemporaryFile
import tomllib
from xml.etree import ElementTree
import zipfile


with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as stream:
    VERSION = tomllib.load(stream)["project"]["version"]
if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", VERSION):
    raise ValueError("a three-part numeric release version is required")
SOURCE_NAME = f"workeros-{VERSION}"
PUBLIC_DOCS = {
    "CONTRIBUTING.md", "SECURITY.md", "docs/releasing.md", "docs/support.md",
    "docs/media/README.md", "docs/media/custody-lanyard.gif", "docs/media/fd-7.gif", "docs/media/one-small-ticket.gif",
    "docs/install.md", "docs/install-0.8.0.md", "docs/package-python.md", "docs/workers.md",
    "docs/api.md", "docs/configuration.md", "docs/host-preflight.md", "docs/guarded-walkthrough.md",
    "docs/start/code.md", "docs/start/config.md", "docs/start/install.md", "docs/start/terminal.md",
    "docs/regular-file-observer.md", "skills/workeros/SKILL.md",
    "go/README.md", "java/README.md", "native/README.md", "node/README.md", "rust/README.md",
    "native/tests/c/CMakeLists.txt", "native/tests/c/conanfile.txt", "native/tests/c/read_input.c",
    "native/tests/cpp/CMakeLists.txt", "native/tests/cpp/conanfile.txt", "native/tests/cpp/read_input.cpp",
    "scripts/check-strict-custody-linux.py",
    "docs/brand/README.md", "docs/brand/workeros-banner.png", "docs/brand/workeros-mark.png", "docs/brand/workeros-social.png",
    *(f"docs/brand/language-{language}.png" for language in ("python", "node", "c", "cpp", "go", "rust", "java")),
    *(f"docs/brand/manager-{manager}.png" for manager in ("pip", "uv", "npm", "conan", "go", "cargo", "maven")),
}
NODE_FILES = {
    "LICENSE", "README.md", "examples/read-input.cjs", "index.cjs",
    "index.mjs", "package.json",
}
NATIVE_NAME = f"workeros-conan-{VERSION}"
NATIVE_FILES = {
    "LICENSE", "README.md", "conanfile.py", "check-conan.sh",
    "include/workeros/input.h", "tests/run_inherited.py",
    "tests/c/CMakeLists.txt", "tests/c/conanfile.txt", "tests/c/read_input.c",
    "tests/cpp/CMakeLists.txt", "tests/cpp/conanfile.txt", "tests/cpp/read_input.cpp",
}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def validate_paths(names):
    seen = set()
    for name in names:
        path = PurePosixPath(name)
        check(
            path.parts and not path.is_absolute() and ".." not in path.parts
            and str(path) == name and "\\" not in name and name not in seen,
            f"invalid or duplicate archive path: {name!r}",
        )
        seen.add(name)


def tar_members(archive):
    members = archive.getmembers()
    validate_paths(member.name for member in members)
    check(all(member.isfile() or member.isdir() for member in members),
          "tar archive contains a link or special file")
    return members


def normalize_tar(path):
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    with NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        normalized = Path(temporary.name)
        try:
            with (
                tarfile.open(path, "r:gz") as original,
                gzip.GzipFile(filename="", mode="wb", fileobj=temporary, mtime=epoch) as compressed,
                tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output,
            ):
                for member in sorted(tar_members(original), key=lambda entry: entry.name):
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    member.mtime = epoch
                    member.pax_headers = {}
                    member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
                    contents = original.extractfile(member) if member.isfile() else None
                    output.addfile(member, contents)
            temporary.flush()
            normalized.replace(path)
        finally:
            normalized.unlink(missing_ok=True)


def check_metadata(contents):
    metadata = BytesParser().parsebytes(contents)
    check(metadata["Name"] == "workeros", "unexpected Python package name")
    check(metadata["Version"] == VERSION, "unexpected Python package version")
    check(not metadata.get_all("Requires-Dist"), "unexpected runtime dependencies")


def check_sdist(path, destination):
    with tarfile.open(path, "r:gz") as archive:
        members = tar_members(archive)
        check(all(m.name == SOURCE_NAME or m.name.startswith(f"{SOURCE_NAME}/")
                  for m in members), "unexpected sdist root")
        files = {m.name.removeprefix(f"{SOURCE_NAME}/") for m in members if m.isfile()}
        core = {"LICENSE", "MANIFEST.in", "PKG-INFO", "README.md", "pyproject.toml", "setup.cfg"}
        core |= PUBLIC_DOCS | {"examples/evidence_config.json", "examples/workflow_policy.json",
                               "src/workeros/configuration.schema.json"}
        check(core <= files, f"missing sdist files: {sorted(core - files)}")
        fixtures = {"examples/report_worker.c", "examples/run_local_report.py",
                    "examples/run_local_workers.py", "examples/run_host_preflight.py"}
        check(fixtures <= files, f"sdist omits documented examples: {sorted(fixtures - files)}")
        check(any(name.startswith("tests/test_") for name in files), "sdist omits tests")
        check(all(
            name in core or re.fullmatch(
                r"(?:examples/[^/]+\.(?:c|cpp|cjs|go|java|py|rs)"
                r"|tests/(?:[\w-]+/)*[\w-]+\.py"
                r"|src/workeros/(?:[\w-]+/)*[\w-]+\.py"
                r"|src/workeros\.egg-info/[\w.-]+\.txt"
                r"|src/workeros\.egg-info/PKG-INFO)",
                name,
            )
            for name in files
        ), f"unexpected files in sdist: {sorted(files)}")
        check_metadata(archive.extractfile(f"{SOURCE_NAME}/PKG-INFO").read())
        archive.extractall(destination, members=members, filter="data")


def check_wheel(path, source):
    with (source / "pyproject.toml").open("rb") as stream:
        config = tomllib.load(stream)
    data = config["tool"]["setuptools"]["data-files"]
    data_files = {f"{SOURCE_NAME}.data/data/{group}/{Path(name).name}": name
                  for group in ("share/workeros/examples", "share/workeros/docs")
                  for name in data.get(group, ())}
    info = f"{SOURCE_NAME}.dist-info/"
    metadata_files = {info + name for name in ("METADATA", "WHEEL", "RECORD", "top_level.txt", "entry_points.txt")}
    license_files = {info + "LICENSE", info + "licenses/LICENSE"}
    schema = "workeros/configuration.schema.json"
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        validate_paths(names)
        files = set(names)
        required = set(data_files) | metadata_files | {schema}
        check(required <= files, "wheel omits metadata, schema or declared guides/examples")
        check(len(files & license_files) == 1, "wheel must include the MIT license")
        check("workeros/__init__.py" in files, "wheel omits the Python package")
        check(all(name in required | license_files or re.fullmatch(
            r"workeros/(?:[\w-]+/)*[\w-]+\.py", name,
        ) for name in files), f"unexpected files in wheel: {sorted(files)}")
        check_metadata(archive.read(f"{info}METADATA"))
        for member, name in data_files.items():
            check(archive.read(member) == (source / name).read_bytes(), f"installed {name} differs from source")
        check(archive.read(schema) == (source / "src" / schema).read_bytes(), "installed schema differs from source")
        check(archive.read(f"{info}entry_points.txt").splitlines() == [
            b"[console_scripts]",
            b"workeros = workeros.cli:main",
            b"workeros-config = workeros.configuration_cli:main",
            b"workeros-demo = workeros.quickstart:main",
            b"workeros-managed = workeros.managed_cli:main",
            b"workeros-owner-access = workeros.owner_access:main",
            b"workeros-roles = workeros.roles_cli:main",
            b"wos = workeros.cli:main",
        ], "unexpected Python entry points")
        wheel = BytesParser().parsebytes(archive.read(f"{info}WHEEL"))
        check(wheel.get_all("Tag") == ["py3-none-any"], "wheel is not architecture-independent")


def check_npm(path):
    with tarfile.open(path, "r:gz") as archive:
        files = {m.name for m in tar_members(archive) if m.isfile()}
        expected = {f"package/{name}" for name in NODE_FILES}
        check(files == expected,
              f"unexpected npm archive contents: {sorted(files ^ expected)}")
        package = json.load(archive.extractfile("package/package.json"))
        check(package.get("name") == "workeros", "unexpected npm package name")
        check(package.get("version") == VERSION, "unexpected npm package version")
        check(package.get("license") == "MIT", "unexpected npm package license")
        check(package.get("private") is True, "npm package must be GitHub-only")
        check(package.get("os") == ["linux"] and sorted(package.get("cpu", ())) == ["arm64", "x64"],
              "npm package must declare Linux x64 and arm64 support")
        dependencies = ("dependencies", "devDependencies", "optionalDependencies",
                        "peerDependencies", "bundledDependencies", "bundleDependencies")
        check(not any(package.get(name) for name in dependencies),
              "unexpected npm dependencies")
        lifecycle_hooks = {
            "preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare",
            "prepack", "postpack", "prepublish", "prepublishOnly", "publish", "postpublish",
        }
        check(not (package.get("scripts", {}).keys() & lifecycle_hooks),
              "unexpected npm install or release hooks")


def check_maven(path, pom):
    source_pom = pom.read_bytes()
    project = ElementTree.fromstring(source_pom)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    group = project.findtext("m:groupId", namespaces=ns)
    package = project.findtext("m:artifactId", namespaces=ns)
    version = project.findtext("m:version", namespaces=ns)
    check((group, package, version) == ("io.github.thisistuhinsen", "workeros", VERSION),
          "unexpected Maven coordinates")
    check(not project.findall("m:dependencies/m:dependency", ns),
          "unexpected Maven dependencies")
    check(project.findtext("m:licenses/m:license/m:name", namespaces=ns) == "MIT License",
          "unexpected Maven license")
    metadata = f"META-INF/maven/{group}/{package}/"
    expected = {
        "META-INF/LICENSE", "META-INF/MANIFEST.MF",
        metadata + "pom.xml", metadata + "pom.properties",
        "io/github/thisistuhinsen/workeros/InheritedReader.class",
    }
    with zipfile.ZipFile(path) as archive:
        validate_paths(entry.filename.rstrip("/") for entry in archive.infolist())
        files = {entry.filename for entry in archive.infolist() if not entry.is_dir()}
        check(expected <= files, f"missing JAR entries: {sorted(expected - files)}")
        check(all(name in expected or re.fullmatch(
            r"io/github/thisistuhinsen/workeros/InheritedReader\$[\w$]+\.class", name,
        ) for name in files), f"unexpected JAR entries: {sorted(files - expected)}")
        check(archive.read("META-INF/LICENSE").startswith(b"MIT License"), "JAR omits MIT license")
        check(archive.read(metadata + "pom.xml") == source_pom, "JAR and release POM differ")


def pack_native(path, source):
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(NATIVE_FILES):
            archive.add(source / name, arcname=f"{NATIVE_NAME}/{name}", recursive=False)
    normalize_tar(path)


def check_native(path, destination):
    with tarfile.open(path, "r:gz") as archive:
        members = tar_members(archive)
        files = {member.name for member in members if member.isfile()}
        expected = {f"{NATIVE_NAME}/{name}" for name in NATIVE_FILES}
        check(files == expected,
              f"unexpected native archive contents: {sorted(files ^ expected)}")
        archive.extractall(destination, members=members, filter="data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    for name in ("normalize", "sdist", "wheel", "npm", "maven", "pack-native", "native"):
        command = commands.add_parser(name)
        command.add_argument("archive", type=Path)
        if name in ("sdist", "native"):
            command.add_argument("destination", type=Path)
        elif name in ("wheel", "pack-native"):
            command.add_argument("source", type=Path)
        elif name == "maven":
            command.add_argument("pom", type=Path)
    args = parser.parse_args()
    if args.command == "version":
        print(VERSION)
    elif args.command == "normalize":
        normalize_tar(args.archive)
    elif args.command == "sdist":
        check_sdist(args.archive, args.destination)
    elif args.command == "wheel":
        check_wheel(args.archive, args.source)
    elif args.command == "npm":
        check_npm(args.archive)
    elif args.command == "maven":
        check_maven(args.archive, args.pom)
    elif args.command == "pack-native":
        pack_native(args.archive, args.source)
    else:
        check_native(args.archive, args.destination)


if __name__ == "__main__":
    main()
