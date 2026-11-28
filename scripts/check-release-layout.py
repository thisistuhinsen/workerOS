"""Replay the published README and candidate wheel's Python quickstarts."""

from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from threading import Thread
from zipfile import ZipFile


REPOSITORY = "https://github.com/thisistuhinsen/workerOS"
README_WHEEL = ("https://github.com/thisistuhinsen/workerOS/releases/download/v0.7.0/"
                "workeros-0.7.0-py3-none-any.whl#sha256="
                "1a418f20bffcfbed304855edb6663ce35c75c818b3f0af1ff51b6dc445e92c3b")
HELLO_OUTPUT = ("hello", "job: exited 0")


@contextmanager
def serve_release(assets, allowed):
    class ReleaseAssets(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=assets, **kwargs)

        def send_head(self):
            if self.path not in allowed:
                self.send_error(404)
                return None
            return super().send_head()

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), ReleaseAssets) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            worker.join()


def quickstart(document, directory, release_url, expected, *, stage_url=None):
    block = re.search(r"(?m)^```sh\n([\s\S]+?)^```$", document.read_text(encoding="utf-8"))
    if block is None:
        raise SystemExit(f"{document.name}: missing first shell block")
    script = block[1]
    if stage_url is None:
        release, artifact = release_url.rsplit("/", 1)
        wheel, digest = artifact.split("#sha256=")
        header = script.replace("\\\n", "").splitlines()[:3]
        expected_pin = [[f"release={release}"], [f"wheel={wheel}"], [f"sha={digest}"]]
        pinned = [shlex.split(line) for line in header] == expected_pin
        pinned = pinned and script.count('"$release/$wheel#sha256=$sha"') == 1
    else:
        pinned = script.count(release_url) == 1
    if not pinned:
        raise SystemExit(f"{document.name}: expected first shell block to use the pinned release URL")
    home = directory / ".home"
    home.mkdir()
    environment = {key: value for key, value in os.environ.items() if key not in (
        "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
        "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST", "NETRC",
    )}
    environment.update(HOME=str(home), PIP_CONFIG_FILE=os.devnull,
                       PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_CACHE_DIR="1")
    result = subprocess.run(
        ["bash"], input=script.replace(release_url, stage_url) if stage_url else script, cwd=directory,
        env=environment,
        encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=90, check=False,
    )
    print(result.stdout, end="", flush=True)
    if result.returncode or not set(expected).issubset(result.stdout.splitlines()):
        raise SystemExit(f"{document.name}: quickstart failed ({result.returncode})")
    print(f"{document.name}: quickstart passed")


def main(assets, source, work, version):
    wheel = f"workeros-{version}-py3-none-any.whl"
    names = {wheel, f"workeros-{version}.tar.gz", f"workeros-{version}.tgz",
             f"workeros-{version}.jar", f"workeros-{version}.pom",
             f"workeros-conan-{version}.tar.gz", "SHA256SUMS"}
    platform = f"workeros-{version}-py3-none-linux_x86_64.whl"
    present = {p.name for p in assets.iterdir()}
    if platform in present:
        names.add(platform)
    if present != names or any(
        not (assets / name).is_file() or (assets / name).is_symlink() for name in names
    ):
        raise SystemExit("unexpected release layout")

    readme = work / "readme-demo"
    metadata = work / "wheel-demo"
    readme.mkdir()
    metadata.mkdir()
    readme_doc = readme / "README.md"
    metadata_doc = metadata / "package-python.md"
    shutil.copyfile(source / "README.md", readme_doc)
    with ZipFile(assets / wheel) as archive:
        body = archive.read(f"workeros-{version}.dist-info/METADATA").partition(b"\n\n")[2]
    if body.strip() != (source / "docs/package-python.md").read_bytes().strip():
        raise SystemExit("wheel metadata description differs from its shipped guide")
    metadata_doc.write_bytes(body)

    # The default README stays on the last published wheel while the next
    # release is pending. Its literal command is checked against that wheel.
    quickstart(readme_doc, readme, README_WHEEL, HELLO_OUTPUT)

    release_url = f"{REPOSITORY}/releases/download/v{version}"
    with serve_release(assets, {f"/{name}" for name in names}) as stage_url:
        quickstart(metadata_doc, metadata, release_url, HELLO_OUTPUT, stage_url=stage_url)
    installed = metadata / f".venv-{version}/bin/python"
    subprocess.run([str(installed), "-I", "-c",
                    "from importlib.metadata import version; import sys; "
                    "assert version('workeros') == sys.argv[1]", version],
                   cwd=metadata, check=True)


if __name__ == "__main__":
    main(*map(Path, sys.argv[1:4]), sys.argv[4])
