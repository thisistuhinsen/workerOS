"""Replay shipped Python quickstarts against only the staged release assets."""

from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from threading import Thread
from zipfile import ZipFile


REPOSITORY = "https://github.com/thisistuhinsen/workerOS"
EXPECTED = ("report: exited 0", "slow job: timed out", "cleanup: reaped")


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


def quickstart(document, directory, release_url, stage_url):
    script = re.search(r"(?m)^```sh\n([\s\S]+?)^```$", document.read_text(encoding="utf-8"))
    if not script or script[1].count(release_url) != 1:
        raise SystemExit(f"{document.name}: expected first shell block to use the pinned release URL")
    result = subprocess.run(
        ["bash"], input=script[1].replace(release_url, stage_url), cwd=directory,
        env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1"},
        encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=90, check=False,
    )
    print(result.stdout, end="", flush=True)
    if result.returncode or not set(EXPECTED).issubset(result.stdout.splitlines()):
        raise SystemExit(f"{document.name}: staged quickstart failed ({result.returncode})")
    print(f"{document.name}: release-layout quickstart passed")


def main(assets, source, work, version):
    wheel = f"workeros-{version}-py3-none-any.whl"
    names = {wheel, f"workeros-{version}.tar.gz", f"workeros-{version}.tgz",
             f"workeros-{version}.jar", f"workeros-{version}.pom",
             f"workeros-conan-{version}.tar.gz", "SHA256SUMS"}
    if {p.name for p in assets.iterdir()} != names or any(
        not (assets / name).is_file() or (assets / name).is_symlink() for name in names
    ):
        raise SystemExit("expected exactly seven regular release assets")

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

    release_url = f"{REPOSITORY}/releases/download/v{version}"
    with serve_release(assets, {f"/{name}" for name in names}) as stage_url:
        quickstart(readme_doc, readme, release_url, stage_url)
        quickstart(metadata_doc, metadata, release_url, stage_url)


if __name__ == "__main__":
    main(*map(Path, sys.argv[1:4]), sys.argv[4])
