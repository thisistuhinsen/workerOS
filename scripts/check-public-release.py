"""Verify a published workerOS release without GitHub credentials."""

import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


REPOSITORY = "thisistuhinsen/workerOS"
API = f"https://api.github.com/repos/{REPOSITORY}"
PUBLIC = f"https://github.com/{REPOSITORY}/releases"
METADATA_LIMIT = 2 * 1024 * 1024
CHUNK = 128 * 1024
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


class VerificationError(ValueError):
    """The public release could not be matched to the staged release."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def package_names(version):
    return (
        f"workeros-{version}-py3-none-any.whl",
        f"workeros-{version}.tar.gz",
        f"workeros-{version}.tgz",
        f"workeros-{version}.jar",
        f"workeros-{version}.pom",
        f"workeros-conan-{version}.tar.gz",
    )


def https_host(url, hosts):
    parts = urlsplit(url)
    require(parts.scheme == "https" and parts.hostname in hosts
            and parts.username is None and parts.password is None and parts.port in (None, 443),
            "refused an unexpected public URL")


class PublicRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        hosts = {"api.github.com"} if urlsplit(request.full_url).hostname == "api.github.com" else DOWNLOAD_HOSTS
        https_host(new_url, hosts)
        return super().redirect_request(request, response, code, message, headers, new_url)


@contextmanager
def public_response(opener, url, *, metadata=False):
    hosts = {"api.github.com"} if metadata else DOWNLOAD_HOSTS
    https_host(url, hosts)
    request = Request(url, headers={
        "Accept": "application/vnd.github+json" if metadata else "application/octet-stream",
        "Cache-Control": "no-cache",
        "User-Agent": "workerOS-public-release-check",
    })
    try:
        with opener.open(request, timeout=30) as response:
            https_host(response.geturl(), hosts)
            require(response.status == 200, "public request did not return HTTP 200")
            yield response
    except HTTPError as exc:
        exc.close()
        raise VerificationError(f"public request failed (HTTP {exc.code})") from None
    except URLError:
        raise VerificationError("public request failed") from None


def public_metadata(opener, url):
    with public_response(opener, url, metadata=True) as response:
        payload = response.read(METADATA_LIMIT + 1)
    require(len(payload) <= METADATA_LIMIT, "public metadata exceeds the size limit")
    data = json.loads(payload)
    require(type(data) is dict, "expected a public metadata object")
    return data


def fingerprint(stream, destination=None, limit=None):
    digest = sha256()
    size = 0
    while chunk := stream.read(CHUNK):
        size += len(chunk)
        require(limit is None or size <= limit, "public asset exceeds its staged size")
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    return size, digest.hexdigest()


def staged_assets(directory, packages):
    names = (*packages, "SHA256SUMS")
    require(directory.is_dir() and not directory.is_symlink(), "expected a staged asset directory")
    require({path.name for path in directory.iterdir()} == set(names), "unexpected staged asset set")
    expected = {}
    for name in packages:
        path = directory / name
        require(path.is_file() and not path.is_symlink(), f"staged asset is not a regular file: {name}")
        with path.open("rb") as stream:
            expected[name] = fingerprint(stream)
    manifest_path = directory / "SHA256SUMS"
    require(manifest_path.is_file() and not manifest_path.is_symlink(), "expected a regular SHA256SUMS file")
    canonical = sorted(f"{digest}  {name}\n".encode("ascii") for name, (_, digest) in expected.items())
    with manifest_path.open("rb") as manifest:
        data = manifest.read(sum(map(len, canonical)) + 1)
    require(sorted(data.splitlines(keepends=True)) == canonical, "staged SHA256SUMS does not match the exact packages")
    expected["SHA256SUMS"] = len(data), sha256(data).hexdigest()
    return expected


def verify_metadata(opener, tag, revision, expected):
    ref = public_metadata(opener, f"{API}/git/ref/tags/{tag}")
    target = ref.get("object")
    require(ref.get("ref") == f"refs/tags/{tag}" and type(target) is dict
            and target.get("type") == "commit" and target.get("sha") == revision,
            "public tag does not point directly to the expected commit")
    release = public_metadata(opener, f"{API}/releases/tags/{tag}")
    require(release.get("tag_name") == tag and release.get("html_url") == f"{PUBLIC}/tag/{tag}"
            and release.get("draft") is False and release.get("prerelease") is False,
            "expected the public final release for this tag")
    release_id, assets = release.get("id"), release.get("assets")
    require(type(release_id) is int and release_id > 0 and type(assets) is list,
            "release identity or assets are missing")
    asset_ids = {}
    for asset in assets:
        require(type(asset) is dict and type(asset.get("name")) is str, "invalid public asset record")
        name = asset["name"]
        require(name in expected and name not in asset_ids, "unexpected or duplicate public asset")
        size, digest = expected[name]
        asset_id = asset.get("id")
        require(type(asset_id) is int and asset_id > 0 and asset_id not in asset_ids.values()
                and asset.get("state") == "uploaded"
                and type(asset.get("size")) is int and asset["size"] == size
                and asset.get("digest") == f"sha256:{digest}"
                and asset.get("browser_download_url") == f"{PUBLIC}/download/{tag}/{name}",
                f"public asset metadata does not match the staged {name}")
        asset_ids[name] = asset_id
    require(asset_ids.keys() == expected.keys(), "public assets are missing")
    return release_id, asset_ids


def require_empty_output(directory):
    require(not directory.is_symlink() and (
        not directory.exists() or (directory.is_dir() and not any(directory.iterdir()))
    ), "output directory must be empty")


def verify_public_release(version, revision, expected_dir, output_dir, *, opener=None):
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version),
            "expected a three-part package version without v")
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "expected an exact lowercase commit SHA")
    require_empty_output(output_dir)
    require(output_dir.parent.is_dir(), "output parent directory must exist")
    require(expected_dir.resolve() not in output_dir.resolve().parents,
            "output must be separate from the staged assets")
    expected = staged_assets(expected_dir, package_names(version))
    opener = build_opener(PublicRedirects()) if opener is None else opener
    tag = f"v{version}"
    release = verify_metadata(opener, tag, revision, expected)
    with TemporaryDirectory(dir=output_dir.parent, prefix=".workerOS-public-") as temporary:
        staged = Path(temporary) / "verified"
        staged.mkdir()
        for name, info in expected.items():
            url = f"{PUBLIC}/download/{tag}/{name}"
            with public_response(opener, url) as response, (staged / name).open("wb") as output:
                require(fingerprint(response, output, limit=info[0]) == info,
                        f"public bytes do not match the staged {name}")
        require(verify_metadata(opener, tag, revision, expected) == release,
                "public release identity changed during verification")
        require_empty_output(output_dir)
        os.replace(staged, output_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("revision")
    parser.add_argument("expected_dir", metavar="EXPECTED_ASSETS_DIR", type=Path)
    parser.add_argument("output_dir", metavar="OUTPUT_DIR", type=Path)
    args = parser.parse_args()
    try:
        verify_public_release(args.version, args.revision, args.expected_dir, args.output_dir)
    except (OSError, ValueError) as exc:
        print(f"Public release verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"Verified anonymous release v{args.version} at {args.revision} (seven assets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
