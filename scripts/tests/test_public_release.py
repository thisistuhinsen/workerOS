"""Inert fixtures for the public release readback gate."""

from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from urllib.error import HTTPError
from urllib.request import Request


gate = SimpleNamespace(**runpy.run_path(str(Path(__file__).parents[1] / "check-public-release.py")))
VERSION = "0.5.0"
TAG = f"v{VERSION}"
COMMIT = "a" * 40
REF_URL = f"{gate.API}/git/ref/tags/{TAG}"
RELEASE_URL = f"{gate.API}/releases/tags/{TAG}"
PACKAGES = (
    f"workeros-{VERSION}-py3-none-any.whl",
    f"workeros-{VERSION}.tar.gz",
    f"workeros-{VERSION}.tgz",
    f"workeros-{VERSION}.jar",
    f"workeros-{VERSION}.pom",
    f"workeros-conan-{VERSION}.tar.gz",
)


class Response(BytesIO):
    status = 200

    def __init__(self, body, url):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url


class PublicFixture:
    def __init__(self, files):
        assets = []
        self.metadata = {
            REF_URL: {"ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": COMMIT}},
            RELEASE_URL: {
                "id": 40, "tag_name": TAG, "html_url": f"{gate.PUBLIC}/tag/{TAG}",
                "draft": False, "prerelease": False, "assets": assets,
            },
        }
        self.downloads = {}
        for asset_id, (name, data) in enumerate(files.items(), start=100):
            url = f"{gate.PUBLIC}/download/{TAG}/{name}"
            self.downloads[url] = data
            assets.append({
                "id": asset_id, "name": name, "browser_download_url": url, "state": "uploaded",
                "size": len(data), "digest": f"sha256:{sha256(data).hexdigest()}",
            })
        self.after_download = {}
        self.requests = []

    def open(self, request, *, timeout):
        url = request.full_url
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") is None
        assert request.get_header("Cookie") is None
        assert request.get_header("Cache-control") == "no-cache"
        assert timeout > 0
        downloaded = any(prior in self.downloads for prior in self.requests)
        self.requests.append(url)
        if url in self.metadata:
            value = self.after_download.get(url, self.metadata[url]) if downloaded else self.metadata[url]
            return Response(json.dumps(value).encode("utf-8"), url)
        if url in self.downloads:
            return Response(self.downloads[url], "https://release-assets.githubusercontent.com/fixture")
        raise HTTPError(url, 404, "Not found", {}, BytesIO())


class PublicReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.expected = self.root / "candidate"
        self.expected.mkdir()
        self.output = self.root / "public"
        self.files = {name: f"staged fixture for {name}\n".encode() for name in PACKAGES}
        self.files["SHA256SUMS"] = "".join(
            f"{sha256(data).hexdigest()}  {name}\n" for name, data in self.files.items()
        ).encode("ascii")
        for name, data in self.files.items():
            (self.expected / name).write_bytes(data)
        self.fixture = PublicFixture(self.files)

    def verify(self):
        gate.verify_public_release(VERSION, COMMIT, self.expected, self.output, opener=self.fixture)

    def test_anonymous_readback_promotes_exact_bytes_only_after_verification(self):
        self.output.mkdir()
        self.verify()
        self.assertEqual({path.name: path.read_bytes() for path in self.output.iterdir()}, self.files)
        self.assertEqual(self.fixture.requests, [
            REF_URL, RELEASE_URL, *self.fixture.downloads, REF_URL, RELEASE_URL,
        ])

    def test_optional_exact_platform_wheel_is_bound_to_manifest_and_readback(self):
        name = f"workeros-{VERSION}-py3-none-linux_x86_64.whl"
        data = b"optional wheel byte fixture"
        self.files[name] = data
        self.files["SHA256SUMS"] += f"{sha256(data).hexdigest()}  {name}\n".encode("ascii")
        (self.expected / name).write_bytes(data)
        (self.expected / "SHA256SUMS").write_bytes(self.files["SHA256SUMS"])
        self.fixture = PublicFixture(self.files)
        self.verify()
        self.assertEqual({path.name: path.read_bytes() for path in self.output.iterdir()}, self.files)

    def test_different_platform_is_refused_before_network_io(self):
        (self.expected / f"workeros-{VERSION}-py3-none-linux_aarch64.whl").write_bytes(b"foreign fixture")
        with self.assertRaisesRegex(gate.VerificationError, "unexpected staged asset set"):
            self.verify()
        self.assertEqual(self.fixture.requests, [])

    def test_missing_annotated_or_wrong_tag_refused_before_downloading(self):
        baseline = self.fixture.metadata[REF_URL]
        for target in (None, {"type": "tag", "sha": COMMIT}, {"type": "commit", "sha": "b" * 40}):
            with self.subTest(target=target):
                self.fixture.metadata[REF_URL] = {**baseline, "object": target}
                self.fixture.requests.clear()
                with self.assertRaises(gate.VerificationError):
                    self.verify()
                self.assertEqual(self.fixture.requests, [REF_URL])
                self.assertFalse(self.output.exists())
        del self.fixture.metadata[REF_URL]
        with self.assertRaisesRegex(gate.VerificationError, "HTTP 404"):
            self.verify()

    def test_unknown_release_and_foreign_asset_metadata_fail_closed(self):
        baseline = deepcopy(self.fixture.metadata[RELEASE_URL])
        for field, value in (
            ("draft", True), ("prerelease", None), ("prerelease", True),
            ("tag_name", "v0.6.0"), ("html_url", "https://example.invalid/release"),
            ("assets", baseline["assets"][:-1]), ("assets", baseline["assets"] + baseline["assets"][:1]),
        ):
            with self.subTest(field=field, value=value):
                self.fixture.metadata[RELEASE_URL] = {**baseline, field: value}
                with self.assertRaises(gate.VerificationError):
                    self.verify()
        for field, value in (
            ("name", "foreign"), ("size", True), ("digest", None), ("state", "new"),
            ("browser_download_url", "https://example.invalid/asset"),
        ):
            with self.subTest(asset_field=field):
                assets = deepcopy(baseline["assets"])
                assets[0][field] = value
                self.fixture.metadata[RELEASE_URL] = {**baseline, "assets": assets}
                with self.assertRaises(gate.VerificationError):
                    self.verify()
        self.assertFalse(self.output.exists())
        self.assertTrue(set(self.fixture.requests) <= {REF_URL, RELEASE_URL})

    def test_stage_manifest_must_match_all_local_packages_before_network_io(self):
        manifest = self.expected / "SHA256SUMS"
        manifest.write_bytes(b"".join(self.files["SHA256SUMS"].splitlines(keepends=True)[:-1]))
        with self.assertRaisesRegex(gate.VerificationError, "staged SHA256SUMS"):
            self.verify()
        self.assertEqual(self.fixture.requests, [])
        self.assertFalse(self.output.exists())

    def test_corrupt_late_download_never_exposes_partial_output(self):
        sum_url = f"{gate.PUBLIC}/download/{TAG}/SHA256SUMS"
        self.output.mkdir()
        candidate = self.files["SHA256SUMS"]
        for corrupt in (b"?" + candidate[1:], candidate + b"x"):
            with self.subTest(size=len(corrupt)):
                self.fixture.downloads[sum_url] = corrupt
                with self.assertRaises(gate.VerificationError):
                    self.verify()
                self.assertEqual(list(self.output.iterdir()), [])
        self.assertFalse(any(self.root.glob(".workerOS-public-*")))

    def test_release_identity_change_after_download_is_refused(self):
        self.fixture.after_download[RELEASE_URL] = {**self.fixture.metadata[RELEASE_URL], "id": 41}
        with self.assertRaisesRegex(gate.VerificationError, "identity changed"):
            self.verify()
        self.assertFalse(self.output.exists())

    def test_https_redirects_allow_only_expected_github_hosts(self):
        redirect = gate.PublicRedirects().redirect_request
        source = Request(next(iter(self.fixture.downloads)))
        accepted = "https://release-assets.githubusercontent.com/asset"
        self.assertEqual(redirect(source, None, 302, "", {}, accepted).full_url, accepted)
        for target in (
            "http://github.com/asset",
            "https://example.invalid/asset",
            "https://account@github.com/asset",
            "https://github.com:80/asset",
        ):
            with self.subTest(target=target), self.assertRaises(gate.VerificationError):
                redirect(source, None, 302, "", {}, target)
        with self.assertRaises(gate.VerificationError):
            redirect(Request(REF_URL), None, 302, "", {}, accepted)
