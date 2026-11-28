"""Archive-level release checks using ordinary inert vendor and wheel fixtures."""

from hashlib import sha256
from pathlib import Path
import runpy
import stat
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile


SCRIPTS = Path(__file__).resolve().parents[1]
packer = SimpleNamespace(**runpy.run_path(str(SCRIPTS / "package-owned-bwrap.py")))


class OwnedRuntimeReleaseTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.base = self.root / "workeros-0.8.0-py3-none-any.whl"
        self.prefix = "workeros-0.8.0.dist-info/"
        self.binary = self.root / "bwrap"
        self.license = self.root / "COPYING"
        self.binary.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00GLIBC_2.38\0")
        self.license.write_bytes(b"license fixture")
        self.enterContext(patch.dict(packer.verify_inputs.__globals__, {
            "LICENSE_SHA256": sha256(self.license.read_bytes()).hexdigest(),
        }))
        with ZipFile(self.base, "w") as wheel:
            wheel.writestr("workeros/managed_executor.py",
                           f"_OWNED_BWRAP_SHA256 = {sha256(self.binary.read_bytes()).hexdigest()!r}\n")
            wheel.writestr(self.prefix + "WHEEL", b"Wheel-Version: 1.0\nTag: py3-none-any\n")
            wheel.writestr(self.prefix + "RECORD", b"")

    def package(self, destination):
        return packer.package(self.base, self.binary, self.license, destination)

    def test_layer_reproduces_and_binds_exact_plain_wheel(self):
        peer = self.root / "peer"
        peer.mkdir()
        candidate = self.package(self.root)
        packer.verify(self.base, candidate)
        self.assertEqual(candidate.read_bytes(), self.package(peer).read_bytes())
        with ZipFile(candidate) as wheel:
            runtime = wheel.getinfo("workeros/_runtime/bwrap")
            self.assertEqual(runtime.external_attr >> 16, stat.S_IFREG | 0o755)
            self.assertEqual(wheel.read(runtime), self.binary.read_bytes())

    def test_missing_and_nonmatching_inputs_do_not_publish_wheel(self):
        self.binary.unlink()
        with self.assertRaisesRegex(ValueError, "required managed runtime input"):
            self.package(self.root)
        self.binary.write_bytes(b"ordinary different fixture")
        with self.assertRaisesRegex(ValueError, "does not match the reviewed pin"):
            self.package(self.root)
        self.assertEqual(list(self.root.glob("*linux*.whl")), [])

    def test_license_must_match_reviewed_bytes(self):
        self.license.write_bytes(b"different license fixture")
        with self.assertRaisesRegex(ValueError, "license does not match the reviewed pin"):
            self.package(self.root)

    def test_platform_verifier_rejects_metadata_and_record_changes(self):
        candidate = self.package(self.root)
        for name, match in (
            ("workeros/managed_executor.py", "changed the original member"),
            (self.prefix + "RECORD", "RECORD does not bind"),
        ):
            with self.subTest(member=name):
                peer = Path(self.enterContext(TemporaryDirectory()))
                changed = peer / candidate.name
                with ZipFile(candidate) as original, ZipFile(changed, "w") as wheel:
                    for info in original.infolist():
                        contents = b"ordinary altered fixture" if info.filename == name else original.read(info)
                        wheel.writestr(info, contents)
                with self.assertRaisesRegex(ValueError, match):
                    packer.verify(self.base, changed)

    def test_release_script_refuses_requested_missing_inputs_before_build(self):
        output = self.root / "not-created"
        result = subprocess.run(
            ["bash", str(SCRIPTS / "build-release.sh"), "--build-only", "--owned-runtime-dir",
             str(self.root / "missing"), str(output)], capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Missing reviewed regular managed runtime file", result.stderr)
        self.assertFalse(output.exists())
