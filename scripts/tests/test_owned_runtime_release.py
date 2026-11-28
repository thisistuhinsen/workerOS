"""Archive-level release checks using ordinary inert vendor and wheel fixtures."""

from hashlib import sha256
from pathlib import Path
import runpy
import shutil
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
            for path, data in packer.source_provenance().items():
                self.assertEqual(wheel.read(self.prefix + path), data)

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

    def test_missing_and_changed_provenance_leaves_no_output_wheel(self):
        for name in ("libcap-Ubuntu-copyright.txt", "inputs.lock.tsv"):
            with self.subTest(name=name):
                directory = Path(self.enterContext(TemporaryDirectory())) / "owned-runtime"
                shutil.copytree(packer.PROVENANCE_DIR, directory)
                member = directory / name
                with patch.dict(packer.verify_inputs.__globals__, {"PROVENANCE_DIR": directory}):
                    member.unlink()
                    with self.assertRaisesRegex(ValueError, "not a regular file"):
                        self.package(self.root)
                    member.write_bytes(b"ordinary unrelated fixture")
                    with self.assertRaisesRegex(ValueError, "provenance does not match the reviewed pin"):
                        self.package(self.root)
                self.assertEqual(list(self.root.glob("*linux*.whl")), [])

    def test_ingress_binds_the_checked_out_pin_and_exact_two_file_artifact(self):
        runtime = self.root / "approved"
        runtime.mkdir()
        for member in (self.binary, self.license):
            (runtime / member.name).write_bytes(member.read_bytes())
        executor = self.root / "managed_executor.py"
        with ZipFile(self.base) as wheel:
            executor.write_bytes(wheel.read("workeros/managed_executor.py"))
        packer.verify_ingress(executor, runtime)
        (runtime / "extra").touch()
        with self.assertRaisesRegex(ValueError, "expected only bwrap and COPYING"):
            packer.verify_ingress(executor, runtime)
        (runtime / "extra").unlink()
        (runtime / "bwrap").write_bytes(b"not the approved executable")
        with self.assertRaisesRegex(ValueError, "does not match the reviewed pin"):
            packer.verify_ingress(executor, runtime)
        (runtime / "bwrap").unlink()
        (runtime / "bwrap").symlink_to(self.binary)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            packer.verify_ingress(executor, runtime)

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

    def test_platform_verifier_rejects_missing_or_changed_runtime_inputs(self):
        candidate = self.package(self.root)
        for name, message in (
            (self.prefix + "licenses/Bubblewrap-COPYING", "license does not match"),
            (self.prefix + "licenses/Libcap-COPYRIGHT", "provenance does not match"),
            (self.prefix + "runtime-provenance/inputs.lock.tsv", "provenance does not match"),
            ("workeros/_runtime/bwrap", "runtime does not match"),
        ):
            for skip_member in (False, True):
                with self.subTest(name=name, missing=skip_member):
                    peer = Path(self.enterContext(TemporaryDirectory()))
                    changed = peer / candidate.name
                    with ZipFile(candidate) as original, ZipFile(changed, "w") as wheel:
                        for info in original.infolist():
                            if info.filename != name:
                                wheel.writestr(info, original.read(info))
                            elif not skip_member:
                                wheel.writestr(info, b"ordinary unrelated fixture")
                    with self.assertRaisesRegex(
                        ValueError, "unexpected owned runtime wheel inventory" if skip_member else message
                    ):
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

    def test_release_script_refuses_requested_off_pin_inputs_before_build(self):
        runtime = self.root / "artifact"
        runtime.mkdir()
        for member in (self.binary, self.license):
            (runtime / member.name).write_bytes(member.read_bytes())
        output = self.root / "not-created"
        result = subprocess.run(
            ["bash", str(SCRIPTS / "build-release.sh"), "--build-only", "--owned-runtime-dir",
             str(runtime), str(output)], capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1, result)
        self.assertIn("does not match the reviewed pin", result.stderr)
        self.assertFalse(output.exists())
