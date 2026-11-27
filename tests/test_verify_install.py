"""Installed package verification against caller-pinned wheel bytes."""

from hashlib import sha256
from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from worker_handoff.verify_install import VerificationError, verify_install


class VerifyInstallTest(TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.wheel = self.directory / "candidate.whl"
        self.distribution = metadata.distribution("workeros")

    def build_fixture(self, *, alter=None):
        with ZipFile(self.wheel, "w", ZIP_DEFLATED) as archive:
            for entry in self.distribution.files:
                name = str(entry)
                if (not name.startswith("worker_handoff/") or "__pycache__" in entry.parts
                        or name.endswith(".pyc")):
                    continue
                data = Path(self.distribution.locate_file(entry)).read_bytes()
                archive.writestr(name, data + b"\n" if name == alter else data)
            archive.writestr("workeros.dist-info/METADATA",
                             f"Metadata-Version: 2.1\nName: workeros\nVersion: {self.distribution.version}\n")
        return sha256(self.wheel.read_bytes()).hexdigest()

    def test_matches_loaded_package_and_rejects_wrong_digest(self):
        digest = self.build_fixture()
        result = verify_install(self.wheel, digest)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["version"], self.distribution.version)
        with self.assertRaisesRegex(VerificationError, "wheel_digest_mismatch"):
            verify_install(self.wheel, "0" * 64)

    def test_refuses_package_content_mismatch_and_ambiguous_owners(self):
        digest = self.build_fixture(alter="worker_handoff/managed.py")
        with self.assertRaisesRegex(VerificationError, "installed_package_file_mismatch"):
            verify_install(self.wheel, digest)
        digest = self.build_fixture()
        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=[self.distribution, self.distribution]):
            with self.assertRaisesRegex(VerificationError, "ambiguous_distribution"):
                verify_install(self.wheel, digest)
        other_owner = SimpleNamespace(metadata={"Name": "other-package"},
                                      files=("worker_handoff/managed.py",))
        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=[self.distribution, other_owner]):
            with self.assertRaisesRegex(VerificationError, "ambiguous_distribution"):
                verify_install(self.wheel, digest)
