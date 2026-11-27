"""Installed package verification against caller-pinned wheel bytes."""

from copy import copy
from hashlib import sha256
from importlib import metadata
from pathlib import Path
from shutil import copytree
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
        # Two sys.path spellings can make importlib.metadata yield the same
        # physical .dist-info tree twice. That is one installation, not two.
        alias_parent = self.directory / "site-packages-alias"
        alias_parent.symlink_to(self.distribution._path.parent, target_is_directory=True)
        alias_distributions = [dist for dist in metadata.distributions(
            path=[str(self.distribution._path.parent), str(alias_parent)])
            if dist.metadata["Name"] == "workeros"]
        self.assertEqual(len(alias_distributions), 2)
        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=alias_distributions):
            self.assertEqual(verify_install(self.wheel, digest)["status"], "matched")

        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=[self.distribution, self.distribution]):
            self.assertEqual(verify_install(self.wheel, digest)["status"], "matched")
        separate_parent = self.directory / "second-site-packages"
        separate_parent.mkdir()
        separate_metadata = separate_parent / self.distribution._path.name
        copytree(self.distribution._path, separate_metadata)
        separate_distribution = copy(self.distribution)
        separate_distribution._path = separate_metadata
        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=[self.distribution, separate_distribution]):
            with self.assertRaisesRegex(VerificationError, "ambiguous_distribution"):
                verify_install(self.wheel, digest)
        linked_metadata = self.directory / "third-site-packages" / self.distribution._path.name
        linked_metadata.parent.mkdir()
        linked_metadata.symlink_to(self.distribution._path, target_is_directory=True)
        linked_distribution = metadata.PathDistribution(linked_metadata)
        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=[self.distribution, linked_distribution]):
            with self.assertRaisesRegex(VerificationError, "ambiguous_distribution"):
                verify_install(self.wheel, digest)
        other_owner = SimpleNamespace(metadata={"Name": "other-package"},
                                      files=("worker_handoff/managed.py",))
        with patch("worker_handoff.verify_install.metadata.distributions",
                   return_value=[self.distribution, other_owner]):
            with self.assertRaisesRegex(VerificationError, "ambiguous_distribution"):
                verify_install(self.wheel, digest)
