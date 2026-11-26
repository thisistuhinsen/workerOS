import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest import TestCase


GATE = Path(__file__).resolve().parents[1] / "release-target.sh"


class ReleaseTargetTest(TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.repository = root / "repo"
        self.repository.mkdir()
        self.output = root / "outputs"
        self.env = {
            "PATH": os.environ["PATH"],
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_TERMINAL_PROMPT": "0",
        }
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("remote", "add", "origin", str(self.repository))
        (self.repository / ".github").mkdir()
        (self.repository / ".github/release-version").write_text("0.4.0\n")
        (self.repository / "pyproject.toml").write_text('[project]\nversion = "0.5.0"\n')
        self.base = self.commit("Candidate")

    def git(self, *args):
        return subprocess.run(
            ("git", *args), cwd=self.repository, env=self.env, check=True,
            text=True, capture_output=True, timeout=10,
        ).stdout.strip()

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def marker(self, contents="0.5.0\n", *, extra=False):
        (self.repository / ".github/release-version").write_text(contents)
        if extra:
            (self.repository / "extra").write_text("unrelated change\n")
        return self.commit("Marker")

    def run_gate(self, **overrides):
        head = self.git("rev-parse", "HEAD")
        self.output.write_text("")
        env = self.env | {
            "GITHUB_REPOSITORY": "thisistuhinsen/workerOS",
            "GITHUB_REF": "refs/heads/main",
            "DEFAULT_BRANCH": "main",
            "GITHUB_SHA": head,
            "REF_PROTECTED": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "REQUESTED_REVISION": head,
            "REQUESTED_VERSION": "0.5.0",
            "REQUESTED_PUBLISH": "false",
            "BEFORE_SHA": self.base,
            "GITHUB_OUTPUT": str(self.output),
        } | overrides
        result = subprocess.run(
            ("bash", str(GATE)), cwd=self.repository, env=env, text=True,
            capture_output=True, timeout=10,
        )
        return result, self.output.read_text()

    def assert_refused(self, **overrides):
        result, output = self.run_gate(**overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(output, "")

    def test_read_only_staging_requires_current_sha_and_version(self):
        result, output = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "version=0.5.0\npublish=false\n")
        self.assert_refused(REQUESTED_VERSION="0.4.0")
        self.assert_refused(REQUESTED_REVISION="1" * 40)
        self.assert_refused(GITHUB_REF="refs/pull/11/merge")
        self.assert_refused(GITHUB_REPOSITORY="example/another-repo")

    def test_publish_requires_marker_and_protected_main(self):
        self.assert_refused(REQUESTED_PUBLISH="true")
        self.marker()
        self.assert_refused(REQUESTED_PUBLISH="true", REF_PROTECTED="false")
        result, output = self.run_gate(GITHUB_EVENT_NAME="push")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "version=0.5.0\npublish=true\n")
        self.assert_refused(GITHUB_EVENT_NAME="push", BEFORE_SHA="1" * 40)

    def test_refuses_non_marker_changes(self):
        self.marker(extra=True)
        self.assert_refused(REQUESTED_PUBLISH="true")

    def test_refuses_inexact_marker_bytes(self):
        self.marker("0.5.0\n\n")
        self.assert_refused(GITHUB_EVENT_NAME="push")

    def test_refuses_marker_symlink_to_matching_bytes(self):
        marker = self.repository / ".github/release-version"
        marker.with_name("other-version").write_text("0.5.0\n")
        self.base = self.commit("Existing version file")
        marker.unlink()
        marker.symlink_to("other-version")
        self.commit("Symlink marker")
        self.assert_refused(GITHUB_EVENT_NAME="push")

    def test_refuses_stale_checkout_even_for_staging(self):
        self.marker()
        self.git("checkout", "-q", "--detach", self.base)
        self.assert_refused()

    def test_refuses_two_parent_marker_merge(self):
        self.git("switch", "-qc", "marker")
        self.marker()
        self.git("switch", "-q", "main")
        self.git("merge", "-q", "--no-ff", "marker")
        self.assert_refused(GITHUB_EVENT_NAME="push")
