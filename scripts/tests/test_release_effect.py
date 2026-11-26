"""Fixture-only checks for the release effect classifier's file input."""
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "classify-release-effect.py"
VERSION = "0.5.0"
SHA = "a" * 40
OTHER_SHA = "b" * 40
TAG = f"v{VERSION}"
REF = f"refs/tags/{TAG}"


def tag_ref(name=REF, sha=SHA, kind="commit"):
    return {"ref": name, "object": {"type": kind, "sha": sha}}


def release(*, tag=TAG, draft=True, body=None):
    return {"id": 7, "tag_name": tag, "draft": draft, "body": body}


def proof(sha=SHA):
    return f"<!-- workerOS release run 123/2 ({sha}) -->"


class ReleaseEffectTest(unittest.TestCase):
    def classify(self, refs, releases, *, version=VERSION, sha=SHA, raw_refs=None, raw_releases=None):
        with TemporaryDirectory() as directory:
            refs_file = Path(directory, "refs.json")
            releases_file = Path(directory, "releases.json")
            refs_file.write_text(raw_refs if raw_refs is not None else json.dumps(refs), encoding="utf-8")
            releases_file.write_text(
                raw_releases if raw_releases is not None else json.dumps(releases), encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), version, sha, str(refs_file), str(releases_file)],
                capture_output=True, text=True, timeout=5,
            )
        self.assertNotIn("Traceback", result.stderr)
        return result

    def assert_stopped(self, label, refs, releases, **kwargs):
        result = self.classify(refs, releases, **kwargs)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"STOP {label}:", result.stdout)

    def test_cli_clears_only_absent_exact_ref_and_release(self):
        for refs in ([], [tag_ref(name=f"{REF}0"), tag_ref(name="refs/tags/v0.4.9")]):
            with self.subTest(refs=refs):
                result = self.classify(refs, [])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("CLEAR:", result.stdout)
                self.assertIn(TAG, result.stdout)

    def test_timed_out_mutation_effects_are_distinguished_from_absence(self):
        cases = (
            ("tag-only", [tag_ref()], []),
            ("recognized-draft", [tag_ref()], [release(body=f"Release notes\n\n{proof()}")]),
            ("published", [tag_ref()], [release(draft=False)]),
            ("published", [], [release(draft=False)]),
        )
        for label, refs, releases in cases:
            with self.subTest(label=label):
                self.assert_stopped(label, refs, releases)

    def test_divergent_tag_identity_is_never_clear(self):
        for ref in (tag_ref(sha=OTHER_SHA), tag_ref(kind="tag")):
            with self.subTest(ref=ref):
                self.assert_stopped("divergent-tag", [ref], [release(body=proof())])

    def test_draft_proof_requires_exact_ref_sha_and_single_marker(self):
        for body in (None, proof(OTHER_SHA), f"x {proof()}", f"{proof()}\n{proof()}"):
            with self.subTest(body=body):
                self.assert_stopped("unrecognized-draft", [tag_ref()], [release(body=body)])
        self.assert_stopped("unrecognized-draft", [], [release(body=proof())])

    def test_ambiguous_duplicate_effects_stop(self):
        self.assert_stopped("unknown", [tag_ref(), tag_ref(sha=OTHER_SHA)], [])
        self.assert_stopped("unknown", [tag_ref()], [release(), release()])

    def test_malformed_snapshots_take_precedence_over_effects(self):
        cases = (
            ({}, [release(draft=False)]),
            ([tag_ref(sha=OTHER_SHA)], {}),
            ([tag_ref(), {"ref": f"{REF}0", "object": {}}], []),
            ([tag_ref(name=f"{REF} "), tag_ref()], []),
            ([tag_ref()], [release(tag=f"{TAG}0")]),
            ([tag_ref()], [release(draft="false")]),
            ([tag_ref()], [release(body=False)]),
        )
        for refs, releases in cases:
            with self.subTest(refs=refs, releases=releases):
                self.assert_stopped("malformed", refs, releases)
        self.assert_stopped("malformed", [], [], raw_refs="[")
        self.assert_stopped("malformed", [], [], raw_refs='[{"ref":0,"ref":"r"}]')
        self.assert_stopped("malformed", [], [], raw_releases="")

    def test_malformed_expected_identity_stops(self):
        self.assert_stopped("malformed", [], [], version="v0.5.0")
        self.assert_stopped("malformed", [], [], sha=SHA[:-1])


if __name__ == "__main__":
    unittest.main()
