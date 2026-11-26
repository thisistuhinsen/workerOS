import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


INSTALLED = Path(sys.prefix) / "share" / "worker-handoff" / "examples" / "run_inherited_fd.py"
CHECKOUT = Path(__file__).resolve().parents[1] / "examples" / "run_inherited_fd.py"


class ExampleLauncherTest(unittest.TestCase):
    def run_examples(self, *options, platform=None):
        launcher = str(INSTALLED if INSTALLED.is_file() else CHECKOUT)
        command = [sys.executable]
        if INSTALLED.is_file():
            command.append("-I")
        if platform is not None:
            command.extend(("-c", """
import runpy
import sys
from types import SimpleNamespace

platform = sys.argv.pop(1)
sys.argv.pop(0)
main = runpy.run_path(sys.argv[0])["main"]
main.__globals__["sys"] = SimpleNamespace(platform=platform)
raise SystemExit(main())
""", platform))
        with TemporaryDirectory() as empty:
            return subprocess.run(
                [*command, launcher, *options], env={**os.environ, "PATH": empty},
                text=True, capture_output=True, timeout=20,
            )

    def test_selected_python_passes_with_other_languages_unselected(self):
        result = self.run_examples("--language", "python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Python: PASSED", result.stdout)
        self.assertIn("Node.js: SKIPPED (language was not selected)", result.stdout)

    def test_selected_unavailable_language_fails_even_with_another_success(self):
        result = self.run_examples("--language", "node", "--language", "python")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Node.js: UNAVAILABLE (node was not found on PATH)", result.stdout)
        self.assertIn("Python: PASSED", result.stdout)

    def test_default_discovery_tolerates_missing_toolchains(self):
        result = self.run_examples()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Node.js: UNAVAILABLE (node was not found on PATH)", result.stdout)
        self.assertIn("Python: PASSED", result.stdout)

    def test_selected_unsupported_platform_reports_skip_and_fails(self):
        result = self.run_examples("--language", "python", platform="win32")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Python: SKIPPED (Linux required)", result.stdout, result.stderr)
