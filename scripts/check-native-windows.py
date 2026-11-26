"""Probe the installed WorkerOS Linux-only boundary on native Windows."""

from importlib.metadata import distribution, packages_distributions
from importlib.util import find_spec
import os
from pathlib import Path
import re
import subprocess
import sys
import sysconfig
import traceback


CONSOLES = ("workeros-config", "worker-handoff-config")
MISSING_FCNTL = "ModuleNotFoundError: No module named 'fcntl'"


def require(condition, message):
    if not condition:
        raise SystemExit(f"Native Windows boundary not verified: {message}")


def main(version):
    require(sys.platform == "win32" and os.name == "nt"
            and sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14),
            "requires native Windows CPython 3.14")
    prefix = Path(sys.prefix).resolve()
    require(sys.flags.isolated and prefix != Path(sys.base_prefix).resolve(),
            "run the probe with -I inside the installed wheel's virtual environment")
    require(not Path.cwd().resolve().is_relative_to(Path(__file__).resolve().parents[1]),
            "run the probe outside the source checkout")

    package = distribution("workeros")
    site = Path(sysconfig.get_path("purelib")).resolve()
    scripts = Path(sysconfig.get_path("scripts")).resolve()
    require(site.is_relative_to(prefix) and scripts.is_relative_to(prefix),
            "installation paths are outside the virtual environment")
    require(package.metadata["Name"] == "workeros" and package.version == version
            and Path(package.locate_file("")).resolve() == site
            and packages_distributions().get("worker_handoff") == ["workeros"],
            "wrong distribution, version, location, or import owner")
    installed = {Path(package.locate_file(path)).resolve() for path in package.files or ()}
    original = site / "worker_handoff" / "original.py"
    init = site / "worker_handoff" / "__init__.py"
    spec = find_spec("worker_handoff")
    require(original.is_file() and init.is_file() and {original, init} <= installed
            and spec is not None and spec.origin is not None and Path(spec.origin).resolve() == init,
            "worker_handoff does not resolve to the installed wheel")
    print(f"Installed {package.metadata['Name']} {package.version} at {site}")
    print(f"Native interpreter {sys.executable} ({sys.version})")

    try:
        import worker_handoff
    except ModuleNotFoundError as exc:
        frames = {Path(frame.filename).resolve() for frame in traceback.extract_tb(exc.__traceback__)}
        require(exc.name == "fcntl" and {original, init} <= frames,
                "raw import failed outside the expected installed fcntl boundary")
        print("Raw import: expected missing fcntl from the installed wheel")
    else:
        raise SystemExit("Native Windows boundary not verified: raw import unexpectedly succeeded")

    entry_points = {entry.name: entry.value for entry in package.entry_points
                    if entry.group == "console_scripts"}
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("PYTHON")}
    environment.update(PYTHONNOUSERSITE="1", PYTHONSAFEPATH="1", PYTHON_COLORS="0")
    for command in CONSOLES:
        executable = scripts / f"{command}.exe"
        require(executable in installed and executable.is_file()
                and entry_points.get(command) == "worker_handoff.configuration_cli:main",
                f"missing or wrong installed launcher for {command}")
        outcome = subprocess.run(
            [str(executable), "--schema"], env=environment, capture_output=True, text=True, timeout=15,
        )
        frames = {Path(path).resolve()
                  for path in re.findall(r'^\s*File "([^"]+)", line \d+', outcome.stderr, re.MULTILINE)}
        require(outcome.returncode != 0 and not outcome.stdout
                and outcome.stderr.rstrip().endswith(MISSING_FCNTL) and {original, init} <= frames,
                f"{command} failed outside the expected installed fcntl boundary: {outcome.stderr.strip()}")
        print(f"{executable}: expected missing fcntl (exit {outcome.returncode})")


if __name__ == "__main__":
    require(len(sys.argv) == 2, "usage: python -I check-native-windows.py VERSION")
    main(sys.argv[1])
