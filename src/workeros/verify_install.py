"""Compare installed WorkerOS package files with a separately trusted wheel."""

import argparse
from hashlib import sha256
from importlib import metadata, util
import json
from pathlib import Path, PurePosixPath
import re
import sys
from zipfile import BadZipFile, ZipFile


class VerificationError(ValueError):
    """The installed package could not be matched to the expected artifact."""


def verify_install(wheel, expected_sha256):
    """Verify package files against wheel bytes whose digest is trusted by the caller.

    This is a point-in-time file comparison. It does not authenticate the
    expected digest, protect files from later change, or inspect Python objects
    already modified in memory.
    """
    if type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise VerificationError("invalid_expected_digest")
    try:
        with Path(wheel).open("rb") as stream:
            digest = sha256()
            while data := stream.read(1024 * 1024):
                digest.update(data)
            if digest.hexdigest() != expected_sha256:
                raise VerificationError("wheel_digest_mismatch")
            stream.seek(0)
            with ZipFile(stream) as archive:
                names = archive.namelist()
                if len(set(names)) != len(names):
                    raise VerificationError("ambiguous_wheel")
                modules = [name for name in names if name.startswith("workeros/") and not name.endswith("/")]
                if not modules or "workeros/__init__.py" not in modules:
                    raise VerificationError("wheel_package_missing")
                for name in modules:
                    path = PurePosixPath(name)
                    info = archive.getinfo(name)
                    if (str(path) != name or ".." in path.parts or "\\" in name
                            or info.file_size > 16 * 1024 * 1024):
                        raise VerificationError("invalid_wheel_entry")
                owners = []
                seen_locations = set()
                for dist in metadata.distributions():
                    name = re.sub(r"[-_.]+", "-", dist.metadata.get("Name", "")).lower()
                    files = dist.files or ()
                    owns_package = any(str(path).startswith("workeros/") for path in files)
                    if name != "workeros" and not owns_package:
                        continue
                    # Some platform installation schemes expose the same
                    # site-packages directory through multiple sys.path
                    # spellings (for example Fedora's lib and lib64 paths).
                    # Collapse only aliases of both the metadata directory and
                    # its installation root. Either location can differ.
                    metadata_dir = getattr(dist, "_path", None)
                    if isinstance(dist, metadata.PathDistribution) and isinstance(metadata_dir, Path):
                        try:
                            location = (metadata_dir.resolve(strict=True),
                                        Path(dist.locate_file("")).resolve(strict=True))
                        except (OSError, RuntimeError):
                            pass
                        else:
                            if location in seen_locations:
                                continue
                            seen_locations.add(location)
                    owners.append(dist)
                if len(owners) != 1 or re.sub(r"[-_.]+", "-", owners[0].metadata["Name"]).lower() != "workeros":
                    raise VerificationError("ambiguous_distribution")
                dist = owners[0]
                records = dist.files
                if records is None:
                    raise VerificationError("installed_manifest_missing")
                installed = {str(path) for path in records if str(path).startswith("workeros/")
                             and "__pycache__" not in path.parts and not str(path).endswith(".pyc")}
                if installed != set(modules):
                    raise VerificationError("installed_package_file_set_mismatch")
                for name in modules:
                    target = Path(dist.locate_file(name))
                    if target.is_symlink() or not target.is_file():
                        raise VerificationError("installed_package_file_missing")
                    if target.read_bytes() != archive.read(name):
                        raise VerificationError("installed_package_file_mismatch")
                expected_init = Path(dist.locate_file("workeros/__init__.py")).resolve(strict=True)
                spec = util.find_spec("workeros")
                if spec is None or spec.origin is None or Path(spec.origin).resolve(strict=True) != expected_init:
                    raise VerificationError("loaded_package_mismatch")
                loaded = sys.modules.get("workeros")
                if loaded is None or Path(loaded.__file__).resolve(strict=True) != expected_init:
                    raise VerificationError("loaded_package_mismatch")
                for name, loaded_module in tuple(sys.modules.items()):
                    if not name.startswith("workeros.") or loaded_module is None:
                        continue
                    origin = getattr(loaded_module, "__file__", None)
                    if origin is None:
                        raise VerificationError("loaded_module_mismatch")
                    path = Path(origin).resolve(strict=True)
                    if not path.is_relative_to(expected_init.parent):
                        raise VerificationError("loaded_module_mismatch")
                    relative = "workeros/" + path.relative_to(expected_init.parent).as_posix()
                    if relative not in modules:
                        raise VerificationError("loaded_module_mismatch")
                wheel_metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
                if len(wheel_metadata) != 1:
                    raise VerificationError("ambiguous_wheel_metadata")
                from email.parser import BytesParser
                meta = BytesParser().parsebytes(archive.read(wheel_metadata[0]))
                if meta["Name"] != "workeros" or meta["Version"] != dist.version:
                    raise VerificationError("wheel_version_mismatch")
                return {"status": "matched", "version": dist.version,
                        "wheel_sha256": expected_sha256, "package_files": len(modules)}
    except VerificationError:
        raise
    except (OSError, BadZipFile, KeyError, ValueError, TypeError) as exc:
        raise VerificationError("verification_unavailable") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", help="wheel file from a trusted source")
    parser.add_argument("--sha256", required=True, help="independently trusted wheel SHA-256")
    args = parser.parse_args(argv)
    try:
        result = verify_install(args.wheel, args.sha256)
    except VerificationError as exc:
        print(json.dumps({"status": "refused", "code": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
