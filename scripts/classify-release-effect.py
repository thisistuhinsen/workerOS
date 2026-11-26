"""Classify release effects in supplied GitHub snapshots without making requests."""

import argparse
import json
from pathlib import Path
import re


VERSION = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")
SHA = re.compile(r"[a-f0-9]{40}")
INVALID_REF_CHARACTER = re.compile(r"[\x00-\x20\x7f~^:?*\\\[]")
PROOF = re.compile(
    r"^<!-- workerOS release run [1-9][0-9]*/[1-9][0-9]* \(([a-f0-9]{40})\) -->$",
    re.MULTILINE,
)


def _checked_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON object members")
    return value


def _invalid_constant(_):
    raise ValueError("invalid JSON constant")


def _read_snapshot(path, label):
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(
                source, object_pairs_hook=_checked_object, parse_constant=_invalid_constant,
            )
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"cannot read a valid {label} JSON snapshot") from exc


def _exact_refs(refs, target):
    if type(refs) is not list:
        raise ValueError("matching-refs snapshot must be an array")
    matches = []
    for position, row in enumerate(refs, 1):
        if type(row) is not dict:
            raise ValueError(f"invalid ref at position {position}")
        ref, object_ = row.get("ref"), row.get("object")
        if (type(ref) is not str or not ref.startswith("refs/tags/")
                or INVALID_REF_CHARACTER.search(ref) or ".." in ref or "@{" in ref
                or ref.endswith(".")
                or any(not part or part.startswith(".") or part.endswith(".lock") for part in ref.split("/"))
                or type(object_) is not dict):
            raise ValueError(f"invalid ref at position {position}")
        kind, sha = object_.get("type"), object_.get("sha")
        if kind not in ("commit", "tag", "tree", "blob") or type(sha) is not str or not SHA.fullmatch(sha):
            raise ValueError(f"invalid ref object at position {position}")
        if ref == target:
            matches.append((kind, sha))
    return matches


def _check_releases(releases, tag):
    if type(releases) is not list:
        raise ValueError("releases-for-tag snapshot must be an array")
    for position, row in enumerate(releases, 1):
        if (type(row) is not dict or row.get("tag_name") != tag or type(row.get("draft")) is not bool
                or type(row.get("id")) is not int or row["id"] <= 0
                or (row.get("body") is not None and type(row["body"]) is not str)):
            raise ValueError(f"invalid release for {tag} at position {position}")


def classify_release_effect(version, sha, refs, releases):
    if not VERSION.fullmatch(version) or not SHA.fullmatch(sha):
        raise ValueError("expected a numeric three-part version and a lowercase 40-digit commit SHA")
    tag = f"v{version}"
    matches = _exact_refs(refs, f"refs/tags/{tag}")
    _check_releases(releases, tag)

    if len(matches) > 1 or len(releases) > 1:
        return 1, f"STOP unknown: multiple exact refs or releases for {tag}"
    if not matches and not releases:
        return 0, f"CLEAR: no exact tag or release for {tag} in the supplied snapshots"

    expected = ("commit", sha)
    target = matches[0] if matches else None
    target_description = "exact tag absent" if target is None else f"tag points to {target[0]} {target[1]}"
    if target is not None and target != expected:
        target_description += f", expected commit {sha}"
    release = releases[0] if releases else None
    if release is not None and not release["draft"]:
        return 1, f"STOP published: release {release['id']} for {tag} is published, {target_description}"
    if target is not None and target != expected:
        detail = f", draft {release['id']} also exists" if release is not None else ""
        return 1, f"STOP divergent-tag: {tag} {target_description}{detail}"
    if release is None:
        return 1, f"STOP tag-only: {tag} {target_description}, no release in the snapshot"
    if target == expected and PROOF.findall(release.get("body") or "") == [sha]:
        return 1, f"STOP recognized-draft: release {release['id']} for {tag} has the expected workflow marker"
    return 1, f"STOP unrecognized-draft: release {release['id']} for {tag} has no matching tag and marker pair"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("sha")
    parser.add_argument("refs_json", type=Path)
    parser.add_argument("releases_json", type=Path)
    args = parser.parse_args()
    try:
        status, summary = classify_release_effect(
            args.version, args.sha, _read_snapshot(args.refs_json, "matching-refs"),
            _read_snapshot(args.releases_json, "releases-for-tag"),
        )
    except ValueError as exc:
        status, summary = 1, f"STOP malformed: {exc}"
    print(summary)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
