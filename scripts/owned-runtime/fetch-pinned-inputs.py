"""Materialize the pinned upstream source and exact Ubuntu toolchain closure."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit


def fetch(row, output):
    expected, name, url = row
    target = output / name
    target.parent.mkdir(exist_ok=True)
    subprocess.run(
        ["curl", "--fail", "--silent", "--show-error", "--location",
         "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15",
         "--max-time", "90", "--retry", "1", "--output", str(target), url],
        check=True,
    )
    with target.open("rb") as stream:
        actual = sha256()
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            actual.update(data)
    if actual.hexdigest() != expected:
        raise ValueError(f"SHA-256 mismatch: {name}")
    target.chmod(0o644)
    return f"{expected}  {name}\n"


def main(lock, output):
    rows = [line.split("\t") for line in lock.read_text().splitlines()]
    names = set()
    for digest, name, url in rows:
        address = urlsplit(url)
        if (re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or re.fullmatch(r"(?:(?:toolchain|addons)/)?[a-zA-Z0-9_.%~+-]+", name) is None
                or ".." in name or name in names or address.scheme != "https"
                or address.netloc not in {"snapshot.ubuntu.com", "github.com"}):
            raise ValueError("unexpected pinned dependency entry")
        names.add(name)
    with ThreadPoolExecutor(max_workers=6) as pool:
        checksums = tuple(pool.map(lambda row: fetch(row, output), rows))
    (output / "SHA256SUMS").write_text("".join(checksums))
    print(f"Verified {len(checksums)} input digests")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
