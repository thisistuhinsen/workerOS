"""Read one byte without changing the inherited original's offset."""

import os


def main():
    value = os.environ.get("WORKER_HANDOFF_FD_INPUT", "")
    if (os.environ.get("WORKER_HANDOFF_ABI") != "1" or not value.isascii()
            or not value.isdecimal() or len(value) > 10):
        return 2
    fd = int(value)
    if not 3 <= fd <= 2**31 - 1 or str(fd) != value:
        return 2
    try:
        try:
            byte = os.pread(fd, 1, 0)
        finally:
            os.close(fd)
    except OSError:
        return 1
    return int(byte != b"W")


if __name__ == "__main__":
    raise SystemExit(main())
