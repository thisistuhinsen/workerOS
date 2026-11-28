"""Publish a caller-owned copy of a result without replacing existing files."""

import errno
import json
import os
from pathlib import Path
from secrets import token_hex
import stat


RESULT_VERSION = 1


def report_path(value):
    """Validate an explicit destination and capture the caller's current base."""
    try:
        name = os.fspath(value)
        if (type(name) is not str or not name or '\0' in name
                or name.rsplit('/', 1)[-1] in ('', '.', '..')):
            raise ValueError('invalid_report_destination')
        path = Path(name)
        return path if path.is_absolute() else Path.cwd() / path
    except (OSError, TypeError) as exc:
        raise ValueError('invalid_report_destination') from exc


def default_report_path(value, base_dir):
    """Bind a relative default to an explicit absolute document base."""
    try:
        path = Path(value)
        if path.is_absolute():
            return report_path(value)
        base = Path(base_dir)
        if not base.is_absolute() or '\0' in str(base):
            raise ValueError('invalid_report_destination')
        report_path(value)
        return base / path
    except TypeError as exc:
        raise ValueError('invalid_report_destination') from exc


def can_export():
    """Avoid using elevated credentials to publish a caller's chosen path."""
    uid = os.getuid()
    if not uid or os.getresuid() != (uid,) * 3 or os.getresgid() != (os.getgid(),) * 3:
        return False
    try:
        with open('/proc/self/status', encoding='ascii') as status:
            for field in status:
                if field.startswith('CapEff:'):
                    return int(field.partition(':')[2], 16) == 0
    except (OSError, ValueError):
        pass
    return False


def _open_directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open(path.anchor, flags)
    try:
        for name in path.parts[1:]:
            child = os.open(name, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(errno.EACCES, 'report directory is not private to its owner')
        return directory
    except BaseException:
        os.close(directory)
        raise


def export_report(path, result):
    """Publish a complete local copy and return a redacted export disposition."""
    directory = None
    temporary = None
    publishing = False
    published = False
    if not can_export():
        return {'status': 'failed', 'code': 'unprivileged_report_caller_required'}
    try:
        directory = _open_directory(path.parent)
        name = '.workeros-report-' + token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        temporary = name
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump(result, output, ensure_ascii=True, separators=(',', ':'), sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        # A same-directory link makes the complete file visible and enforces no replacement.
        publishing = True
        os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        published = True
        os.unlink(temporary, dir_fd=directory)
        temporary = None
        os.fsync(directory)
        return {'status': 'written', 'code': 'report_written'}
    except OSError as exc:
        if published:
            return {'status': 'unknown', 'code': 'report_durability_unconfirmed'}
        code = {
            errno.EEXIST: 'report_destination_exists',
            errno.ENOENT: 'report_parent_missing',
            errno.ENOTDIR: 'report_parent_unavailable',
            errno.ELOOP: 'report_parent_unavailable',
            errno.EACCES: 'report_destination_denied',
            errno.EPERM: 'report_destination_denied',
            errno.ENOSPC: 'report_storage_exhausted',
            errno.EDQUOT: 'report_storage_exhausted',
        }.get(exc.errno, 'report_write_failed')
        return {'status': 'failed', 'code': code}
    except KeyboardInterrupt:
        if publishing:
            return {'status': 'unknown', 'code': 'report_durability_unconfirmed'}
        return {'status': 'failed', 'code': 'report_interrupted'}
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
        if directory is not None:
            os.close(directory)
