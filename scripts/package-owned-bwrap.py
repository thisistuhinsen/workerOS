#!/usr/bin/env python3
"""Build or check the platform wheel containing the reviewed WorkerOS runtime."""
import argparse
import ast
import base64
import csv
from hashlib import sha256
from io import StringIO
from pathlib import Path
import stat
import sys
import zipfile


PLAIN_TAG = 'py3-none-any'
RUNTIME_TAG = 'py3-none-linux_x86_64'
RUNTIME_PATH = 'workeros/_runtime/bwrap'
RUNTIME_REQUIRED = 'workeros/_runtime/REQUIRED'
RUNTIME_DESCRIPTION = b'WorkerOS pinned Bubblewrap 0.12.0\n'
LICENSE_SHA256 = 'dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551'


def digest(body):
    return 'sha256=' + base64.urlsafe_b64encode(sha256(body).digest()).decode().rstrip('=')


def wheel_identity(wheel):
    suffix = f'-{PLAIN_TAG}.whl'
    if not wheel.name.startswith('workeros-') or not wheel.name.endswith(suffix):
        raise ValueError('expected the plain WorkerOS wheel')
    name = wheel.name.removesuffix(suffix)
    return name, name + '.dist-info/'


def read_entries(wheel):
    entries = {}
    with zipfile.ZipFile(wheel) as archive:
        for item in archive.infolist():
            if item.filename in entries:
                raise ValueError('repeated wheel member')
            entries[item.filename] = (item, archive.read(item))
    return entries


def verify_runtime(source, runtime, license_text):
    manifest = ast.parse(source)
    pins = [ast.literal_eval(node.value) for node in manifest.body if isinstance(node, ast.Assign)
            and any(isinstance(key, ast.Name) and key.id == '_OWNED_BWRAP_SHA256' for key in node.targets)]
    if len(pins) != 1:
        raise ValueError('managed runtime pin missing or repeated')
    pin, = pins
    if sha256(runtime).hexdigest() != pin:
        raise ValueError('managed runtime does not match the reviewed pin')
    if (runtime[:6] != b'\x7fELF\x02\x01' or runtime[18:20] != b'\x3e\x00'
            or b'GLIBC_2.38\0' not in runtime):
        raise ValueError('unexpected managed runtime ABI')
    if sha256(license_text).hexdigest() != LICENSE_SHA256:
        raise ValueError('upstream Bubblewrap license does not match the reviewed pin')


def verify_inputs(entries, runtime, license_text):
    verify_runtime(entries['workeros/managed_executor.py'][1], runtime, license_text)


def platform_metadata(body):
    marker = f'Tag: {PLAIN_TAG}\n'.encode()
    if body.count(marker) != 1 or body.count(b'Tag: ') != 1:
        raise ValueError('unexpected input wheel platform')
    return body.replace(marker, f'Tag: {RUNTIME_TAG}\n'.encode())


def input_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'required managed runtime input is not a regular file: {path.name}')
    return path.read_bytes()


def verify_ingress(executor, directory):
    if (directory.is_symlink() or not directory.is_dir()
            or {item.name for item in directory.iterdir()} != {'bwrap', 'COPYING'}):
        raise ValueError('expected only bwrap and COPYING in the approved runtime artifact')
    verify_runtime(input_bytes(executor), input_bytes(directory / 'bwrap'),
                   input_bytes(directory / 'COPYING'))


def package(wheel, binary, license_file, output):
    name, info = wheel_identity(wheel)
    entries = read_entries(wheel)
    runtime, license_text = input_bytes(binary), input_bytes(license_file)
    verify_inputs(entries, runtime, license_text)
    metadata, body = entries[info + 'WHEEL']
    entries[info + 'WHEEL'] = (metadata, platform_metadata(body))

    def extra(path, content, mode):
        if path in entries:
            raise ValueError('wheel already owns a runtime')
        item = zipfile.ZipInfo(path, date_time=metadata.date_time)
        item.create_system = 3
        item.external_attr = (stat.S_IFREG | mode) << 16
        item.compress_type = zipfile.ZIP_DEFLATED
        entries[path] = (item, content)

    extra(RUNTIME_PATH, runtime, 0o755)
    extra(RUNTIME_REQUIRED, RUNTIME_DESCRIPTION, 0o644)
    extra(info + 'licenses/Bubblewrap-COPYING', license_text, 0o644)
    record_path = info + 'RECORD'
    record_info, _ = entries.pop(record_path)
    record = StringIO(newline='')
    rows = csv.writer(record, lineterminator='\n')
    for member, (_, data) in entries.items():
        rows.writerow((member, digest(data), len(data)))
    rows.writerow((record_path, '', ''))
    entries[record_path] = (record_info, record.getvalue().encode())
    result = output / f'{name}-{RUNTIME_TAG}.whl'
    with zipfile.ZipFile(result, 'x') as candidate:
        for item, data in entries.values():
            candidate.writestr(item, data)
    return result


def verify(wheel, platform_wheel):
    name, info = wheel_identity(wheel)
    if platform_wheel.name != f'{name}-{RUNTIME_TAG}.whl':
        raise ValueError('unexpected platform wheel name')
    plain, platform = read_entries(wheel), read_entries(platform_wheel)
    wheel_path, record_path = info + 'WHEEL', info + 'RECORD'
    license_path = info + 'licenses/Bubblewrap-COPYING'
    added = {RUNTIME_PATH: 0o755, RUNTIME_REQUIRED: 0o644, license_path: 0o644}
    if set(plain) & added.keys() or set(platform) != set(plain) | added.keys():
        raise ValueError('unexpected owned runtime wheel inventory')
    for path, (original, contents) in plain.items():
        current, candidate = platform[path]
        if path == wheel_path:
            contents = platform_metadata(contents)
        if ((current.create_system, current.external_attr) != (original.create_system, original.external_attr)
                or (path != record_path and contents != candidate)):
            raise ValueError(f'platform wheel changed the original member: {path}')
    for path, mode in added.items():
        member, _ = platform[path]
        if member.create_system != 3 or member.external_attr >> 16 != stat.S_IFREG | mode:
            raise ValueError(f'unexpected managed runtime member mode: {path}')
    if platform[RUNTIME_REQUIRED][1] != RUNTIME_DESCRIPTION:
        raise ValueError('unexpected owned-runtime marker')
    verify_inputs(plain, platform[RUNTIME_PATH][1], platform[license_path][1])
    reader = csv.reader(StringIO(platform[record_path][1].decode(), newline=''))
    rows = [tuple(row) for row in reader]
    expected = {(path, digest(data), str(len(data))) for path, (_, data) in platform.items() if path != record_path}
    expected.add((record_path, '', ''))
    if len(rows) != len(expected) or set(rows) != expected:
        raise ValueError('platform wheel RECORD does not bind the exact wheel members')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    if sys.argv[1:2] == ['--verify-ingress']:
        parser.add_argument('executor', type=Path)
        parser.add_argument('runtime_dir', type=Path)
        args = parser.parse_args(sys.argv[2:])
        verify_ingress(args.executor, args.runtime_dir)
    elif sys.argv[1:2] == ['--verify']:
        parser.add_argument('wheel', type=Path)
        parser.add_argument('platform_wheel', type=Path)
        args = parser.parse_args(sys.argv[2:])
        verify(args.wheel, args.platform_wheel)
    else:
        for argument in ('wheel', 'binary', 'license', 'output'):
            parser.add_argument(argument, type=Path)
        args = parser.parse_args()
        print(package(args.wheel, args.binary, args.license, args.output))
