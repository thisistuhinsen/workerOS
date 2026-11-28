"""Verify the bundle's kernel descriptor boundary without starting a service."""

from contextlib import ExitStack
from dataclasses import asdict, replace
import errno
import fcntl
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from workeros.managed_service_scope import ServiceBundle, ServiceCapability, ServiceDescriptor, ServiceRefusal


class ManagedServiceScopeTest(TestCase):
    def setUp(self):
        self.stack = self.enterContext(ExitStack())
        self.root = Path(self.stack.enter_context(TemporaryDirectory()))

    def open_fd(self, path, flags):
        fd = os.open(path, flags | os.O_CLOEXEC)
        self.stack.callback(os.close, fd)
        return fd

    def descriptor(self, path, *, slot='stdin', scope='report', mode='read', flags=os.O_RDONLY):
        fd = self.open_fd(path, flags)
        info = os.fstat(fd)
        return ServiceDescriptor(slot, scope, info.st_uid, mode, info.st_dev, info.st_ino, fd)

    def bundle(self, descriptors, **values):
        params = dict(root_directory='/approved/rootfs', root_device=1, root_inode=2,
                      executable='/processor', principal_gid=1, descriptors=descriptors,
                      active_ms=1000, cleanup_ms=500, metered=False)
        return ServiceBundle(**{**params, **values})

    def test_exact_retained_read_write_original_survives_path_replacement(self):
        path = self.root / 'report'
        path.write_bytes(b'report')
        reference = self.descriptor(path, mode='read-write', flags=os.O_RDWR)
        bundle = self.bundle((reference,), observation_scope='report')
        original = self.root / 'held'
        with ExitStack() as resources:
            retained = bundle.retain(resources)
            fd = retained.streams['stdin']
            self.assertNotEqual(fd, reference.fd)
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(retained.digest, bundle.digest)
            self.assertEqual(retained.observation_original, reference.original)
            path.rename(original)
            path.write_bytes(b'newest')
            retained.check_original()
            self.assertEqual(os.pread(fd, 6, 0), b'report')
            self.assertEqual(os.pwrite(fd, b'R', 0), 1)
            self.assertEqual(original.read_bytes(), b'Report')
            self.assertEqual(path.read_bytes(), b'newest')
        with self.assertRaises(OSError) as error:
            os.fstat(fd)
        self.assertEqual(error.exception.errno, errno.EBADF)

    def test_read_write_and_write_only_descriptor_rights_reject_mode_substitution(self):
        path = self.root / 'report'
        path.write_bytes(b'report')
        reader = self.descriptor(path)
        writer = self.descriptor(path, slot='stdout', mode='write', flags=os.O_WRONLY)
        with self.assertRaises(OSError) as read_error:
            os.pwrite(reader.fd, b'R', 0)
        self.assertEqual(read_error.exception.errno, errno.EBADF)
        with self.assertRaises(OSError) as write_error:
            os.pread(writer.fd, 6, 0)
        self.assertEqual(write_error.exception.errno, errno.EBADF)
        for entry in (reader, writer):
            self.bundle((entry,)).check_original()
        for entry in (replace(reader, mode='read-write'), replace(writer, mode='read-write'),
                      replace(reader, owner_uid=(reader.owner_uid + 1) % 65536),
                      replace(reader, inode=reader.inode + 1),
                      replace(reader, fd=self.open_fd(path, os.O_PATH)),
                      replace(writer, fd=self.open_fd(path, os.O_WRONLY | os.O_APPEND)),
                      replace(reader, fd=self.open_fd(self.root, os.O_RDONLY | os.O_DIRECTORY))):
            with self.subTest(entry=entry), self.assertRaisesRegex(
                    ServiceRefusal, '^service_descriptor_mismatch$'):
                self.bundle((entry,)).check_original()

    def test_retention_refusal_closes_every_duplicate_but_not_originals(self):
        readable = self.root / 'readable'
        writable = self.root / 'writable'
        readable.touch()
        writable.touch()
        reader = self.descriptor(readable)
        writer = self.descriptor(writable, slot='stdout', scope='output', mode='write', flags=os.O_WRONLY)
        writer = replace(writer, owner_uid=(writer.owner_uid + 1) % 65536)
        bundle = self.bundle((reader, writer))
        duplicated = []
        real_fcntl = fcntl.fcntl

        def collect(fd, command, *args):
            result = real_fcntl(fd, command, *args)
            if command == fcntl.F_DUPFD_CLOEXEC:
                duplicated.append(result)
            return result

        with ExitStack() as resources, patch.object(fcntl, 'fcntl', side_effect=collect):
            with self.assertRaisesRegex(ServiceRefusal, '^service_descriptor_mismatch$'):
                bundle.retain(resources)
        self.assertEqual(len(duplicated), 2)
        for fd in duplicated:
            with self.assertRaises(OSError) as error:
                os.fstat(fd)
            self.assertEqual(error.exception.errno, errno.EBADF)
        for entry in (reader, writer):
            self.assertEqual(os.fstat(entry.fd).st_ino, entry.inode)

    def test_overflow_uid_is_not_an_exact_owner(self):
        path = self.root / 'report'
        path.touch()
        entry = self.descriptor(path)
        with patch('workeros.managed_service_scope._overflow_uid', return_value=entry.owner_uid):
            with self.assertRaisesRegex(ServiceRefusal, '^service_descriptor_owner_unmapped$'):
                self.bundle((entry,)).check_original()

    def test_manifest_digest_canonicalizes_slot_order_and_excludes_live_fd_numbers(self):
        input_slot = ServiceDescriptor('stdin', 'document', 124, 'read', 1, 30, 5)
        output_slot = ServiceDescriptor('stdout', 'result', 125, 'write', 1, 31, 6)
        a = self.bundle([asdict(output_slot), asdict(input_slot)], observation_scope='document', metered=True)
        b = self.bundle((replace(input_slot, fd=90), replace(output_slot, fd=91)),
                        observation_scope='document', metered=True)
        self.assertEqual(a.digest, b.digest)
        self.assertEqual(tuple(a.streams), ('stdin', 'stdout'))
        self.assertEqual(a.operations, {'read', 'write'})
        self.assertEqual(a.observation_original, ('1', '30'))
        self.assertIsNone(replace(a, observation_scope=None).observation_original)
        for changed in (replace(a, root_inode=3), replace(a, active_ms=1001),
                        replace(a, observation_scope='result'), replace(a, metered=False),
                        replace(a, descriptors=(replace(input_slot, mode='read-write'), output_slot)),
                        replace(a, descriptors=(replace(input_slot, owner_uid=126), output_slot))):
            self.assertNotEqual(a.digest, changed.digest)

    def test_manifest_refuses_duplicate_or_unapproved_roles(self):
        input_slot = ServiceDescriptor('stdin', 'document', 124, 'read', 1, 30, 5)
        output_slot = ServiceDescriptor('stdout', 'result', 125, 'write', 1, 31, 6)
        for crossed_slot in (replace(output_slot, slot=input_slot.slot),
                             replace(output_slot, scope=input_slot.scope),
                             replace(output_slot, owner_uid=input_slot.owner_uid),
                             replace(output_slot, fd=input_slot.fd),
                             replace(output_slot, inode=input_slot.inode)):
            with self.subTest(crossed_slot=crossed_slot), self.assertRaisesRegex(
                    ServiceRefusal, '^duplicate_service_descriptor$'):
                self.bundle((input_slot, crossed_slot))
        with self.assertRaisesRegex(ServiceRefusal, '^service_observation_scope_mismatch$'):
            self.bundle((input_slot, output_slot), observation_scope='unrelated')
        with self.assertRaisesRegex(ServiceRefusal, '^invalid_service_descriptors$'):
            self.bundle([asdict(input_slot), 'untrusted'])
        bundle = self.bundle((input_slot, output_slot))
        role = {'scopes': ['document', 'result'], 'operations': ['launch', 'read', 'write'],
                'resources': {'document': {'device': '1', 'inode': '30'},
                              'result': {'device': '1', 'inode': '31'}}}
        self.assertTrue(bundle.match_role(role))
        self.assertFalse(bundle.match_role({**role, 'operations': ['launch', 'read']}))
        self.assertFalse(bundle.match_role({**role, 'scopes': ['document']}))
        wrong_identity = {**role['resources'], 'result': {'device': '1', 'inode': '30'}}
        self.assertFalse(bundle.match_role({**role, 'resources': wrong_identity}))
        wrong_owner = {**role['resources'], 'result': {'device': '1', 'inode': '31', 'owner_uid': 124}}
        self.assertFalse(bundle.match_role({**role, 'resources': wrong_owner}))

    def test_elevated_manifest_requires_all_exact_admin_capabilities(self):
        reader = ServiceDescriptor('stdin', 'input', 124, 'read', 1, 30, 5)
        writer = ServiceDescriptor('stdout', 'output', 125, 'write', 1, 31, 6)
        entries = (reader, writer)
        capabilities = (ServiceCapability('copy-source', 'input', 'read'),
                        ServiceCapability('record-result', 'output', 'write'))
        bundle = self.bundle(entries, elevated_capabilities=capabilities)
        privileges = [{'capability': entry.name, 'scope': entry.scope, 'approved': True} for entry in capabilities]
        role = {'scopes': ['input', 'output'], 'operations': ['launch', *(entry.name for entry in capabilities)],
                'resources': {'input': {'device': '1', 'inode': '30'}, 'output': {'device': '1', 'inode': '31'}},
                'privileged': privileges, 'operation_aliases': {entry.name: {
                    'scope': entry.scope, 'capability': entry.operation, 'provider_sha256': bundle.digest}
                    for entry in capabilities}}
        self.assertTrue(bundle.match_role(role))
        self.assertEqual(bundle.digest, self.bundle(entries, elevated_capabilities=capabilities[::-1]).digest)
        self.assertNotEqual(bundle.digest, self.bundle(entries).digest)
        self.assertFalse(bundle.match_role({**role, 'privileged': privileges[:1]}))
        self.assertFalse(bundle.match_role({**role, 'privileged': [{**privileges[0], 'approved': False}, privileges[1]]}))
        with self.assertRaisesRegex(ServiceRefusal, '^service_capability_scope_mismatch$'):
            self.bundle(entries, elevated_capabilities=(replace(capabilities[0], operation='write'),))

    def test_manifest_enforces_enrollment_budgets_and_typed_meter_selection(self):
        entry = ServiceDescriptor('stdin', 'document', 124, 'read', 1, 30, 5)
        self.bundle((entry,), active_ms=86_400_000, cleanup_ms=60_000)
        for values in ({'active_ms': 0}, {'active_ms': 86_400_001}, {'active_ms': True},
                       {'cleanup_ms': 0}, {'cleanup_ms': 60_001}, {'cleanup_ms': ''}):
            with self.subTest(values=values), self.assertRaisesRegex(ServiceRefusal, '^invalid_service_budget$'):
                self.bundle((entry,), **values)
        with self.assertRaisesRegex(ServiceRefusal, '^invalid_service_meter$'):
            self.bundle((entry,), metered=1)
