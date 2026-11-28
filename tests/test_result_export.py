"""Caller-owned export is separate from guarded outcomes and transport."""

from contextlib import chdir, redirect_stderr, redirect_stdout
import errno
from io import BytesIO, StringIO, TextIOWrapper
import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from workeros import managed_executor, result_export


class ResultExportTest(unittest.TestCase):
    request_id = 'a' * 64
    workflow = 'sample-workflow'
    terminal = {'status': 'terminal', 'effect': 'dispatched', 'code': 'service_observed'}

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        # A real disposable test under a non-administrator must qualify the
        # privilege gate. On a root-capable CI runner exercise the file logic
        # under the process's own directory and test the gate separately.
        if os.getuid() == 0:
            check = patch.object(result_export, 'can_export', return_value=True)
            self.addCleanup(check.stop)
            check.start()

    def invoke(self, *args, document=b''):
        output, diagnostics = StringIO(), StringIO()
        with (redirect_stdout(output), redirect_stderr(diagnostics),
              patch.object(managed_executor.sys, 'stdin', TextIOWrapper(BytesIO(document)))):
            status = managed_executor.main('launch-status', args)
        return status, json.loads(output.getvalue()), diagnostics.getvalue()

    def test_flags_json_yaml_and_python_copy_the_same_result(self):
        yaml_python = os.environ.get('WORKEROS_YAML_PYTHON')
        if yaml_python and Path(yaml_python).absolute() != Path(sys.executable).absolute():
            # The main CI test environment intentionally has no PyYAML.
            # Run this complete parity assertion in the same installed
            # optional environment used by the other YAML integration tests.
            child = subprocess.run([
                yaml_python, '-I', '-c',
                'import sys, unittest; sys.path.insert(0, sys.argv[1]); '
                'unittest.main(module="test_result_export", argv=["unittest", sys.argv[2]])',
                str(Path(__file__).resolve().parent),
                'ResultExportTest.test_flags_json_yaml_and_python_copy_the_same_result',
            ], capture_output=True, text=True, timeout=12)
            self.assertEqual(child.returncode, 0, child.stderr)
            return
        keys = {'version': 1, 'workflow': self.workflow, 'request_id': self.request_id}
        flags = ('--workflow', self.workflow, '--request-id', self.request_id)
        body = json.dumps({**keys, 'report': 'évidence one.json'}).encode()
        yaml = ('version: 1\nworkflow: ' + self.workflow + '\nrequest_id: "' + self.request_id
                + '"\nreport: yaml.json\n').encode()
        with (chdir(self.directory), patch.object(managed_executor, '_registered_launch',
                                                  return_value=self.terminal) as readback):
            for arguments, document, name in [
                    ((*flags, '--report', 'flags.json'), b'', 'flags.json'),
                    (('--format', 'json'), body, 'évidence one.json'),
                    (('--format', 'yaml'), yaml, 'yaml.json'),
                    (('--format', 'json', '--report', 'override.json'), body, 'override.json')]:
                with self.subTest(name=name):
                    status, result, diagnostics = self.invoke(*arguments, document=document)
                    self.assertEqual((status, diagnostics, result.pop('export')['status']), (0, '', 'written'))
                    self.assertEqual(json.loads(Path(name).read_bytes()), result)
                    self.assertEqual(result, {**keys, **self.terminal})
                    self.assertEqual(Path(name).stat().st_mode & 0o777, 0o600)
            result = managed_executor.registered_launch(
                self.request_id, workflow=self.workflow, readback=True, report=Path('python.json'))
            self.assertEqual(result.pop('export')['status'], 'written')
            self.assertEqual(json.loads(Path('python.json').read_text()), result)
            self.assertEqual(readback.call_count, 5)
            for invocation in readback.call_args_list:
                self.assertEqual(invocation.args, (self.request_id, self.workflow, True))

    def test_failed_export_preserves_effect_and_offers_same_id_readback(self):
        target = self.directory / 'existing.json'
        target.write_text('keep')
        with patch.object(managed_executor, '_registered_launch', return_value=self.terminal) as operation:
            args = ('--workflow', self.workflow, '--request-id', self.request_id, '--report', str(target))
            status, result, diagnostics = self.invoke(*args)
            operation.assert_called_once_with(self.request_id, self.workflow, True)
        self.assertEqual((status, result['status'], result['effect']), (1, 'terminal', 'dispatched'))
        self.assertEqual(result['export'], {'status': 'failed', 'code': 'report_destination_exists',
                         'next_action': {'operation': 'launch-status', 'workflow': self.workflow,
                                         'request_id': self.request_id}})
        self.assertEqual(target.read_text(), 'keep')
        self.assertNotIn(str(target), diagnostics)
        self.assertIn(self.request_id, diagnostics)

    def test_explicit_report_overrides_file_relative_default(self):
        profile = self.directory / 'profile é'
        profile.mkdir()
        document = profile / 'request.json'
        keys = {'version': 1, 'workflow': self.workflow, 'request_id': self.request_id}
        document.write_text(json.dumps({**keys, 'report_default': 'saved.json'}))
        args = ('--format', 'json', '--input', str(document))
        with (chdir(self.directory), patch.object(managed_executor, '_registered_launch',
                                                  return_value=self.terminal) as operation):
            status, result, _ = self.invoke(*args)
            self.assertEqual((status, result['export']['status']), (0, 'written'))
            self.assertTrue((profile / 'saved.json').is_file())
            status, result, _ = self.invoke(*args, '--report', 'override.json')
            self.assertEqual((status, result['export']['status']), (0, 'written'))
            self.assertTrue(Path('override.json').is_file())
            body = json.dumps({**keys, 'report_default': 'saved.json'}).encode()
            status, result, _ = self.invoke('--format', 'json', document=body)
            self.assertEqual((status, result['code']), (1, 'invalid_report_destination'))
            record = managed_executor.registered_launch(self.request_id, workflow=self.workflow,
                       readback=True, report_default='from-python.json', base_dir=profile)
            self.assertEqual(record['export']['status'], 'written')
            self.assertTrue((profile / 'from-python.json').is_file())
            self.assertEqual(operation.call_count, 3)

    def test_report_path_refuses_before_dispatch_when_invalid_or_privileged(self):
        with patch.object(managed_executor, '_registered_launch') as operation:
            invalid = managed_executor.registered_launch(self.request_id, report='')
            with patch.object(result_export, 'can_export', return_value=False):
                elevated = managed_executor.registered_launch(self.request_id, report=self.directory / 'no.json')
            operation.assert_not_called()
        self.assertEqual((invalid['code'], invalid['effect']), ('invalid_report_destination', 'not_attempted'))
        self.assertEqual((elevated['code'], elevated['effect']),
                         ('unprivileged_report_caller_required', 'not_attempted'))

    def test_invalid_arguments_use_versioned_machine_refusal(self):
        status, result, diagnostics = self.invoke('--request-id', self.request_id, '--report')
        self.assertEqual((status, diagnostics), (1, ''))
        self.assertEqual(result, {'version': 1, 'status': 'refused', 'effect': 'not_attempted',
                                  'code': 'invalid_launch_request'})

    def test_failed_and_concurrent_publications_leave_no_partial_copy(self):
        target = self.directory / 'same.json'
        missing = self.directory / 'missing' / target.name
        self.assertEqual(result_export.export_report(missing, self.terminal)['code'], 'report_parent_missing')
        with patch.object(result_export.os, 'fsync', side_effect=OSError(errno.ENOSPC, 'synthetic full storage')):
            self.assertEqual(result_export.export_report(target, self.terminal)['code'], 'report_storage_exhausted')
        with patch.object(result_export.os, 'fsync', side_effect=KeyboardInterrupt):
            self.assertEqual(result_export.export_report(target, self.terminal)['code'], 'report_interrupted')
        self.assertEqual(list(self.directory.iterdir()), [])
        with ThreadPoolExecutor(max_workers=2) as threads:
            results = list(threads.map(lambda _source: result_export.export_report(target, self.terminal), range(2)))
        self.assertCountEqual([result['code'] for result in results], ['report_written', 'report_destination_exists'])
        self.assertEqual(json.loads(target.read_text()), self.terminal)
        self.assertEqual(list(self.directory.iterdir()), [target])

    def test_export_refuses_unowned_path_types_and_preserves_destination(self):
        target = self.directory / 'report.json'
        target.mkdir()
        self.assertEqual(result_export.export_report(target, self.terminal)['code'], 'report_destination_exists')
        shared = self.directory / 'shared'
        shared.mkdir()
        shared.chmod(0o775)
        self.assertEqual(result_export.export_report(shared / target.name, self.terminal)['code'],
                         'report_destination_denied')
        self.assertTrue(target.is_dir())
        self.assertEqual(list(shared.iterdir()), [])
