"""Durable journal tests on owned disposable files, with no provider authority."""
import os
from dataclasses import asdict, replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from worker_handoff.managed_host import ManagedHostAdapter
from worker_handoff.managed_journal import ManagedJournal
from worker_handoff.profile_setup import SetupResult
from test_aggregate_setup import make_scope


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name); self.directory.chmod(0o700)
        self.scopes=tuple(make_scope(n,'run-'+n) for n in ('one','two','three'))
        self.defs=tuple(s.manager.selection.definition for s in self.scopes)
        self.journal=ManagedJournal(self.directory,definitions=self.defs)
        self.identity='a'*64; self.key='b'*64

    def test_claim_is_durable_and_never_replayed(self):
        self.assertEqual(self.journal.read(self.identity,self.key).state,'not_started')
        self.assertEqual(self.journal.claim(self.identity,self.key),'claimed')
        self.assertEqual(ManagedJournal(self.directory,definitions=self.defs).read(self.identity,self.key).state,'pending')
        self.assertEqual(ManagedJournal(self.directory,definitions=self.defs).claim(self.identity,self.key),'existing')

    def test_final_result_survives_separate_process(self):
        self.assertEqual(self.journal.claim(self.identity,self.key),'claimed')
        results=tuple((d.name,SetupResult('accepted','manager_readback_verified','unknown',d)) for d in self.defs)
        self.assertTrue(self.journal.finish(self.identity,self.key,results))
        code='''import sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[2])\nfrom test_aggregate_setup import make_scope\nfrom worker_handoff.managed_journal import ManagedJournal\nd=tuple(make_scope(n,"run-"+n).manager.selection.definition for n in ("one","two","three"))\nj=ManagedJournal(Path(sys.argv[1]),definitions=d)\nr=j.read("a"*64,"b"*64)\nprint(r.state, len(r.results), j.claim("a"*64,"b"*64))\n'''
        result=subprocess.run([sys.executable,'-I','-c',code,str(self.directory),str(Path(__file__).parent.resolve())],
                              capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'recorded 3 existing')

    def test_partial_claim_stays_unavailable(self):
        key=self.journal._key(self.identity,self.key,'claim')
        (self.directory/('.'+key.filename()+'.pending')).write_bytes(b'partial')
        self.assertEqual(self.journal.read(self.identity,self.key).state,'unavailable')

    def test_untrusted_directory_is_not_not_started(self):
        self.directory.chmod(0o777)
        self.assertEqual(self.journal.read(self.identity,self.key).state,'unavailable')
        self.directory.chmod(0o700)

    def test_boolean_version_is_not_a_valid_claim(self):
        key=self.journal._key(self.identity,self.key,'claim')
        self.journal._commit(key,{'version':True,'identity':self.identity,
                                 'operation_key':self.key,'state':'claimed'})
        self.assertEqual(self.journal.read(self.identity,self.key).state,'unavailable')

    def scoped_journal(self, definitions=None, generation='generation-1'):
        pins = ('fixture', 'revision-1', (('operator', generation),) * len(self.defs))
        return ManagedJournal(self.directory, definitions=self.defs if definitions is None else definitions,
                              scope_pins=pins)

    def crash_after_scope_writes(self, identity, operation_key, count):
        code = """
import os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[2])
from test_aggregate_setup import make_scope
from worker_handoff.managed_journal import ManagedJournal
from worker_handoff.recording import Persistence

definitions = tuple(make_scope(n, 'run-' + n).manager.selection.definition for n in ('one', 'two', 'three'))
journal = ManagedJournal(Path(sys.argv[1]), definitions=definitions,
    scope_pins=('fixture', 'revision-1', (('operator', 'generation-1'),) * len(definitions)))
assert journal.claim(sys.argv[3], sys.argv[4]) == 'claimed'
for definition in definitions[:int(sys.argv[5])]:
    assert journal.commit_mapping(definition) is Persistence.COMMITTED
os._exit(81)
"""
        result = subprocess.run([sys.executable, '-I', '-c', code, str(self.directory),
                                 str(Path(__file__).parent.resolve()), identity, operation_key, str(count)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 81, result.stderr)

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.directory.iterdir()}

    def recovery_adapter(self):
        return ManagedHostAdapter(profile='fixture', revision='revision-1', operation_key=self.key,
            scopes=self.scopes, definitions=self.defs, generations=('generation-1',)*3,
            wheel='trust-pin-unused-for-history.whl', wheel_sha256=self.defs[0].package_sha256,
            clock_id=self.defs[0].clock_id, store=self.scoped_journal())

    def check_interruption(self, count):
        commissioned = self.recovery_adapter()
        self.crash_after_scope_writes(commissioned.identity, self.key, count)
        adapter = self.recovery_adapter()
        before = self.snapshot()
        result = adapter.reconcile()
        self.assertEqual((result['status'], result['effect'], result['observation']),
                         ('incomplete' if count else 'unknown', 'unknown', None))
        self.assertEqual([(scope['setup'], scope['final'], scope['effect'], scope['code'])
                          for scope in result['scopes']],
                         [('recorded', 'not_checked', 'committed', 'scope_commit_verified')] * count +
                         [('unknown', 'not_checked', 'unknown', 'scope_commit_unconfirmed')] * (3-count))
        self.assertEqual(adapter.store.claim(adapter.identity, self.key), 'existing')
        with self.assertRaises(PermissionError):
            adapter.store.commit_mapping(self.defs[-1])
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(all((scope.manager.reads, scope.manager.creates, scope.manager.starts) == (0, 0, 0)
                            for scope in self.scopes))

    def test_crash_before_mapping_keeps_absence_unknown(self):
        self.check_interruption(0)

    def test_crash_with_partial_scope_commits_reports_only_attributed_effect(self):
        self.check_interruption(1)

    def test_crash_after_all_mappings_does_not_invent_aggregate_finish(self):
        self.check_interruption(3)

    def test_prior_mapping_does_not_prove_this_attempt_effect(self):
        previous = self.scoped_journal()
        self.assertEqual(previous.claim(self.identity, 'c'*64), 'claimed')
        previous.commit_mapping(self.defs[0])
        self.assertEqual(self.scoped_journal().claim(self.identity, self.key), 'claimed')
        before = self.snapshot()
        result = self.scoped_journal().recover_pending(self.identity, self.key)[0][1]
        self.assertEqual((result.status, result.code, result.effect),
                         ('unknown', 'scope_commit_unattributed', 'unknown'))
        self.assertEqual(self.snapshot(), before)

    def test_conflicting_mapping_and_scope_pins_are_never_attributed(self):
        current = self.scoped_journal()
        self.assertEqual(current.claim(self.identity, self.key), 'claimed')
        key, mapping = current._mappings[self.defs[0].name]
        old = {**mapping, 'definition': asdict(replace(self.defs[0], policy_sha256='f'*64))}
        current._commit(key, old)
        before = self.snapshot()
        result = self.scoped_journal().recover_pending(self.identity, self.key)[0][1]
        self.assertEqual((result.status, result.code, result.effect),
                         ('conflict', 'scope_mapping_conflict', 'unknown'))
        self.assertEqual(self.scoped_journal(generation='generation-2').recover_pending(self.identity, self.key), ())
        self.assertEqual(self.snapshot(), before)

    def test_legacy_pending_claim_and_mapping_are_not_reinterpreted(self):
        self.assertEqual(self.journal.claim(self.identity, self.key), 'claimed')
        upgraded = self.scoped_journal()
        key, mapping = upgraded._mappings[self.defs[0].name]
        self.journal._commit(key, mapping)
        before = self.snapshot()
        self.assertEqual(upgraded.read(self.identity, self.key).state, 'pending')
        self.assertEqual(upgraded.current_mapping(self.defs[0]).state, 'present')
        self.assertEqual(upgraded.recover_pending(self.identity, self.key), ())
        self.assertEqual(self.snapshot(), before)
