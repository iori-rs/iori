"""Fault injection for accounting: unavailable work must never become a pass."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import run
from catalogue import coverage_report, load_catalogue, validate_catalogue


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)

    def test_success_records_command_and_both_streams(self):
        result = run.execute([sys.executable, '-c', 'import sys; print("out"); print("err", file=sys.stderr)'], self.out, 'success')
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(Path(result['stdout']).read_text(), 'out\n')
        self.assertEqual(Path(result['stderr']).read_text(), 'err\n')
        self.assertEqual(json.loads((self.out / 'success.command.json').read_text())['exit_code'], 0)

    def assert_failure_record(self, argv, name, timeout=2):
        with self.assertRaises(RuntimeError):
            run.execute(argv, self.out, name, timeout=timeout)
        result = json.loads((self.out / f'{name}.command.json').read_text())
        self.assertEqual(result['status'], 'fail')
        self.assertTrue(Path(result['stderr']).exists())
        self.assertGreaterEqual(result['elapsed_seconds'], 0)
        return result

    def test_nonzero_exit_is_failure(self):
        result = self.assert_failure_record([sys.executable, '-c', 'raise SystemExit(13)'], 'exit')
        self.assertEqual(result['exit_code'], 13)

    def test_crashing_tool_is_failure(self):
        result = self.assert_failure_record([sys.executable, '-c', 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'], 'crash')
        self.assertLess(result['exit_code'], 0)

    def test_missing_tool_is_failure(self):
        result = self.assert_failure_record([str(self.out / 'absent-executable')], 'absent')
        self.assertIsNone(result['exit_code'])
        self.assertIn('error', result)

    def test_hanging_tool_is_bounded_failure(self):
        result = self.assert_failure_record([sys.executable, '-c', 'import time; time.sleep(10)'], 'timeout', timeout=0.05)
        self.assertIsNone(result['exit_code'])
        self.assertLess(result['elapsed_seconds'], 5)


class LockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'tools.json'
        self.found = {'oracle': {'path': '/not-part-of-identity', 'sha256': 'a' * 64, 'version': 'v1'}}

    def test_lock_requires_explicit_baseline(self):
        with self.assertRaises(RuntimeError):
            run.lock_tools(self.found, self.path)
        self.assertFalse(self.path.exists())
        run.lock_tools(self.found, self.path, record=True)
        run.lock_tools(self.found, self.path)

    def test_hash_and_version_changes_cannot_reuse_cache_identity(self):
        run.lock_tools(self.found, self.path, record=True)
        for field in ('sha256', 'version'):
            changed = copy.deepcopy(self.found)
            changed['oracle'][field] += 'changed'
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                run.lock_tools(changed, self.path)
        self.assertEqual(json.loads(self.path.read_text())['tools']['oracle']['version'], 'v1')

    def test_empty_tool_manifest_rejected(self):
        with self.assertRaises((RuntimeError, ValueError)):
            run.lock_tools({}, self.path, record=True)


class AccountingTests(unittest.TestCase):
    def test_empty_media_corpus_is_not_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(run, 'sources', return_value={}), patch.object(run, 'execute'):
                with self.assertRaisesRegex(RuntimeError, 'empty'):
                    run.interop(Path(temporary), {})

    def test_empty_catalogue_cannot_report_complete(self):
        catalogue = load_catalogue()
        catalogue['families'] = []
        catalogue['requirements'] = []
        catalogue['cases'] = []
        self.assertTrue(validate_catalogue(catalogue))
        with self.assertRaises(ValueError):
            coverage_report(catalogue=catalogue)

    def test_junit_pass_fail_and_unexecuted_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'junit.xml'
            run.junit([{'id': 'executed', 'status': 'pass'},
                       {'id': 'broken', 'status': 'fail', 'error': 'ciphertext unchanged'},
                       {'id': 'missing', 'status': 'tool-unsupported'}], path)
            root = ET.parse(path).getroot()
            self.assertEqual(root.attrib['tests'], '3')
            self.assertEqual(root.attrib['failures'], '1')
            self.assertIsNotNone(root.find('./testcase[@name="broken"]/failure'))
            self.assertIsNotNone(root.find('./testcase[@name="missing"]/skipped'))
            self.assertIsNone(root.find('./testcase[@name="executed"]/skipped'))

    def test_junit_streaming_comparison_has_implicit_single_part(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'junit.xml'
            run.junit([{'id': 'stream', 'status': 'pass', 'comparisons': [
                {'decoder': 'iori', 'status': 'pass'}]}], path)
            self.assertEqual(ET.parse(path).getroot().find('testcase').get('name'), 'stream/0/iori')

    def test_junit_parent_failure_survives_successful_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'junit.xml'
            run.junit([{'id': 'stream', 'status': 'fail', 'error': 'later part failed', 'comparisons': [
                {'decoder': 'iori', 'part': 0, 'status': 'pass'}]}], path)
            root = ET.parse(path).getroot()
            self.assertEqual(root.get('failures'), '1')
            self.assertIsNotNone(root.find('./testcase[@name="stream/case-failure"]/failure'))

    def test_empty_junit_is_not_a_successful_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises((RuntimeError, ValueError)):
                run.junit([], Path(temporary) / 'junit.xml')


if __name__ == '__main__':
    unittest.main()
