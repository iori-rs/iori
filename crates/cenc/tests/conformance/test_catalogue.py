import copy
import unittest
from catalogue import coverage_report, load_catalogue, validate_catalogue, observed_results, observed_external


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.catalogue = load_catalogue()

    def test_all_75_families_have_explicit_gaps(self):
        self.assertEqual(validate_catalogue(self.catalogue), [])
        report = coverage_report(catalogue=self.catalogue)
        self.assertEqual(report['family_count'], 75)
        self.assertEqual(report['covered_family_count'], 0)
        self.assertEqual(report['partial_family_count'] + report['unimplemented_family_count'], 75)
        self.assertTrue(all(f['open_requirement_ids'] for f in report['families']))
        self.assertFalse(report['full_conformance'])
        self.assertEqual(report['executions']['pass'], 0)
        self.assertEqual(report['executions']['not-run'], report['case_count'])

    def test_missing_requirement_is_detected(self):
        data = copy.deepcopy(self.catalogue)
        data['requirements'] = [r for r in data['requirements'] if r['family_id'] != 'ITEM-01']
        self.assertTrue(any('ITEM-01' in e for e in validate_catalogue(data)))

    def test_broken_requirement_link_is_detected(self):
        data = copy.deepcopy(self.catalogue)
        data['cases'][0]['requirements'] = []
        self.assertTrue(validate_catalogue(data))

    def test_missing_executable_test_is_detected(self):
        data = copy.deepcopy(self.catalogue)
        data['cases'][0]['test_name'] = 'this_test_does_not_exist'
        self.assertTrue(any('missing executable test' in e for e in validate_catalogue(data)))

    def test_execution_does_not_establish_feature_completeness(self):
        results = {c['id']: 'pass' for c in self.catalogue['cases']}
        report = coverage_report(results, self.catalogue)
        self.assertEqual(report['executions']['pass'], report['case_count'])
        self.assertEqual(report['covered_family_count'], 0)
        self.assertFalse(report['full_conformance'])

    def test_invalid_execution_accounting_fails_closed(self):
        cid = self.catalogue['cases'][0]['id']
        for result in ({'not-a-case': 'pass'}, {cid: 'skipped-as-success'}):
            with self.assertRaises(ValueError):
                coverage_report(result, self.catalogue)

    def test_unverified_complete_claim_is_detected(self):
        data = copy.deepcopy(self.catalogue)
        data['requirements'][0]['status'] = 'complete'
        self.assertTrue(any('unsupported complete claim' in e for e in validate_catalogue(data)))

    def test_explicit_test_results_are_required(self):
        case = self.catalogue['cases'][0]
        name, cid = case['test_name'], case['id']
        for output in ('test result: ok. 100 passed', f'test {name}_wrong ... ok', f'test {name} ... ignored'):
            self.assertEqual(observed_results(output, '', self.catalogue)[cid], 'not-run')
        self.assertEqual(observed_results(f'test jobs::tests::{name} ... ok\n', '', self.catalogue)[cid], 'pass')
        self.assertEqual(observed_results(f'test {name} ... FAILED\ntest {name} ... ok\n', '', self.catalogue)[cid], 'fail')

    def test_python_results_require_matching_module(self):
        case = next(c for c in self.catalogue['cases'] if c['test_name'] == 'test_selection_boundaries')
        cid = case['id']
        output = 'test_selection_boundaries (test_knowledge.SelectionTests.test_selection_boundaries) ... ok\n'
        self.assertEqual(observed_results('', output, self.catalogue)[cid], 'pass')
        self.assertEqual(observed_results('', output.replace('test_knowledge.', 'wrong_module.'), self.catalogue)[cid], 'not-run')
        self.assertEqual(observed_results('', output.replace(' ... ok', ' ... skipped "missing"'), self.catalogue)[cid], 'not-run')

    def runtime_record(self, media='avc', producer='bento4', status='pass'):
        parts = [0, 1] if media == 'av' and producer == 'shaka' else [0]
        return {'id': f'{producer}-{media}-cenc', 'status': status,
                'source_sha256': 'a'*64, 'encrypted_sha256': ['b'*64 for _ in parts],
                'comparisons': [{'part': part, 'decoder': decoder, 'status': 'pass',
                                 'output_sha256': ['c'*64], 'decoded_hashes': ['SHA256='+'d'*64]}
                                for part in parts for decoder in ('iori', 'bento4', 'shaka')]}

    def test_runtime_requires_artifacts_and_individual_comparisons(self):
        case = 'REAL-01-RUNTIME-bento4-avc-cenc-iori'
        record = self.runtime_record()
        self.assertEqual(observed_external([record], self.catalogue)[case], 'pass')
        self.assertEqual(observed_external([], self.catalogue)[case], 'not-run')
        for field in ('source_sha256', 'encrypted_sha256', 'comparisons'):
            bad = copy.deepcopy(record)
            del bad[field]
            with self.subTest(field=field):
                self.assertEqual(observed_external([bad], self.catalogue)[case], 'not-run')
        record['comparisons'][0]['output_sha256'] = []
        self.assertEqual(observed_external([record], self.catalogue)[case], 'not-run')

    def test_runtime_qualified_and_failed_decoders_do_not_become_passes(self):
        record = self.runtime_record(status='qualified')
        record['comparisons'][1]['status'] = 'known-oracle-deviation'
        result = observed_external([record], self.catalogue)
        self.assertEqual(result['REAL-01-RUNTIME-bento4-avc-cenc-iori'], 'pass')
        self.assertEqual(result['REAL-01-RUNTIME-bento4-avc-cenc-bento4'], 'known-oracle-deviation')
        record['comparisons'][1]['status'] = 'tool-unsupported'
        self.assertEqual(observed_external([record], self.catalogue)['REAL-01-RUNTIME-bento4-avc-cenc-bento4'], 'tool-unsupported')
        record['comparisons'][1]['status'] = 'fail'
        record['status'] = 'fail'
        self.assertEqual(observed_external([record], self.catalogue)['REAL-01-RUNTIME-bento4-avc-cenc-bento4'], 'fail')
        self.assertEqual(observed_external([record], self.catalogue)['REAL-01-RUNTIME-bento4-avc-cenc-iori'], 'pass')

    def test_runtime_requires_all_parts_and_playback_evidence(self):
        record = self.runtime_record(media='av', producer='shaka')
        cid = 'REAL-01-RUNTIME-shaka-av-cenc-iori'
        self.assertEqual(observed_external([record], self.catalogue)[cid], 'pass')
        record['comparisons'] = record['comparisons'][:3]
        self.assertEqual(observed_external([record], self.catalogue)[cid], 'not-run')
        record = self.runtime_record()
        record['comparisons'][0]['decoded_hashes'] = []
        result = observed_external([record], self.catalogue)
        self.assertEqual(result['REAL-01-RUNTIME-bento4-avc-cenc-iori'], 'pass')
        self.assertEqual(result['REAL-05-RUNTIME-bento4-avc-cenc-iori'], 'not-run')

    def test_runtime_duplicate_accounting_rejected(self):
        record = self.runtime_record()
        with self.assertRaises(ValueError):
            observed_external([record, record], self.catalogue)
        record['comparisons'].append(copy.deepcopy(record['comparisons'][0]))
        with self.assertRaises(ValueError):
            observed_external([record], self.catalogue)


if __name__ == '__main__':
    unittest.main()
