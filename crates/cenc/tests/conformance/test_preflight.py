"""Adversarial producer preflight and auxiliary metadata preservation."""
import copy
import unittest

from mp4 import assert_in_place, extract
from run import assert_fixture
from test_mp4 import box, progressive, words

KID = '00112233445566778899aabbccddeeff'


def fixture():
    expected = extract(progressive())
    encrypted = copy.deepcopy(expected)
    encrypted[0]['samples'][0]['sha256'] = 'ciphertext-hash'
    records = []
    for index, sample in enumerate(encrypted[0]['samples']):
        records.append(dict(track_id=encrypted[0]['id'], index=index,
            offset=sample['offset'], size=sample['size'], protected=True,
            scheme='cenc', kid=KID,
            encrypted_ranges=[(sample['offset'], sample['offset'] + sample['size'])]))
    return expected, encrypted, {'samples': records}


class FixturePreflightTests(unittest.TestCase):
    def check(self, values):
        assert_fixture(*values, 'cenc', [KID])

    def test_active_changed_fixture_is_accepted(self):
        self.check(fixture())

    def test_empty_tracks_and_samples_are_rejected(self):
        for target in (0, 1):
            values = list(fixture())
            values[target] = []
            with self.subTest(target=target), self.assertRaisesRegex(AssertionError, 'empty'):
                self.check(values)
            values = list(fixture())
            values[target][0]['samples'] = []
            with self.subTest(target=target), self.assertRaisesRegex(AssertionError, 'empty'):
                self.check(values)

    def test_clear_copy_producer_cannot_pass(self):
        expected, encrypted, observed = fixture()
        encrypted = copy.deepcopy(expected)
        for record in observed['samples']:
            record['protected'] = False
            record['encrypted_ranges'] = []
        with self.assertRaisesRegex(AssertionError, 'no active'):
            self.check((expected, encrypted, observed))

    def test_ciphertext_must_change_even_with_encryption_signaling(self):
        expected, _, observed = fixture()
        with self.assertRaisesRegex(AssertionError, 'unchanged'):
            self.check((expected, copy.deepcopy(expected), observed))

    def test_requested_scheme_and_kid_are_enforced(self):
        for field, value, message in [('scheme', 'cbcs', 'scheme'), ('kid', 'ff' * 16, 'KID')]:
            values = fixture()
            values[2]['samples'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, message):
                self.check(values)

    def test_malformed_overlapping_and_out_of_sample_ranges_fail(self):
        for mode in ('before', 'after', 'overlap', 'empty', 'reverse', 'string', 'bool'):
            values = fixture()
            record = values[2]['samples'][0]
            start, end = record['offset'], record['offset'] + record['size']
            spans = {'before': [(start-1, end)], 'after': [(start, end+1)],
                'overlap': [(start, end), (start, end)], 'empty': [(start, start)],
                'reverse': [(end, start)], 'string': [('bad', end)], 'bool': [(True, end)]}
            record['encrypted_ranges'] = spans[mode]
            with self.subTest(mode=mode), self.assertRaisesRegex(AssertionError, 'range'):
                self.check(values)

    def test_missing_duplicate_and_misaligned_range_records_fail(self):
        for mode in ('missing', 'duplicate', 'offset', 'size'):
            values = fixture()
            records = values[2]['samples']
            if mode == 'missing': records.pop()
            elif mode == 'duplicate': records[1] = copy.deepcopy(records[0])
            else: records[0][mode] += 1
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                self.check(values)

    def test_mutated_timing_and_description_are_not_hidden_by_hash_normalization(self):
        for field in ('duration', 'description'):
            values = fixture()
            values[1][0]['samples'][0][field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.check(values)

    def test_unrelated_typed_auxiliary_parameters_must_survive(self):
        base = progressive()
        for kind in (b'saiz', b'saio'):
            original = box(kind, words(1) + b'cenc' + words(99, 0))
            with self.subTest(kind=kind), self.assertRaisesRegex(AssertionError, 'unrelated box'):
                assert_in_place(base + original, base + box(b'free', bytes(len(original)-8)))


if __name__ == '__main__':
    unittest.main()
