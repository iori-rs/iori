"""Known-deviation exceptions must be narrower than the comparison failures."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import deviations
from mp4 import extract
from test_validity import fixture


class DeviationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = self.root / 'source.mp4'
        self.output = self.root / 'output.mp4'
        self.source = fixture(size=33)
        self.original.write_bytes(self.source)
        self.expected = extract(self.source)
        self.expected[0]['descriptions'][0]['codec'] = 'mp4a'
        self.offset = self.expected[0]['samples'][0]['offset']
        self.found = {'mp4decrypt': {'sha256': deviations.BENTO_DECRYPT},
                      'mp4encrypt': {'sha256': deviations.BENTO_ENCRYPT},
                      'shaka': {'sha256': deviations.SHAKA}}

    def changed(self, indexes=(32,)):
        data = bytearray(self.source)
        for index in indexes:
            data[self.offset + index] ^= 1
        self.output.write_bytes(data)
        return bytes(data)

    def audio_extract(self, path):
        tracks = extract(path)
        for track in tracks:
            track['descriptions'][0]['codec'] = 'mp4a'
        return tracks

    def classify(self, found=None, scheme='cens'):
        return deviations.classify('bento4', scheme, 'iori', self.original, self.original,
                                  [self.output], self.expected, AssertionError('sha256 differs'),
                                  self.found if found is None else found)

    def test_exact_tail_witness_is_explicit_deviation(self):
        self.changed()
        with patch.object(deviations, 'extract', side_effect=self.audio_extract):
            result = self.classify()
        self.assertEqual(result['status'], 'known-oracle-deviation')
        self.assertEqual(result['affected_sample_tails'], 1)
        self.assertNotEqual(result['status'], 'pass')

    def test_non_tail_corruption_and_disappeared_deviation_fail_closed(self):
        for indexes in ((0,), (16,), (31,), (0, 32), ()):
            self.changed(indexes)
            with self.subTest(indexes=indexes), patch.object(deviations, 'extract', side_effect=self.audio_extract):
                self.assertIsNone(self.classify())

    def test_unknown_tool_hash_and_trigger_are_not_exemptions(self):
        self.changed()
        with patch.object(deviations, 'extract', side_effect=self.audio_extract):
            for tool in ('mp4encrypt', 'shaka'):
                found = copy.deepcopy(self.found)
                found[tool]['sha256'] = 'unknown-binary'
                with self.subTest(tool=tool):
                    self.assertIsNone(self.classify(found))
            self.assertIsNone(self.classify(scheme='cbcs'))
            self.assertIsNone(deviations.classify('unknown-producer', 'cens', 'iori',
                              self.original, self.original, [self.output], self.expected, '', self.found))

    def test_metadata_mismatch_cannot_be_normalized_away(self):
        self.changed()
        tracks = self.audio_extract(self.output)
        tracks[0]['samples'][0]['duration'] = [7, 1]
        with patch.object(deviations, 'extract', return_value=tracks):
            self.assertIsNone(self.classify())

    def test_video_tail_is_not_an_audio_exception(self):
        self.changed()
        expected = extract(self.source)
        with self.assertRaisesRegex(AssertionError, 'outside exact audio tail'):
            deviations.audio_tail_witness(self.original, [self.output], expected)

    def test_empty_and_duplicate_tracks_do_not_establish_witness(self):
        self.changed()
        with patch.object(deviations, 'extract', side_effect=self.audio_extract):
            with self.assertRaisesRegex(AssertionError, 'track count'):
                deviations.audio_tail_witness(self.original, [], self.expected)
            with self.assertRaisesRegex(AssertionError, 'ambiguous'):
                deviations.audio_tail_witness(self.original, [self.output, self.output], self.expected)

    def test_progressive_unchanged_ciphertext_is_unsupported_not_pass(self):
        self.output.write_bytes(self.source)
        args = ('ffmpeg', 'cenc', 'bento4', self.original, self.original,
                [self.output], extract(self.source), 'mismatch')
        result = deviations.classify(*args, self.found)
        self.assertEqual(result['status'], 'tool-unsupported')
        unknown = copy.deepcopy(self.found)
        unknown['mp4decrypt']['sha256'] = 'unknown'
        self.assertIsNone(deviations.classify(*args, unknown))
        self.changed((0,))
        self.assertIsNone(deviations.classify(*args, self.found))

    def test_shaka_rejection_requires_exact_diagnostics_and_known_binary(self):
        for message in ('', 'PARSER_FAILURE', 'default_is_protected == 0'):
            with self.subTest(message=message):
                self.assertIsNone(deviations.classify('ffmpeg', 'cenc', 'shaka', self.original,
                                  self.original, [], self.expected, message, self.found))
        result = deviations.classify('ffmpeg', 'cenc', 'shaka', self.original, self.original,
                                    [], self.expected, 'default_is_protected == 0 PARSER_FAILURE', self.found)
        self.assertEqual(result['status'], 'tool-unsupported')


if __name__ == '__main__':
    unittest.main()
