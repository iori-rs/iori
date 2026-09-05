import unittest
from streaming import rotated_keys, split_fragments, expected_fragment, classify_rotation
from test_mp4 import box, fragment, progressive
from mp4 import extract


class StreamingRecipeTests(unittest.TestCase):
    def test_rotation_is_byte_based_and_includes_original(self):
        keys = rotated_keys(bytes(range(16)).hex(), bytes(range(16, 32)).hex())
        self.assertEqual(len(set(keys)), 16)
        self.assertEqual(keys[1][0], (bytes(range(1, 16)) + b'\0').hex())
        with self.assertRaises(ValueError):
            rotated_keys('00', '00')

    def test_detached_fragments_preserve_samples(self):
        original = fragment()
        init, media = split_fragments(original)
        self.assertEqual(len(media), 1)
        self.assertEqual(extract(original), extract(init + b''.join(media)))
        with self.assertRaises(ValueError):
            split_fragments(progressive())

    def test_rotation_deviation_is_exact_and_version_bound(self):
        from deviations import BENTO_DECRYPT, SHAKA
        found = {'mp4decrypt': {'sha256': BENTO_DECRYPT}, 'shaka': {'sha256': SHAKA}}
        encrypted = fragment()
        args = ('bento4', 'mismatch', found, ['a', 'b'], ['a', 'b'], True, encrypted, encrypted)
        self.assertEqual(classify_rotation(*args)['status'], 'tool-unsupported')
        for index, replacement in [(2, {}), (3, ['a']), (4, ['a']), (5, False),
                                    (7, encrypted[:-1] + b'X')]:
            changed = list(args)
            changed[index] = replacement
            self.assertIsNone(classify_rotation(*changed))
        self.assertIsNotNone(classify_rotation('shaka', 'PARSER_FAILURE ParseFromSampleEncryptionData',
            found, ['a', 'b'], ['a', 'b'], True, encrypted, encrypted))
        self.assertIsNone(classify_rotation('shaka', 'PARSER_FAILURE unrelated',
            found, ['a', 'b'], ['a', 'b'], True, encrypted, encrypted))

    def test_expected_fragment_cannot_drop_or_retime(self):
        reference = extract(fragment())
        expected = expected_fragment(reference, reference)
        self.assertEqual(expected, reference)
        actual = extract(fragment())
        actual[0]['samples'][0]['dts'] = [99, 1]
        with self.assertRaisesRegex(AssertionError, 'timeline'):
            expected_fragment(reference, actual)
        with self.assertRaises(ValueError):
            expected_fragment(reference + reference, reference)


if __name__ == '__main__':
    unittest.main()
