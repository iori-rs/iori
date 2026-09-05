import unittest
from mp4 import extract
from test_mp4 import box, words
from validity import (UnsupportedLayout, assert_cens_tail_only_difference,
                      assert_clear_bytes, protected_ranges, protection, validate)


def fixture(scheme='cens', pattern=0x11, size=33, subsamples=None, groups=b''):
    tenc = bytes([1, 0, 0, 0, 0, pattern, 1, 16]) + bytes(16)
    sinf = box(b'sinf', box(b'frma', b'avc1') +
               box(b'schm', words(0) + scheme.encode() + words(0x10000)) +
               box(b'schi', box(b'tenc', tenc)))
    entry = box(b'encv', bytes(78) + box(b'avcC', b'config') + sinf)
    senc = words(2 if subsamples else 0, 1) + bytes(16)
    if subsamples:
        import struct
        senc += struct.pack('>H', len(subsamples))
        senc += b''.join(struct.pack('>HI', *s) for s in subsamples)
    def moov(offset):
        stbl = box(b'stbl', box(b'stsd', words(0, 1) + entry) +
            box(b'stsz', words(0, size, 1)) + box(b'stts', words(0, 1, 1, 1000)) +
            box(b'stsc', words(0, 1, 1, 1, 1)) + box(b'stco', words(0, 1, offset)) +
            box(b'senc', senc) + groups)
        mdia = box(b'mdia', box(b'mdhd', words(0, 0, 0, 1000)) + box(b'minf', stbl))
        return box(b'moov', box(b'trak', box(b'tkhd', words(0, 0, 0, 1)) + mdia))
    return moov(len(moov(0)) + 8) + box(b'mdat', bytes(range(size)))


class EncryptionValidityTests(unittest.TestCase):
    def test_scheme_block_boundaries(self):
        self.assertEqual(protected_ranges(10, 17, 'cenc'), ([(10, 27)], []))
        for scheme in ('cbc1', 'cens', 'cbcs'):
            self.assertEqual(protected_ranges(10, 17, scheme), ([(10, 26)], [(26, 27)]))
        self.assertEqual(protected_ranges(0, 49, 'cens', 1, 1),
                         ([(0, 16), (32, 48)], []))
        self.assertEqual(protected_ranges(0, 33, 'cens', 1, 1),
                         ([(0, 16)], [(32, 33)]))

    def test_all_nibbles_and_tail_remainders_bounded(self):
        for crypt in range(16):
            for skip in range(16):
                for tail in range(16):
                    size = 16 * (crypt + skip + 1) + tail
                    enc, tails = protected_ranges(11, size, 'cens', crypt, skip)
                    self.assertTrue(all(a >= 11 and b <= 11 + size and b - a == 16 for a, b in enc))
                    self.assertTrue(all(a >= 11 and b == 11 + size and b - a == tail for a, b in tails))
                    self.assertEqual(len(set(a for a, _ in enc)), len(enc))

    def test_subsample_pattern_restart(self):
        data = fixture(size=32, subsamples=[(0, 16), (0, 16)])
        s = validate(data)['samples'][0]
        self.assertEqual(s['encrypted_ranges'], [(s['offset'], s['offset'] + 16),
                                                 (s['offset'] + 16, s['offset'] + 32)])

    def test_clear_skip_and_tail_faults(self):
        data = fixture()
        s = validate(data)['samples'][0]
        for index in (0, 15):
            bad = bytearray(data)
            bad[s['offset'] + index] ^= 1
            assert_clear_bytes(data, bytes(bad))
        for index in (16, 31, 32):
            bad = bytearray(data)
            bad[s['offset'] + index] ^= 1
            with self.assertRaisesRegex(AssertionError, 'clear byte'):
                assert_clear_bytes(data, bytes(bad))

    def test_tail_diagnostic_requires_exact_boundary_and_difference(self):
        data = fixture()
        start = extract(data)[0]['samples'][0]['offset']
        bad = bytearray(data)
        bad[start + 32] ^= 1
        result = assert_cens_tail_only_difference(data, bytes(bad), data)
        self.assertEqual(result['differing_bytes'], 1)
        bad[start + 16] ^= 1
        with self.assertRaisesRegex(AssertionError, 'outside CENS'):
            assert_cens_tail_only_difference(data, bytes(bad), data)
        with self.assertRaisesRegex(AssertionError, 'did not occur'):
            assert_cens_tail_only_difference(data, data, data)

    def test_invalid_subsample_coverage(self):
        with self.assertRaisesRegex(ValueError, 'coverage'):
            validate(fixture(size=33, subsamples=[(0, 16)]))

    def test_seig_reserved_order_explicit_and_default_group(self):
        description = bytes([0, 0x19, 1, 16]) + bytes(16)
        for default in (False, True):
            sgpd = box(b'sgpd', words(0x02000000 if default else 0x01000000) +
                b'seig' + words(20) + (words(1) if default else b'') + words(1) + description)
            sbgp = b'' if default else box(b'sbgp', words(0) + b'seig' + words(1, 1, 1))
            s = validate(fixture(size=64, groups=sgpd + sbgp))['samples'][0]
            self.assertEqual(s['encrypted_ranges'], [(s['offset'], s['offset'] + 16)])

    def test_scheme_restrictions(self):
        with self.assertRaisesRegex(ValueError, 'pattern'):
            validate(fixture('cenc'))
        with self.assertRaises(UnsupportedLayout):
            validate(fixture('xxxx'))
        bad = bytes([0, 0, 1, 8]) + bytes(16)
        with self.assertRaisesRegex(ValueError, 'CBC requires'):
            protection(bad, 'cbcs')


if __name__ == '__main__':
    unittest.main()
