"""Fault injection for the independent encoded-sample oracle."""
import copy
import struct
import unittest
from pathlib import Path

from mp4 import assert_in_place, boxes, compare_samples, esds_config, extract


def box(kind, p=b''):
    return struct.pack('>I4s', 8 + len(p), kind) + p


def words(*values):
    return struct.pack('>' + 'I' * len(values), *values)


def movie(fragment=False, offset=0):
    entry = box(b'avc1', bytes(78) + box(b'avcC', b'config'))
    stsd = box(b'stsd', words(0, 1) + entry)
    if fragment:
        tables = box(b'stsz', words(0, 0, 0))
    else:
        tables = (box(b'stsz', words(0, 0, 2, 3, 4)) +
                  box(b'stts', words(0, 1, 2, 1000)) +
                  box(b'stsc', words(0, 1, 1, 2, 1)) +
                  box(b'stco', words(0, 1, offset)))
    stbl = box(b'stbl', stsd + tables)
    mdia = box(b'mdia', box(b'mdhd', words(0, 0, 0, 1000)) + box(b'minf', stbl))
    trak = box(b'trak', box(b'tkhd', words(0, 0, 0, 1)) + mdia)
    mvex = box(b'mvex', box(b'trex', words(0, 1, 1, 1000, 3, 0))) if fragment else b''
    return box(b'moov', trak + mvex)


def progressive():
    return movie(offset=len(movie()) + 8) + box(b'mdat', b'abcdefg')


def fragment(explicit=False):
    m = movie(True)
    if explicit:
        # Media precedes moof; signed trun offset is relative to explicit base.
        media = box(b'mdat', b'abcdef')
        base = len(m) + len(media)
        tfhd = box(b'tfhd', words(1, 1) + struct.pack('>Q', base))
        run1 = box(b'trun', words(1, 1) + struct.pack('>i', -6))
        run2 = box(b'trun', words(0, 1))
        return m + media + box(b'moof', box(b'traf', tfhd + run1 + run2))
    tfhd = box(b'tfhd', words(0x20000, 1))
    run2 = box(b'trun', words(0, 1))
    run1 = box(b'trun', words(1, 1, 0))
    moof = box(b'moof', box(b'traf', tfhd + run1 + run2))
    run1 = box(b'trun', words(1, 1, len(moof) + 8))
    return m + box(b'moof', box(b'traf', tfhd + run1 + run2)) + box(b'mdat', b'abcdef')


def table_fixture(width=0, wide_offsets=False, ctts_version=0, edit_version=None):
    sizes = [3, 4]
    if width == 4:
        size_table = box(b'stz2', words(0) + bytes([0, 0, 0, 4]) + words(2) + b'\x34')
    elif width in (8, 16):
        raw = b''.join(n.to_bytes(width // 8, 'big') for n in sizes)
        size_table = box(b'stz2', words(0) + bytes([0, 0, 0, width]) + words(2) + raw)
    else:
        size_table = box(b'stsz', words(0, 0, 2, *sizes))
    def moov(offset):
        entry = box(b'avc1', bytes(78) + box(b'avcC', b'config'))
        offset_box = (box(b'co64', words(0, 1) + struct.pack('>Q', offset)) if wide_offsets
                      else box(b'stco', words(0, 1, offset)))
        ctts = box(b'ctts', words(ctts_version << 24, 1, 2, 0xffffffff if ctts_version else 500))
        stbl = box(b'stbl', box(b'stsd', words(0, 1) + entry) + size_table +
            box(b'stts', words(0, 1, 2, 1000)) + box(b'stsc', words(0, 1, 1, 2, 1)) + offset_box + ctts)
        mdia = box(b'mdia', box(b'mdhd', words(0, 0, 0, 1000)) + box(b'minf', stbl))
        edits = b''
        if edit_version is not None:
            fmt = '>Qqi' if edit_version else '>Iii'
            elst = words(edit_version << 24, 2)
            elst += struct.pack(fmt, 500, -1, 65536)
            elst += struct.pack(fmt, 2000, 10, 65536)
            edits = box(b'edts', box(b'elst', elst))
        return box(b'moov', box(b'mvhd', words(0, 0, 0, 1000)) +
                   box(b'trak', box(b'tkhd', words(0, 0, 0, 1)) + edits + mdia))
    return moov(len(moov(0)) + 8) + box(b'mdat', b'abcdefg')


class SampleOracleTests(unittest.TestCase):
    def test_progressive_samples(self):
        t = extract(progressive())[0]
        self.assertEqual([s['size'] for s in t['samples']], [3, 4])
        self.assertEqual(t['samples'][1]['dts'], [1, 1])
        compare_samples(progressive(), progressive())

    def test_fragment_trex_and_run_continuation(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                t = extract(fragment(explicit))[0]
                self.assertEqual([s['size'] for s in t['samples']], [3, 3])
                self.assertEqual(t['samples'][1]['offset'], t['samples'][0]['offset'] + 3)
                self.assertEqual(t['samples'][1]['dts'], [1, 1])

    def test_reject_unchanged_ciphertext_and_corruption(self):
        plain = progressive()
        corrupt = plain[:-1] + b'X'
        with self.assertRaisesRegex(AssertionError, 'sha256'):
            compare_samples(plain, corrupt)

    def test_every_semantic_field_checked(self):
        original = extract(progressive())
        for field in ('size', 'sha256', 'dts', 'cts', 'duration', 'description'):
            bad = copy.deepcopy(original)
            bad[0]['samples'][0][field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(AssertionError):
                compare_samples(original, bad)
        bad = copy.deepcopy(original)
        bad[0]['samples'].reverse()
        with self.assertRaises(AssertionError):
            compare_samples(original, bad)
        bad = copy.deepcopy(original)
        bad[0]['samples'].pop()
        with self.assertRaisesRegex(AssertionError, 'count'):
            compare_samples(original, bad)

    def test_ids_offsets_and_equivalent_timescale_do_not_matter(self):
        original = extract(progressive())
        changed = copy.deepcopy(original)
        changed[0]['id'] = 42
        changed[0]['timescale'] = 90000
        changed[0]['samples'][0]['offset'] = 900
        compare_samples(original, changed)

    def test_track_and_configuration_mismatch(self):
        a = extract(progressive())
        with self.assertRaisesRegex(AssertionError, 'track count'):
            compare_samples(a, [])
        b = copy.deepcopy(a)
        b[0]['descriptions'][0]['config_sha256'] = 'bad'
        with self.assertRaisesRegex(AssertionError, 'configuration'):
            compare_samples(a, b)
        with self.assertRaisesRegex(AssertionError, 'ambiguous'):
            compare_samples(a + a, a + a)

    def test_invalid_offset_and_truncated_box(self):
        with self.assertRaisesRegex(ValueError, 'outside mdat'):
            extract(movie(offset=8) + box(b'mdat', b'abcdefg'))
        with self.assertRaises(ValueError):
            boxes(progressive()[:-1])

    def test_size_preserving_cleanup_and_byte_allowlist(self):
        plain = progressive()
        encrypted = plain + box(b'sinf', box(b'schi', box(b'tenc', bytes(20))))
        cleaned = plain + box(b'free', bytes(len(encrypted) - len(plain) - 8))
        assert_in_place(encrypted, cleaned)
        assert_in_place(plain, plain[:-1] + b'X')
        with self.assertRaisesRegex(AssertionError, 'size'):
            assert_in_place(plain, plain + b'X')
        bad = bytearray(plain)
        # A codec configuration byte is unrelated metadata.
        bad[plain.index(b'config')] ^= 1
        with self.assertRaisesRegex(AssertionError, 'unrelated byte'):
            assert_in_place(plain, bytes(bad))
        roll = plain + box(b'sgpd', words(0) + b'roll' + words(0))
        lost = plain + box(b'free', bytes(12))
        with self.assertRaisesRegex(AssertionError, 'unrelated box'):
            assert_in_place(roll, lost)

    def test_mdat_padding_cannot_change(self):
        data = progressive()
        # Increase mdat length without increasing sample sizes.
        start = data.index(b'mdat') - 4
        data = data[:start] + box(b'mdat', b'abcdefgPAD')
        with self.assertRaisesRegex(AssertionError, 'unrelated byte'):
            assert_in_place(data, data[:-1] + b'X')

    def test_esds_canonicalizer_retains_decoder_config(self):
        def descriptor(tag, value):
            return bytes([tag, len(value)]) + value
        def config(es_id, bitrate, asc):
            decoder = b'\x40\x15' + bytes(3) + words(bitrate, bitrate) + descriptor(5, asc)
            return words(0) + descriptor(3, struct.pack('>HB', es_id, 0) + descriptor(4, decoder))
        self.assertEqual(esds_config(config(1, 128000, b'\x12\x10')),
                         esds_config(config(2, 256000, b'\x12\x10')))
        self.assertNotEqual(esds_config(config(1, 128000, b'\x12\x10')),
                            esds_config(config(1, 128000, b'\x11\x90')))
        with self.assertRaises(ValueError):
            esds_config(config(1, 1, b'a')[:-1])

    def test_edit_timing_cannot_disappear(self):
        a = extract(progressive())
        b = copy.deepcopy(a)
        b[0]['edit_list'] = [[[1, 1], [-1, 10], [1, 1]]]
        with self.assertRaisesRegex(AssertionError, 'edit-list'):
            compare_samples(a, b)

    def test_compact_sizes_and_wide_offsets(self):
        expected = extract(table_fixture())
        for width in (4, 8, 16):
            for wide in (False, True):
                with self.subTest(width=width, wide=wide):
                    compare_samples(expected, extract(table_fixture(width, wide)))

    def test_ctts_signed_version_and_edit_versions(self):
        self.assertEqual(extract(table_fixture(ctts_version=0))[0]['samples'][0]['cts'], [1, 2])
        self.assertEqual(extract(table_fixture(ctts_version=1))[0]['samples'][0]['cts'], [-1, 1000])
        a, b = table_fixture(edit_version=0), table_fixture(edit_version=1)
        compare_samples(a, b)
        self.assertEqual(extract(a)[0]['edit_list'],
                         [[[1, 2], None, [1, 1]], [[2, 1], [1, 100], [1, 1]]])

    def test_box_extended_and_eof_sizes(self):
        extended = words(1) + b'uuid' + struct.pack('>Q', 24) + bytes(8)
        terminal = words(0) + b'free' + b'padding'
        self.assertEqual(boxes(extended + terminal),
                         [(b'uuid', 0, 16, 24), (b'free', 24, 32, 39)])
        for data in (extended[:12], words(1) + b'free' + struct.pack('>Q', 15),
                     words(100) + b'free', b'1234567'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                boxes(data)
        # Unknown boxes remain byte-for-byte stable in the invariant oracle.
        before = progressive() + extended
        assert_in_place(before, before)
        with self.assertRaisesRegex(AssertionError, 'unrelated byte'):
            assert_in_place(before, before[:-1] + b'X')

    def test_explicit_track_mapping_disambiguates_identical_codecs(self):
        a = extract(progressive())
        other = copy.deepcopy(a[0])
        other['id'] = 2
        other['samples'][0]['sha256'] = 'distinct-track'
        left = a + [other]
        right = copy.deepcopy(list(reversed(left)))
        right[0]['id'], right[1]['id'] = 42, 43
        compare_samples(left, right, track_map={1: 43, 2: 42})
        with self.assertRaisesRegex(AssertionError, 'sha256'):
            compare_samples(left, right, track_map={1: 42, 2: 43})
        for mapping in ({1: 43}, {1: 43, 2: 43}, {1: 43, 3: 42}):
            with self.subTest(mapping=mapping), self.assertRaisesRegex(AssertionError, 'bijectively'):
                compare_samples(left, right, track_map=mapping)

    def test_fragment_tfdt_v1_and_signed_composition_offset(self):
        m = movie(True)
        tfhd = box(b'tfhd', words(0x20000, 1))
        tfdt = box(b'tfdt', words(0x01000000) + struct.pack('>Q', 2**32 + 1))
        def moof(offset):
            trun = box(b'trun', words(0x01000801, 1, offset) + struct.pack('>i', -1))
            return box(b'moof', box(b'traf', tfhd + tfdt + trun))
        data = m + moof(len(moof(0)) + 8) + box(b'mdat', b'abc')
        sample = extract(data)[0]['samples'][0]
        self.assertEqual(sample['dts'], [2**32 + 1, 1000])
        self.assertEqual(sample['cts'], [-1, 1000])

    def test_implicit_second_traf_base(self):
        m = movie(True)
        first_tfhd = box(b'tfhd', words(0x20000, 1))
        second_tfhd = box(b'tfhd', words(0, 1))
        second = box(b'traf', second_tfhd + box(b'trun', words(0, 1)))
        def moof(offset):
            first = box(b'traf', first_tfhd + box(b'trun', words(1, 1, offset)))
            return box(b'moof', first + second)
        data = m + moof(len(moof(0)) + 8) + box(b'mdat', b'abcdef')
        samples = extract(data)[0]['samples']
        self.assertEqual(samples[1]['offset'], samples[0]['offset'] + 3)
        self.assertEqual(samples[1]['dts'], [1, 1])

    def test_typed_auxiliary_metadata_allowlist(self):
        base = progressive()
        for kind in (b'saiz', b'saio'):
            for aux_type in (b'cenc', b'cens', b'cbc1', b'cbcs', b'abcd'):
                original_box = box(kind, words(1) + aux_type + words(0, 0))
                before = base + original_box
                after = base + box(b'free', bytes(len(original_box) - 8))
                with self.subTest(kind=kind, aux_type=aux_type):
                    if aux_type == b'abcd':
                        with self.assertRaisesRegex(AssertionError, 'unrelated box'):
                            assert_in_place(before, after)
                    else:
                        assert_in_place(before, after)
        # A free replacement cannot move its start or resize an adjacent box.
        first, second = box(b'senc', bytes(8)), box(b'free', bytes(8))
        before = base + first + second
        after = base + box(b'free', bytes(12)) + box(b'free', bytes(4))
        with self.assertRaisesRegex(AssertionError, 'offset/size'):
            assert_in_place(before, after)

    def test_clear_protected_description_aliases_preserve_sample_config(self):
        left = extract(progressive())
        right = copy.deepcopy(left)
        right[0]['descriptions'].append(copy.deepcopy(right[0]['descriptions'][0]))
        right[0]['samples'][0]['description_index'] = 2
        compare_samples(left, right)
        right[0]['samples'][0]['description'] = {'codec': 'avc1', 'config_sha256': 'different'}
        with self.assertRaisesRegex(AssertionError, 'description'):
            compare_samples(left, right)

    def test_checked_in_real_files(self):
        root = Path(__file__).resolve().parents[1] / 'fixtures'
        for name in ('fmp4', 'non-fmp4'):
            data = (root / name / 'plain.mp4').read_bytes()
            with self.subTest(name=name):
                tracks = extract(data)
                self.assertGreater(sum(len(t['samples']) for t in tracks), 0)
                compare_samples(data, data)
                assert_in_place(data, data)


if __name__ == '__main__':
    unittest.main()
