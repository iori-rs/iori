"""Reference-mechanism tests confer no production SVE1/XML support credit."""
import base64
import struct
import unittest
from knowledge import (CENC_NAMESPACE, default_kids, pack_selected, xor_selected,
                       selected_counter_inputs, parse_pssh_base64, descriptor_pssh)


class SelectionTests(unittest.TestCase):
    def test_literal_cross_byte_order(self):
        # 10101100 01010011 at coordinates 7,8,0,15,3 -> 00110.
        data = bytes.fromhex('ac53')
        positions = [7, 8, 0, 15, 3]
        self.assertEqual(pack_selected(data, positions), bytes.fromhex('30'))
        self.assertEqual(xor_selected(data, positions, bytes.fromhex('f8')), bytes.fromhex('3dd2'))

    def test_selection_boundaries(self):
        data = bytes((i * 73 + 19) % 256 for i in range(100))
        for count in (0, 1, 7, 8, 9, 127, 128, 129, 255, 256, 257):
            with self.subTest(count=count):
                positions = [(i * 3 + 1) for i in range(count)]
                packed = pack_selected(data, positions)
                # Independent string oracle fixes coordinates and packing order.
                bits = ''.join(f'{byte:08b}' for byte in data)
                expected = ''.join(bits[p] for p in positions)
                expected += '0' * ((-count) % 8)
                self.assertEqual(packed, bytes(int(expected[i:i+8], 2) for i in range(0, len(expected), 8)))
                mask = bytes([0xA5] * ((count + 7) // 8))
                changed = xor_selected(data, positions, mask)
                self.assertEqual(xor_selected(changed, positions, mask), data)
                changed_bits = ''.join(f'{byte:08b}' for byte in changed)
                selected = set(positions)
                for bit in range(len(bits)):
                    if bit not in selected:
                        self.assertEqual(bits[bit], changed_bits[bit])
                self.assertEqual(len(changed), len(data))

    def test_invalid_selection_is_rejected(self):
        for positions in ([0, 0], [-1], [8], [True]):
            with self.subTest(positions=positions), self.assertRaises(ValueError):
                pack_selected(b'\x00', positions)
        with self.assertRaises(ValueError):
            xor_selected(b'\x00', [0], b'')


class XmlIdentityTests(unittest.TestCase):
    KID = '00112233-4455-6677-8899-aabbccddeeff'

    def fixture(self, value, prefix='cenc', namespace=CENC_NAMESPACE):
        return f'<ContentProtection xmlns:{prefix}="{namespace}" {prefix}:default_KID="{value}"/>'

    def test_namespace_and_uuid_identity(self):
        self.assertEqual(default_kids(self.fixture(self.KID)), default_kids(self.fixture('  '+self.KID.upper()+'  ', 'x')))
        other = 'ffeeddcc-bbaa-9988-7766-554433221100'
        self.assertEqual(default_kids(self.fixture(self.KID+' '+other)), (self.KID, other))
        self.assertNotEqual(default_kids(self.fixture(self.KID)), default_kids(self.fixture(other)))
        self.assertEqual(default_kids(self.fixture(self.KID+' '+self.KID)), (self.KID, self.KID))

    def test_wrong_namespace_or_lexical_value(self):
        for value in ('', ' ', '0'*32, '{'+self.KID+'}', self.KID+'x', 'g'+self.KID[1:]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                default_kids(self.fixture(value))
        with self.assertRaises(ValueError):
            default_kids(self.fixture(self.KID, namespace='urn:wrong'))
        with self.assertRaises(ValueError):
            default_kids(f'<ContentProtection default_KID="{self.KID}"/>')


class PsshFixtureTests(unittest.TestCase):
    SYSTEM = '00112233-4455-6677-8899-aabbccddeeff'
    KID = bytes.fromhex('ffeeddccbbaa99887766554433221100')

    def raw(self, version=0, kids=(), payload=b'abc'):
        data = bytes([version, 0, 0, 0]) + bytes.fromhex(self.SYSTEM.replace('-', ''))
        if version == 1:
            data += struct.pack('>I', len(kids)) + b''.join(kids)
        data += struct.pack('>I', len(payload)) + payload
        return struct.pack('>I4s', len(data) + 8, b'pssh') + data

    def encode(self, raw):
        return base64.b64encode(raw).decode()

    def descriptor(self, value, system=SYSTEM, prefix='cenc'):
        return f'<ContentProtection schemeIdUri="urn:uuid:{system}" xmlns:{prefix}="{CENC_NAMESPACE}"><{prefix}:pssh>{value}</{prefix}:pssh></ContentProtection>'

    def test_pssh_v0_v1_full_box_and_uuid_associations(self):
        for version in (0, 1):
            raw = self.raw(version, [self.KID] if version else [])
            encoded = self.encode(raw)
            parsed = parse_pssh_base64(encoded)
            self.assertEqual(parsed['version'], version)
            self.assertEqual(parsed['data'], b'abc')
            self.assertEqual(parsed['system_id'], self.SYSTEM)
            self.assertEqual(parsed['kids'], ('ffeeddcc-bbaa-9988-7766-554433221100',) if version else ())
            self.assertEqual(descriptor_pssh(self.descriptor(encoded))[0], parsed)
            self.assertEqual(descriptor_pssh(self.descriptor('  '+encoded[:8]+'\n'+encoded[8:]+' ', self.SYSTEM.upper(), 'x'))[0], parsed)

    def test_pssh_every_truncation_and_surplus_rejected(self):
        raw = self.raw(1, [self.KID])
        for end in range(len(raw)):
            with self.subTest(end=end), self.assertRaises(ValueError):
                parse_pssh_base64(self.encode(raw[:end]))
        for corrupt in (raw + b'X', raw[:4] + b'free' + raw[8:], raw[:8] + b'\x02' + raw[9:],
                        raw[:9] + b'\x01' + raw[10:], raw[:28] + b'\xff'*4 + raw[32:]):
            with self.subTest(corrupt=corrupt), self.assertRaises(ValueError):
                parse_pssh_base64(self.encode(corrupt))
        # Keep the full box size valid so the data-size check itself is exercised.
        corrupt = self.raw()[:-3] + b'xx'
        corrupt = struct.pack('>I', len(corrupt)) + corrupt[4:]
        with self.assertRaisesRegex(ValueError, 'data size'):
            parse_pssh_base64(self.encode(corrupt))

    def test_pssh_namespace_system_and_base64_errors(self):
        encoded = self.encode(self.raw())
        for value in ('!', encoded + '!', 'AA=', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_pssh_base64(value)
        with self.assertRaisesRegex(ValueError, 'disagree'):
            descriptor_pssh(self.descriptor(encoded, 'ffeeddcc-bbaa-9988-7766-554433221100'))
        with self.assertRaisesRegex(ValueError, 'missing namespaced'):
            descriptor_pssh(self.descriptor(encoded).replace(CENC_NAMESPACE, 'urn:other'))
        for identity in ('', 'urn:uuid:bad', 'urn:uuid:'+self.SYSTEM+'x'):
            xml = self.descriptor(encoded).replace('urn:uuid:'+self.SYSTEM, identity)
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                descriptor_pssh(xml)

    def test_empty_and_duplicate_kid_payloads_remain_explicit(self):
        self.assertEqual(parse_pssh_base64(self.encode(self.raw(1, [], b'')))['kids'], ())
        value = parse_pssh_base64(self.encode(self.raw(1, [self.KID, self.KID], b'')))
        self.assertEqual(len(value['kids']), 2)
        self.assertEqual(value['kids'][0], value['kids'][1])


class SelectedCounterModelTests(unittest.TestCase):
    def test_frozen_selected_bit_counter_boundaries(self):
        initial = bytes.fromhex('102030405060708000000000000000fe')
        frozen = tuple(bytes.fromhex(x) for x in (
            '102030405060708000000000000000fe',
            '102030405060708000000000000000ff',
            '10203040506070800000000000000100'))
        for bits, blocks in ((0, 0), (1, 1), (7, 1), (8, 1), (9, 1), (127, 1),
                             (128, 1), (129, 2), (255, 2), (256, 2), (257, 3)):
            with self.subTest(bits=bits):
                self.assertEqual(selected_counter_inputs(initial, bits), frozen[:blocks])
        # A fresh call starts from its supplied IV; no retained sample state.
        self.assertEqual(selected_counter_inputs(initial, 1), frozen[:1])

    def test_counter_model_rejects_undeclared_wrap_and_invalid_counts(self):
        with self.assertRaisesRegex(ValueError, 'wrap'):
            selected_counter_inputs(bytes.fromhex('1020304050607080ffffffffffffffff'), 129)
        for value in (-1, 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                selected_counter_inputs(bytes(16), value)
        with self.assertRaises(ValueError):
            selected_counter_inputs(bytes(8), 1)


if __name__ == '__main__':
    unittest.main()
