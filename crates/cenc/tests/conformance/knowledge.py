"""Isolated reference mechanisms; NOT an implementation of SVE1 or Annex A.

Selection maps are externally supplied MSB-first bit coordinates. XML helpers
validate fixture identity only, not the complete Part 7 manifest requirements.
"""
import re
import xml.etree.ElementTree as ET

CENC_NAMESPACE = 'urn:mpeg:cenc:2013'
UUID_PATTERN = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')


def _validate_positions(data: bytes, positions: list[int]) -> None:
    if len(set(positions)) != len(positions):
        raise ValueError('duplicate bit selection')
    if any(type(p) is not int or not 0 <= p < len(data) * 8 for p in positions):
        raise ValueError('bit selection outside buffer')


def pack_selected(data: bytes, positions: list[int]) -> bytes:
    """Pack supplied coordinates in supplied order; zero-pad last byte on right."""
    _validate_positions(data, positions)
    result = bytearray((len(positions) + 7) // 8)
    for index, bit in enumerate(positions):
        result[index // 8] |= ((data[bit // 8] >> (7 - bit % 8)) & 1) << (7 - index % 8)
    return bytes(result)


def xor_selected(data: bytes, positions: list[int], mask: bytes) -> bytes:
    """Scatter XOR mask without choosing eligibility or cryptographic state."""
    _validate_positions(data, positions)
    if len(mask) * 8 < len(positions):
        raise ValueError('insufficient selected-bit mask')
    result = bytearray(data)
    for index, bit in enumerate(positions):
        result[bit // 8] ^= ((mask[index // 8] >> (7 - index % 8)) & 1) << (7 - bit % 8)
    return bytes(result)


def default_kids(xml: str) -> tuple[str, ...]:
    """Read namespaced fixture UUID identities, retaining order and duplicates."""
    node = ET.fromstring(xml)
    value = node.attrib.get(f'{{{CENC_NAMESPACE}}}default_KID')
    if value is None:
        raise ValueError('missing namespaced default_KID')
    tokens = value.split()
    if not tokens or any(not UUID_PATTERN.fullmatch(token) for token in tokens):
        raise ValueError('invalid UUID list')
    return tuple(token.lower() for token in tokens)


def selected_counter_inputs(initial: bytes, selected_bits: int) -> tuple[bytes, ...]:
    """Explicit harness model: one AES block per 128 selected bits, low64 count.

    Reject low-word wrap as a fixture-construction error. This does not choose
    SVE1's normative state reset or wrap policy, or implement its AES transform.
    """
    if len(initial) != 16 or type(selected_bits) is not int or selected_bits < 0:
        raise ValueError('invalid selected-bit counter request')
    count = (selected_bits + 127) // 128
    low = int.from_bytes(initial[8:], 'big')
    if count and low + count - 1 >= 1 << 64:
        raise ValueError('reference counter model forbids low-word wrap')
    return tuple(initial[:8] + (low + i).to_bytes(8, 'big') for i in range(count))


def parse_pssh_base64(value: str) -> dict:
    """Decode a complete ordinary-size v0/v1 PSSH fixture with bounded counts."""
    import base64
    import binascii
    import struct
    import uuid
    try:
        data = base64.b64decode(''.join(value.split()), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError('invalid PSSH base64') from error
    if len(data) < 32:
        raise ValueError('truncated full PSSH box')
    size, kind = struct.unpack_from('>I4s', data)
    if size != len(data) or kind != b'pssh':
        raise ValueError('PSSH size/type mismatch')
    version = data[8]
    if version not in (0, 1) or data[9:12] != bytes(3):
        raise ValueError('unsupported PSSH version or flags')
    system_id = str(uuid.UUID(bytes=data[12:28]))
    pos, kids = 28, []
    if version == 1:
        count = int.from_bytes(data[pos:pos + 4], 'big')
        pos += 4
        if count > (len(data) - pos - 4) // 16:
            raise ValueError('truncated PSSH KID array')
        kids = [str(uuid.UUID(bytes=data[pos + i * 16:pos + (i + 1) * 16])) for i in range(count)]
        pos += count * 16
    if len(data) - pos < 4:
        raise ValueError('missing PSSH data size')
    data_size = int.from_bytes(data[pos:pos + 4], 'big')
    pos += 4
    if data_size != len(data) - pos:
        raise ValueError('PSSH data size mismatch')
    return {'version': version, 'system_id': system_id, 'kids': tuple(kids), 'data': data[pos:]}


def descriptor_pssh(xml: str) -> tuple[dict, ...]:
    """Cross-check fixture descriptor system IDs against namespaced PSSH boxes.

    Unknown but well-formed system UUIDs are allowed. Payload-specific DRM
    semantics and complete DASH/Part7 descriptor rules are outside this helper.
    """
    node = ET.fromstring(xml)
    identity = node.attrib.get('schemeIdUri', '')
    prefix = 'urn:uuid:'
    if not identity.lower().startswith(prefix) or not UUID_PATTERN.fullmatch(identity[len(prefix):]):
        raise ValueError('invalid descriptor system UUID')
    system = identity[len(prefix):].lower()
    values = [parse_pssh_base64(child.text or '') for child in node
              if child.tag == f'{{{CENC_NAMESPACE}}}pssh']
    if not values:
        raise ValueError('missing namespaced PSSH')
    if any(value['system_id'] != system for value in values):
        raise ValueError('descriptor and PSSH system ID disagree')
    return tuple(values)
