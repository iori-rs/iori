"""Independent encryption-range oracle for single-key track fixtures.

Checks the parsed witness, not ISO completeness. Unsupported signaling fails
explicitly; no production parser is imported. Offsets are absolute/end-exclusive.
"""
import struct
from mp4 import _bytes, boxes, children, entry_info, extract, one, payload, u32


class UnsupportedLayout(ValueError):
    pass


def protected_ranges(start, size, scheme, crypt=0, skip=0):
    """Return encrypted ranges and clear partial blocks in a crypt phase."""
    if scheme not in ('cenc', 'cens', 'cbc1', 'cbcs'):
        raise UnsupportedLayout('unknown protection scheme')
    if scheme == 'cenc':
        return ([(start, start + size)] if size else []), []
    result, tails = [], []
    blocks, tail = divmod(size, 16)
    patterned = scheme in ('cens', 'cbcs') and (crypt or skip)
    for i in range(blocks):
        if not patterned or i % (crypt + skip) < crypt:
            result.append((start + i * 16, start + (i + 1) * 16))
    if tail and (not patterned or blocks % (crypt + skip) < crypt):
        tails.append((start + blocks * 16, start + size))
    return result, tails


def protection(p, scheme, tenc=False):
    if tenc:
        if len(p) < 24 or p[0] not in (0, 1) or p[1:4] != bytes(3):
            raise ValueError('invalid tenc header')
        p = p[4:]
    if len(p) < 20 or p[0] != 0 or p[2] not in (0, 1):
        raise ValueError('invalid protection description')
    crypt, skip, enabled, iv_size = p[1] >> 4, p[1] & 15, p[2], p[3]
    if scheme in ('cenc', 'cbc1') and (crypt or skip):
        raise ValueError('pattern on unpatterned scheme')
    if enabled and iv_size not in (0, 8, 16):
        raise ValueError('invalid IV width')
    if enabled and scheme in ('cbc1', 'cbcs') and iv_size == 8:
        raise ValueError('CBC requires 16-byte IV')
    if enabled and iv_size == 0:
        if len(p) < 21 or p[20] != 16 or len(p) != 37:
            raise ValueError('invalid constant IV')
        if scheme not in ('cbcs',):
            raise ValueError('constant IV outside CBCS fixture profile')
    elif len(p) != 20:
        raise ValueError('unexpected protection payload')
    return dict(scheme=scheme, crypt=crypt, skip=skip, protected=bool(enabled), iv_size=iv_size, kid=p[4:20].hex())


def group_table(data, scope, scheme):
    found = [b for b in scope if b[0] == b'sgpd' and data[b[2] + 4:b[2] + 8] == b'seig']
    if not found:
        return [], 0
    if len(found) != 1:
        raise ValueError('duplicate seig table')
    p = payload(data, found[0])
    version = p[0]
    if version not in (1, 2):
        raise UnsupportedLayout('seig sgpd version zero')
    default_length, pos, default_index = u32(p, 8), 12, 0
    if version == 2:
        default_index, pos = u32(p, pos), pos + 4
    count, pos = u32(p, pos), pos + 4
    entries = []
    if count > len(p):
        raise ValueError('unbounded group count')
    for _ in range(count):
        length = default_length
        if not length:
            length, pos = u32(p, pos), pos + 4
        if length > len(p) - pos:
            raise ValueError('truncated group description')
        entries.append(protection(p[pos:pos + length], scheme))
        pos += length
    if pos != len(p) or default_index > len(entries):
        raise ValueError('invalid group table')
    return entries, default_index


def validate(source):
    data = _bytes(source)
    top = boxes(data)
    moov = children(data, one(top, b'moov'))
    tracks = {t['id']: t for t in extract(data)}
    configs, tables, cursors, records = {}, {}, {}, []
    def scope_samples(scope, tid, count, fragment=False):
        start = cursors[tid]
        samples = tracks[tid]['samples'][start:start + count]
        if len(samples) != count:
            raise ValueError('encryption/sample count mismatch')
        base = configs[tid][0]
        local, default_index = group_table(data, scope, base['scheme'])
        track_entries, track_default = tables[tid]
        assignments = [0] * count
        maps = [b for b in scope if b[0] == b'sbgp' and data[b[2] + 4:b[2] + 8] == b'seig']
        if len(maps) > 1:
            raise ValueError('duplicate seig map')
        if maps:
            p = payload(data, maps[0])
            if p[0] not in (0, 1):
                raise UnsupportedLayout('sbgp version')
            pos = 12 if p[0] == 1 else 8
            n, pos = u32(p, pos), pos + 4
            assignments = []
            for _ in range(n):
                size, index = u32(p, pos), u32(p, pos + 4)
                pos += 8
                if size > count - len(assignments):
                    raise ValueError('group sample overflow')
                assignments.extend([index] * size)
            if pos != len(p) or len(assignments) != count:
                raise ValueError('group map length mismatch')
        effective = []
        for sample, index in zip(samples, assignments):
            selected = configs[tid][sample['description_index'] - 1]
            if index:
                source_table = local if not fragment or index >= 0x10000 else track_entries
                index = index - 0x10000 if fragment and index >= 0x10000 else index
                if not 1 <= index <= len(source_table):
                    raise ValueError('invalid group description reference')
                selected = source_table[index - 1]
            elif default_index:
                selected = local[default_index - 1]
            elif track_default:
                selected = track_entries[track_default - 1]
            effective.append(selected)
        senc = one(scope, b'senc', False)
        p, pos, flags = b'', 0, 0
        if senc:
            p = payload(data, senc)
            flags = u32(p, 0) & 0xffffff
            if p[0] != 0 or flags & ~2:
                raise UnsupportedLayout('senc version/override/multi-key flags')
            if u32(p, 4) != count:
                raise ValueError('senc count mismatch')
            pos = 8
        elif any(c['protected'] and c['iv_size'] for c in effective):
            raise UnsupportedLayout('auxiliary records without senc')
        for i, (sample, config) in enumerate(zip(samples, effective)):
            if senc:
                width = config['iv_size'] if config['protected'] else 0
                if width > len(p) - pos:
                    raise ValueError('truncated sample IV')
                pos += width
            ranges = [(0, sample['size'])]
            if senc and flags & 2:
                if len(p) - pos < 2:
                    raise ValueError('missing subsample count')
                n = struct.unpack_from('>H', p, pos)[0]
                pos += 2
                if n:
                    ranges, cursor = [], 0
                    for _ in range(n):
                        if len(p) - pos < 6:
                            raise ValueError('truncated subsample')
                        clear, protected = struct.unpack_from('>HI', p, pos)
                        pos += 6
                        cursor += clear
                        ranges.append((cursor, protected))
                        cursor += protected
                    if cursor != sample['size']:
                        raise ValueError('subsample coverage differs from sample size')
            encrypted, tails = [], []
            if config['protected']:
                for offset, size in ranges:
                    enc, tail = protected_ranges(sample['offset'] + offset, size,
                        config['scheme'], config['crypt'], config['skip'])
                    encrypted.extend(enc)
                    tails.extend(tail)
            records.append(dict(track_id=tid, index=start + i, offset=sample['offset'],
                size=sample['size'], scheme=config['scheme'], kid=config.get('kid'), protected=config['protected'], encrypted_ranges=encrypted,
                clear_tail_ranges=tails if config['scheme'] == 'cens' else []))
        if senc and pos != len(p):
            raise ValueError('unconsumed senc bytes')
        cursors[tid] += count
    for trak in [b for b in moov if b[0] == b'trak']:
        tc = children(data, trak)
        p = payload(data, one(tc, b'tkhd'))
        tid = u32(p, 20 if p[0] == 1 else 12)
        stbl = children(data, one(children(data, one(children(data, one(tc, b'mdia')), b'minf')), b'stbl'))
        stsd = one(stbl, b'stsd')
        entries = boxes(data, stsd[2] + 8, stsd[3])
        entry_configs = []
        for entry in entries:
            _, _, pos = entry_info(data, entry)
            sinf = one(boxes(data, pos, entry[3]), b'sinf', False)
            if sinf:
                sc = children(data, sinf)
                schm = payload(data, one(sc, b'schm'))
                scheme = schm[4:8].decode('ascii')
                if scheme not in ('cenc', 'cens', 'cbc1', 'cbcs'):
                    raise UnsupportedLayout('scheme ' + scheme)
                tenc = one(children(data, one(sc, b'schi')), b'tenc')
                config = protection(payload(data, tenc), scheme, True)
            else:
                config = dict(scheme='cenc', crypt=0, skip=0, protected=False, iv_size=0)
            entry_configs.append(config)
        configs[tid], cursors[tid] = entry_configs, 0
        tables[tid] = group_table(data, stbl, entry_configs[0]['scheme'])
        stsz = one(stbl, b'stsz', False)
        if not stsz:
            raise UnsupportedLayout('compact-size encrypted fixture')
        scope_samples(stbl, tid, u32(data, stsz[2] + 8))
    for moof in [b for b in top if b[0] == b'moof']:
        for traf in [b for b in children(data, moof) if b[0] == b'traf']:
            tc = children(data, traf)
            tid = u32(data, one(tc, b'tfhd')[2] + 4)
            count = sum(u32(data, b[2] + 4) for b in tc if b[0] == b'trun')
            scope_samples(tc, tid, count, True)
    if any(cursors[t] != len(tracks[t]['samples']) for t in tracks):
        raise ValueError('samples lack encryption mapping')
    return dict(samples=records, validation='supported-single-key-track-witness')


def assert_clear_bytes(encrypted, decrypted):
    before, after = _bytes(encrypted), _bytes(decrypted)
    if len(before) != len(after):
        raise AssertionError('in-place size changed')
    for sample in validate(before)['samples']:
        mask = bytearray(sample['size'])
        for start, end in sample['encrypted_ranges']:
            mask[start - sample['offset']:end - sample['offset']] = b'\1' * (end - start)
        for i, allowed in enumerate(mask):
            pos = sample['offset'] + i
            if not allowed and before[pos] != after[pos]:
                raise AssertionError(f'clear byte changed at {pos}, track {sample["track_id"]} sample {sample["index"]}')


def assert_cens_tail_only_difference(source, actual, encrypted):
    """Require an actual mismatch, confined exactly to CENS clear crypt tails.

    The caller must separately establish codec/timing identity. Never counts as
    ordinary sample-oracle success; returns evidence for a named compatibility deviation.
    """
    source, actual, encrypted = _bytes(source), _bytes(actual), _bytes(encrypted)
    original, output, enc = extract(source), extract(actual), extract(encrypted)
    if len(original) != 1 or len(output) != 1 or len(enc) != 1:
        raise UnsupportedLayout('tail diagnostic requires explicit single-track pairing')
    aa, bb, cc = original[0]['samples'], output[0]['samples'], enc[0]['samples']
    records = validate(encrypted)['samples']
    if not len(aa) == len(bb) == len(cc) == len(records):
        raise AssertionError('tail diagnostic sample count mismatch')
    differences = 0
    for a, b, c, record in zip(aa, bb, cc, records):
        if a['size'] != b['size'] or a['size'] != c['size']:
            raise AssertionError('tail diagnostic sample size mismatch')
        permitted = set()
        for start, end in record['clear_tail_ranges']:
            permitted.update(range(start - c['offset'], end - c['offset']))
        for i in range(a['size']):
            if source[a['offset'] + i] != actual[b['offset'] + i]:
                if i not in permitted:
                    raise AssertionError(f'difference outside CENS clear tail at sample {record["index"]} byte {i}')
                differences += 1
    if not differences:
        raise AssertionError('expected CENS tail deviation did not occur')
    return dict(differing_bytes=differences, boundary='CENS partial crypt-block tails only')
