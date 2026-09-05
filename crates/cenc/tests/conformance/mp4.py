"""Independent, bounded ISO BMFF sample oracle (Python standard library only).

Unsupported sample-entry layouts and table inconsistencies fail closed. This is
an oracle for conventional audio/video MP4, not a complete ISO BMFF validator.
"""
import hashlib
import json
import struct
from fractions import Fraction
from pathlib import Path


def _bytes(value):
    return value if isinstance(value, bytes) else Path(value).read_bytes()


def u32(data, pos):
    return struct.unpack_from('>I', data, pos)[0]


def i32(data, pos):
    return struct.unpack_from('>i', data, pos)[0]


def u64(data, pos):
    return struct.unpack_from('>Q', data, pos)[0]


def boxes(data, start=0, end=None):
    end = len(data) if end is None else end
    result = []
    while start < end:
        if end - start < 8:
            raise ValueError('truncated box header')
        size, kind = u32(data, start), data[start + 4:start + 8]
        header = 8
        if size == 1:
            if end - start < 16:
                raise ValueError('truncated extended size')
            size, header = u64(data, start + 8), 16
        elif size == 0:
            size = end - start
        if size < header or size > end - start:
            raise ValueError('invalid box size')
        result.append((kind, start, start + header, start + size))
        start += size
    return result


def children(data, box):
    return boxes(data, box[2], box[3])


def one(items, kind, required=True):
    matches = [b for b in items if b[0] == kind]
    if len(matches) > 1 or (required and not matches):
        raise ValueError('missing or duplicate ' + kind.decode())
    return matches[0] if matches else None


def payload(data, box):
    return data[box[2]:box[3]]


def expand_table(data, box, signed=False):
    p = payload(data, box)
    count = u32(p, 4)
    if len(p) != 8 + count * 8:
        raise ValueError('invalid time table')
    result = []
    for pos in range(8, len(p), 8):
        n = u32(p, pos)
        if n > len(data) - len(result):
            raise ValueError('unbounded time table')
        value = i32(p, pos + 4) if signed else u32(p, pos + 4)
        result.extend([value] * n)
    return result


def rational(n, scale):
    f = Fraction(n, scale)
    return [f.numerator, f.denominator]


def esds_config(data):
    """Keep decoder identity/configuration, excluding muxer ES IDs and bitrate."""
    def descriptors(p):
        result = []
        pos = 0
        while pos < len(p):
            tag, pos = p[pos], pos + 1
            length = 0
            for _ in range(4):
                if pos >= len(p):
                    raise ValueError('truncated descriptor length')
                value, pos = p[pos], pos + 1
                length = (length << 7) | (value & 127)
                if not value & 128:
                    break
            else:
                raise ValueError('invalid descriptor length')
            if length > len(p) - pos:
                raise ValueError('truncated descriptor')
            result.append((tag, p[pos:pos + length]))
            pos += length
        return result
    records = descriptors(data[4:])
    if len(records) != 1 or records[0][0] != 3:
        raise ValueError('expected ES descriptor')
    es = records[0][1]
    if len(es) < 3:
        raise ValueError('short ES descriptor')
    flags, pos = es[2], 3
    if flags & 128:
        pos += 2
    if flags & 64:
        if pos >= len(es):
            raise ValueError('short ES URL')
        pos += 1 + es[pos]
    if flags & 32:
        pos += 2
    configs = [p for tag, p in descriptors(es[pos:]) if tag == 4]
    if len(configs) != 1 or len(configs[0]) < 13:
        raise ValueError('missing decoder descriptor')
    config = configs[0]
    specific = [p for tag, p in descriptors(config[13:]) if tag == 5]
    if len(specific) != 1:
        raise ValueError('missing decoder-specific information')
    return config[:2] + specific[0]


def entry_info(data, entry):
    p = entry[2]
    kind = entry[0]
    visual = {b'avc1', b'avc3', b'hvc1', b'hev1', b'encv', b'vp09', b'av01'}
    audio = {b'mp4a', b'enca', b'ac-3', b'ec-3', b'Opus', b'fLaC'}
    if kind in visual:
        offset = p + 78
    elif kind in audio:
        version = struct.unpack_from('>H', data, p + 8)[0]
        if version not in (0, 1, 2):
            raise ValueError('unsupported audio sample entry version')
        offset = p + {0: 28, 1: 44, 2: 64}[version]
    else:
        raise ValueError('unsupported sample entry ' + repr(kind))
    nested = boxes(data, offset, entry[3])
    sinf = one(nested, b'sinf', False)
    if sinf:
        frma = one(children(data, sinf), b'frma')
        kind = payload(data, frma)
    configs = [b[0] + (esds_config(payload(data, b)) if b[0] == b'esds' else payload(data, b)) for b in nested if b[0] in
               {b'avcC', b'hvcC', b'av1C', b'vpcC', b'esds', b'dac3', b'dec3', b'dOps', b'dfLa'}]
    return kind.decode('ascii'), hashlib.sha256(b''.join(configs)).hexdigest(), offset


def extract(source):
    data = _bytes(source)
    top = boxes(data)
    moov = one(top, b'moov')
    movie = children(data, moov)
    mvhd = one(movie, b'mvhd', False)
    movie_scale = None
    if mvhd:
        p = payload(data, mvhd)
        movie_scale = u32(p, 20 if p[0] == 1 else 12)
    tracks = {}
    states = {}
    media = [(b[2], b[3]) for b in top if b[0] == b'mdat']
    def sample(track, offset, size, dts, duration, cts, description):
        if not any(lo <= offset <= offset + size <= hi for lo, hi in media):
            raise ValueError('sample outside mdat')
        if description < 1 or description > len(track['descriptions']):
            raise ValueError('invalid sample description index')
        track['samples'].append(dict(offset=offset, size=size,
            sha256=hashlib.sha256(data[offset:offset + size]).hexdigest(),
            dts=rational(dts, track['timescale']),
            cts=rational(cts, track['timescale']),
            duration=rational(duration, track['timescale']),
            description=track['descriptions'][description - 1], description_index=description))
    for trak in [b for b in movie if b[0] == b'trak']:
        tk = children(data, trak)
        p = payload(data, one(tk, b'tkhd'))
        tid = u32(p, 20 if p[0] == 1 else 12)
        mdia = children(data, one(tk, b'mdia'))
        p = payload(data, one(mdia, b'mdhd'))
        scale = u32(p, 20 if p[0] == 1 else 12)
        if not scale or tid in tracks:
            raise ValueError('invalid timescale or duplicate track')
        stbl = children(data, one(children(data, one(mdia, b'minf')), b'stbl'))
        stsd = one(stbl, b'stsd')
        entries = boxes(data, stsd[2] + 8, stsd[3])
        if len(entries) != u32(data, stsd[2] + 4):
            raise ValueError('sample description count mismatch')
        descriptions = [dict(zip(('codec', 'config_sha256'), entry_info(data, e)[:2])) for e in entries]
        track = dict(id=tid, timescale=scale, descriptions=descriptions, samples=[])
        # Preserve edit lists: an output remuxer must not silently discard priming.
        edts = one(tk, b'edts', False)
        track['edit_list'] = []
        if edts:
            if not movie_scale:
                raise ValueError('edit list without movie timescale')
            elst = one(children(data, edts), b'elst')
            p = payload(data, elst)
            width = 20 if p[0] == 1 else 12
            if p[0] not in (0, 1) or len(p) != 8 + u32(p, 4) * width:
                raise ValueError('invalid edit list')
            for pos in range(8, len(p), width):
                if p[0]:
                    duration, media_time, rate = struct.unpack_from('>Qqi', p, pos)
                else:
                    duration, media_time, rate = struct.unpack_from('>Iii', p, pos)
                track['edit_list'].append([rational(duration, movie_scale),
                    None if media_time == -1 else rational(media_time, scale), rational(rate, 65536)])
        tracks[tid] = track
        stsz = one(stbl, b'stsz', False)
        if stsz:
            p = payload(data, stsz)
            fixed, count = u32(p, 4), u32(p, 8)
            if count > len(data) or (not fixed and len(p) != 12 + count * 4):
                raise ValueError('invalid sample size table')
            sizes = [fixed] * count if fixed else [u32(p, 12 + i * 4) for i in range(count)]
        else:
            small = one(stbl, b'stz2', False)
            if not small:
                raise ValueError('missing size table')
            p = payload(data, small)
            width, count = p[7], u32(p, 8)
            if width not in (4, 8, 16) or len(p) != 12 + (width * count + 7) // 8:
                raise ValueError('invalid compact sizes')
            sizes = [(p[12 + i // 2] >> (4 if i % 2 == 0 else 0)) & 15 for i in range(count)] if width == 4 else [int.from_bytes(p[12 + i * (width // 8):12 + (i + 1) * (width // 8)], 'big') for i in range(count)]
        dts = 0
        if sizes:
            durations = expand_table(data, one(stbl, b'stts'))
            ct = one(stbl, b'ctts', False)
            cts = expand_table(data, ct, data[ct[2]] == 1) if ct else [0] * len(sizes)
            if len(durations) != len(sizes) or len(cts) != len(sizes):
                raise ValueError('time/sample count mismatch')
            chunks = one(stbl, b'stco', False) or one(stbl, b'co64')
            p = payload(data, chunks)
            width = 4 if chunks[0] == b'stco' else 8
            if len(p) != 8 + u32(p, 4) * width:
                raise ValueError('invalid chunk table')
            offsets = [int.from_bytes(p[i:i + width], 'big') for i in range(8, len(p), width)]
            p = payload(data, one(stbl, b'stsc'))
            if len(p) != 8 + u32(p, 4) * 12:
                raise ValueError('invalid stsc')
            mapping = [struct.unpack_from('>III', p, i) for i in range(8, len(p), 12)]
            if not mapping or mapping[0][0] != 1 or any(a[0] >= b[0] for a, b in zip(mapping, mapping[1:])):
                raise ValueError('invalid chunk mapping')
            index = row = 0
            for chunk_index, offset in enumerate(offsets, 1):
                while row + 1 < len(mapping) and mapping[row + 1][0] <= chunk_index:
                    row += 1
                _, n, desc = mapping[row]
                if n > len(sizes) - index:
                    raise ValueError('chunk sample count overflow')
                for _ in range(n):
                    sample(track, offset, sizes[index], dts, durations[index], cts[index], desc)
                    offset += sizes[index]
                    dts += durations[index]
                    index += 1
            if index != len(sizes):
                raise ValueError('unmapped samples')
        states[tid] = dts
    defaults = {}
    mvex = one(movie, b'mvex', False)
    if mvex:
        for b in children(data, mvex):
            if b[0] == b'trex':
                p = payload(data, b)
                defaults[u32(p, 4)] = [u32(p, i) for i in (8, 12, 16, 20)]
    for moof in [b for b in top if b[0] == b'moof']:
        preceding_end = moof[1]
        for traf in [b for b in children(data, moof) if b[0] == b'traf']:
            tc = children(data, traf)
            p = payload(data, one(tc, b'tfhd'))
            flags, tid, pos = u32(p, 0) & 0xffffff, u32(p, 4), 8
            if tid not in tracks:
                raise ValueError('fragment for unknown track')
            desc, duration, size, _ = defaults.get(tid, [1, None, None, 0])
            base = moof[1] if flags & 0x20000 else preceding_end
            if flags & 1:
                base, pos = u64(p, pos), pos + 8
            if flags & 2:
                desc, pos = u32(p, pos), pos + 4
            if flags & 8:
                duration, pos = u32(p, pos), pos + 4
            if flags & 16:
                size, pos = u32(p, pos), pos + 4
            if flags & 32:
                pos += 4
            if pos != len(p):
                raise ValueError('invalid tfhd length')
            tfdt = one(tc, b'tfdt', False)
            dts = states[tid]
            if tfdt:
                p = payload(data, tfdt)
                dts = u64(p, 4) if p[0] else u32(p, 4)
            end = base
            for run in [b for b in tc if b[0] == b'trun']:
                p = payload(data, run)
                flags, count, pos = u32(p, 0) & 0xffffff, u32(p, 4), 8
                if count > len(data):
                    raise ValueError('unbounded run')
                offset = end
                if flags & 1:
                    offset, pos = base + i32(p, pos), pos + 4
                if flags & 4:
                    pos += 4
                for _ in range(count):
                    dur, length, cts = duration, size, 0
                    if flags & 0x100:
                        dur, pos = u32(p, pos), pos + 4
                    if flags & 0x200:
                        length, pos = u32(p, pos), pos + 4
                    if flags & 0x400:
                        pos += 4
                    if flags & 0x800:
                        cts, pos = (i32(p, pos) if p[0] == 1 else u32(p, pos)), pos + 4
                    if dur is None or length is None:
                        raise ValueError('missing fragment size/duration')
                    sample(tracks[tid], offset, length, dts, dur, cts, desc)
                    offset += length
                    dts += dur
                if pos != len(p):
                    raise ValueError('invalid trun length')
                end = offset
            preceding_end = end
            states[tid] = dts
    return list(tracks.values())


def compare_samples(reference, actual, track_map=None):
    """Compare logical tracks independent of IDs, offsets, and timescale units.

    Identical codec configurations on multiple tracks require an explicit bijective
    track_map from reference IDs to output IDs; ambiguous matching fails closed.
    """
    left_bytes = None if isinstance(reference, list) else _bytes(reference)
    right_bytes = None if isinstance(actual, list) else _bytes(actual)
    left = extract(left_bytes) if left_bytes is not None else reference
    right = extract(right_bytes) if right_bytes is not None else actual
    def key(t):
        # Clear/protected aliases of one encoded format may occupy two stsd entries.
        return json.dumps(sorted({json.dumps(d, sort_keys=True) for d in t['descriptions']}))
    if track_map is not None:
        left_ids = {t['id']: t for t in left}
        right_ids = {t['id']: t for t in right}
        if (len(left_ids) != len(left) or len(right_ids) != len(right) or
                set(track_map) != set(left_ids) or set(track_map.values()) != set(right_ids) or
                len(set(track_map.values())) != len(track_map)):
            raise AssertionError('track_map must bijectively cover all tracks')
        pairs = [(left_ids[a], right_ids[b]) for a, b in track_map.items()]
    else:
        if len({key(t) for t in left}) != len(left) or len({key(t) for t in right}) != len(right):
            raise AssertionError('ambiguous track identity; supply explicit track_map')
        pairs = zip(sorted(left, key=key), sorted(right, key=key))
    if len(left) != len(right):
        raise AssertionError('track count mismatch')
    for a, b in pairs:
        if key(a) != key(b):
            raise AssertionError('codec configuration mismatch')
        if a['edit_list'] != b['edit_list']:
            raise AssertionError('edit-list representation differs; explicit normalization required')
        if len(a['samples']) != len(b['samples']):
            raise AssertionError('sample count mismatch')
        for i, (x, y) in enumerate(zip(a['samples'], b['samples'])):
            for field in ('size', 'sha256', 'dts', 'cts', 'duration', 'description'):
                if x[field] != y[field]:
                    if field == 'sha256' and left_bytes is not None and right_bytes is not None:
                        aa = left_bytes[x['offset']:x['offset'] + x['size']]
                        bb = right_bytes[y['offset']:y['offset'] + y['size']]
                        first = next((j for j, pair in enumerate(zip(aa, bb)) if pair[0] != pair[1]), min(len(aa), len(bb)))
                        raise AssertionError(f'track {a["id"]} sample {i} sha256 mismatch, first differing byte {first}: {x[field]} != {y[field]}')
                    raise AssertionError(f'track {a["id"]} sample {i} {field}: {x[field]} != {y[field]}')


def assert_in_place(before, after):
    """Validate stable box layout and a conservative encryption edit allowlist.

    Media samples may change; mdat padding may not. Encryption signaling can be
    replaced with free; unrelated groups/typed auxiliary tables cannot disappear.
    """
    before, after = _bytes(before), _bytes(after)
    if len(before) != len(after):
        raise AssertionError('file size changed')
    allowed = bytearray(len(before))
    for track in extract(before):
        for s in track['samples']:
            allowed[s['offset']:s['offset'] + s['size']] = b'\1' * s['size']
    containers = {b'moov', b'trak', b'mdia', b'minf', b'stbl', b'mvex', b'moof', b'traf', b'edts', b'sinf', b'schi'}
    def encryption(b):
        kind, _, p, e = b
        if kind in {b'sinf', b'senc', b'tenc', b'pssh'}:
            return True
        if kind in {b'sbgp', b'sgpd'}:
            return before[p + 4:p + 8] == b'seig'
        if kind in {b'saiz', b'saio'}:
            if not (u32(before, p) & 1):
                return True
            if e - p < 12:
                return False
            aux_type, parameter = before[p + 4:p + 8], u32(before, p + 8)
            return aux_type == bytes(4) or (aux_type in {b'cenc', b'cens', b'cbc1', b'cbcs'} and parameter <= 1)
        return False
    def walk(old, new):
        if len(old) != len(new):
            raise AssertionError('box count changed')
        for a, b in zip(old, new):
            if a[1:] != b[1:]:
                raise AssertionError('box offset/size changed')
            if encryption(a):
                if b[0] not in (a[0], b'free'):
                    raise AssertionError('unexpected encryption box replacement')
                allowed[a[1] + 4:a[3]] = b'\1' * (a[3] - a[1] - 4)
                continue
            if a[0] in {b'encv', b'enca'}:
                codec, _, offset = entry_info(before, a)
                if b[0] not in (a[0], codec.encode()):
                    raise AssertionError('incorrect clear sample-entry type')
                allowed[a[1] + 4:a[1] + 8] = b'\1' * 4
                walk(boxes(before, offset, a[3]), boxes(after, offset, b[3]))
            elif a[0] != b[0]:
                raise AssertionError('unrelated box type changed')
            elif a[0] in containers:
                walk(children(before, a), children(after, b))
            elif a[0] == b'stsd':
                walk(boxes(before, a[2] + 8, a[3]), boxes(after, b[2] + 8, b[3]))
    walk(boxes(before), boxes(after))
    for i, (a, b) in enumerate(zip(before, after)):
        if a != b and not allowed[i]:
            raise AssertionError(f'unrelated byte changed at {i}')


if __name__ == '__main__':
    import sys
    print(json.dumps(extract(sys.argv[1]), indent=2))
