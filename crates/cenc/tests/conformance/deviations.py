"""Version-bound observed oracle deviations. Never count as normative passes."""
import copy
import json
from pathlib import Path
from mp4 import extract, compare_samples

BENTO_DECRYPT = 'c23dc01aa4157423001efe2f545138f58bc86e83d8124e9b043aedb005414a03'
BENTO_ENCRYPT = '162ab5ad12a9d180e997a86ba1bb121bc23c75ddd51db2e6ea8afd4019650d0a'
SHAKA = 'b3049e743451aab5c2cd7b1316a4ce055682c41effe06a49e2e6c95a9243d351'


def identity(track):
    return json.dumps(track['descriptions'], sort_keys=True)


def audio_tail_witness(original, outputs, expected):
    """Require exact metadata and every byte except audio's final 1..15 bytes."""
    actual = []
    blobs = {}
    for p in outputs:
        for track in extract(p):
            if identity(track) in blobs:
                raise AssertionError('ambiguous oracle track')
            actual.append(track)
            blobs[identity(track)] = Path(p).read_bytes()
    source = Path(original).read_bytes()
    left, right = sorted(expected, key=identity), sorted(actual, key=identity)
    if len(left) != len(right): raise AssertionError('track count')
    normalized = copy.deepcopy(right)
    differing_tails = 0
    for a, b, n in zip(left, right, normalized):
        if len(a['samples']) != len(b['samples']): raise AssertionError('sample count')
        for x, y, z in zip(a['samples'], b['samples'], n['samples']):
            aa = source[x['offset']:x['offset'] + x['size']]
            bb = blobs[identity(b)][y['offset']:y['offset'] + y['size']]
            tail = len(aa) % 16 if a['descriptions'][0]['codec'] == 'mp4a' else 0
            if aa != bb:
                if not tail or len(aa) != len(bb) or aa[:-tail] != bb[:-tail]:
                    raise AssertionError('difference outside exact audio tail')
                differing_tails += 1
            z['sha256'] = x['sha256']
    compare_samples(left, normalized)
    if not differing_tails: raise AssertionError('expected oracle deviation disappeared')
    return differing_tails


def classify(producer, scheme, decoder, original, encrypted, outputs, expected, error, found):
    """Unknown binaries/triggers return None and remain failures."""
    bento = found['mp4decrypt']['sha256'] == BENTO_DECRYPT
    shaka = found['shaka']['sha256'] == SHAKA
    if scheme == 'cens' and (
        (producer == 'bento4' and found['mp4encrypt']['sha256'] == BENTO_ENCRYPT and decoder in ('iori', 'shaka') and shaka)
        or (producer == 'shaka' and shaka and decoder == 'bento4' and bento)
    ):
        try:
            count = audio_tail_witness(original, outputs, expected)
        except (AssertionError, ValueError, OSError):
            return None
        return {'status': 'known-oracle-deviation', 'deviation': 'CENS-AUDIO-TAIL', 'affected_sample_tails': count}
    if producer == 'ffmpeg' and scheme == 'cenc':
        if decoder == 'bento4' and bento and outputs:
            try:
                compare_samples(encrypted, outputs[0])
            except (AssertionError, ValueError, OSError):
                return None
            return {'status': 'tool-unsupported', 'deviation': 'BENTO-PROGRESSIVE-CENC-UNCHANGED'}
        if decoder == 'shaka' and shaka and 'default_is_protected == 0' in str(error) and 'PARSER_FAILURE' in str(error):
            return {'status': 'tool-unsupported', 'deviation': 'SHAKA-PROGRESSIVE-CENC-REJECTED'}
    return None
