"""Real Shaka clear-lead, rotation, and detached-fragment interoperability.

Raw-key rotation derives test keys using byte-left-rotation, as documented by
Shaka RawKeySource::GetCryptoPeriodKey (test-only, never production key logic):
https://github.com/shaka-project/shaka-packager/blob/main/packager/media/base/raw_key_source.cc
Actual per-sample KIDs are independently checked against this finite key set.
"""
import copy
import json
from pathlib import Path
from mp4 import boxes, compare_samples, extract, assert_in_place
from validity import validate, assert_clear_bytes


def rotated_keys(kid, key):
    kid, key = bytes.fromhex(kid), bytes.fromhex(key)
    if len(kid) != 16 or len(key) != 16:
        raise ValueError('test rotation requires AES-128 key and 16-byte KID')
    return [((kid[i:] + kid[:i]).hex(), (key[i:] + key[:i]).hex()) for i in range(16)]


def split_fragments(data):
    """Retain ftyp/moov init and each moof with its following mdat(s)."""
    init, fragments, pending = [], [], None
    for kind, start, _, end in boxes(data):
        raw = data[start:end]
        if kind in (b'ftyp', b'moov'):
            init.append(raw)
        elif kind == b'moof':
            if pending is not None:
                fragments.append(b''.join(pending))
            pending = [raw]
        elif kind == b'mdat':
            if pending is None:
                raise ValueError('media before first fragment')
            pending.append(raw)
    if pending is not None:
        fragments.append(b''.join(pending))
    if not init or not fragments:
        raise ValueError('missing initialization or media fragments')
    return b''.join(init), fragments


def expected_fragment(source_tracks, encrypted_tracks):
    """Select the exact source interval by rational DTS; never trim to force match."""
    if len(source_tracks) != 1 or len(encrypted_tracks) != 1:
        raise ValueError('streaming fixture requires one explicit video track')
    reference = copy.deepcopy(source_tracks[0])
    by_dts = {tuple(s['dts']): s for s in reference['samples']}
    if len(by_dts) != len(reference['samples']):
        raise ValueError('ambiguous source DTS')
    selected = []
    for sample in encrypted_tracks[0]['samples']:
        original = by_dts.get(tuple(sample['dts']))
        if original is None or any(original[k] != sample[k] for k in ('size', 'duration', 'cts', 'description')):
            raise AssertionError('fragment does not map exactly to source sample timeline')
        selected.append(original)
    if not selected:
        raise AssertionError('empty fragment witness')
    reference['samples'] = selected
    return [reference]


def classify_rotation(decoder, error, found, observed, expected_kids, iori_pass, encrypted, output):
    """Version-bound capability failures, after the independent iori/source pass."""
    from deviations import BENTO_DECRYPT, SHAKA
    if (not iori_pass or len(observed) < 2 or not set(observed) <= set(expected_kids)
            or found.get('shaka', {}).get('sha256') != SHAKA):
        return None
    if decoder == 'bento4' and found.get('mp4decrypt', {}).get('sha256') == BENTO_DECRYPT:
        try:
            compare_samples(encrypted, output)
        except (AssertionError, ValueError, OSError):
            return None
        return dict(status='tool-unsupported', deviation='BENTO-SEIG-ROTATION-UNCHANGED',
                    evidence='all encoded samples and timing equal encrypted input')
    if decoder == 'shaka' and 'PARSER_FAILURE' in str(error) and 'ParseFromSampleEncryptionData' in str(error):
        return dict(status='tool-unsupported', deviation='SHAKA-SEIG-ROTATION-REJECTED',
                    evidence='pinned producer rejects its own seig rotation in senc parser')
    return None


def run_streaming(out, found, adapter):
    from run import execute, KEYS, digest
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    t = {k: v['path'] for k, v in found.items()}
    source = out / 'source.mp4'
    execute([t['ffmpeg'], '-v', 'error', '-y', '-f', 'lavfi', '-i',
        'testsrc2=size=160x96:rate=12:duration=1.5', '-c:v', 'libx264',
        '-profile:v', 'baseline', '-g', '6', '-threads', '1', '-use_editlist', '0', source], out, 'source')
    source_tracks = extract(source)
    results = []
    for mode in ('clear-lead', 'key-rotation', 'detached-all', 'detached-last'):
        case = out / mode
        case.mkdir(parents=True, exist_ok=True)
        record = dict(id='shaka-streaming-' + mode, producer='shaka', scheme='cenc', status='pass', comparisons=[])
        try:
            encrypted = case / 'encrypted.mp4'
            rotation = mode == 'key-rotation'
            keys = rotated_keys(*KEYS[0]) if rotation else [KEYS[0]]
            argv = [t['shaka'], f'input={source},stream=video,output={encrypted},drm_label=VIDEO',
                '--enable_raw_key_encryption', '--keys', f'label=VIDEO:key_id={KEYS[0][0]}:key={KEYS[0][1]}',
                '--protection_scheme', 'cenc', '--clear_lead', '0.5' if mode == 'clear-lead' else '0',
                '--iv', '000102030405060708090a0b0c0d0e0f', '--segment_duration', '0.5', '--fragment_duration', '0.5']
            if rotation:
                argv += ['--crypto_period_duration', '1']
            execute(argv, case, 'encrypt')
            witness = validate(encrypted)
            protected = [s for s in witness['samples'] if s['protected']]
            if not protected or not any(s['encrypted_ranges'] for s in protected):
                raise AssertionError('generated no encrypted sample ranges')
            if mode == 'clear-lead':
                if not any(not s['protected'] for s in witness['samples']):
                    raise AssertionError('clear-lead fixture has no clear samples')
            if rotation:
                observed = {s['kid'] for s in protected}
                if len(observed) < 2 or not observed <= {kid for kid, _ in keys}:
                    raise AssertionError('rotation did not select at least two known distinct KIDs')
                record['observed_kids'] = sorted(observed)
            init = None
            input_path = encrypted
            comparison_input = encrypted
            if mode.startswith('detached'):
                initialization, fragments = split_fragments(encrypted.read_bytes())
                if len(fragments) < 2:
                    raise AssertionError('fixture needs several fragments')
                init = case / 'init.mp4'
                init.write_bytes(initialization)
                input_path = case / 'media.m4s'
                input_path.write_bytes(b''.join(fragments) if mode == 'detached-all' else fragments[-1])
                comparison_input = case / 'combined.mp4'
                comparison_input.write_bytes(initialization + input_path.read_bytes())
            expected = expected_fragment(source_tracks, extract(comparison_input))
            encrypted_samples = extract(comparison_input)[0]['samples']
            changed = sum(a['sha256'] != b['sha256'] for a, b in zip(expected[0]['samples'], encrypted_samples))
            if not changed:
                raise AssertionError('encrypted fixture contains only unchanged source samples')
            record['changed_sample_count'] = changed
            record['sample_count'] = len(expected[0]['samples'])
            record['source_sha256'], record['encrypted_sha256'] = digest(source), digest(encrypted)
            (case / 'expected-samples.json').write_text(json.dumps(expected, indent=2))
            (case / 'encryption-witness.json').write_text(json.dumps(witness, indent=2))
            for decoder in ('iori', 'bento4', 'shaka'):
                result = dict(decoder=decoder, status='pass')
                try:
                    dest = case / (decoder + '.mp4')
                    if decoder == 'iori':
                        command = [adapter, input_path, dest, *[f'{kid}:{key}' for kid, key in keys]]
                        if init:
                            command += ['--init', init]
                        execute(command, case, decoder)
                    elif decoder == 'bento4':
                        command = [t['mp4decrypt']]
                        for kid, key in keys:
                            command += ['--key', f'{kid}:{key}']
                        if init:
                            command += ['--fragments-info', init]
                        execute([*command, input_path, dest], case, decoder)
                    else:
                        key_spec = ','.join(f'label=K{i}:key_id={kid}:key={key}' for i, (kid, key) in enumerate(keys))
                        execute([t['shaka'], f'input={comparison_input},stream=video,output={dest}',
                            '--enable_raw_key_decryption', '--keys', key_spec], case, decoder)
                    actual = dest
                    if init and decoder != 'shaka':
                        actual = case / (decoder + '-combined.mp4')
                        actual.write_bytes(init.read_bytes() + dest.read_bytes())
                    if decoder == 'iori':
                        assert_in_place(comparison_input, actual)
                        assert_clear_bytes(comparison_input, actual)
                    compare_samples(expected, extract(actual))
                    result['output_sha256'] = digest(dest)
                except Exception as error:
                    result.update(status='fail', error=str(error))
                    if rotation:
                        classified = classify_rotation(decoder, error, found, record['observed_kids'],
                            [kid for kid, _ in keys], any(c['decoder'] == 'iori' and c['status'] == 'pass'
                            for c in record['comparisons']), encrypted, dest)
                        if classified:
                            result.update(classified)
                result['verification'] = 'exact-encoded-samples; iori also in-place and clear-byte preservation'
                record['comparisons'].append(result)
            if any(c['status'] == 'fail' for c in record['comparisons']):
                record['status'] = 'fail'
            elif any(c['status'] != 'pass' for c in record['comparisons']):
                record['status'] = 'qualified'
        except Exception as error:
            record.update(status='fail', error=str(error))
        (case / 'result.json').write_text(json.dumps(record, indent=2))
        results.append(record)
    return results
