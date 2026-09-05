#!/usr/bin/env python3
"""Strict, artifact-preserving CENC test runner (stdlib only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
KEYS = [('00112233445566778899aabbccddeeff', '0123456789abcdef0123456789abcdef'),
        ('ffeeddccbbaa99887766554433221100', 'fedcba9876543210fedcba9876543210')]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(argv, directory, name, timeout=120):
    started = time.monotonic()
    directory.mkdir(parents=True, exist_ok=True)
    record = {'argv': [str(a) for a in argv], 'name': name}
    try:
        p = subprocess.run(record['argv'], cwd=ROOT, capture_output=True, timeout=timeout)
        record.update(exit_code=p.returncode, status='pass' if p.returncode == 0 else 'fail')
        stdout, stderr = p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        record.update(exit_code=None, status='fail', error=str(error))
        stdout, stderr = b'', str(error).encode()
    record['elapsed_seconds'] = time.monotonic() - started
    for label, data in [('stdout', stdout), ('stderr', stderr)]:
        path = directory / f'{name}.{label}.log'
        path.write_bytes(data)
        record[label] = str(path)
    (directory / f'{name}.command.json').write_text(json.dumps(record, indent=2))
    if record['status'] != 'pass':
        raise RuntimeError(f'{name}: {record.get("error", stderr.decode(errors="replace")[-1500:])}')
    return record


def tools(args):
    wanted = {'ffmpeg': args.ffmpeg, 'mp4encrypt': args.mp4encrypt,
              'mp4decrypt': args.mp4decrypt, 'mp4fragment': args.mp4fragment,
              'shaka': args.shaka}
    found = {}
    for name, configured in wanted.items():
        path = shutil.which(configured)
        if not path:
            raise RuntimeError(f'missing required tool: {name} ({configured})')
        resolved = str(Path(path).resolve())
        flags = ['-version'] if name == 'ffmpeg' else (['--version'] if name == 'shaka' else [])
        version = subprocess.run([resolved, *flags], capture_output=True, timeout=15)
        found[name] = {'path': resolved, 'sha256': digest(resolved),
                       'version': (version.stdout + version.stderr).decode(errors='replace')[:1500]}
    return found


def lock_tools(found, path, record=False):
    if not found:
        raise RuntimeError('empty tool manifest')
    identity = {k: {'sha256': v['sha256'], 'version': v['version']} for k, v in found.items()}
    if record:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'schema_version': 1, 'tools': identity}, indent=2) + '\n')
    elif not path.exists():
        raise RuntimeError(f'tool lock missing: {path}; establish baseline explicitly with --record-tools')
    elif json.loads(path.read_text())['tools'] != identity:
        raise RuntimeError('tool identity differs from lock; review upgrade and use --record-tools explicitly')


def sources(out, t):
    result = {}
    for name, inputs, codec in [
        ('audio', ['-f', 'lavfi', '-i', 'sine=frequency=997:duration=1'], ['-c:a', 'aac', '-b:a', '64k']),
        ('avc', ['-f', 'lavfi', '-i', 'testsrc2=size=160x96:rate=12:duration=1'], ['-c:v', 'libx264', '-profile:v', 'baseline', '-g', '6', '-threads', '1']),
        ('hevc', ['-f', 'lavfi', '-i', 'testsrc2=size=160x96:rate=12:duration=1'], ['-c:v', 'libx265', '-tag:v', 'hvc1', '-x265-params', 'pools=1:frame-threads=1:keyint=6:bframes=0', '-threads', '1'])]:
        dest = out / f'{name}.mp4'
        execute([t['ffmpeg'], '-v', 'error', '-y', *inputs, *codec, '-use_editlist', '0', dest], out, f'source-{name}')
        result[name] = dest
    dest = out / 'av.mp4'
    execute([t['ffmpeg'], '-v', 'error', '-y', '-i', result['avc'], '-i', result['audio'],
             '-map', '0:v', '-map', '1:a', '-c', 'copy', '-use_editlist', '0', dest], out, 'source-av')
    result['av'] = dest
    return result


def keyargs():
    return [f'{kid}:{key}' for kid, key in KEYS]


def shaka_keys():
    return ','.join(f'label={label}:key_id={kid}:key={key}' for label, (kid, key) in zip(['VIDEO', 'AUDIO'], KEYS))


def junit(results, path):
    if not results:
        raise RuntimeError('empty result manifest')
    entries = []
    for r in results:
        if r.get('comparisons'):
            for c in r['comparisons']:
                entries.append({**c, 'id': f"{r['id']}/{c.get('part', 0)}/{c['decoder']}"})
            if r['status'] == 'fail' and not any(c['status'] == 'fail' for c in r['comparisons']):
                entries.append({**r, 'id': r['id'] + '/case-failure'})
        else:
            entries.append(r)
    suite = ET.Element('testsuite', tests=str(len(entries)),
                       failures=str(sum(r['status'] == 'fail' for r in entries)),
                       skipped=str(sum(r['status'] not in ('pass', 'fail') for r in entries)))
    for r in entries:
        case = ET.SubElement(suite, 'testcase', name=r['id'])
        if r['status'] == 'fail':
            ET.SubElement(case, 'failure', message=r.get('error', 'failed'))
        elif r['status'] != 'pass':
            ET.SubElement(case, 'skipped', message=r.get('deviation', r['status']))
    ET.ElementTree(suite).write(path, encoding='utf-8', xml_declaration=True)


def decoded_hash(path, stream, ffmpeg, directory, name):
    execute([ffmpeg, '-v', 'error', '-i', path, '-map', f'0:{stream}',
             '-c:v', 'rawvideo', '-c:a', 'pcm_s16le', '-threads', '1',
             '-f', 'hash', '-hash', 'sha256', '-'], directory, name)
    value = (directory / f'{name}.stdout.log').read_text().strip()
    if not value.startswith('SHA256='):
        raise AssertionError('decoder emitted no media hash')
    return value


def assert_fixture(expected, encrypted_tracks, observed, scheme, allowed_kids):
    """Cross-check both independent views and require changed protected data.

    A producer copying its clear input must not create a false-green matrix.
    """
    import copy
    from mp4 import compare_samples
    if not expected or not encrypted_tracks:
        raise AssertionError('empty source or encrypted track list')
    if any(not track.get('samples') for track in expected + encrypted_tracks):
        raise AssertionError('empty source or encrypted sample list')
    identity = lambda track: json.dumps(track['descriptions'], sort_keys=True)
    originals = {identity(track): track for track in expected}
    outputs = {identity(track): track for track in encrypted_tracks}
    if (len(originals) != len(expected) or len(outputs) != len(encrypted_tracks)
            or originals.keys() != outputs.keys()):
        raise AssertionError('ambiguous or mismatched fixture tracks')
    normalized = copy.deepcopy(encrypted_tracks)
    changed, samples = set(), {}
    for track, normal_track in zip(encrypted_tracks, normalized):
        original = originals[identity(track)]
        if len(original['samples']) != len(track['samples']):
            raise AssertionError('fixture sample count changed')
        for index, (plain, encrypted, normal) in enumerate(zip(
                original['samples'], track['samples'], normal_track['samples'])):
            key = (track['id'], index)
            if key in samples:
                raise AssertionError('duplicate fixture track/sample identity')
            samples[key] = encrypted
            if plain['sha256'] != encrypted['sha256']:
                changed.add(key)
            normal['sha256'] = plain['sha256']
    compare_samples(expected, normalized)
    records = observed.get('samples', [])
    if len(records) != len(samples):
        raise AssertionError('encryption witness sample count mismatch')
    seen, active, changed_active = set(), False, False
    allowed_kids = {kid.lower() for kid in allowed_kids}
    for record in records:
        key = (record.get('track_id'), record.get('index'))
        if key not in samples or key in seen:
            raise AssertionError('missing or duplicate encryption sample identity')
        seen.add(key)
        sample = samples[key]
        start, size = sample['offset'], sample['size']
        if (record.get('offset'), record.get('size')) != (start, size):
            raise AssertionError('encryption witness sample geometry mismatch')
        ranges = record.get('encrypted_ranges', [])
        previous_end = start
        for span in ranges:
            if (not isinstance(span, (list, tuple)) or len(span) != 2
                    or any(type(value) is not int for value in span)):
                raise AssertionError('malformed encrypted range')
            left, right = span
            if not start <= previous_end <= left < right <= start + size:
                raise AssertionError('encrypted range outside sample or overlapping')
            previous_end = right
        if record.get('protected'):
            if record.get('scheme') != scheme:
                raise AssertionError('producer used unexpected protection scheme')
            if record.get('kid', '').lower() not in allowed_kids:
                raise AssertionError('producer used unexpected KID')
            active |= bool(ranges)
            changed_active |= bool(ranges) and key in changed
        elif ranges:
            raise AssertionError('clear sample declares encrypted ranges')
    if not active:
        raise AssertionError('producer emitted no active encrypted ranges')
    if not changed_active:
        raise AssertionError('producer left protected sample ciphertext unchanged')


def interop(out, found, quick=False, compatibility=False):
    from mp4 import extract, compare_samples, assert_in_place
    from validity import validate, assert_clear_bytes
    t = {k: v['path'] for k, v in found.items()}
    source = sources(out / 'sources', t)
    execute(['cargo', 'build', '--locked', '-p', 'iori-cenc', '--example', 'conformance_decrypt'], out, 'build', 300)
    adapter = ROOT / 'target/debug/examples/conformance_decrypt'
    results = []
    decode_cache = {}
    for producer in ['bento4', 'shaka', 'ffmpeg']:
        for name, original in source.items():
            if quick and name not in ('audio', 'avc'): continue
            if producer == 'ffmpeg' and name == 'av': continue
            for scheme in (['cenc'] if producer == 'ffmpeg' else ['cenc', 'cbc1', 'cens', 'cbcs']):
                if compatibility and not (producer == 'ffmpeg' or (scheme == 'cens' and name in ('audio', 'av'))):
                    continue
                case_id = f'{producer}-{name}-{scheme}'
                case = out / case_id
                case.mkdir(parents=True)
                record = {'id': case_id, 'producer': producer, 'scheme': scheme, 'status': 'pass', 'comparisons': []}
                try:
                    reference = extract(original)
                    (case / 'source-samples.json').write_text(json.dumps(reference, indent=2))
                    encrypted_files = []
                    if producer == 'bento4':
                        plain = case / 'fragmented.mp4'
                        execute([t['mp4fragment'], '--fragment-duration', '500', original, plain], case, 'fragment')
                        # The fragmenter's output is the encryption input; validate its
                        # sample content separately from any timing normalization.
                        compare_samples(reference, extract(plain))
                        encrypted = case / 'encrypted.mp4'
                        argv = [t['mp4encrypt'], '--method', 'MPEG-' + scheme.upper()]
                        for index, track in enumerate(reference):
                            key_index = 1 if track['descriptions'][0]['codec'] == 'mp4a' else 0
                            kid, key = KEYS[key_index]
                            argv += ['--key', f'{track["id"]}:{key}:000102030405060708090a0b0c0d0e0f', '--property', f'{track["id"]}:KID:{kid}']
                        execute([*argv, plain, encrypted], case, 'encrypt')
                        encrypted_files.append((encrypted, reference))
                    elif producer == 'shaka':
                        argv = [t['shaka']]
                        for index, track in enumerate(reference):
                            encrypted = case / f'encrypted-{index}.mp4'
                            label = 'AUDIO' if track['descriptions'][0]['codec'] == 'mp4a' else 'VIDEO'
                            argv += [f'input={original},stream={index},output={encrypted},drm_label={label}']
                            encrypted_files.append((encrypted, [track]))
                        execute([*argv, '--enable_raw_key_encryption', '--keys', shaka_keys(), '--protection_scheme', scheme,
                                 '--clear_lead', '0', '--iv', '000102030405060708090a0b0c0d0e0f', '--segment_duration', '0.5', '--fragment_duration', '0.5'], case, 'encrypt')
                    else:
                        encrypted = case / 'encrypted.mp4'
                        kid, key = KEYS[1 if name == 'audio' else 0]
                        execute([t['ffmpeg'], '-v', 'error', '-y', '-i', original, '-c', 'copy', '-use_editlist', '0',
                                 '-fflags', '+bitexact', '-encryption_scheme', 'cenc-aes-ctr', '-encryption_key', key, '-encryption_kid', kid, encrypted], case, 'encrypt')
                        encrypted_files.append((encrypted, reference))
                    record['source_sha256'] = digest(original)
                    record['encrypted_sha256'] = [digest(p) for p, _ in encrypted_files]
                    record['observed_encryption'] = [validate(p) for p, _ in encrypted_files]
                    for part, (encrypted, expected) in enumerate(encrypted_files):
                        assert_fixture(expected, extract(encrypted), record['observed_encryption'][part], scheme, {kid for kid, _ in KEYS})
                        for decoder in ['iori', 'bento4', 'shaka']:
                            outputs = []
                            try:
                                if decoder == 'iori':
                                    dest = case / f'{part}-iori.mp4'
                                    execute([adapter, encrypted, dest, *keyargs()], case, f'{part}-iori')
                                    assert_in_place(encrypted.read_bytes(), dest.read_bytes())
                                    assert_clear_bytes(encrypted, dest)
                                    outputs.append(dest)
                                elif decoder == 'bento4':
                                    dest = case / f'{part}-bento4.mp4'
                                    argv = [t['mp4decrypt']]
                                    for pair in keyargs(): argv += ['--key', pair]
                                    execute([*argv, encrypted, dest], case, f'{part}-bento4')
                                    outputs.append(dest)
                                else:
                                    argv = [t['shaka']]
                                    for index, _ in enumerate(expected):
                                        dest = case / f'{part}-shaka-{index}.mp4'
                                        argv += [f'input={encrypted},stream={index},output={dest}']
                                        outputs.append(dest)
                                    execute([*argv, '--enable_raw_key_decryption', '--keys', shaka_keys()], case, f'{part}-shaka')
                                actual = [track for output in outputs for track in extract(output)]
                                compare_samples(expected, actual)
                                decoded = []
                                for oi, output in enumerate(outputs):
                                    for si, track in enumerate(extract(output)):
                                        source_index = next(i for i, t in enumerate(reference) if t['descriptions'] == track['descriptions'])
                                        cache_key = (str(original), source_index)
                                        if cache_key not in decode_cache:
                                            decode_cache[cache_key] = decoded_hash(original, source_index, t['ffmpeg'], case, f'source-decode-{source_index}')
                                        output_hash = decoded_hash(output, si, t['ffmpeg'], case, f'{part}-{decoder}-decode-{oi}-{si}')
                                        if output_hash != decode_cache[cache_key]:
                                            raise AssertionError('decoded media differs from original')
                                        decoded.append(output_hash)
                                record['comparisons'].append({'part': part, 'decoder': decoder, 'status': 'pass', 'decoded_hashes': decoded, 'output_sha256': [digest(p) for p in outputs]})
                            except Exception as error:
                                from deviations import classify
                                deviation = classify(producer, scheme, decoder, original, encrypted, outputs, expected, error, found)
                                result = {'part': part, 'decoder': decoder, 'status': 'fail', 'error': str(error)}
                                if deviation:
                                    result.update(deviation)
                                record['comparisons'].append(result)
                                if not deviation:
                                    record['error'] = str(error)
                except Exception as error:
                    record.update(status='fail', error=str(error))
                if any(c['status'] == 'fail' for c in record['comparisons']):
                    record['status'] = 'fail'
                elif record['status'] != 'fail' and any(c['status'] != 'pass' for c in record['comparisons']):
                    record['status'] = 'qualified'
                results.append(record)
                (case / 'result.json').write_text(json.dumps(record, indent=2))
                print(case_id, record['status'], record.get('error', '')[:180], flush=True)
    if not results: raise RuntimeError('empty interop matrix')
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['unit', 'track-interop', 'full-part7', 'compatibility'], default='unit')
    parser.add_argument('--output', type=Path, default=ROOT / 'target/cenc-conformance' / time.strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--tool-lock', type=Path, default=HERE / 'tools.lock.json')
    parser.add_argument('--record-tools', action='store_true')
    parser.add_argument('--require-complete', action='store_true', help='fail if any normative coverage remains unverified')
    parser.add_argument('--quick', action='store_true', help='smaller development matrix, never full coverage')
    for name, default in [('ffmpeg', 'ffmpeg'), ('mp4encrypt', 'mp4encrypt'), ('mp4decrypt', 'mp4decrypt'), ('mp4fragment', 'mp4fragment'), ('shaka', os.environ.get('SHAKA_PACKAGER', 'packager'))]:
        parser.add_argument('--' + name, default=default)
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'suite_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'schema_version': 1, 'profile': args.profile, 'normative_completeness': 'unverified', 'results': []}
    try:
        import catalogue
        errors = catalogue.validate_catalogue()
        if errors: raise RuntimeError('; '.join(errors))
        report['coverage'] = catalogue.coverage_report()
        execute([sys.executable, '-m', 'unittest', 'discover', '-v', '-s', HERE, '-p', 'test_*.py'], args.output, 'python-tests')
        execute(['cargo', 'test', '--locked', '-p', 'iori-cenc'], args.output, 'rust-tests', 300)
        observed = catalogue.observed_results((args.output / 'rust-tests.stdout.log').read_text(),
                                               (args.output / 'python-tests.stderr.log').read_text())
        report['coverage'] = catalogue.coverage_report(observed)
        report['results'].append({'id': 'local-tests', 'status': 'pass'})
        if args.profile != 'unit':
            found = tools(args)
            lock_tools(found, args.tool_lock, args.record_tools)
            report['tools'] = found
            report['results'] += interop(args.output / 'media', found, args.quick, args.profile == 'compatibility')
            if not args.quick and args.profile != 'compatibility':
                from streaming import run_streaming
                report['results'] += run_streaming(args.output / 'streaming', found,
                                                   ROOT / 'target/debug/examples/conformance_decrypt')
            observed.update(catalogue.observed_external(report['results']))
            report['coverage'] = catalogue.coverage_report(observed)
    except Exception as error:
        report['results'].append({'id': 'preflight-or-local-tests', 'status': 'fail', 'error': str(error)})
        print(str(error), file=sys.stderr)
    finally:
        comparisons = [c for r in report['results'] for c in r.get('comparisons', [])]
        report['comparison_counts'] = {status: sum(c['status'] == status for c in comparisons)
                                       for status in sorted({c['status'] for c in comparisons})}
        report['normative_coverage_claim'] = False
        report['quick_matrix'] = args.quick
        (args.output / 'summary.md').write_text(
            '# CENC conformance run\n\n'
            + f"Profile: {args.profile}. Normative completeness: unverified.\n\n"
            + '\n'.join(f"- {status}: {count}" for status, count in report['comparison_counts'].items())
            + '\n\nSee report.json for individual executions and open requirement coverage.\n')
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        junit(report['results'], args.output / 'junit.xml')
    incomplete = args.require_complete and report['normative_completeness'] != 'verified'
    if incomplete:
        print('Full normative completeness is unverified; see coverage gaps in report.', file=sys.stderr)
    return int(incomplete or any(r['status'] == 'fail' for r in report['results']))


if __name__ == '__main__':
    sys.exit(main())
