"""Traceable partial coverage, independent from execution and product support.

Existing witnesses do not discharge broad family requirements. In particular,
reference-mechanism passes never count as implemented product capabilities.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent.parent
EXECUTION_STATUSES = {'pass', 'fail', 'not-run', 'tool-unsupported', 'blocked-source', 'blocked-interpretation', 'known-oracle-deviation'}


def load_catalogue(directory: Path = HERE) -> dict:
    with (directory / 'families.csv').open(newline='') as stream:
        families = list(csv.DictReader(stream))
    requirements = json.loads((directory / 'requirements.json').read_text())
    return {'families': families, **requirements,
            'cases': json.loads((directory / 'cases.json').read_text())['cases']}


def validate_catalogue(catalogue: dict | None = None) -> list[str]:
    data = load_catalogue() if catalogue is None else catalogue
    errors = []
    tables = {}
    for table, key in [('families', 'family_id'), ('requirements', 'id'), ('cases', 'id')]:
        if not data[table]:
            errors.append(f'empty {table} catalogue')
        tables[table] = {entry[key]: entry for entry in data[table]}
        if len(tables[table]) != len(data[table]):
            errors.append(f'duplicate {table} ID')
    families, requirements, cases = (tables[t] for t in ['families', 'requirements', 'cases'])
    for fid in families:
        if not any(req['family_id'] == fid for req in requirements.values()):
            errors.append(f'{fid}: missing requirement enumeration')
    for rid, req in requirements.items():
        if req['family_id'] not in families:
            errors.append(f'{rid}: unknown family')
        if not req.get('property') or not req.get('provenance') or not req.get('applicability'):
            errors.append(f'{rid}: incomplete requirement')
        if req['status'] == 'complete' and (not req['source_verified'] or not req['cases']):
            errors.append(f'{rid}: unsupported complete claim')
        for cid in req['cases']:
            if cid not in cases or rid not in cases[cid]['requirements']:
                errors.append(f'{rid}: broken case link {cid}')
    for cid, case in cases.items():
        if not case['requirements']:
            errors.append(f'{cid}: no requirement link')
        for rid in case['requirements']:
            if rid not in requirements or cid not in requirements[rid]['cases']:
                errors.append(f'{cid}: broken requirement link {rid}')
            elif requirements[rid]['family_id'] != case['family_id']:
                errors.append(f'{cid}: family mismatch')
        if case['execution'] != 'not-run':
            errors.append(f'{cid}: static catalogue must not claim execution')
        if case['full_family_credit']:
            errors.append(f'{cid}: single witness cannot claim full family credit')
        if case['implementation'] == 'runtime-interop':
            if not case.get('runtime_record_id') or case.get('runtime_decoder') not in ('iori', 'bento4', 'shaka') or not case.get('runtime_parts'):
                errors.append(f'{cid}: incomplete runtime witness')
        source = (CRATE / case['source']).resolve()
        if not source.is_relative_to(CRATE):
            errors.append(f'{cid}: source escapes crate')
            continue
        if not source.is_file():
            errors.append(f'{cid}: missing source {source}')
            continue
        text = source.read_text()
        name = re.escape(case['test_name'])
        pattern = (rf'#\[test\]\s*fn\s+{name}\s*\(' if source.suffix == '.rs'
                   else rf'^\s*def\s+{name}\s*\(')
        if not re.search(pattern, text, re.MULTILINE):
            errors.append(f'{cid}: missing executable test {case["test_name"]}')
    return errors


def coverage_report(results: dict[str, str] | None = None, catalogue: dict | None = None) -> dict:
    """Return family accounting; results keys are explicit catalogue case IDs.

    Omitted results are not-run, never inferred from source presence. Invalid
    case IDs or statuses fail closed rather than silently dropping executions.
    """
    data = load_catalogue() if catalogue is None else catalogue
    errors = validate_catalogue(data)
    if errors:
        raise ValueError('; '.join(errors))
    results = {} if results is None else results
    case_ids = {c['id'] for c in data['cases']}
    if set(results) - case_ids:
        raise ValueError(f'unknown execution case IDs: {sorted(set(results) - case_ids)}')
    if set(results.values()) - EXECUTION_STATUSES:
        raise ValueError('unknown execution status')
    families = []
    for family in data['families']:
        fid = family['family_id']
        reqs = [r for r in data['requirements'] if r['family_id'] == fid]
        cases = [c for c in data['cases'] if c['family_id'] == fid]
        complete = all(r['status'] == 'complete' for r in reqs)
        families.append({'family_id': fid,
                         'status': 'covered' if complete else 'partial' if cases else 'unimplemented',
                         'open_requirement_ids': [r['id'] for r in reqs if r['status'] != 'complete'],
                         'cases': {c['id']: results.get(c['id'], 'not-run') for c in cases}})
    return {'source_audit_complete': data['source_audit_complete'],
            'full_conformance': False,
            'family_count': len(families),
            'covered_family_count': sum(f['status'] == 'covered' for f in families),
            'partial_family_count': sum(f['status'] == 'partial' for f in families),
            'unimplemented_family_count': sum(f['status'] == 'unimplemented' for f in families),
            'requirement_count': len(data['requirements']),
            'case_count': len(case_ids),
            'case_kinds': {kind: sum(c['implementation'] == kind for c in data['cases'])
                           for kind in sorted({c['implementation'] for c in data['cases']})},
            'executions': {status: sum(results.get(cid, 'not-run') == status for cid in case_ids)
                           for status in sorted(EXECUTION_STATUSES)},
            'families': families}


def observed_results(rust_stdout: str, python_verbose_stderr: str, catalogue: dict | None = None) -> dict[str, str]:
    """Map explicit completed test lines; aggregate exit success is insufficient.

    Rust names are matched at their full final path segment. Python verbose
    output additionally identifies the test module. Ignored/skipped cases stay
    not-run. A conflicting pass/fail for a repeated name conservatively fails.
    """
    data = load_catalogue() if catalogue is None else catalogue
    rust = {}
    for match in re.finditer(r'^test ([A-Za-z_0-9:]+) \.\.\. (ok|FAILED|ignored)(?:\b.*)?$', rust_stdout, re.MULTILINE):
        name, status = match.groups()
        name = name.split('::')[-1]
        value = {'ok': 'pass', 'FAILED': 'fail', 'ignored': 'not-run'}[status]
        rust[name] = 'fail' if 'fail' in (rust.get(name), value) else value
    python = {}
    for match in re.finditer(r'^(test_\w+) \(([^)]+)\) \.\.\. (ok|FAIL|ERROR|skipped)(?:\b.*)?$', python_verbose_stderr, re.MULTILINE):
        name, qualified, status = match.groups()
        module = qualified.split('.')[0]
        key = (module, name)
        value = {'ok': 'pass', 'FAIL': 'fail', 'ERROR': 'fail', 'skipped': 'not-run'}[status]
        python[key] = 'fail' if 'fail' in (python.get(key), value) else value
    return {case['id']: (rust.get(case['test_name'], 'not-run')
                        if Path(case['source']).suffix == '.rs'
                        else python.get((Path(case['source']).stem, case['test_name']), 'not-run'))
            for case in data['cases']}


def observed_external(results: list[dict], catalogue: dict | None = None) -> dict[str, str]:
    """Account for exact external decoder comparisons, including qualified runs.

    Cases require every expected part and artifact identity. A successful
    aggregate record with absent comparisons cannot establish execution.
    """
    data = load_catalogue() if catalogue is None else catalogue
    records = {}
    for record in results:
        if record['id'] in records:
            raise ValueError('duplicate external result ID: ' + record['id'])
        records[record['id']] = record
    observed = {}
    valid_hash = lambda value: isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None
    for case in data['cases']:
        if case['implementation'] != 'runtime-interop':
            continue
        record = records.get(case['runtime_record_id'])
        status = 'not-run'
        if record is not None:
            comparisons = [c for c in record.get('comparisons', []) if c.get('decoder') == case['runtime_decoder']]
            by_part = {c.get('part'): c for c in comparisons}
            if len(by_part) != len(comparisons):
                raise ValueError('duplicate external decoder part: ' + case['id'])
            if set(by_part) == set(case['runtime_parts']):
                statuses = {c.get('status') for c in comparisons}
                if 'fail' in statuses:
                    status = 'fail'
                elif statuses == {'pass'}:
                    hashes = [record.get('source_sha256')]
                    hashes += record.get('encrypted_sha256', [])
                    hashes += [h for c in comparisons for h in c.get('output_sha256', [])]
                    present = bool(record.get('encrypted_sha256')) and all(c.get('output_sha256') for c in comparisons)
                    if present and all(valid_hash(h) for h in hashes):
                        status = 'pass'
                        if case.get('require_decoded_hashes') and not all(
                            c.get('decoded_hashes') and all(re.fullmatch(r'SHA256=[0-9a-f]{64}', h) for h in c['decoded_hashes'])
                            for c in comparisons):
                            status = 'not-run'
                elif statuses <= {'pass', 'known-oracle-deviation', 'tool-unsupported'}:
                    status = 'tool-unsupported' if 'tool-unsupported' in statuses else 'known-oracle-deviation'
                else:
                    status = 'fail'
            elif record.get('status') == 'fail':
                status = 'fail'
        observed[case['id']] = status
    return observed


if __name__ == '__main__':
    print(json.dumps(coverage_report(), indent=2))
