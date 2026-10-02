#!/usr/bin/env python3
"""Validate a returned diagnostic ZIP without printing credentials or readings.

Usage: python3 scripts/inspect-lingo-diagnostics.py lingo-diagnostics.zip
No third-party Python packages required. Exit 2 means damaged/truncated binary
values, malformed records, or missing event files; missing capture stages are
reported separately and are not proof of corruption.
"""
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def inspect(path):
    errors, reports = [], []
    with zipfile.ZipFile(path) as archive:
        paths = sorted(n for n in archive.namelist()
                       if n.endswith('/events.jsonl') or n.endswith('/events-export.jsonl'))
        # Prefer the export snapshot when both exist in an externally assembled ZIP.
        chosen = {str(Path(n).parent): n for n in paths}
        for n in paths:
            if n.endswith('/events-export.jsonl'):
                chosen[str(Path(n).parent)] = n
        for run, name in sorted(chosen.items()):
            binary_count = 0

            def check(value):
                nonlocal binary_count
                if isinstance(value, dict):
                    if {'hex', 'length', 'sha256', 'truncated'} <= value.keys():
                        binary_count += 1
                        try:
                            raw = bytes.fromhex(value['hex'])
                            if value['truncated'] or len(raw) != value['length']:
                                raise ValueError('binary value is incomplete')
                            if hashlib.sha256(raw).hexdigest() != value['sha256']:
                                raise ValueError('binary SHA-256 mismatch')
                        except (TypeError, ValueError) as e:
                            errors.append(f'{name}: {e}')
                    else:
                        for v in value.values():
                            check(v)
                elif isinstance(value, list):
                    for v in value:
                        check(v)

            events = []
            for line_number, line in enumerate(archive.read(name).splitlines(), 1):
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict) or row.get('schema') != 1:
                        raise ValueError('unknown schema')
                    check(row)
                    events.append(row)
                except (ValueError, TypeError) as e:
                    errors.append(f'{name}:{line_number}: {e}')
            starts, active, attempts = {}, {}, []
            tables, fingerprints = set(), set()
            good_packets, memory_errors = 0, 0
            for row in events:
                kind, context = row.get('event'), row.get('context')
                if kind == 'call_start':
                    starts[row['call']] = row
                elif kind == 'call_end':
                    before = starts.pop(row['call'], None)
                    if before is None:
                        errors.append(f'{name}: call_end without call_start')
                        continue
                    method, result = row['method'], row.get('result')
                    ok = row.get('error') is None and result is not None and result is not False
                    if method == 'initECDH':
                        args = before.get('args', [])
                        attempt = dict(context=context, full=bool(args) and args[0] is None,
                                       init_success=result is True, methods=set(), packets=0)
                        active[context] = attempt
                        attempts.append(attempt)
                    attempt = active.get(context)
                    if attempt and ok:
                        attempt['methods'].add(method)
                elif kind == 'fields' and row.get('class', '').endswith('.GKSSecurityCredentials'):
                    for key, val in row.get('fields', {}).items():
                        if val is not None and not (isinstance(val, str) and val.startswith('UNAVAILABLE:')):
                            tables.add(key)
                elif kind == 'fingerprint':
                    fingerprints.add(row['file'])
                elif kind == 'realtime' and isinstance(row.get('clear'), dict) and row['clear'].get('length') == 51:
                    good_packets += 1
                    if context in active:
                        active[context]['packets'] += 1
                elif kind == 'memory_unavailable':
                    memory_errors += 1
            full_required = {'initECDH', 'getAppCertificate', 'setPatchCertificate',
                             'generateEphemeralKeys', 'generateKAuth', 'encrypt',
                             'decrypt', 'exportAuthorizationKey'}
            resumed_required = {'initECDH', 'encrypt', 'decrypt', 'exportAuthorizationKey'}
            full = sum(a['full'] and a['init_success'] and full_required <= a['methods'] and a['packets'] > 0 for a in attempts)
            resumed = sum(not a['full'] and a['init_success'] and resumed_required <= a['methods'] and a['packets'] > 0 for a in attempts)
            reports.append(dict(run=run, events=len(events), binary_values_verified=binary_count,
                                credential_fields=sorted(tables), fingerprinted_files=sorted(fingerprints),
                                full_handshakes_with_readings=full, resumed_handshakes_with_readings=resumed,
                                decrypted_realtime_packets=good_packets,
                                memory_unavailable_events=memory_errors,
                                memory_image_files=sum(n.startswith(run + '/memory-') and n.endswith('.bin') for n in archive.namelist()),
                                unfinished_calls=len(starts), capture_limit_reached=any(r.get('event') == 'capture_limit' for r in events)))
        if not paths:
            errors.append('No diagnostic event files found')
    return dict(runs=reports, integrity_errors=errors)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    try:
        report = inspect(sys.argv[1])
    except (OSError, zipfile.BadZipFile, KeyError) as e:
        raise SystemExit(f'Cannot inspect diagnostics: {e}')
    print(json.dumps(report, indent=2))
    raise SystemExit(2 if report['integrity_errors'] else 0)
