"""Recompute selected historical local measurements without starting services."""
import argparse
import hashlib
import json
import math
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'docs/evidence/resource-improvements-20261122'


def text_hash(path):
    # Git may check JSON/text evidence out as CRLF on Windows.
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-current-source', action='store_true',
                        help='also require this working source to match the measured source')
    args = parser.parse_args()
    summary = json.loads((DATA / 'summary.json').read_text())
    for name, digest in summary['input_sha256'].items():
        assert text_hash(DATA / name) == digest, name
    if args.check_current_source:
        for name, digest in summary['source_sha256'].items():
            assert text_hash(ROOT / name) == digest, name
    samples = {'baseline': [], 'candidate': []}
    for i, mode in [(1, 'baseline'), (2, 'candidate'), (3, 'candidate'), (4, 'baseline')]:
        report = json.loads((DATA / f'final-abba-{i}-{mode}.json').read_text())
        assert report['false_allows'] == report['false_denies'] == 0
        assert report['real_api_crypto_bypass_controls'] == 7
        assert len(report['samples']) == 128 and report['concurrency'] == 1
        assert report['warmups_per_workload'] == 3
        assert report['go'] == 'go1.27.4' and report['kubernetes'] == 'v1.31.0'
        samples[mode].extend(report['samples'])
    for row in summary['admission']:
        for mode in samples:
            for path in ('admission-enabled', 'api-baseline'):
                values = sorted(s['nanoseconds'] / 1e6 for s in samples[mode]
                                if s['mode'] == path and s['containers'] == row['containers'])
                expected = row[f'{mode}_{path}']
                assert len(values) == expected['count'] == 64
                for p in (50, 95, 99):
                    assert values[math.ceil(len(values) * p / 100) - 1] == expected[f'p{p}_ms']
        reduction = 100 * (1 - row['candidate_admission-enabled']['p95_ms'] / row['baseline_admission-enabled']['p95_ms'])
        assert reduction == row['p95_reduction_percent']
    for mode in ('baseline', 'candidate'):
        log = (DATA / f'allocation-{mode}.txt').read_text()
        matches = re.findall(r'^(Benchmark\w+)-\d+\s+5\s+([\d.]+) ns/op\s+[\d.]+ MB/s\s+(\d+) B/op\s+(\d+) allocs/op', log, re.M)
        for name, expected in summary['allocation'].items():
            values = [(float(ns), int(allocated), int(allocs)) for n, ns, allocated, allocs in matches if n == name]
            assert len(values) == 3
            for index, metric in enumerate(('median_ns_per_op', 'median_bytes_per_op', 'median_allocs_per_op')):
                assert statistics.median(v[index] for v in values) == expected[mode][metric]
            reduction = 100 * (1 - expected['candidate']['median_bytes_per_op'] / expected['baseline']['median_bytes_per_op'])
            assert reduction == expected['allocated_bytes_reduction_percent']
    print('PASS: selected evidence hashes, sample counts, quantiles, allocation medians and retained regression')
    print('Historical local observations only; no live execution or production certification.')


if __name__ == '__main__':
    main()
