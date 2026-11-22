"""Recompute historical October samples; no cluster or current-source assertion."""
import json
import math
from collections import Counter
from pathlib import Path


def q(values, p):
    return sorted(values)[math.ceil(len(values) * p / 100) - 1]


def main():
    root = Path(__file__).resolve().parents[1]
    record = json.loads((root / 'docs/evidence/october-latency-20261026/comparison.json').read_text())
    assert record['passed'] and record['requestsPerPhase'] == 50
    assert [b['implementation'] for b in record['blocks']] == ['baseline', 'candidate', 'candidate', 'baseline']
    total = 0
    warmups = 0
    for block in record['blocks']:
        assert block['exclusiveReadyImageVerified']
        assert block['runningImages'] and all(image.endswith(record['imageIDs'][block['implementation']]) for image in block['runningImages'])
        assert [(p['containersPerPod'], p['concurrency']) for p in block['phases']] == [(1, 1), (8, 1), (1, 4), (8, 4)]
        for phase in block['phases']:
            samples = phase['samples']
            assert phase['passed'] and phase['warmup'] == 3 and len(samples) == 50
            assert dict(Counter(s['outcome'] for s in samples)) == phase['outcomes'] == {'allowed': 50}
            values = [s['milliseconds'] for s in samples]
            for p in (50, 95, 99):
                assert q(values, p) == phase[f'p{p}Milliseconds']
                assert q(values, p) == phase['latencyMillisecondsByOutcome']['allowed'][f'p{p}']
            total += len(samples)
            warmups += phase['warmup']
    assert total == 800 and warmups == 48
    assert {(r['containers'], r['workers']) for r in record['pooledResults']} == {(1, 1), (8, 1), (1, 4), (8, 4)}
    for row in record['pooledResults']:
        for impl in ('baseline', 'candidate'):
            phases = [p for b in record['blocks'] if b['implementation'] == impl for p in b['phases'] if (p['containersPerPod'], p['concurrency']) == (row['containers'], row['workers'])]
            assert len(phases) == 2
            values = [s['milliseconds'] for p in phases for s in p['samples']]
            assert len(values) == 100
            for percentile in (50, 95, 99):
                assert q(values, percentile) == row[impl][f'p{percentile}Milliseconds']
        reduction = 100 * (1 - row['candidate']['p95Milliseconds'] / row['baseline']['p95Milliseconds'])
        assert abs(reduction - row['p95ReductionPercent']) < 1e-9
        print(f"containers={row['containers']} workers={row['workers']}: p95 {row['baseline']['p95Milliseconds']:.3f} -> {row['candidate']['p95Milliseconds']:.3f} ms; reduction={reduction:.3f}%")
    print('PASS: 800 samples, 48 recorded warmups, ABBA order, recorded image identities and nearest-rank quantiles')
    print('Saved historical observations only; not a live reproduction, current-source certification or production SLO.')


if __name__ == '__main__':
    main()
