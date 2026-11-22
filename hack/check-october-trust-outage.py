"""Recompute saved local signature/outage trials without starting infrastructure."""
import json
import math
import re
import statistics
from collections import Counter
from pathlib import Path


def q(values, p):
    return sorted(values)[math.ceil(len(values) * p / 100) - 1]


def main():
    root = Path(__file__).resolve().parents[1]
    record = json.loads((root / 'docs/evidence/october-trust-outage-20261026/trials.json').read_text())
    assert [run['run'] for run in record['runs']] == [1, 2, 3]
    controls = {
        'unsigned': ('policy_denied', 100),
        'rotated-key-denies-old-signature': ('policy_denied', 20),
        'other-namespace-rejects-rotated-key': ('policy_denied', 20),
        'rotated-key-allows-new-signature': ('allowed', 20),
        'other-namespace-retains-original-key': ('allowed', 20),
        'restored-key-allows': ('allowed', 20),
        'webhook-outage': ('webhook_unavailable', 20),
        'post-outage-recovery': ('allowed', 20),
    }
    totals = Counter()
    warmups = 0
    for run in record['runs']:
        env = run['environment']
        assert env['passed'] and not env['restorationErrors']
        assert env['kubernetesVersion'] == 'v1.31.0'
        # The combined record hashes candidate handler sources separately;
        # each trial hashes evaluator/orchestration inputs, not those handlers.
        assert env['sourceSHA256'] == record['runs'][0]['environment']['sourceSHA256']
        for digest in [*env['sourceSHA256'].values(), *record['candidateSourceSHA256'].values()]:
            assert re.fullmatch(r'[a-f0-9]{64}', digest)
        for name, phase in run['phases'].items():
            assert phase['passed'] or name.startswith('recovery-probe-')
            samples = phase['samples']
            assert samples
            outcomes = Counter(s['outcome'] for s in samples)
            assert dict(outcomes) == phase['outcomes']
            for percentile in (50, 95, 99):
                assert q([s['milliseconds'] for s in samples], percentile) == phase[f'p{percentile}Milliseconds']
                for outcome, metrics in phase['latencyMillisecondsByOutcome'].items():
                    assert q([s['milliseconds'] for s in samples if s['outcome'] == outcome], percentile) == metrics[f'p{percentile}']
            assert set(phase['latencyMillisecondsByOutcome']) == set(outcomes)
            totals.update(outcomes)
            warmups += phase['warmup']
        for name, (outcome, count) in controls.items():
            assert run['phases'][name]['outcomes'] == {outcome: count}
        assert run['phases']['post-outage-recovery']['passed']
        probes = [p for name, p in run['phases'].items() if name.startswith('recovery-probe-')]
        assert probes and probes[-1]['outcomes'] == {'allowed': 1}
    assert dict(totals) == record['aggregateOutcomes']
    assert sum(totals.values()) == record['measuredRequests'] == 2019
    assert warmups == 75
    times = [r['environment']['observedRecoverySeconds'] for r in record['runs']]
    assert times == record['recoveryTrialsSeconds'] and all(t > 0 for t in times)
    assert statistics.median(times) == record['recoveryMedianSeconds']
    assert q(times, 95) == record['recoveryP95Seconds']
    print('PASS: 2019 measured outcomes, 75 recorded warmups, phase quantiles, aggregate counts and restoration records')
    print('Negative-signature controls: 420/420 denied; selected positive controls: 120/120 admitted')
    print('Injected webhook-outage requests: 60/60 blocked; post-recovery controls: 60/60 admitted')
    print('Observed recovery seconds:', ', '.join(f'{t:.6f}' for t in times))
    print('Historical local evidence only; no live reproduction, current-source certification or general dependency-outage claim.')


if __name__ == '__main__':
    main()
