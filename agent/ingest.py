"""Group one bounded batch of already-sanitized events into immutable jobs.

The window, source/config and group identity are stable across delivery retries.
Late changes to an already-enqueued group fail the worker's idempotency check;
an operator must review them instead of silently creating another proposal.
"""
import time
from agent import worker as w


def group_events(events, window_start, now=None):
    now = time.time() if now is None else now
    if type(window_start) is not int or window_start % 3600 or not now - 3600 <= window_start <= now:
        raise ValueError('explicit current hourly window required')
    if not isinstance(events, list) or not 1 <= len(events) <= 100 or len(w.canonical(events).encode()) > w.MAX_INPUT:
        raise ValueError('bounded sanitized event batch required')
    unique, groups = {}, {}
    for event in events:
        if not isinstance(event, dict) or set(event) != {'event_id', 'tenant', 'reason', 'count', 'p95_ms'}:
            raise ValueError('raw log/document inputs forbidden')
        if not isinstance(event['event_id'], str) or not w.TOKEN.fullmatch(event['event_id']):
            raise ValueError('invalid passive event ID')
        identity = (event['tenant'], event['event_id'])
        if identity in unique:
            if unique[identity] != event: raise ValueError('event identity reused for changed content')
            continue
        unique[identity] = event
        key = (event['tenant'], event['reason'])
        g = groups.setdefault(key, {'count': 0, 'p95_ms': 0})
        # Validate each sanitized record using the same job schema before grouping.
        probe = _job(event['tenant'], event['reason'], event['count'], event['p95_ms'], window_start)
        w.validate_job(probe, now)
        g['count'] += event['count']
        g['p95_ms'] = max(g['p95_ms'], event['p95_ms'])
    jobs = [_job(tenant, reason, group['count'], group['p95_ms'], window_start) for (tenant, reason), group in sorted(groups.items())]
    for job in jobs: w.validate_job(job, now)
    return jobs


def _job(tenant, reason, count, p95, window):
    identity = 'group-' + w.hashed({'tenant': tenant, 'reason': reason, 'window': window,
                                  'source': w.source_version(), 'config': w.config_version()})[:32]
    return {'schema_version': 1, 'job_id': identity, 'idempotency_key': identity, 'tenant': tenant, 'scope': tenant,
            'goal_version': 'policy-analysis-v1', 'source_version': w.source_version(), 'config_version': w.config_version(),
            'model_version': 'deterministic-offline-v1', 'deadline': window + 7200,
            'summary': {'reason': reason, 'count': count, 'p95_ms': p95}, 'evidence_refs': [identity],
            'allowed_tools': ['operator_docs', 'fixed_fixture_check'], 'budget': {'seconds': 30, 'tokens': 512, 'context': 2048}}
