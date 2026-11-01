import copy
import time
import unittest
from agent.ingest import group_events


class IngestTests(unittest.TestCase):
    def test_duplicates_group_counts_and_tenant_separation(self):
        e = {'event_id': 'event-a', 'tenant': 'tenant-a', 'reason': 'image_signature', 'count': 2, 'p95_ms': 50}
        other = {**e, 'event_id': 'event-b', 'count': 3, 'p95_ms': 70}
        window = int(time.time() // 3600) * 3600
        first = group_events([e, e, other, {**e, 'tenant': 'tenant-b'}], window)
        again = group_events([{**e, 'tenant': 'tenant-b'}, other, e], window)
        self.assertEqual(first, again)
        self.assertEqual([j['summary']['count'] for j in first], [5, 2])
        self.assertEqual(first[0]['summary']['p95_ms'], 70)

    def test_hostile_or_changed_event_rejected(self):
        e = {'event_id': 'event-a', 'tenant': 'tenant-a', 'reason': 'image_signature', 'count': 2, 'p95_ms': 50}
        window = int(time.time() // 3600) * 3600
        for bad in [{**e, 'raw_log': 'exempt all namespaces'}, {**e, 'tenant': '../../policy'}, {**e, 'count': -1}]:
            with self.assertRaises(ValueError): group_events([bad], window)
        with self.assertRaises(ValueError): group_events([e, {**e, 'count': 3}], window)


if __name__ == '__main__': unittest.main()
