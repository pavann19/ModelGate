# Proposal-only analysis worker

This standard-library Python worker accepts sanitized typed summaries and stores
bounded runbook proposals in a single-worker SQLite WAL queue. It never participates
in admission or writes trust policy. Missing models block work; there is no download
or cloud fallback. Unknown, oversized, cross-tenant and stale results are rejected.
A fixed action allowlist renders proposals for human review. Confidence is not authority.

Run the isolated regression suite from the repository root:

```sh
python3 -B -m unittest discover -s agent -v
python3 -B -m agent.worker --help
docker build -f agent/Dockerfile -t modelgate-analysis:local .
```

Use --db <new-fixture-path> --once --offline for explicit deterministic offline
processing. Enqueue a strict v1 envelope with --enqueue <job.json>; see
validate_job in worker.py and synthetic examples in test_worker.py. A prepared
proposal requires an operator-pinned fixture report and its SHA-256. Without that
report work requires review. Offline output is not a model-quality result.

One process owns one local database. Claims and terminal results are transactional;
lease tokens fence stale owners. Expired uncertain jobs require review rather than
replay of consequential actions. Retention rejects new work at its ceiling instead
of dropping history. Store.backup creates a new SQLite backup including committed
WAL records; restore into a new path and verify integrity and deduplication before
use. Preserve the failed original. No distributed queue or production RTO/RPO is claimed.

The optional deployment in deploy/manifests/agent.yaml uses an explicit local image,
Recreate, one RWO volume, offline mode and no API token. Build/load the image into a
disposable cluster before applying it; storage provisioning, directory ownership and
CNI enforcement must be verified separately. It is not installed by the webhook chart.
Never scale SQLite on an unverified shared filesystem. The root image excludes the
worker, so worker outage cannot weaken admission. Retain its store on rollback;
no down migration or automatic replay is supplied. Jobs pin source/config hashes,
so source upgrades can invalidate old envelopes and need explicit review.
