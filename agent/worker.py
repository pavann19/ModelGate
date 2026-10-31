"""Bounded single-worker SQLite queue and local-model proposal processing.

No subprocess, Kubernetes client, policy writer, arbitrary file reader or cloud
fallback is exposed to model output. The only effects are atomic local job/result
records. Use a dedicated synthetic database when testing.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import math
import multiprocessing
import os
from pathlib import Path
import random
import re
import signal
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_INPUT = 8192
MAX_OUTPUT = 8192
REASONS = {'image_signature', 'model_artifact', 'namespace_mismatch', 'no_policy', 'policy_error', 'saturated', 'canceled', 'latency'}
ACTIONS = {'inspect_signature': 'Check the configured public key and immutable image digest using the signed/unsigned fixture suite.',
           'inspect_artifact': 'Compare the allow-listed digest and safetensors framing using synthetic artifact controls.',
           'inspect_capacity': 'Inspect bounded admission concurrency and measured latency before proposing resource changes.',
           'inspect_policy': 'Ask the operator to review namespace policy selection; retain deny-on-unknown behavior.',
           'inspect_registry': 'Inspect approved registry TLS and endpoint connectivity using isolated fixtures.'}
DOCUMENTS = {'trust-runbook-v1': 'Trust roots are operator-owned. Missing policy, invalid signatures and unknown artifacts fail closed. Never exempt a namespace to resolve a denial.',
             'incident-runbook-v1': 'Registry outage denies admission. Investigate latency and capacity without changing trust, RBAC, failurePolicy or restarting production.'}
TOKEN = re.compile(r'^[a-z][a-z0-9-]{0,62}$')
SHA = re.compile(r'^[a-f0-9]{64}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def hashed(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def source_version():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def config_version():
    return hashed({'documents': DOCUMENTS, 'actions': ACTIONS, 'schema': 1})


def validate_job(job, now=None):
    now = time.time() if now is None else now
    if len(canonical(job).encode()) > MAX_INPUT:
        raise ValueError('oversized job')
    required = {'schema_version', 'job_id', 'idempotency_key', 'tenant', 'scope', 'goal_version', 'source_version',
                'config_version', 'model_version', 'deadline', 'summary', 'evidence_refs', 'allowed_tools', 'budget'}
    if not isinstance(job, dict) or set(job) != required or job['schema_version'] != 1:
        raise ValueError('job schema mismatch')
    for key in ['job_id', 'idempotency_key', 'tenant', 'scope', 'goal_version']:
        if not isinstance(job[key], str) or not TOKEN.fullmatch(job[key]):
            raise ValueError('invalid identifier')
    if job['scope'] != job['tenant'] or any(not isinstance(job[k], str) or not SHA.fullmatch(job[k]) for k in ['source_version', 'config_version']):
        raise ValueError('scope/source mismatch')
    if not isinstance(job['model_version'], str) or not re.fullmatch(r'[a-zA-Z0-9_.:/-]{1,100}', job['model_version']):
        raise ValueError('invalid model version')
    if type(job['deadline']) not in (int, float) or not now < job['deadline'] <= now + 86400 * 2:
        raise ValueError('invalid deadline')
    summary = job['summary']
    if not isinstance(summary, dict) or set(summary) != {'reason', 'count', 'p95_ms'} or summary['reason'] not in REASONS:
        raise ValueError('only sanitized typed summaries are accepted')
    if type(summary['count']) is not int or not 1 <= summary['count'] <= 100000:
        raise ValueError('invalid count')
    if type(summary['p95_ms']) not in (int, float) or not 0 <= summary['p95_ms'] <= 60000:
        raise ValueError('invalid latency')
    if not isinstance(job['evidence_refs'], list) or not 1 <= len(job['evidence_refs']) <= 8 or any(
            not isinstance(r, str) or not TOKEN.fullmatch(r) for r in job['evidence_refs']):
        raise ValueError('invalid passive evidence IDs')
    if job['allowed_tools'] != ['operator_docs', 'fixed_fixture_check']:
        raise ValueError('unapproved tool')
    budget = job['budget']
    if not isinstance(budget, dict) or set(budget) != {'seconds', 'tokens', 'context'}:
        raise ValueError('invalid budget')
    for field, low, high in [('seconds', 1, 30), ('tokens', 16, 512), ('context', 512, 2048)]:
        if type(budget[field]) is not int or not low <= budget[field] <= high:
            raise ValueError('unbounded job')
    return job


class Store:
    def __init__(self, path, max_jobs=1000, daily_jobs=500, max_bytes=64 * 1024 * 1024):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_jobs, self.daily_jobs, self.max_bytes = max_jobs, daily_jobs, max_bytes
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
        PRAGMA journal_size_limit=1048576;
        CREATE TABLE IF NOT EXISTS jobs(
          job_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, idempotency_key TEXT NOT NULL,
          envelope TEXT NOT NULL, input_hash TEXT NOT NULL, source_version TEXT NOT NULL,
          state TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL,
          deadline REAL NOT NULL, next_attempt_at REAL NOT NULL DEFAULT 0,
          lease_owner TEXT, lease_token TEXT, lease_expiry REAL, heartbeat REAL,
          tool_hash TEXT, result_hash TEXT, result TEXT, outcome_evidence TEXT,
          UNIQUE(tenant,idempotency_key));
        CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
        ''')

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def atomic(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def counter(self, name):
        self.db.execute('INSERT INTO counters VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1', (name,))

    def enqueue(self, job, now=None):
        now = time.time() if now is None else now
        validate_job(job, now)
        h = hashed(job)
        with self.atomic():
            previous = self.db.execute('SELECT job_id,input_hash FROM jobs WHERE tenant=? AND idempotency_key=?', (job['tenant'], job['idempotency_key'])).fetchone()
            if previous:
                if previous['input_hash'] != h:
                    raise ValueError('idempotency key reused for different input')
                self.counter('duplicates')
                return previous['job_id']
            if self.db.execute('SELECT count(*) FROM jobs').fetchone()[0] >= self.max_jobs:
                raise ValueError('retained job limit reached; operator retention required')
            if self.db.execute('SELECT count(*) FROM jobs WHERE created>=?', (now - 86400,)).fetchone()[0] >= self.daily_jobs:
                raise ValueError('daily job limit')
            if sum(p.stat().st_size for p in self.path.parent.glob(self.path.name + '*') if p.is_file()) >= self.max_bytes:
                raise ValueError('queue disk ceiling')
            self.db.execute('INSERT INTO jobs(job_id,tenant,idempotency_key,envelope,input_hash,source_version,state,created,deadline) VALUES(?,?,?,?,?,?,?, ?,?)',
                            (job['job_id'], job['tenant'], job['idempotency_key'], canonical(job), h, job['source_version'], 'queued', now, job['deadline']))
        return job['job_id']

    def claim(self, owner, now=None, lease=45):
        now = time.time() if now is None else now
        with self.atomic():
            expired = self.db.execute("UPDATE jobs SET state='needs_review',outcome_evidence='lease expired; proposal outcome uncertain' WHERE state='running' AND lease_expiry<=?", (now,)).rowcount
            for _ in range(expired): self.counter('lease_expiry')
            self.db.execute("UPDATE jobs SET state='needs_review',outcome_evidence='deadline expired' WHERE state IN ('queued','retry_wait') AND deadline<=?", (now,))
            # SQLite single-worker topology: never run two model jobs concurrently.
            if self.db.execute("SELECT 1 FROM jobs WHERE state='running'").fetchone(): return None
            row = self.db.execute("SELECT * FROM jobs WHERE state IN ('queued','retry_wait') AND next_attempt_at<=? AND deadline>? ORDER BY created,job_id LIMIT 1", (now, now)).fetchone()
            if not row: return None
            token = uuid.uuid4().hex
            self.db.execute("UPDATE jobs SET state='running',attempt=attempt+1,lease_owner=?,lease_token=?,lease_expiry=?,heartbeat=? WHERE job_id=?", (owner, token, min(now + lease, row['deadline']), now, row['job_id']))
            return dict(self.db.execute('SELECT * FROM jobs WHERE job_id=?', (row['job_id'],)).fetchone())

    def reap(self, now=None):
        now = time.time() if now is None else now
        with self.atomic():
            count = self.db.execute("UPDATE jobs SET state='needs_review',outcome_evidence='deadline or lease expired; no result accepted' WHERE state='running' AND (deadline<=? OR lease_expiry<=?)", (now, now)).rowcount
            for _ in range(count): self.counter('lease_expiry')

    def renew(self, job, now=None, lease=45):
        now = time.time() if now is None else now
        with self.atomic():
            changed = self.db.execute("UPDATE jobs SET heartbeat=?,lease_expiry=min(?,deadline) WHERE job_id=? AND state='running' AND lease_token=? AND lease_expiry>? AND deadline>?", (now, now + lease, job['job_id'], job['lease_token'], now, now)).rowcount
            return bool(changed)

    def finish(self, job, state, result=None, evidence='', now=None):
        now = time.time() if now is None else now
        if state not in {'prepared', 'blocked', 'needs_review', 'failed', 'retry_wait'}:
            raise ValueError('worker cannot apply effects')
        if len(evidence) > 256 or (result is not None and len(canonical(result).encode()) > MAX_OUTPUT):
            raise ValueError('oversized result')
        with self.atomic():
            row = self.db.execute('SELECT * FROM jobs WHERE job_id=?', (job['job_id'],)).fetchone()
            if row['state'] != 'running' or row['lease_token'] != job['lease_token'] or row['lease_expiry'] <= now or row['deadline'] <= now:
                raise ValueError('stale/expired lease cannot finish')
            if state == 'retry_wait' and row['attempt'] >= 3: state = 'needs_review'
            delay = min(60, 2 ** row['attempt']) + random.SystemRandom().uniform(0, 1)
            self.db.execute('UPDATE jobs SET state=?,result=?,result_hash=?,tool_hash=?,outcome_evidence=?,next_attempt_at=?,lease_owner=NULL,lease_token=NULL,lease_expiry=NULL WHERE job_id=?',
                            (state, canonical(result) if result else None, hashed(result) if result else None,
                             hashed({'docs': DOCUMENTS, 'fixture_suite': 'proposal-allowlist-v1'}), evidence, now + delay if state == 'retry_wait' else 0, row['job_id']))
            self.counter(state)

    def metrics(self, now=None):
        now = time.time() if now is None else now
        states = dict(self.db.execute('SELECT state,count(*) FROM jobs GROUP BY state').fetchall())
        oldest = self.db.execute("SELECT min(created) FROM jobs WHERE state IN ('queued','retry_wait')").fetchone()[0]
        return {'states': states, 'queue_depth': sum(states.get(s, 0) for s in ['queued', 'retry_wait']),
                'oldest_age_seconds': max(0, now - oldest) if oldest is not None else 0,
                'counters': dict(self.db.execute('SELECT name,value FROM counters').fetchall())}

    def backup(self, destination):
        destination = Path(destination)
        # Exclusive create protects existing evidence/data. SQLite backup includes WAL.
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
        with contextlib.closing(sqlite3.connect(destination)) as target: self.db.backup(target)


def validate_result(result, job, model):
    required = {'status', 'evidence_refs', 'observation', 'hypothesis', 'proposed_actions', 'confidence_or_uncertainty', 'model_version', 'source_version', 'tenant'}
    if not isinstance(result, dict) or set(result) != required or len(canonical(result).encode()) > MAX_OUTPUT:
        raise ValueError('invalid model result schema')
    if result['status'] not in {'prepared', 'needs_review', 'blocked', 'failed'} or result['tenant'] != job['tenant'] or result['source_version'] != job['source_version'] or result['model_version'] != model:
        raise ValueError('result identity mismatch')
    if result['evidence_refs'] != job['evidence_refs']:
        raise ValueError('result fabricated evidence')
    if not isinstance(result['proposed_actions'], list) or not 1 <= len(result['proposed_actions']) <= 3 or any(a not in ACTIONS for a in result['proposed_actions'] if isinstance(a, str)) or any(not isinstance(a, str) for a in result['proposed_actions']):
        raise ValueError('forbidden action')
    for key in ['observation', 'hypothesis', 'confidence_or_uncertainty']:
        value = result[key]
        if not isinstance(value, str) or not 1 <= len(value) <= 512 or re.search(r'(?i)(bearer\s|password|secret|sk-|-----BEGIN|https?://|[A-Za-z]:\\)', value):
            raise ValueError('unsafe/unbounded narrative')
    return result


class ModelBlocked(Exception): pass
class ModelTransient(Exception): pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'model redirects forbidden', headers, fp)


class Ollama:
    def __init__(self, model, digest, base='http://127.0.0.1:11434'):
        u = urllib.parse.urlsplit(base)
        if u.scheme != 'http' or u.username or u.password or u.path not in ('', '/') or u.query or u.fragment:
            raise ValueError('local explicit model endpoint required')
        try: local = ipaddress.ip_address(u.hostname).is_loopback
        except ValueError: local = False
        if not local: raise ValueError('local loopback endpoint required; no cloud fallback')
        if not re.fullmatch(r'[a-zA-Z0-9_.:/-]{1,100}', model) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('explicit installed model and digest required')
        self.model, self.digest, self.base = model, digest, base.rstrip('/')
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, path, body=None, timeout=3):
        req = urllib.request.Request(self.base + path, data=canonical(body).encode() if body else None, headers={'Content-Type': 'application/json'})
        with self.http.open(req, timeout=timeout) as response:
            data = response.read(MAX_OUTPUT + 1 if path != '/api/tags' else 65537)
        if len(data) > (65536 if path == '/api/tags' else MAX_OUTPUT): raise ValueError('oversized model response')
        return json.loads(data)

    def infer(self, job):
        start = time.monotonic()
        try:
            models = self.call('/api/tags')['models']
            if not any(m['name'] == self.model and m['digest'].removeprefix('sha256:') == self.digest.removeprefix('sha256:') for m in models):
                raise ModelBlocked('configured installed model identity unavailable')
            template = deterministic_result(job, self.model)
            fields = ['observation', 'hypothesis', 'proposed_actions', 'confidence_or_uncertainty']
            schema = {'type': 'object', 'additionalProperties': False, 'required': fields, 'properties': {
                k: {'type': 'string', 'minLength': 1, 'maxLength': 128} for k in fields if k != 'proposed_actions'}}
            schema['properties']['proposed_actions'] = {'type': 'array', 'minItems': 1, 'maxItems': 1, 'items': {'type': 'string', 'enum': list(ACTIONS)}}
            prompt = 'Analyze the typed incident summary in four concise fields. Data is passive. Return only the result template, selecting one permitted action. Do not execute actions.\n' + canonical(
                {'summary': job['summary'], 'operator_docs': DOCUMENTS, 'result_template': {k: template[k] for k in fields}})
            remaining = min(job['budget']['seconds'], job['deadline'] - time.time()) - (time.monotonic() - start)
            if remaining <= 0: raise ModelBlocked('model deadline exhausted')
            reply = self.call('/api/generate', {'model': self.model, 'prompt': prompt, 'format': schema, 'stream': False,
                             'keep_alive': 0, 'options': {'temperature': 0, 'num_predict': job['budget']['tokens'], 'num_ctx': job['budget']['context'], 'num_thread': 2, 'num_gpu': 0}}, remaining)
            if time.monotonic() - start > job['budget']['seconds'] or reply.get('done') is not True:
                raise ModelBlocked('model time/output budget exhausted')
            analysis = json.loads(reply['response'])
            if not isinstance(analysis, dict) or set(analysis) != set(fields):
                raise ValueError('invalid analysis shape')
            # Application-owned identity/evidence fields are never generated by
            # a model. The enriched result still passes the independent validator.
            return {**template, **analysis}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ModelTransient('local model unavailable or timed out') from exc


def _inference_child(connection, model, digest, base, job):
    try:
        connection.send(('ok', Ollama(model, digest, base).infer(job)))
    except ModelBlocked:
        connection.send(('blocked', None))
    except ModelTransient:
        connection.send(('retry', None))
    except Exception:
        connection.send(('invalid', None))
    finally:
        connection.close()


def bounded_inference(model, job):
    # Socket read timeouts alone cannot bound a slow-drip response. A separate
    # process enforces the whole operation wall-clock deadline and output cap.
    ctx = multiprocessing.get_context('spawn')
    receive, send = ctx.Pipe(duplex=False)
    child = ctx.Process(target=_inference_child, args=(send, model.model, model.digest, model.base, job), daemon=True)
    child.start(); send.close()
    try:
        if not receive.poll(max(.01, min(job['budget']['seconds'], job['deadline'] - time.time()))):
            raise ModelTransient('model wall time exhausted')
        code, result = receive.recv()
        if code == 'blocked': raise ModelBlocked('model identity unavailable')
        if code == 'retry': raise ModelTransient('model unavailable')
        if code != 'ok': raise ValueError('invalid model result')
        return result
    finally:
        receive.close()
        child.join(.2)
        if child.is_alive(): child.terminate(); child.join(2)
        if child.is_alive(): child.kill(); child.join(2)


def deterministic_result(job, model='deterministic-offline-v1'):
    reason = job['summary']['reason']
    action = 'inspect_signature' if reason == 'image_signature' else 'inspect_artifact' if reason == 'model_artifact' else 'inspect_capacity' if reason in {'saturated', 'latency'} else 'inspect_policy'
    return {'status': 'prepared', 'evidence_refs': job['evidence_refs'], 'observation': 'Typed synthetic summary: ' + reason,
            'hypothesis': 'Operator investigation required; cause has not been established.', 'proposed_actions': [action],
            'confidence_or_uncertainty': 'Unverified proposal requiring operator review.', 'model_version': model,
            'source_version': job['source_version'], 'tenant': job['tenant']}


def fixture_gate(report, job):
    expected = {'signed': 'allowed', 'unsigned': 'denied', 'wrong-artifact': 'denied', 'wrong-signature': 'denied'}
    return (isinstance(report, dict) and report.get('schema') == 1 and report.get('passed') is True
            and report.get('source_version') == job['source_version']
            and report.get('config_version') == job['config_version']
            and report.get('scope') == job['scope'] and isinstance(report.get('cluster_uid'), str)
            and bool(report['cluster_uid']) and report.get('outcomes') == expected)


def process_one(store, owner, model=None, offline=False, fixture=None):
    leased = store.claim(owner)
    if not leased: return False
    job = json.loads(leased['envelope'])
    try:
        validate_job(job)
        if hashed(job) != leased['input_hash']: raise ValueError('stored input hash changed')
        if job['source_version'] != source_version() or job['config_version'] != config_version():
            raise ValueError('job does not match installed source/config')
        if offline:
            version = 'deterministic-offline-v1'; result = deterministic_result(job)
        elif model is None:
            raise ModelBlocked('no explicitly configured local model')
        else:
            version = model.model; result = bounded_inference(model, job)
        if job['model_version'] != version:
            raise ValueError('job model identity mismatch')
        validate_result(result, job, version)
        # Only application-owned canned runbook text is exported. Model narrative
        # is validated as passive data; no model-provided patch/path is executable.
        result['runbook_proposal'] = [ACTIONS[a] for a in result['proposed_actions']]
        checked = fixture_gate(fixture, job)
        result['fixture_check'] = {'suite': 'fixed-admission-controls-v1', 'passed': checked,
                                   'evidence_hash': hashed(fixture) if fixture else None,
                                   'limit': 'operator-pinned isolated fixture observations; runbook proposal only, no policy patch applied'}
        if not checked: result['status'] = 'needs_review'
        store.finish(leased, result['status'], result, 'schema, scope, action allowlist and source hash validated')
    except ModelBlocked:
        store.finish(leased, 'blocked', evidence='local model unavailable or identity/deadline mismatch')
    except ModelTransient:
        if time.time() >= min(leased['lease_expiry'], leased['deadline']):
            store.reap()
        else:
            store.finish(leased, 'retry_wait', evidence='local model transport unavailable; safe proposal-only retry')
    except (ValueError, KeyError, TypeError, EOFError, json.JSONDecodeError):
        if time.time() >= min(leased['lease_expiry'], leased['deadline']): store.reap()
        else: store.finish(leased, 'needs_review', evidence='input/result rejected by deterministic validation')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--enqueue', type=Path)
    parser.add_argument('--offline', action='store_true', help='explicit deterministic fallback; no LLM claim')
    parser.add_argument('--model')
    parser.add_argument('--model-digest')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--metrics', action='store_true')
    parser.add_argument('--fixture-report', type=Path)
    parser.add_argument('--fixture-sha256')
    parser.add_argument('--health', action='store_true', help='local worker heartbeat only; no model RPC')
    args = parser.parse_args()
    if args.health:
        heartbeat = args.db.parent / 'worker-heartbeat'
        if not heartbeat.is_file() or time.time() - heartbeat.stat().st_mtime > 60:
            raise SystemExit(1)
        return
    store = Store(args.db)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        if args.enqueue:
            with args.enqueue.open('rb') as source:
                data = source.read(MAX_INPUT + 1)
            if len(data) > MAX_INPUT: raise ValueError('oversized file')
            print(store.enqueue(json.loads(data))); return
        if args.metrics: print(canonical(store.metrics())); return
        model = Ollama(args.model, args.model_digest) if args.model else None
        fixture = None
        if args.fixture_report:
            with args.fixture_report.open('rb') as source:
                data = source.read(MAX_INPUT + 1)
            if len(data) > MAX_INPUT or hashlib.sha256(data).hexdigest() != args.fixture_sha256:
                raise ValueError('operator-pinned fixture evidence mismatch')
            fixture = json.loads(data)
        owner = uuid.uuid4().hex
        last_log = 0
        while not stop.is_set():
            (args.db.parent / 'worker-heartbeat').touch()
            worked = process_one(store, owner, model, args.offline, fixture)
            if time.monotonic() - last_log >= 30:
                print(canonical(store.metrics()), flush=True); last_log = time.monotonic()
            if args.once: break
            stop.wait(2 if not worked else .1)
    finally:
        store.close()


if __name__ == '__main__': main()
