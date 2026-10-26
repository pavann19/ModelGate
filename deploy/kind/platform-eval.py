#!/usr/bin/env python3
"""Operator-only experiment on a disposable cluster prepared by private-registry-smoke.py.

Measures the real Kubernetes API without subprocess-per-request timing. Never persists
workload Pods. Key rotation and deployment outage are intentionally destructive to this
disposable installation only; the original policy and replica count are restored.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--confirm-disposable-cluster', required=True, help='must equal --context')
    args = parser.parse_args()
    if args.context != args.confirm_disposable_cluster or not args.context.startswith('kind-'):
        parser.error('explicit matching disposable kind context confirmation required')
    if not 10 <= args.requests <= 1000:
        parser.error('requests must be 10..1000')
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    bootstrap = json.loads(next(line[19:] for line in args.bootstrap.read_text().splitlines()
                                if line.startswith('REGISTRY_BOOTSTRAP=')))
    kube = ['kubectl', '--context', args.context]
    evidence = {'schema': 1, 'platform': platform.platform(), 'context': args.context,
                'requestsPerLoadPhase': args.requests, 'phases': [], 'passed': False,
                'measurement': 'closed-loop API-server dry-run; real TLS registry and offline cosign; no cache',
                'limitations': ['minimal OCI fixture, no kubelet execution', 'single disposable kind node',
                                'no production SLO or improvement baseline claimed']}

    def command(argv, body=None):
        result = subprocess.run(argv, input=json.dumps(body) if body is not None else None,
                                capture_output=True, text=True, cwd=root, timeout=180)
        with (args.output / 'operations.log').open('a', encoding='utf-8') as log:
            log.write(json.dumps(argv) + '\n' + result.stdout + result.stderr + '\n')
        if result.returncode:
            raise RuntimeError('operator command failed; see operations.log')
        return result.stdout

    binary = args.output / ('admission-eval.exe' if os.name == 'nt' else 'admission-eval')
    command(['go', 'build', '-o', str(binary), './cmd/admission-eval'])
    evidence['commit'] = command(['git', 'rev-parse', 'HEAD']).strip()
    evidence['dirty'] = bool(command(['git', 'status', '--porcelain']).strip())
    evidence['goVersion'] = command(['go', 'version']).strip()
    evidence['docker'] = json.loads(command(['docker', 'info', '--format', '{"version":"{{.ServerVersion}}","cpus":{{.NCPU}},"memoryBytes":{{.MemTotal}}}']))
    evidence['concurrentDockerContainersAtStart'] = len(command(['docker', 'ps', '-q']).splitlines())
    evidence['sourceSHA256'] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in
                                ['cmd/admission-eval/main.go', 'deploy/kind/platform-eval.py', 'go.mod', 'go.sum', 'Dockerfile']}
    evidence['kubernetesVersion'] = json.loads(command(kube + ['version', '-o', 'json']))['serverVersion']['gitVersion']
    deployment = json.loads(command(kube + ['-n', 'modelgate-system', 'get', 'deployment', 'modelgate-webhook', '-o', 'json']))
    evidence['webhookImage'] = deployment['spec']['template']['spec']['containers'][0]['image']
    evidence['webhookResources'] = deployment['spec']['template']['spec']['containers'][0]['resources']
    evidence['nodeAllocatable'] = [x['status']['allocatable'] for x in json.loads(command(kube + ['get', 'nodes', '-o', 'json']))['items']]
    replicas = deployment['spec'].get('replicas', 1)
    namespace = 'modelgate-eval'
    # Refuse to overwrite an existing tenant policy/namespace.
    existing = subprocess.run(kube + ['get', 'namespace', namespace, '--ignore-not-found', '-o', 'name'],
                              capture_output=True, text=True, timeout=20)
    if existing.returncode or existing.stdout.strip():
        raise RuntimeError('evaluation namespace must not already exist')
    command(kube + ['create', 'namespace', namespace])
    policy = {'apiVersion': 'modelgate.dev/v1alpha1', 'kind': 'ModelGatePolicy',
              'metadata': {'name': 'evaluation', 'namespace': namespace},
              'spec': {'cosignPublicKeyPEM': bootstrap['publicKey']}}

    def apply_policy(key):
        policy['spec']['cosignPublicKeyPEM'] = key
        command(kube + ['apply', '-f', '-'], policy)

    def phase(name, repo='signed', count=None, concurrency=1, expected='allowed', warmup=5, check=True):
        path = args.output / (name + '.json')
        result = subprocess.run([str(binary), '--context', args.context, '--namespace', namespace,
                                 '--image', bootstrap['host'] + '/' + repo + '@' + bootstrap['digest'],
                                 '--requests', str(count or args.requests), '--concurrency', str(concurrency),
                                 '--expect', expected, '--warmup', str(warmup), '--output', str(path)],
                                capture_output=True, text=True, cwd=root, timeout=240)
        with (args.output / 'operations.log').open('a', encoding='utf-8') as log:
            log.write(name + '\n' + result.stdout + result.stderr + '\n')
        record = {'name': name, 'file': path.name, 'exit': result.returncode}
        evidence['phases'].append(record)
        print(result.stdout + result.stderr, flush=True)
        if check and result.returncode:
            raise RuntimeError(name + ' failed; all samples retained')
        return result.returncode

    def scale(n):
        command(kube + ['-n', 'modelgate-system', 'scale', 'deployment/modelgate-webhook', '--replicas=' + str(n)])

    try:
        apply_policy(bootstrap['publicKey'])
        for c in [1, 4, 8, 16]:
            phase('signed-c' + str(c), concurrency=c, expected='allowed' if c == 1 else 'overload')
        phase('unsigned', repo='unsigned', expected='policy_denied')
        phase('bounded-saturation', repo='slow-registry', count=32, concurrency=16, expected='saturation', warmup=0)
        apply_policy(bootstrap['otherPublicKey'])
        phase('rotated-key-denies-old-signature', count=20, expected='policy_denied', warmup=0)
        apply_policy(bootstrap['publicKey'])
        phase('restored-key-allows', count=20, warmup=0)
        (args.output / 'webhook-before-outage.log').write_text(command(kube + ['-n', 'modelgate-system', 'logs', 'deployment/modelgate-webhook']), encoding='utf-8')
        scale(0)
        command(kube + ['-n', 'modelgate-system', 'wait', '--for=delete', 'pod', '-l', 'app=modelgate-webhook', '--timeout=60s'])
        phase('webhook-outage', count=20, expected='webhook_unavailable', warmup=0)
        started = time.monotonic()
        scale(replicas)
        command(kube + ['-n', 'modelgate-system', 'rollout', 'status', 'deployment/modelgate-webhook', '--timeout=90s'])
        for attempt in range(30):
            if phase('recovery-probe-' + str(attempt), count=1, warmup=0, check=False) == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('webhook did not recover')
        evidence['observedRecoverySeconds'] = time.monotonic() - started
        phase('post-outage-recovery', count=20, warmup=0)
        evidence['passed'] = True
    finally:
        restoration_errors = []
        for label, operation in [
            ('restore-key', lambda: apply_policy(bootstrap['publicKey'])),
            ('restore-replicas', lambda: scale(replicas)),
            ('restore-readiness', lambda: command(kube + ['-n', 'modelgate-system', 'rollout', 'status', 'deployment/modelgate-webhook', '--timeout=90s'])),
            ('remove-evaluation-namespace', lambda: command(kube + ['delete', 'namespace', namespace, '--timeout=60s'])),
        ]:
            try:
                operation()
            except Exception as error:
                restoration_errors.append({'operation': label, 'error': str(error)})
        evidence['restorationErrors'] = restoration_errors
        try:
            evidence['concurrentDockerContainersAtEnd'] = len(command(['docker', 'ps', '-q']).splitlines())
        except Exception as error:
            evidence['environmentCaptureError'] = str(error)
        try:
            (args.output / 'webhook.log').write_text(command(kube + ['-n', 'modelgate-system', 'logs', 'deployment/modelgate-webhook']), encoding='utf-8')
        except Exception as error:
            evidence['logCaptureError'] = str(error)
        if restoration_errors:
            evidence['passed'] = False
        (args.output / 'summary.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
        if restoration_errors:
            raise RuntimeError('restoration failed; see summary.json')
    print('Evaluation complete; delete the disposable cluster after inspecting evidence.', flush=True)


if __name__ == '__main__':
    main()
