#!/usr/bin/env python3
"""Matched real-admission comparison of preloaded baseline/candidate images.

Run after private-registry-smoke.py on a disposable kind cluster. Four blocks
alternate baseline/candidate/candidate/baseline to expose ordering effects.
Every block uses identical images, resource limits, request counts and workers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--confirm-disposable-cluster', required=True)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--baseline-image', required=True)
    parser.add_argument('--candidate-image', required=True)
    parser.add_argument('--baseline-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--requests', type=int, default=50)
    args = parser.parse_args()
    if args.context != args.confirm_disposable_cluster or not args.context.startswith('kind-'):
        parser.error('matching disposable kind context required')
    if not 10 <= args.requests <= 1000 or args.baseline_image == args.candidate_image:
        parser.error('distinct preloaded images and 10..1000 requests required')
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    kube = ['kubectl', '--context', args.context, '-n', 'modelgate-system']
    bootstrap = json.loads(next(line[19:] for line in args.bootstrap.read_text().splitlines() if line.startswith('REGISTRY_BOOTSTRAP=')))
    evidence = {'schema': 1, 'baselineCommit': args.baseline_commit, 'context': args.context,
                'requestsPerPhase': args.requests, 'blocks': [], 'passed': False,
                'limitations': ['local shared Docker engine; minimal OCI fixture; no kubelet execution',
                                'same-image multi-container Pods; no production capacity claim']}

    def command(argv):
        p = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=180)
        with (args.output / 'operations.log').open('a', encoding='utf-8') as log:
            log.write(json.dumps(argv) + '\n' + p.stdout + p.stderr + '\n')
        if p.returncode:
            raise RuntimeError('command failed; see operations.log')
        return p.stdout

    binary = args.output / ('admission-eval.exe' if os.name == 'nt' else 'admission-eval')
    command(['go', 'build', '-o', str(binary), './cmd/admission-eval'])
    evidence['sourceSHA256'] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in
        ['internal/webhook/handler.go', 'internal/webhook/artifact_open_linux.go', 'cmd/admission-eval/main.go',
         'deploy/kind/repeated-image-eval.py', 'Dockerfile', 'go.mod', 'go.sum']}
    evidence['docker'] = json.loads(command(['docker', 'info', '--format', '{"version":"{{.ServerVersion}}","cpus":{{.NCPU}},"memoryBytes":{{.MemTotal}}}']))
    evidence['containersAtStart'] = command(['docker', 'ps', '--format', '{{.Names}}']).splitlines()
    evidence['imageIDs'] = {label: command(['docker', 'image', 'inspect', image, '--format', '{{.Id}}']).strip()
                            for label, image in [('baseline', args.baseline_image), ('candidate', args.candidate_image)]}
    if len(set(evidence['imageIDs'].values())) != 2:
        raise RuntimeError('baseline and candidate resolve to the same local image')
    deployment = json.loads(command(kube + ['get', 'deployment', 'modelgate-webhook', '-o', 'json']))
    container = deployment['spec']['template']['spec']['containers'][0]
    evidence['resources'] = container['resources']
    original_image = container['image']
    original_pull_policy = container.get('imagePullPolicy', 'IfNotPresent')
    evaluator = [str(binary), '--context', args.context, '--namespace', 'default', '--image',
                 bootstrap['host'] + '/signed@' + bootstrap['digest'], '--expect', 'allowed']

    def set_image(image, pull_policy='Never', expected_identity=None):
        patch = {'spec': {'template': {'spec': {'containers': [{'name': container['name'], 'image': image, 'imagePullPolicy': pull_policy}]}}}}
        command(kube + ['patch', 'deployment', 'modelgate-webhook', '--type=strategic', '-p', json.dumps(patch)])
        command(kube + ['rollout', 'status', 'deployment/modelgate-webhook', '--timeout=90s'])
        pods = json.loads(command(kube + ['get', 'pods', '-l', 'app=modelgate-webhook', '-o', 'json']))
        # rollout status can succeed while an older Pod is still terminating.
        # Wait for its deletion before timing requests or attributing image identity.
        for pod in pods['items']:
            if pod['metadata'].get('deletionTimestamp') or any(
                    c['image'] != image for c in pod['spec']['containers'] if c['name'] == container['name']):
                command(kube + ['wait', '--for=delete', 'pod/' + pod['metadata']['name'], '--timeout=60s'])
        pods = json.loads(command(kube + ['get', 'pods', '-l', 'app=modelgate-webhook', '-o', 'json']))
        if len(pods['items']) != deployment['spec'].get('replicas', 1):
            raise RuntimeError('unexpected webhook Pod count after rollout')
        for pod in pods['items']:
            statuses = [s for s in pod.get('status', {}).get('containerStatuses', []) if s['name'] == container['name']]
            ready = any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', []))
            if (pod['metadata'].get('deletionTimestamp') or not ready or len(statuses) != 1
                    or not statuses[0].get('ready') or not statuses[0].get('imageID')
                    or any(c['image'] != image for c in pod['spec']['containers'] if c['name'] == container['name'])):
                raise RuntimeError('webhook image is not exclusively ready')
            if expected_identity and not statuses[0]['imageID'].endswith(expected_identity):
                raise RuntimeError('running image identity differs from preloaded image')
        return pods

    try:
        for block, label in enumerate(['baseline', 'candidate', 'candidate', 'baseline']):
            image = args.baseline_image if label == 'baseline' else args.candidate_image
            pods = set_image(image, expected_identity=evidence['imageIDs'][label])
            # A checked, recorded warmup precedes each measured phase.
            item = {'implementation': label, 'image': image, 'phases': []}
            item['runningImages'] = [status.get('imageID') for pod in pods['items']
                                     for status in pod.get('status', {}).get('containerStatuses', [])]
            item['exclusiveReadyImageVerified'] = True
            evidence['blocks'].append(item)
            for containers, workers in [(1, 1), (8, 1), (1, 4), (8, 4)]:
                path = args.output / f'{block}-{label}-n{containers}-c{workers}.json'
                command(evaluator + ['--containers', str(containers), '--concurrency', str(workers),
                                     '--requests', str(args.requests), '--warmup', '3', '--output', str(path)])
                item['phases'].append(json.loads(path.read_text()))
                print(f'{block} {label} containers={containers} workers={workers}: PASS', flush=True)
        evidence['passed'] = True
    finally:
        try:
            set_image(original_image, original_pull_policy)
        except Exception as exc:
            evidence['passed'] = False
            evidence['restorationError'] = str(exc)
        evidence['finishedUTC'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        (args.output / 'summary.json').write_text(json.dumps(evidence, indent=2) + '\n')
    if not evidence['passed']:
        raise RuntimeError('experiment or restoration failed')


if __name__ == '__main__':
    main()
