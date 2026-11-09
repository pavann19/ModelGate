#!/usr/bin/env python3
"""Read-only ModelGate deployment audit. Never reads Secrets or changes a cluster."""
import argparse
import datetime
import json
import re
from pathlib import Path
import subprocess


def assess(namespace, deployment, policies, webhook, role, nodes):
    checks = []

    def add(name, passed, detail):
        checks.append({'check': name, 'status': 'PASS' if passed else 'FAIL', 'detail': detail})

    pod = deployment.get('spec', {}).get('template', {}).get('spec', {})
    containers = pod.get('containers', [])
    spec = deployment.get('spec', {})
    status = deployment.get('status', {})
    desired = spec.get('replicas', 1)
    add('available_replicas', desired >= 2 and status.get('availableReplicas', 0) >= desired and
        status.get('updatedReplicas', 0) >= desired and
        status.get('observedGeneration', 0) >= deployment.get('metadata', {}).get('generation', 1),
        'At least two desired and available replicas; single-host HA is separate.')
    add('digest_pinned_images', bool(containers) and all(re.fullmatch(r'[^@\s]+@sha256:[a-f0-9]{64}', c.get('image', '')) for c in containers),
        'All deployed webhook container references must use immutable digests.')
    security = pod.get('securityContext', {})
    add('pod_security', security.get('runAsNonRoot') is True and
        security.get('seccompProfile', {}).get('type') == 'RuntimeDefault',
        'Non-root and RuntimeDefault seccomp required.')
    add('container_security', bool(containers) and all(
        c.get('securityContext', {}).get('allowPrivilegeEscalation') is False and
        c.get('securityContext', {}).get('readOnlyRootFilesystem') is True and
        'ALL' in c.get('securityContext', {}).get('capabilities', {}).get('drop', [])
        for c in containers), 'Read-only root, no escalation, drop all capabilities.')
    add('bounded_resources', bool(containers) and all(
        all(k in c.get('resources', {}).get(mode, {}) for k in ('cpu', 'memory', 'ephemeral-storage'))
        for c in containers for mode in ('requests', 'limits')), 'CPU, memory and ephemeral-storage bounds required.')
    labels = namespace.get('metadata', {}).get('labels', {})
    add('namespace_psa', labels.get('pod-security.kubernetes.io/enforce') == 'restricted',
        'The exempt system namespace still needs Restricted Pod Security Admission.')
    matching = []
    labels = deployment.get('spec', {}).get('template', {}).get('metadata', {}).get('labels', {})
    for policy in policies.get('items', []):
        selector = policy.get('spec', {}).get('podSelector', {})
        # Expression selectors need operator review rather than inferred matching.
        if selector.get('matchExpressions'):
            continue
        if all(labels.get(k) == v for k, v in selector.get('matchLabels', {}).items()):
            matching.append(policy)
    add('network_policy_selected', any(set(p.get('spec', {}).get('policyTypes', [])) == {'Ingress', 'Egress'} for p in matching),
        'Selection only; reachability and CNI enforcement require active isolated tests.')
    hooks = webhook.get('webhooks', [])
    add('fail_closed_webhooks', bool(hooks) and all(h.get('failurePolicy') == 'Fail' and
        bool(h.get('clientConfig', {}).get('caBundle')) and 13 <= h.get('timeoutSeconds', 10) <= 30
        for h in hooks), 'Fail policy, CA and timeout exceeding the 12s handler budget.')
    add('least_privilege_reader', role.get('rules') == [
        {'apiGroups': ['modelgate.dev'], 'resources': ['modelgatepolicies'], 'verbs': ['list']}],
        'Webhook identity may only list ModelGatePolicy objects.')
    ready_nodes = [n for n in nodes.get('items', []) if any(
        c.get('type') == 'Ready' and c.get('status') == 'True' for c in n.get('status', {}).get('conditions', []))]
    checks.append({'check': 'failure_domains', 'status': 'UNVERIFIED',
                   'detail': f'{len(ready_nodes)} Ready Kubernetes nodes; node count does not establish independent physical hosts.'})
    for name in ('cni_enforcement', 'etcd_encryption_and_restore', 'control_plane_cis_review',
                 'certificate_rotation_and_expiry', 'image_distribution_scan', 'production_slo'):
        checks.append({'check': name, 'status': 'UNVERIFIED', 'detail': 'Requires separate infrastructure or integration evidence.'})
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--namespace', default='modelgate-system')
    parser.add_argument('--release', default='modelgate')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    def get(resource, name=None, namespaced=False):
        command = ['kubectl', '--context', args.context, '--request-timeout=10s']
        if namespaced:
            command += ['--namespace', args.namespace]
        command += ['get', resource] + ([name] if name else []) + ['-o', 'json']
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        if result.returncode:
            # Do not persist potentially sensitive server error text.
            raise RuntimeError('Read-only query failed for ' + resource)
        return json.loads(result.stdout)

    checks = assess(get('namespace', args.namespace),
                    get('deployment', args.release + '-webhook', True),
                    get('networkpolicy', namespaced=True),
                    get('validatingwebhookconfiguration', args.release),
                    get('clusterrole', args.release + '-webhook'), get('nodes'))
    report = {'schema_version': 1, 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'context': args.context, 'read_only': True, 'secrets_read': False,
              'checks': checks, 'status': 'FAIL' if any(c['status'] == 'FAIL' for c in checks) else 'PASS_WITH_UNVERIFIED_GATES'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite a previous audit/evidence receipt.
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
    print(json.dumps(report, indent=2))
    return 1 if report['status'] == 'FAIL' else 0


if __name__ == '__main__':
    raise SystemExit(main())
