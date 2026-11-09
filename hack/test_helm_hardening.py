"""Render actual Helm resources and assert security boundaries (no cluster access)."""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELM = os.environ.get('HELM_BIN', 'helm')
VALUES = ROOT / 'deploy/helm/hardening-test-values.yaml'


class HelmHardeningTests(unittest.TestCase):
    def render(self, *args, fixture=True):
        command = [HELM, 'template', 'modelgate', str(ROOT / 'deploy/helm'),
                   '--namespace', 'modelgate-system']
        if fixture:
            command += ['-f', str(VALUES)]
        return subprocess.run(command + list(args), capture_output=True, text=True, timeout=30)

    def test_secure_resources(self):
        # kubectl's local client parser is unnecessary: PyYAML is only needed
        # here for structural assertions and is installed explicitly in CI.
        import yaml
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = list(yaml.safe_load_all(result.stdout))
        deployment = next(d for d in docs if d['kind'] == 'Deployment')
        pod = deployment['spec']['template']['spec']
        container = pod['containers'][0]
        self.assertIn('@sha256:', container['image'])
        self.assertFalse(pod['enableServiceLinks'])
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertIn('ephemeral-storage', container['resources']['limits'])
        role = next(d for d in docs if d['kind'] == 'ClusterRole')
        self.assertEqual(role['rules'], [{'apiGroups': ['modelgate.dev'], 'resources': ['modelgatepolicies'], 'verbs': ['list']}])
        policy = next(d for d in docs if d['kind'] == 'NetworkPolicy')['spec']
        self.assertEqual(set(policy['policyTypes']), {'Ingress', 'Egress'})
        self.assertEqual(policy['ingress'], [{'from': [{'ipBlock': {'cidr': '192.0.2.10/32'}}],
                                             'ports': [{'protocol': 'TCP', 'port': 9443}]}])
        self.assertTrue(all(rule.get('to') and rule.get('ports') for rule in policy['egress']))
        self.assertNotIn('0.0.0.0/0', json.dumps(policy))
        webhook = next(d for d in docs if d['kind'] == 'ValidatingWebhookConfiguration')['webhooks'][0]
        self.assertEqual(webhook['failurePolicy'], 'Fail')
        self.assertEqual(webhook['timeoutSeconds'], 15)

    def test_reject_unsafe_overrides(self):
        for key, value in [('failurePolicy', 'Ignore'), ('replicaCount', '1'),
                           ('failurePolcy', 'Ignore'), ('tls.secreName', 'typo'),
                           ('timeoutSeconds', '5'), ('image.digest', 'invalid'),
                           ('networkPolicy.apiServerCIDRs[0]', '0.0.0.0/0'),
                           ('networkPolicy.apiServerCIDRs[0]', '0:0:0:0:0:0:0:0/0'),
                           ('networkPolicy.registryEndpoints[0].port', '0')]:
            with self.subTest(key=key):
                self.assertNotEqual(self.render('--set', key + '=' + value).returncode, 0)

    def test_required_inputs(self):
        missing_ca = self.render('--set-string', 'tls.caBundle=')
        self.assertNotEqual(missing_ca.returncode, 0)
        self.assertIn('tls.caBundle is required', missing_ca.stderr)
        for args in [[], ['--set-string', 'tls.caBundle=dGVzdA=='],
                     ['--set-string', 'tls.caBundle=dGVzdA==', '--set-string',
                      'image.digest=sha256:' + 'a' * 64]]:
            self.assertNotEqual(self.render(*args, fixture=False).returncode, 0)

    def test_metrics_are_scoped_and_explicit(self):
        import yaml
        result = self.render('--set', 'networkPolicy.metricsNamespaceSelector.team=observability')
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = next(d for d in yaml.safe_load_all(result.stdout) if d['kind'] == 'NetworkPolicy')
        rule = policy['spec']['ingress'][1]
        self.assertEqual(rule['from'], [{'namespaceSelector': {'matchLabels': {'team': 'observability'}}}])
        self.assertEqual(rule['ports'], [{'protocol': 'TCP', 'port': 8080}])

    def test_disabled_metrics_has_no_listener_or_ingress(self):
        import yaml
        result = self.render('--set', 'metrics.enabled=false', '--set',
                             'networkPolicy.metricsNamespaceSelector.team=observability')
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = list(yaml.safe_load_all(result.stdout))
        pod = next(d for d in docs if d['kind'] == 'Deployment')['spec']['template']['spec']
        self.assertIn('--metrics-bind-address=0', pod['containers'][0]['args'])
        policy = next(d for d in docs if d['kind'] == 'NetworkPolicy')['spec']
        self.assertEqual(len(policy['ingress']), 1)
        service = next(d for d in docs if d['kind'] == 'Service')
        self.assertEqual([p['name'] for p in service['spec']['ports']], ['webhook'])


if __name__ == '__main__':
    unittest.main()
