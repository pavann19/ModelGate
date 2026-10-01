# Helm Install Guide

This chart installs the ModelGate webhook Deployment, Service, RBAC, and
`ValidatingWebhookConfiguration`. It intentionally does not generate private keys. The operator must
provide a serving certificate and inject the matching CA bundle into the webhook configuration.

## Prerequisites

- A Kubernetes cluster with admission webhooks enabled.
- `kubectl` pointed at the target cluster.
- Helm 3.
- A webhook serving certificate whose DNS names include
  `modelgate-webhook.modelgate-system.svc`.
- A pushed webhook image tag that contains both `/webhook` and the `cosign` binary.

For a local kind cluster, use `deploy/kind/deploy.sh` instead. That path generates ephemeral TLS
material and is exercised by the `kind-smoke` CI job.

The chart is rendered in CI by the `helm-chart` job. That job runs `helm lint`, renders the chart
with a dummy CA bundle, and asserts that rendering fails when `tls.caBundle` is omitted.

## Install

Create the namespace and TLS secret:

```bash
kubectl create namespace modelgate-system
kubectl -n modelgate-system create secret tls modelgate-webhook-certs \
  --cert=tls.crt \
  --key=tls.key
```

Install the CRD:

```bash
kubectl apply -f deploy/crd/modelgate.dev_modelgatepolicies.yaml
```

Install or upgrade the chart with the CA that signed `tls.crt`:

```bash
CA_BUNDLE="$(base64 -w0 ca.crt)"

helm upgrade --install modelgate deploy/helm \
  --namespace modelgate-system \
  --set-string tls.caBundle="$CA_BUNDLE" \
  --set image.repository=ghcr.io/pavann19/modelgate \
  --set image.tag=<immutable-tag> \
  --set failurePolicy=Fail \
  --set timeoutSeconds=15
```

`tls.caBundle` is required. Helm rendering fails without it so the chart cannot create a webhook
that looks installed but is unreachable by the API server.

## Create a Namespace Policy

Every protected namespace needs exactly one `ModelGatePolicy`. A namespace with no policy fails
closed.

```yaml
apiVersion: modelgate.dev/v1alpha1
kind: ModelGatePolicy
metadata:
  name: default-policy
  namespace: default
spec:
  cosignPublicKeyPEM: |
    -----BEGIN PUBLIC KEY-----
    <your-cosign-public-key>
    -----END PUBLIC KEY-----
  artifactAllowList:
    - id: /models/model.safetensors
      sha256: <64 lowercase hex characters>
```

## Verify

```bash
kubectl -n modelgate-system rollout status deployment/modelgate-webhook
kubectl get validatingwebhookconfiguration modelgate -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | wc -c
kubectl -n modelgate-system logs deployment/modelgate-webhook --since=10m | grep 'admission decision'
```

The deployment being Ready is not enough by itself. The CA bundle must be present in the
`ValidatingWebhookConfiguration`, and protected namespaces must have a `ModelGatePolicy`.

## Metrics

Enable a Prometheus Operator `ServiceMonitor` when the CRD exists:

```bash
helm upgrade --install modelgate deploy/helm \
  --namespace modelgate-system \
  --set-string tls.caBundle="$CA_BUNDLE" \
  --set image.repository=ghcr.io/pavann19/modelgate \
  --set image.tag=<immutable-tag> \
  --set metrics.serviceMonitor.enabled=true
```

Without Prometheus, port-forward the service:

```bash
kubectl -n modelgate-system port-forward service/modelgate-webhook 8080:8080
curl -s http://127.0.0.1:8080/metrics | grep '^modelgate_admission_'
```

