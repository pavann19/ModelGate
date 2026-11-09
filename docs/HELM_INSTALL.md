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
- A reviewed webhook image digest containing `/webhook`; bounded-v1 verification uses Go crypto, with no Cosign runtime executable.
- An enforcing NetworkPolicy CNI, observed API-server source/destination CIDRs, registry endpoint CIDRs/ports and working cluster DNS selectors.

For a local kind cluster, use `deploy/kind/deploy.sh` instead. That path generates ephemeral TLS
material and is exercised by the `kind-smoke` CI job.

The chart is rendered in CI by the `helm-chart` job. That job runs `helm lint`, renders the chart
with a dummy CA bundle, and asserts that rendering fails when `tls.caBundle` is omitted.

## Install

Create the namespace and TLS secret:

```bash
kubectl create namespace modelgate-system
kubectl label namespace modelgate-system \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.31 \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
kubectl -n modelgate-system create secret tls modelgate-webhook-certs \
  --cert=tls.crt \
  --key=tls.key
```

Install the CRD:

```bash
kubectl apply -f deploy/crd/modelgate.dev_modelgatepolicies.yaml
```

Create an operator-reviewed registry destination Secret before installing:

```bash
kubectl -n modelgate-system create secret generic modelgate-registry-policy \
  --from-file=registry-policy.json=/secure/reviewed-registry-policy.json
```

See [registry security](REGISTRY_SECURITY.md) for the host/CIDR JSON, private CA and authentication contract.

Create a private `platform-values.yaml` with the actual control-plane and registry addresses.
The following documentation addresses are placeholders; never install them unchanged:

```yaml
networkPolicy:
  apiServerCIDRs: [192.0.2.10/32]
  apiServerPorts: [443, 6443]
  registryEndpoints: [{cidr: 203.0.113.10/32, port: 443}]
  # Optional; absent by default, so remote metrics scraping is blocked.
  metricsNamespaceSelector: {team: observability}
```

Account for control-plane traffic source NAT and API Service DNAT in the target CNI.
The DNS rule selects `k8s-app: kube-dns` pods in `kube-system`; NodeLocal DNS needs a
separately reviewed destination rule. Registry rules must include any approved token-service
endpoints from the registry policy. CIDRs must be canonical and limited to necessary endpoints;
the chart rejects universal `/0` access. Test actual allow/deny connectivity before promotion.

Install or upgrade the chart with the CA that signed `tls.crt`:

```bash
CA_BUNDLE="$(base64 -w0 ca.crt)"

helm upgrade --install modelgate deploy/helm \
  --namespace modelgate-system \
  -f platform-values.yaml \
  --set-string tls.caBundle="$CA_BUNDLE" \
  --set image.repository=ghcr.io/pavann19/modelgate \
  --set-string image.digest=sha256:<reviewed-64-character-digest> \
  --set failurePolicy=Fail \
  --set timeoutSeconds=15
```

`tls.caBundle` is required. Helm rendering fails without it so the chart cannot create a webhook
that looks installed but is unreachable by the API server.
Rendering also requires an immutable image digest and explicit network destinations. Schema
validation rejects fail-open policy, fewer than two replicas, invalid ports, and an admission
timeout shorter than the handler's 12-second work budget plus response margin. Only local
development may explicitly select `image.allowMutableTags=true` with `image.tag`, or
`networkPolicy.enabled=false`; either choice leaves the corresponding release gate unmet.

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
  -f platform-values.yaml \
  --set-string tls.caBundle="$CA_BUNDLE" \
  --set image.repository=ghcr.io/pavann19/modelgate \
  --set-string image.digest=sha256:<reviewed-64-character-digest> \
  --set metrics.serviceMonitor.enabled=true
```

Without Prometheus, port-forward the service:

```bash
kubectl -n modelgate-system port-forward service/modelgate-webhook 8080:8080
curl -s http://127.0.0.1:8080/metrics | grep '^modelgate_admission_'
```


## Operational boundary

Cluster policy writers are security administrators. Do not grant their rights to workload users.
The chart excludes its own namespace and kube-system; protect both from tenant workloads.
Use digest-pinned workload images and verify webhook image provenance before deployment.
Docker build/runtime base images are digest-pinned; Cosign is a pinned independent test oracle only.
Model files require a separately designed read-only mount; the chart does not configure one.
Metrics are unauthenticated and must stay behind the scoped network rule or a loopback port-forward.
NetworkPolicy existence is not enforcement evidence. Certificate rotation, physical failure domains
and recovery still require platform-specific validation. Readiness checks the local serving TLS
handshake and draining state; it deliberately does not depend on the registry or analysis model.
See [platform hardening](PLATFORM_HARDENING.md) for the threat model, migration and remaining gates.
