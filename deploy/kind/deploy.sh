#!/usr/bin/env bash
# Deploys ModelGate to a running kind cluster: generates a self-signed CA
# and server cert for the webhook, applies the namespace/RBAC/CRD/Deployment/
# Service, and installs the ValidatingWebhookConfiguration with the real CA
# bundle injected. Assumes the modelgate-webhook:kind image has already been
# built (`docker build -t modelgate-webhook:kind .`) and loaded into the
# cluster (`kind load docker-image modelgate-webhook:kind --name <cluster>`).
#
# This script is what deploy/manifests/validatingwebhookconfiguration.yaml's
# header comment refers to as "how the certs and CA bundle are generated and
# injected"; it is exercised by deploy/kind/smoke.sh in CI and can also be run
# manually against a local kind cluster.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/deploy/kind/certs"
KUBE_REPO_ROOT="$REPO_ROOT"
KUBE_CERT_DIR="$CERT_DIR"
if command -v cygpath >/dev/null 2>&1; then
  KUBE_REPO_ROOT="$(cygpath -w "$REPO_ROOT")"
  KUBE_CERT_DIR="$(cygpath -w "$CERT_DIR")"
fi
SVC=modelgate-webhook
NS=modelgate-system

echo "==> Generating self-signed CA and server cert for $SVC.$NS.svc"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"
export MSYS_NO_PATHCONV=1 # harmless on non-Windows, avoids git-bash path mangling of -subj values

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=modelgate-ca" >/dev/null 2>&1

cat > san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SVC}.${NS}.svc
DNS.2 = ${SVC}.${NS}.svc.cluster.local
DNS.3 = ${SVC}
EOF

openssl genrsa -out tls.key 2048 >/dev/null 2>&1
openssl req -new -key tls.key -out tls.csr -subj "/CN=${SVC}.${NS}.svc" -config san.cnf >/dev/null 2>&1
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 365 -extensions v3_req -extfile san.cnf >/dev/null 2>&1

echo "==> Applying namespace, RBAC, and the ModelGatePolicy CRD"
kubectl apply -f "$KUBE_REPO_ROOT/deploy/manifests/namespace.yaml"
kubectl apply -f "$KUBE_REPO_ROOT/deploy/manifests/rbac.yaml"
kubectl apply -f "$KUBE_REPO_ROOT/deploy/crd/modelgate.dev_modelgatepolicies.yaml"

echo "==> Creating the webhook's TLS secret"
kubectl create secret tls "${SVC}-certs" \
  --cert="$KUBE_CERT_DIR/tls.crt" --key="$KUBE_CERT_DIR/tls.key" \
  -n "$NS" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying the webhook"
kubectl apply -f "$KUBE_REPO_ROOT/deploy/manifests/deployment.yaml"
kubectl -n "$NS" rollout restart deployment/modelgate-webhook
kubectl -n "$NS" rollout status deployment/modelgate-webhook --timeout=90s

echo "==> Installing the ValidatingWebhookConfiguration with the real CA bundle"
CA_BUNDLE=$(base64 -w0 "$CERT_DIR/ca.crt" 2>/dev/null || base64 "$CERT_DIR/ca.crt" | tr -d '\n')
kubectl apply -f "$KUBE_REPO_ROOT/deploy/manifests/validatingwebhookconfiguration.yaml"
kubectl patch validatingwebhookconfiguration modelgate --type='json' \
  -p="[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\":\"$CA_BUNDLE\"}]"

echo "==> Done. Remember: you still need a ModelGatePolicy per namespace you test in"
echo "    (see docs/DECISIONS.md's M1 fail-closed-on-no-policy behavior), and a real"
echo "    signed/unsigned image pair reachable from inside the cluster to exercise"
echo "    cosign verification end to end (a local-only registry is NOT reachable from"
echo "    pod network without extra kind network wiring -- ttl.sh or another public"
echo "    registry is the simplest way to get a real signed/unsigned pair for this)."
