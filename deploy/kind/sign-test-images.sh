#!/usr/bin/env bash
# Prepares a real signed/unsigned image pair for a kind cluster smoke test,
# and prints the ModelGatePolicy YAML to apply for them.
#
# Why ttl.sh: a webhook pod running inside a kind cluster's pod network
# cannot reach a plain local Docker container by "localhost" (that resolves
# to the pod itself, not the host) without extra kind network wiring (see
# https://kind.sigs.k8s.io/docs/user/local-registry/). ttl.sh is a free,
# public, ephemeral, real-HTTPS OCI registry made for exactly this kind of
# throwaway testing -- no extra cluster networking needed, and it proves
# cosign verification over a real network path, not a loopback shortcut.
# Images pushed here expire after the given TTL (10m below); this is a
# manual verification step, not something wired into CI (see
# docs/DECISIONS.md's "kind cluster" section for why).
set -euo pipefail

RAND=$(date +%s)
SIGNED_IMAGE="ttl.sh/modelgate-kind-signed-${RAND}:10m"
UNSIGNED_IMAGE="ttl.sh/modelgate-kind-unsigned-${RAND}:10m"
KEY_DIR=$(mktemp -d)

echo "==> Tagging and pushing $SIGNED_IMAGE and $UNSIGNED_IMAGE" >&2
docker pull alpine:3.20 >/dev/null
docker pull alpine:3.19 >/dev/null # genuinely different digest, not just a different tag
docker tag alpine:3.20 "$SIGNED_IMAGE"
docker tag alpine:3.19 "$UNSIGNED_IMAGE"
docker push "$SIGNED_IMAGE" >/dev/null
docker push "$UNSIGNED_IMAGE" >/dev/null

echo "==> Generating a cosign keypair and signing only $SIGNED_IMAGE" >&2
(
  cd "$KEY_DIR"
  COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null 2>&1
  COSIGN_PASSWORD="" cosign sign --key cosign.key --tlog-upload=false --yes "$SIGNED_IMAGE" >/dev/null 2>&1
)

echo "==> Export these and use with deploy/kind/fixtures/*.yaml (envsubst):" >&2
echo "export SIGNED_IMAGE=$SIGNED_IMAGE"
echo "export UNSIGNED_IMAGE=$UNSIGNED_IMAGE"

echo "" >&2
echo "==> ModelGatePolicy to apply for the namespace you test in:" >&2
echo "apiVersion: modelgate.dev/v1alpha1"
echo "kind: ModelGatePolicy"
echo "metadata:"
echo "  name: default-policy"
echo "  namespace: default"
echo "spec:"
echo "  cosignPublicKeyPEM: |"
sed 's/^/    /' "$KEY_DIR/cosign.pub"
