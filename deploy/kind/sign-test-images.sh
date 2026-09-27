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
# Images pushed here expire after the given TTL. CI defaults to a longer TTL
# than the smoke's job timeout so a slow build/deploy/sign phase cannot race
# expiry before the admission assertions run.
set -euo pipefail

RAND=$(date +%s)
IMAGE_TTL="${IMAGE_TTL:-1h}"
SIGNED_IMAGE="ttl.sh/modelgate-kind-signed-${RAND}:${IMAGE_TTL}"
UNSIGNED_IMAGE="ttl.sh/modelgate-kind-unsigned-${RAND}:${IMAGE_TTL}"
KEY_DIR=$(mktemp -d)
IMAGE_DIR=$(mktemp -d)
trap 'rm -rf "$KEY_DIR" "$IMAGE_DIR"' EXIT

retry() {
  local attempt
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" == 3 ]]; then
      return 1
    fi
    echo "retrying after failed attempt $attempt: $*" >&2
    sleep $((attempt * 5))
  done
}

echo "==> Tagging and pushing $SIGNED_IMAGE and $UNSIGNED_IMAGE" >&2
printf 'signed image %s\n' "$RAND" > "$IMAGE_DIR/signed.txt"
printf 'unsigned image %s\n' "$RAND" > "$IMAGE_DIR/unsigned.txt"
cat > "$IMAGE_DIR/Dockerfile.signed" <<'EOF'
FROM scratch
COPY signed.txt /modelgate-smoke-marker
EOF
cat > "$IMAGE_DIR/Dockerfile.unsigned" <<'EOF'
FROM scratch
COPY unsigned.txt /modelgate-smoke-marker
EOF
docker build --provenance=false -t "$SIGNED_IMAGE" -f "$IMAGE_DIR/Dockerfile.signed" "$IMAGE_DIR" >/dev/null
docker build --provenance=false -t "$UNSIGNED_IMAGE" -f "$IMAGE_DIR/Dockerfile.unsigned" "$IMAGE_DIR" >/dev/null
retry docker push "$SIGNED_IMAGE" >/dev/null
retry docker push "$UNSIGNED_IMAGE" >/dev/null

echo "==> Generating a cosign keypair and signing only $SIGNED_IMAGE" >&2
(
  cd "$KEY_DIR"
  export COSIGN_PASSWORD=""
  cosign generate-key-pair >/dev/null 2>&1
  retry cosign sign --key cosign.key --tlog-upload=false --yes "$SIGNED_IMAGE" >/dev/null 2>&1
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
