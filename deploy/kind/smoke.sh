#!/usr/bin/env bash
# End-to-end smoke test against a running kind cluster (current kubectl
# context). Builds the webhook image, loads it into kind, deploys it with
# deploy.sh, pushes and signs a real image pair, then asserts on what the
# LIVE webhook actually does:
#
#   - a pod using the signed image is admitted
#   - a pod using the unsigned image is denied by the webhook, with cosign's
#     real "no signatures found" error
#   - privileged / hostNetwork / hostPath pods are denied by the webhook
#
# Every assertion checks that the denial came from the ModelGate webhook
# itself (not from some unrelated API error), and the script exits non-zero
# on the first failed assertion. CI runs it and uploads the full output as
# an artifact (see the kind-smoke job in .github/workflows/ci.yml).
#
# Prerequisites: docker, kind (with a cluster already created, named by
# $CLUSTER, default "modelgate"), kubectl, openssl, cosign, envsubst.
# Network access to ttl.sh is needed (see sign-test-images.sh for why).
set -euo pipefail

CLUSTER="${CLUSTER:-modelgate}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
pass() { echo "SMOKE PASS: $*"; }

echo "==> Building and loading the webhook image"
docker build -t modelgate-webhook:kind .
kind load docker-image modelgate-webhook:kind --name "$CLUSTER"

echo "==> Deploying ModelGate (deploy/kind/deploy.sh)"
bash deploy/kind/deploy.sh

echo "==> Pushing and signing a real image pair, creating the namespace policy"
SIGN_OUT="$(mktemp)"
bash deploy/kind/sign-test-images.sh > "$SIGN_OUT"
# The script prints `export ...` lines and then a ModelGatePolicy manifest.
eval "$(grep '^export ' "$SIGN_OUT")"
grep -v '^export ' "$SIGN_OUT" | kubectl apply -f -
echo "signed image:   $SIGNED_IMAGE"
echo "unsigned image: $UNSIGNED_IMAGE"

apply_fixture() { # name -> prints kubectl's combined output, returns its exit code
  envsubst < "deploy/kind/fixtures/$1.yaml" | kubectl apply -f - 2>&1
}

echo "==> Fixture: good-pod (signed image) must be ADMITTED"
if out="$(apply_fixture good-pod)"; then
  echo "$out"; pass "good-pod admitted"
else
  echo "$out"; fail "good-pod was rejected"
fi

expect_denied() { # fixture, substring the webhook's message must contain
  local name="$1" want="$2" out
  echo "==> Fixture: $name must be DENIED by the webhook (expecting: $want)"
  if out="$(apply_fixture "$name")"; then
    echo "$out"; fail "$name was admitted"
  fi
  echo "$out"
  grep -q 'admission webhook "validate-pods.modelgate.dev" denied the request' <<<"$out" \
    || fail "$name was rejected, but not by the ModelGate webhook"
  grep -q "$want" <<<"$out" || fail "$name was denied, but the message did not contain: $want"
  pass "$name denied by the webhook"
}

expect_denied bad-pod-unsigned    'no signatures found'
expect_denied bad-pod-privileged  'privileged container'
expect_denied bad-pod-hostnetwork 'hostNetwork is not permitted'
expect_denied bad-pod-hostpath    'hostPath volume'

echo "==> Control-plane sanity: kube-system pods still running with the webhook installed"
kubectl -n kube-system get pods
if kubectl -n kube-system get pods --no-headers | grep -vE 'Running|Completed'; then
  fail "some kube-system pods are not Running"
fi
pass "kube-system unaffected"

echo "SMOKE TEST COMPLETE: all assertions passed"
