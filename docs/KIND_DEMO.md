# kind Demo and Log Evidence

The real cluster demo is `deploy/kind/smoke.sh`. It builds the webhook image, loads it into a kind
cluster, deploys ModelGate with generated TLS, pushes a signed and unsigned image pair to `ttl.sh`,
creates a namespace `ModelGatePolicy`, and checks admission behavior through the Kubernetes API
server.

## Run Locally

Prerequisites:

- Docker
- kind
- kubectl
- openssl
- cosign
- envsubst
- outbound HTTPS access to `ttl.sh`

```bash
kind create cluster --name modelgate
CLUSTER=modelgate IMAGE_TTL=1h bash deploy/kind/smoke.sh 2>&1 | tee kind-smoke-output.$(date +%Y%m%d-%H%M%S).txt
```

On Windows, prefer MSYS Bash if `bash.exe` resolves to WSL and WSL has no installed distro:

```powershell
& 'C:\msys64\usr\bin\bash.exe' deploy/kind/smoke.sh 2>&1 |
  Tee-Object -FilePath kind-smoke-output.20261001-165153.txt
```

The latest local run summarized in [docs/VALIDATION.md](VALIDATION.md) passed on October 1, 2026.
It included:

```text
SMOKE PASS: good-pod admitted
SMOKE PASS: bad-pod-unsigned denied by the webhook
SMOKE PASS: bad-pod-privileged denied by the webhook
SMOKE PASS: bad-pod-hostnetwork denied by the webhook
SMOKE PASS: bad-pod-hostpath denied by the webhook
SMOKE PASS: kube-system unaffected
SMOKE TEST COMPLETE: all assertions passed
```

This is log evidence, not a video file. Raw local logs are intentionally ignored by Git; the same
script is also run by the public `kind-smoke` CI job, which uploads the full `kind-smoke-output`
artifact for each workflow run.

## What the Demo Proves

- A signed workload image is admitted.
- A genuinely different unsigned image is denied by the live webhook.
- Privileged containers, `hostNetwork`, and `hostPath` are denied by the live webhook.
- The webhook's namespace selector avoids breaking `kube-system`.

## Boundary

The kind demo proves Kubernetes admission behavior in a real local cluster. It does not prove AKS,
EKS, GKE, or managed production operation.

