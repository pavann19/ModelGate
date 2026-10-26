# Real admission performance and failure evaluation

This experiment measures the implemented Kubernetes admission path: a real API-server dry-run,
direct namespace-policy lookup, controlled HTTPS registry downloads, and local pinned cosign
cryptography inside the hardened webhook container. It does not use the historical benchmark's
always-successful image verifier.

Use a **new disposable cluster only**. The experiment intentionally rotates its own namespace key
and scales the webhook to zero. `failurePolicy: Fail` remains enabled throughout. Never run it on
a cluster serving real workloads. Existing evaluation namespaces and evidence directories are refused.

```sh
kind create cluster --name modelgate-platform --image kindest/node:v1.31.0
CLUSTER=modelgate-platform python3 deploy/kind/private-registry-smoke.py
python3 deploy/kind/platform-eval.py \
  --context kind-modelgate-platform \
  --confirm-disposable-cluster kind-modelgate-platform \
  --bootstrap artifacts/private-kind/fixture-bootstrap.txt \
  --output artifacts/platform-eval
kind delete cluster --name modelgate-platform
```

Prerequisites match [kind integration](KIND_DEMO.md), plus Go 1.27.3 to build `cmd/admission-eval`.
Windows users can select an installed MSYS bash using `BASH_BIN` and put its openssl/envsubst on
PATH. `MODELGATE_EVIDENCE_DIR` redirects the smoke's bootstrap/evidence location; pass that same
bootstrap file to this runner. Generated evidence and binaries stay out of Git and Docker contexts.

The runner builds a Go client using the existing Kubernetes libraries, with explicit kubeconfig
context and server-side `dryRun=All`. Every measured request goes through the actual API server.
It disables client retries and sets high client token-bucket limits, so client throttling and
subprocess startup do not become the reported webhook capacity. Each request has a 20-second
client deadline; production handler/verifier deadlines remain unchanged. Workload Pods are never
persisted. This is an operator tool; its kubeconfig needs namespace/policy and deployment privileges.

## Experiment contract

| Phase | Workload and required behavior |
| --- | --- |
| Signed load | 100 requests each at 1, 4, 8 and 16 closed-loop workers; valid signatures allowed or explicit capacity rejection under contention; no hidden transport failures |
| Unsigned image | 100 requests; explicit policy denial required, not an API outage |
| Bounded saturation | 32 slow-registry requests, 16 workers; capacity rejection must be observed; other requests must be denied, never allowed |
| Key rotation | Replace only the experiment namespace's trusted key; 20 previously valid signatures must be denied without restarting the webhook |
| Key restoration | Restore trust; 20 valid signatures admitted |
| Webhook outage | Scale to zero and wait for Pod deletion; 20 API requests must fail through webhook transport, never succeed |
| Recovery | Restore the original replica count, wait for rollout, retain every recovery probe and its result, then admit 20 valid signatures |

Five sequential warmup requests precede each load phase and the unsigned phase. They are checked
but excluded from measured quantiles. Failure phases have no warmup. `summary.json` records
source hashes, commit/dirty state, Go and Kubernetes versions, container resource limits, Docker
CPU/memory and recovery duration. Each phase writes every sample and its classified outcome.
Files use exclusive creation: a new run cannot overwrite old measurements. The runner restores
the key and replica count in `finally`, removes only its created namespace, and records restoration
errors separately. Preserve failed runs as well as successful ones.

Reported latency is client-observed API admission time, including networking/API processing,
policy reads, registry requests and verification. It is not isolated handler CPU time. Quantiles
use nearest rank; 100 samples provide a coarse p99. Reports include both all-request and
per-outcome quantiles. Successful admission throughput is separate from total completion rate:
fast rejections must not be presented as successful throughput.

The workload is closed-loop, single-node kind with a controlled private TLS registry and minimal
OCI fixtures. It does not establish production scale, an SLO, workload-image execution or a
performance improvement over a baseline. No verification cache or insecure fallback is added.
The fixture process expires after 15 minutes; rerun smoke setup if it has expired.

## Automation

The existing CI kind job runs the same experiment after its unchanged smoke assertions and
uploads raw JSON/logs. Timing values have no pass/fail speed threshold; phase outcome and
restoration requirements remain strict. This experiment is separate from the historical
`bench/results/admission_latency.json`. Execution of the extended CI job must be verified after
publication; a local run is not a GitHub Actions result.

Measured results and their exact environment are recorded in [the case study](CASE_STUDY.md).
