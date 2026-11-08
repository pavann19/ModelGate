# Reproducible security demonstration

Validated locally on 4 November 2026: Windows amd64, Go 1.27.3, private Kubernetes 1.31.0 envtest API server/etcd, synthetic TLS OCI registry and generated P-256 keys. No existing cluster, Docker daemon or other project runtime was accessed. Selected [first-run samples](../evidence/admission-20261104/admission-performance.json) and [clean-source rerun samples](../evidence/admission-20261104/committed-admission-performance.json) are retained separately; see the [threat model](threat_model.md).

## What is checked

- Admission policy and bypass controls: missing/ambiguous policy, namespace mismatch, unsafe host access, image updates, init/ephemeral containers, explicit exemption semantics and typed-field ambiguity.
- Real image signatures and exact repository/digest/type binding: signed allows; unsigned, wrong-key, tampered and malformed inputs deny. Current native API test couples real policy reads, TLS registry and bounded-v1 production crypto. Separate envtest bypass tests use verifier mocks and are labeled accordingly.
- Fail/Ignore call-error matrix: timeout, refusal, malformed response, panic and injected HTTP 503. Each begins with a healthy observed call; Fail errors identify this webhook. HTTP 503 is an injected availability fault; separate transport tests actually saturate decoder slots and verify recovery.
- Bounded body/deadline/concurrency, registry parser/authentication ambiguity, redaction, panic recovery, key rotation and request-local reuse have regression tests.
- Threat/trust boundaries, deployment prerequisites, CI steps and measured admission overhead are documented.

Provenance verification and invalid/expired/missing attestation enforcement are **not checked**: they are unsupported. Missing/invalid image signatures are different cases. No keyless identity, issuer, transparency-log, expiry or revocation semantics exist. The scope is signature and admission enforcement, with broader supply-chain enforcement incomplete.

## Test prerequisites and commands

Use synthetic inputs and a disposable process environment. Core tests need no existing cluster:

```sh
go test ./internal/... ./cmd/... ./api/... ./test/deployment -p=1 -count=1 -timeout=120s
go vet ./internal/... ./cmd/... ./api/... ./test/...
python -B -m unittest discover -s agent -v
helm lint deploy/helm -f deploy/helm/hardening-test-values.yaml
python -B hack/test_helm_hardening.py -v
```

Install Kubernetes envtest **1.31.0** assets and set `KUBEBUILDER_ASSETS` to that installation. This starts private API-server/etcd processes; it does not use a current kubeconfig. The registry fixture uses an OS-assigned port on this host's private interface because production forbids loopback registries. It restricts peers to the fixture host's own IP and pins a synthetic TLS CA. If no suitable private interface exists it must fail/skip explicitly; never relax production destination checks.

```sh
go test ./test/e2e/... -v -p=1 -count=1 -timeout=180s
go test ./test/cosign -v -p=1 -count=1 -timeout=120s
mkdir -p artifacts/native-admission
MODELGATE_NATIVE_ADMISSION=1 MODELGATE_EVIDENCE_DIR=artifacts/native-admission \
  go test ./test/cosign -run '^TestNativeAdmissionTrustAndOverhead$' -v -p=1 -count=1 -timeout=120s
```

For independent detached interoperability, put **Cosign v3.1.4** on process-local PATH and set `MODELGATE_REQUIRE_COSIGN_ORACLE=1`; run `go test ./internal/webhook -run '^TestDetachedSignatureCosignInteroperability$' -v -count=1`. Absence is a hard error when this variable is set, otherwise an explicit skip. Production does not execute this tool. The registry suite produces actual signed objects; it does not accept a fake signed-name predicate.

Windows isolation used in the receipts:

```powershell
$goRoot = go env GOROOT
python hack/run-isolated-windows.py --output .tools/repro-core --timeout 180 --toolchain $goRoot -- go test ./internal/... ./cmd/... ./api/... ./test/deployment -p=1 -count=1 -timeout=120s
python hack/run-isolated-windows.py --output .tools/repro-native --timeout 180 --toolchain $goRoot --assets $env:KUBEBUILDER_ASSETS -- go test ./test/cosign -run '^TestNativeAdmissionTrustAndOverhead$' -v -p=1 -count=1 -timeout=120s
```

Choose new output directories. The runner assigns a suspended root to a kill-on-close Job Object before resuming it, bounds job memory/processes/time, replaces TEMP/KUBECONFIG, and records cleanup of only descendants. Windows envtest stop may warn about unsupported signals; receipts require zero remaining owned processes. This is fixture cleanup evidence, not production graceful-shutdown evidence. It intentionally disables CGO, so Windows race testing is not claimed.

Bounded fuzz reproduction (each target separately):

```sh
go test ./internal/webhook -run '^$' -fuzz '^FuzzRegistryJSONKeys$' -fuzztime=5s -parallel=1
go test ./internal/webhook -run '^$' -fuzz '^FuzzBearerChallenge$' -fuzztime=5s -parallel=1
go test ./internal/webhook -run '^$' -fuzz '^FuzzBoundedVerificationKey$' -fuzztime=5s -parallel=1
```

CI is configured in `.github/workflows/ci.yml` for units, envtest, native trust/overhead, mandatory independent oracle, bounded parser fuzz, Helm and separate Kind jobs. Workflow results must be checked for the exact pull request commit; local results do not establish hosted CI success. The distribution workflow scans the extracted shipped Go binary; a complete OS image scan remains a separate gate.

## Kubernetes deployment and operator checks

Read [Helm installation](../HELM_INSTALL.md), [registry destination security](../REGISTRY_SECURITY.md), [platform hardening](../PLATFORM_HARDENING.md) and [operations](../OPERATIONS.md). Supply a reviewed immutable image digest, nonempty CA bundle, TLS Secret, operator-owned registry Secret with explicit endpoint/CIDR/CA trust, and reviewed API/registry/DNS egress. Hardening test values are synthetic fixtures and must never be installed as production trust.

Keep `failurePolicy: Fail`; protect policy writes, exempt namespaces and webhook configuration with administrator RBAC. Exemptions intentionally skip every check. P-256-only trust is a breaking migration: do not automatically replace other key types or silently change keys. A successful image signature does not bind an optional webhook-local model file to workload runtime mounts.

Use a separately approved disposable cluster for install/upgrade/uninstall, TLS/key rotation, CNI enforcement, kubelet image pulls, readiness/drain and outage/recovery. The local process-only experiment did **not** run those full deployment operations. Raw Kind fixtures and rendered NetworkPolicies are not deployment or CNI proof. The historical local API-server demonstration used Kubernetes 1.31.0; no supported version range or managed-service support is claimed.

## Admission overhead

128 measured API dry-runs, concurrency 1, 32 observations per cell, 3 checked warmups per workload. Alternate baseline/enabled order on the same API server. Baseline intentionally excludes the fixture webhook with an object selector; enabled calls must increment an observed callback and perform real policy/registry/crypto work. Never copy this bypass selector into production. One/eight repeated containers are synthetic workloads, not an independent-image stress test.

| Workload | Mode | p50 ms | p90 ms | p95 ms | p99 ms | successful requests / active second |
|---|---|---:|---:|---:|---:|---:|
| 1 container | API baseline | 2.238 | 2.771 | 3.225 | 3.376 | 404.7 |
| 1 container | Admission enabled | 11.518 | 12.969 | 13.897 | 14.707 | 86.6 |
| 8 repeated containers | API baseline | 3.249 | 3.994 | 5.612 | 5.916 | 303.6 |
| 8 repeated containers | Admission enabled | 12.085 | 15.133 | 18.891 | 19.599 | 77.2 |

False allows: 0; false denies: 0 in this experiment. These are end-to-end API timings, not phase-specific webhook CPU or production throughput. Whole-command peak process-tree memory was 867,856,384 bytes, user CPU 7.703s and kernel CPU 9.265s, including compilation/setup and private control plane. The test uses request-local reuse, no cross-request trust cache. First observation follows correctness controls; **cold-launch, stress capacity, phase-specific resource and production SLO measurements remain unverified**. Historical load/soak evidence is retained separately, never relabeled as this candidate.
