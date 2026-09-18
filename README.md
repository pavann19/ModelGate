# ModelGate

A Kubernetes `ValidatingAdmissionWebhook` that only admits pods whose container images are
cosign-signed and whose model artifacts are hash-verified, non-pickle files — the supply-chain
security layer most AI/ML clusters don't enforce at admission time.

See [docs/DECISIONS.md](docs/DECISIONS.md) for design trade-offs and an honest status of what is
and isn't verified yet.

## What it checks

Rules are declared per namespace via a `ModelGatePolicy` custom resource (one per namespace):

1. **Image signatures** — every container (including init and ephemeral containers) must be signed
   with `cosign` against the namespace's policy's pinned public key.
2. **Model artifacts** — a pod annotated `modelgate.dev/model-artifact: <id>` must reference an
   artifact on that namespace's policy's allow-list, and the artifact must be a well-formed
   `safetensors` file (not a pickle in disguise) whose SHA-256 matches the allow-listed hash.
3. **Host-level access** — `hostPID`, `hostNetwork`, `hostPath` volumes, and `privileged: true`
   containers are denied unconditionally (not configurable per policy).

A namespace with no `ModelGatePolicy` is **denied by default** (fail closed), and a policy can set
`exempt: true` (with a required `exemptionReason`) to explicitly bypass all checks for its
namespace — see [docs/DECISIONS.md](docs/DECISIONS.md) for why both are deliberate, not oversights.

## Layout

- `api/v1alpha1` — the `ModelGatePolicy` CRD types.
- `internal/pickle` — opcode-based pickle detector (raw pickle streams and PyTorch zip archives).
- `internal/artifact` — safetensors header/hash validation.
- `internal/policy` — `Resolver`, which looks up the `ModelGatePolicy` for a pod's namespace.
- `internal/webhook` — the admission `Handler` and cosign verifier.
- `cmd/webhook` — the server binary.
- `deploy/crd` — the generated `ModelGatePolicy` CRD manifest (`controller-gen`).

## Running tests

```bash
go test ./...
```

## Status

MVP, M1 (the `ModelGatePolicy` CRD), and M2 (fail-open/fail-closed) are done. Admission logic, unit
tests, resolver tests against a fake client, an `envtest` suite (real `kube-apiserver` + `etcd`,
the CRD installed, a real `ValidatingWebhookConfiguration`, real TLS, three namespaces with
different policies), and `failurePolicy: Fail` vs. `Ignore` tests that actually kill a running
webhook process mid-test all pass and run in CI — see
[test/e2e/envtest_test.go](test/e2e/envtest_test.go) and
[test/e2e/failurepolicy/failure_policy_test.go](test/e2e/failurepolicy/failure_policy_test.go).
Real cosign signature verification against an actual signed/unsigned image pair, and a
`kind`-cluster deployment for extra realism, are the next gaps — see
[docs/DECISIONS.md](docs/DECISIONS.md) for exactly what's verified so far, and for the fail-open
vs. fail-closed trade-off write-up.
