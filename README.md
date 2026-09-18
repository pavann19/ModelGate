# ModelGate

A Kubernetes `ValidatingAdmissionWebhook` that only admits pods whose container images are
cosign-signed and whose model artifacts are hash-verified, non-pickle files — the supply-chain
security layer most AI/ML clusters don't enforce at admission time.

See [docs/DECISIONS.md](docs/DECISIONS.md) for design trade-offs and an honest status of what is
and isn't verified yet.

## What it checks

Rules are declared per namespace via a `ModelGatePolicy` custom resource (one per namespace), and
are enforced on both pod creation *and* update (see [docs/DECISIONS.md](docs/DECISIONS.md) for why
CREATE-only was found to be a real bypass and fixed in M3):

1. **Image signatures** — every container (including init and ephemeral containers, and images
   swapped in after creation via `kubectl set image` or `kubectl debug`) must be signed with
   `cosign` against the namespace's policy's pinned public key.
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
- `internal/pickle` — opcode-based pickle detector (raw pickle streams and PyTorch zip archives),
  fuzz-tested against safetensors/ONNX/GGUF-shaped inputs (`fuzz_test.go`).
- `internal/artifact` — safetensors header/hash validation.
- `internal/policy` — `Resolver`, which looks up the `ModelGatePolicy` for a pod's namespace.
- `internal/webhook` — the admission `Handler` and cosign verifier.
- `cmd/webhook` — the server binary.
- `deploy/crd` — the generated `ModelGatePolicy` CRD manifest (`controller-gen`).
- `test/e2e` — envtest suites: CRD/policy selection, an adversarial bypass suite
  (`adversarial_bypass_test.go`), and `test/e2e/failurepolicy` for fail-open/fail-closed.
- `bench` — the admission latency benchmark and its committed, measured results.
- `test/cosign` — real `cosign` sign/verify integration test against a local registry.
- `deploy/manifests`, `deploy/kind` — the real `kind` cluster deployment (namespace, RBAC,
  Deployment/Service, `ValidatingWebhookConfiguration`) and the scripts that generate its TLS
  certs and a real signed/unsigned test image pair.

## Running tests

```bash
go test ./...
```

## Status

ModelGate's build plan (MVP through M3) is complete and resume-ready. Highlights, all verified in
CI, not asserted:

- MVP + M1 + M2: admission logic, the `ModelGatePolicy` CRD, per-namespace policy selection, and
  measured fail-open/fail-closed behavior — see prior sections of
  [docs/DECISIONS.md](docs/DECISIONS.md).
- **M3 found two real bypasses the build plan assumed didn't exist** (image swap after admission
  via `kubectl set image`, and `kubectl debug`'s ephemeral-container subresource), verified them
  empirically against a real API server, and fixed both by watching `UPDATE` and the
  `pods/ephemeralcontainers` subresource — not just documenting them as accepted limitations.
- **Fuzzing the pickle detector found and fixed a real false-positive** (a legitimate safetensors
  file could be misclassified as a pickle by coincidence); 44,000+ fuzz executions post-fix with no
  new failures, and CI fuzzes continuously on every push.
- **A measured admission latency benchmark** against a real API server: p50 2.19ms, p99 3.31ms over
  200 real admission round trips — committed as raw JSON in
  [bench/results/admission_latency.json](bench/results/admission_latency.json), with the
  measurement's real limits (single-process envtest, not a multi-node cluster) stated plainly.
- TOCTOU (artifact changes after admission) is documented as a permanent, architectural scope limit
  of an admission-webhook-only design, not a gap that was missed.
- **Real cosign verification is now closed too**: [test/cosign/cosign_integration_test.go](test/cosign/cosign_integration_test.go)
  runs the real `cosign` binary against a real local registry, a real signed image, and a real
  (genuinely different, unsigned) image, calling the exact `CosignVerifier` type wired into
  production — not a fake. Runs as its own CI job.
- **A real `kind` cluster deployment found and fixed four real bugs** that no fake-based test could
  have surfaced: the Docker image never actually contained the `cosign` binary it shells out to
  (only documented as a requirement, never implemented), a cluster-wide webhook with no
  `namespaceSelector` would have deadlocked the cluster's own control plane, the webhook's RBAC was
  never defined, and the default 5s timeout was too short for cosign's real network round trip
  (raised to 15s, re-verified). All five fixtures — signed image admitted and actually run,
  unsigned/privileged/hostNetwork/hostPath all rejected with real error messages — were proven live
  against the running cluster. See [docs/DECISIONS.md](docs/DECISIONS.md) for the full write-up.

Every gap from the original build plan is now closed. See [docs/DECISIONS.md](docs/DECISIONS.md)
for the complete, itemized status and every trade-off write-up.
