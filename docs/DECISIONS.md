# Design decisions

## Status as of this commit

What is actually true right now, so nothing here is overclaimed:

- Core admission logic (`internal/webhook`, `internal/pickle`, `internal/artifact`, `internal/policy`)
  is implemented and covered by unit tests that run in CI (`go test ./...`), verified green.
- The MVP exit criterion — "a good pod is admitted, a bad pod (unsigned image, pickle artifact,
  privileged/host-access) is rejected, proven by `envtest` in CI, not by hand" — is now met:
  `test/e2e/envtest_test.go` boots a real `kube-apiserver` + `etcd` (via controller-runtime's
  `envtest`), installs a real `ValidatingWebhookConfiguration` with envtest-issued TLS certs, and
  submits real `Pod` objects through `kubectl`-equivalent client-go `Create` calls. All 7 cases
  (signed image admitted, unsigned image / privileged / hostNetwork / hostPath rejected, valid
  model artifact admitted, unlisted artifact rejected) pass against the real API server, and this
  now runs as its own job in CI (`.github/workflows/ci.yml`).
  - This proves the webhook *wiring* — TLS, admission review round-trip, rule routing to
    `Handle()` — works end-to-end. It still uses a fake `ImageVerifier`/`ArtifactFetcher` (see
    below), so it does not prove real cosign verification.
  - A `kind` cluster (a full kubelet, real container runtime, a deployed webhook Docker image)
    is a heavier, more realistic environment than envtest but was not built, since the plan's own
    exit criterion names envtest as the bar and envtest already exercises the actual
    `ValidatingWebhookConfiguration` object and real API-server admission path. Building the `kind`
    deployment (Dockerfile push into kind, Service, generated webhook TLS via cert-manager or a
    self-signed job, RBAC) remains a reasonable follow-up for extra realism, not a gap in what the
    plan requires.
- `cosign` signature verification shells out to the real `cosign` CLI (`internal/webhook/verifier.go`);
  it has not yet been exercised against a real signed/unsigned image pair — only against a fake
  `ImageVerifier` in both the unit tests and the envtest suite. Verifying it against a real
  `cosign sign`/`cosign verify` round trip (e.g. a local registry + generated keypair in CI) is
  the next gap to close before "rejects unsigned images" is a fully end-to-end verified claim.

## Shelling out to `cosign` instead of vendoring its Go packages

`CosignVerifier` runs `cosign verify --key <path> <image>` as a subprocess rather than importing
`sigs.k8s.io/cosign` as a library.

**Why:** cosign's Go module pulls in a very large dependency tree (sigstore, rekor, fulcio clients,
etc.) for functionality this project only needs in its simplest form (local public-key verification,
no keyless/Fulcio/transparency-log flow yet). Shelling out keeps the binary's own dependency graph
small and matches how cosign is normally invoked in CI/CD pipelines, at the cost of requiring the
`cosign` binary to be present in the webhook's container image.

**Revisit if:** a future milestone needs keyless verification or transparency-log inspection, where
the CLI's output parsing would become more fragile than using the library directly.

## Pickle detection is opcode-based, not extension-based

`internal/pickle` scans for actual pickle protocol opcodes (`PROTO`, `STOP`, `MEMOIZE`, etc.) rather
than trusting a `.pkl`/`.pt` file extension.

**Why:** an attacker controls the annotation/filename; a `.safetensors`-named file could contain a
pickle payload, and a legitimately-named `.pt` file is frequently a zip archive of one or more
pickled tensors (PyTorch's default save format), not a raw pickle stream. `IsPyTorchPickle` checks
both the raw-opcode case and the zip-with-`data.pkl`-entry case.

**Trade-off documented, not yet resolved:** the opcode heuristic (require `PROTO` + at least 4
distinct opcode hits) was chosen to avoid flagging arbitrary binary files as false positives, but it
has not been fuzzed against a large corpus of real-world safetensors/ONNX/GGUF files to measure a
false-positive rate. That measurement is scoped for M3 alongside the adversarial bypass suite.

## Policy is a static Go struct in the MVP, not yet a CRD

`internal/policy.Config` is loaded once from a JSON file at startup.

**Why:** M1 replaces this with a `ModelGatePolicy` CRD per namespace (see the build plan). Building
the CRD, its controller, and per-namespace exemption logic before the core admission rules were even
tested against fixtures would have meant debugging two new things at once. The MVP intentionally
defers that plumbing.

## Deferred (explicitly out of scope for MVP, tracked for later milestones)

- Fail-open vs. fail-closed behavior under webhook unavailability — M2.
- `ModelGatePolicy` CRD and per-namespace exemptions — M1.
- Adversarial bypass suite (image swap post-admission, ephemeral container swap timing, artifact
  TOCTOU) and measured admission latency — M3.
