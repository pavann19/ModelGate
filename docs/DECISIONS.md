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
- **M1 is done**: the three MVP checks now live behind a `ModelGatePolicy` CRD
  (`api/v1alpha1/modelgatepolicy_types.go`), one instance per namespace, with an explicit
  `exempt`/`exemptionReason` field. `internal/policy.Resolver` looks it up per admission request
  using a direct (uncached) API reader. Verified at two layers:
  - `internal/policy/resolver_test.go` — unit tests against the controller-runtime fake client:
    missing policy, config round-trip, per-namespace isolation, and the "multiple policies in one
    namespace picks the oldest" tie-break.
  - `test/e2e/envtest_test.go` — the same envtest environment from the MVP, now with the CRD
    installed (`CRDDirectoryPaths`) and three real `ModelGatePolicy` objects seeded across three
    namespaces (a normal policy, an exempt one, and a namespace with no policy at all), proving
    policy CRUD and namespace-based selection against a real API server, not just the fake client.

## `ModelGatePolicy` fails closed when a namespace has no policy

A namespace with no `ModelGatePolicy` object is **denied**, not silently admitted.

**Why:** the MVP's static config effectively "allowed everything not explicitly checked"; moving to
a CRD is the natural point to fix that into "no policy is an explicit gap, not an implicit allow."
An operator who forgets to create a policy for a new namespace should get loud, immediate denials,
not silent admission of unsigned/unverified workloads. This is a different question from the M2
fail-open/fail-closed trade-off (which is about the *webhook itself* being unreachable) — this is
about a *missing policy object* while the webhook is healthy and reachable.

**Trade-off:** this makes onboarding a new namespace a two-step operation (create the namespace,
then create its policy) with a hard failure window in between if a pod lands there first. That is
treated as acceptable for a security-boundary webhook; a convenience default policy could be added
later but would need to be a deliberate, documented decision, not an accidental fallback.

## Policy is read via the API server directly, not the manager's cache

`cmd/webhook/main.go` builds `policy.Resolver` from `mgr.GetAPIReader()`, not `mgr.GetClient()`.

**Why:** the manager's cached client is backed by an informer whose cache can lag the API server by
a sync interval. A `ModelGatePolicy` created immediately before a pod in the same namespace must
never be missed because the cache hadn't caught up yet — that would either wrongly deny (if treated
as "no policy") or, worse, silently fall through to a stale/absent config. The extra per-request API
server round trip is an acceptable cost for an admission webhook, which is already synchronous and
low-QPS relative to, say, a controller's reconcile loop.

## `ArtifactAllowList` is a list of structs in the CRD, not a map

The Go-side `policy.Config.ArtifactAllowList` is `map[string]string`, but the CRD's
`ModelGatePolicySpec.ArtifactAllowList` is `[]ArtifactAllowListEntry{ID, SHA256}`.

**Why:** Kubernetes CRD schemas (OpenAPI v3) don't have a first-class "map with a validated pattern
constraint on each value" idiom that plays well with `kubectl apply` diffing and `kubectl explain`;
a list of `{id, sha256}` structs is the conventional CRD shape (validated per-field, e.g. the
`sha256` field's regex pattern) and is converted to the internal map form in
`Resolver.Resolve` at read time.

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

## Deferred (explicitly out of scope so far, tracked for later milestones)

- Fail-open vs. fail-closed behavior under webhook unavailability — M2. (Note: this is distinct
  from the "no policy for this namespace" fail-closed behavior added in M1, above.)
- Adversarial bypass suite (image swap post-admission, ephemeral container swap timing, artifact
  TOCTOU) and measured admission latency — M3.
- A reconciling controller for `ModelGatePolicy` (e.g. validating `cosignPublicKeyPEM` is
  well-formed PEM at creation time via a `Status` condition, rather than only at admission time) —
  not built. The webhook reads `Spec` directly on every request; `Status` is defined but unused.
  This is a reasonable follow-up, not a gap in the M1 plan, which only calls for CRD CRUD and
  namespace-based selection, both of which are done and tested.
