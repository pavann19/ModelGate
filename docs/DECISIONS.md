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
- **M2 is done**: `deploy/manifests/validatingwebhookconfiguration.yaml` exposes `failurePolicy`
  (`Fail` or `Ignore`) as the fail-closed/fail-open switch for when the webhook itself is
  unreachable, and both modes are measured for real in
  `test/e2e/failurepolicy/failure_policy_test.go`: each test boots a real envtest environment,
  starts a real ModelGate webhook server, creates a pod (proving the webhook is up), **kills the
  webhook mid-test** by canceling the manager's context and waiting for the TLS port to actually
  stop accepting connections, then creates a second pod. With `failurePolicy: Fail` the second pod
  is denied; with `failurePolicy: Ignore` it is admitted. Both pass in CI as their own job.

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

## Fail-open vs. fail-closed: `failurePolicy: Fail` is the default, and both modes are measured

`deploy/manifests/validatingwebhookconfiguration.yaml` ships with `failurePolicy: Fail`.

**What "the webhook is unreachable" actually means:** kube-apiserver calls the webhook's HTTPS
endpoint synchronously on every matching `Pod` create/update, with a timeout (`timeoutSeconds: 5`
here). "Unreachable" covers the webhook Deployment being scaled to zero, crash-looping, network-
partitioned from the API server, or simply too slow to answer within the timeout. `failurePolicy`
is kube-apiserver's own field — ModelGate doesn't implement this behavior itself, it only chooses
the value, so "implementing both modes" means proving the value actually does what it claims, not
writing failure-detection logic in the handler.

**The trade-off, stated plainly:**
- `Fail` (chosen default): if ModelGate is down, **every** pod create in the cluster is rejected
  until it comes back. This is secure by construction — an attacker (or a bug) taking down the
  webhook cannot use that outage to slip an unsigned image or a pickle artifact past admission —
  but it makes ModelGate itself a single point of failure for cluster scheduling. A bad rollout of
  the webhook, or an unrelated outage in whatever it depends on (registry reachability for cosign,
  in particular), can freeze all deployments cluster-wide.
- `Ignore`: if ModelGate is down, every pod is admitted as if no policy existed at all. The cluster
  stays available, but for the duration of the outage every check this webhook exists for —
  signature verification, pickle detection, host-access denial — is silently not happening. An
  attacker who can trigger or wait out a webhook outage (e.g. by exhausting its resources) gets a
  free pass for exactly that window.

**Why `Fail` is the default here:** ModelGate's stated purpose is a supply-chain security boundary,
not a best-effort advisory check. A security control that silently disables itself under load or
during an incident is a well-known real-world failure pattern (this is the same shape of trade-off
as, e.g., a WAF or an mTLS sidecar failing open) — the failure mode should be loud and blocking, not
quiet and permissive. `Fail` also composes with the M1 decision to fail closed when a namespace has
no policy: both defaults agree that "ModelGate can't confirm this is safe" should block, not admit.

**Why this is still a real, live trade-off, not a settled one:** a cluster operator who cannot
tolerate ModelGate becoming a scheduling-blocking dependency (e.g. no on-call coverage for it, or a
cluster where availability is contractually prioritized over this particular control) has a
legitimate reason to choose `Ignore` instead. That's exactly why it's a per-cluster manifest value
and a namespace-level `exempt` escape hatch exists (M1) rather than either being hardcoded — the
right answer depends on what the operator is actually optimizing for, and ModelGate's job is to
make that choice explicit and measured, not to make it for them.

**What is and isn't measured:** `test/e2e/failurepolicy` proves the *binary* behavior (denied vs.
admitted) for both settings against a real API server, by actually killing a running webhook
process mid-test. It does not yet measure graceful-degradation behavior under partial failure
(e.g. the webhook responding slowly but not down, right up against `timeoutSeconds`) — that would
be a natural extension of the M3 latency benchmark work, not part of M2's stated scope.

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

- Adversarial bypass suite (image swap post-admission, ephemeral container swap timing, artifact
  TOCTOU) and measured admission latency — M3.
- A reconciling controller for `ModelGatePolicy` (e.g. validating `cosignPublicKeyPEM` is
  well-formed PEM at creation time via a `Status` condition, rather than only at admission time) —
  not built. The webhook reads `Spec` directly on every request; `Status` is defined but unused.
  This is a reasonable follow-up, not a gap in the M1 plan, which only calls for CRD CRUD and
  namespace-based selection, both of which are done and tested.
