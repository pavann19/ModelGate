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
    `Handle()` — works end-to-end. It still uses a fake `ImageVerifier`/`ArtifactFetcher`, so it
    does not by itself prove real cosign verification — see "Real cosign verification" below for
    where that gap was closed.
  - A `kind` cluster (a full kubelet, real container runtime, a deployed webhook Docker image) is
    now also built and proven — see "`kind` cluster deployment" below. It found four real bugs
    envtest's fakes couldn't surface, including one that would have broken every real deployment
    (`cosign` was never actually copied into the Docker image).
- **Real cosign verification is now done.** `test/cosign/cosign_integration_test.go` runs the real
  `cosign` binary end to end: it starts a real local OCI registry (`registry:2` in Docker), pushes
  two genuinely different images (different digests, not just different tags of the same content),
  signs only one of them with a freshly generated cosign keypair, and calls
  `internal/webhook.CosignVerifier.VerifySignature` — the exact type wired into production, not a
  fake — against both. It passes: the signed image verifies, the unsigned one is rejected. This
  runs as its own CI job (`cosign-integration` in `.github/workflows/ci.yml`, using
  `sigstore/cosign-installer`). Locally it skips if `docker`/`cosign` aren't on `PATH`; when the `CI`
  environment variable is set it fails instead, so the job cannot pass without the test having run.
  (The run log for CI run 35348685402 shows it executing, 7.26s, rather than skipping.)
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
- **M3 is done**: see "M3 adversarial bypass suite" and "M3 pickle false-positive measurement" and
  "M3 admission latency benchmark" below for what was found, fixed, and measured.

## M3 adversarial bypass suite: two of the plan's assumptions were wrong, and were fixed, not just documented

The build plan's bypass list included: *"Image swap after admission ... confirm this is genuinely
out of scope for an admission webhook and document why ... verify this is actually true in your
test, don't assume it."* That verification found the opposite of what the plan assumed:

- **Image swap after admission is a real bypass, not out of scope.** `spec.containers[*].image`
  (and `spec.initContainers[*].image`) is a mutable field on an already-admitted Pod in Kubernetes
  — this is the whole mechanism behind `kubectl set image pod/x container=image`. `test/e2e`'s
  original `ValidatingWebhookConfiguration` only watched `operations: [CREATE]`, so an attacker
  could create a pod with a signed image, then `Update` it to an unsigned or pickle-laden image, and
  the webhook would never see the change. `test/e2e/bypass_probe_test.go`'s original probe
  confirmed this empirically against a real API server (`TestProbe_ImageSwapAfterAdmission`, since
  renamed to `TestBypass_ImageSwapAfterAdmission` after the fix below).
- **`kubectl debug`'s ephemeral-container addition is a separate, unmatched resource.** Adding an
  ephemeral container goes through the `pods/ephemeralcontainers` subresource, which is a distinct
  resource from `pods` in admission-review terms — a webhook rule matching `resources: ["pods"]`
  never sees it, regardless of which operations it lists. This was also empirically confirmed to
  succeed unblocked.

**The fix** (not a documented limitation, since both are closable without new architecture): both
`test/e2e/testdata/webhook-config.yaml` and `deploy/manifests/validatingwebhookconfiguration.yaml`
now declare two rule entries — `resources: ["pods"], operations: ["CREATE", "UPDATE"]` and
`resources: ["pods/ephemeralcontainers"], operations: ["UPDATE"]`. No `Handle()` logic changed:
it already re-validates the whole incoming pod spec fresh on every call (including ephemeral
containers, already covered since the MVP), so watching more operations was the entire fix.
`test/e2e/bypass_probe_test.go` (despite the filename, no longer just probes) now asserts both
vectors are blocked, plus a control test (`TestBypass_ImageSwapToSignedImageStillWorks`) proving a
legitimate update (still-signed image, unrelated mutable field change) is not collateral damage.

**Trade-off now taken on, worth naming:** watching `UPDATE` on `pods` means *every* pod update in
the cluster that touches a mutable field now round-trips through ModelGate, not just creates. This
is more admission-webhook load per unit of cluster activity than the MVP/M1/M2 milestones assumed,
and is exactly why M3's latency benchmark (below) matters — closing this gap is not free, and its
cost needed to be, and now is, measured rather than assumed away.

**What's still out of scope, correctly:** `initContainers` carrying an unsigned image was already
covered since the MVP (both `internal/webhook/handler_test.go` and, now, an end-to-end
`TestBypass_InitContainerUnsignedImage`); it needed no fix here, only end-to-end regression
coverage alongside the two real findings.

## M3 TOCTOU (artifact changes after admission): explicitly out of scope

A pod's `modelgate.dev/model-artifact` annotation names a file path; nothing stops that file's
contents from being overwritten after the pod is admitted (e.g. someone rewrites the mounted file,
or a shared volume is later repointed).

**Why this is out of scope for an admission webhook, and not something the fixes above should be
stretched to cover:** the two bypasses above (image swap, ephemeral containers) are closable by an
admission webhook because Kubernetes always routes the *relevant API mutation* — a `Pod` create or
update — through admission control, and the fix was simply watching the right operations/resources.
A file changing on disk *after* admission is not a Kubernetes API mutation at all; no admission rule
change can intercept it, because there is no API call to intercept. Actually defending against this
would require a fundamentally different mechanism — e.g. a runtime agent that periodically
re-verifies mounted artifacts, or mounting artifacts read-only from an immutable, content-addressed
store — which is a different architecture (closer to a runtime security agent than an admission
webhook) and out of scope for this project as scoped.

**What this means in practice:** ModelGate's guarantee is "the artifact matched its allow-listed
hash at the moment this pod was admitted," not "the artifact the running pod's process reads is
guaranteed to match at every later moment." That is a real, permanent limitation of an
admission-webhook-only architecture, stated plainly rather than glossed over.

## M3 pickle false-positive measurement: three threshold fixes failed in CI before the real fix

The MVP's `docs/DECISIONS.md` entry on pickle detection promised this measurement for M3 rather than
asserting a false-positive rate with no evidence. It was done via Go's native fuzzer
(`internal/pickle/fuzz_test.go`), seeded with byte-accurate framing for safetensors, ONNX
(protobuf), and GGUF files (fixed magic bytes/header structure, fuzzed payload), rather than a small
hand-curated corpus of downloaded real model files — this repo has no practical way to source and
store real multi-hundred-MB model weights, and fuzzing the actual byte *shapes* those formats use is
a more rigorous way to explore the false-positive space than a handful of static fixtures anyway.

**Round 1 (caught locally):** the original heuristic counted total occurrences of any byte in a
fixed 12-byte "known opcode" set anywhere in the buffer. A legitimate safetensors file could be
misclassified: `.` (STOP) was itself a counted hit, and a real safetensors JSON header routinely has
two or more `}` (one per tensor's own JSON object). Tensor data ending in `0x2E` (`.`) — a 1-in-256
per-file coincidence — combined with the header's `}` hits reached the 4-hit threshold by pure
chance. **Fix attempted:** raise the non-`PROTO`-prefixed ("fallback") path's threshold to 8. Looked
sufficient in a 30s local fuzz run and shipped.

**Round 2 (caught by CI, not locally — this is the point of running fuzzing continuously, not once):**
the *next* push's CI `fuzz-pickle` job failed within 11 seconds on a new input: `"XXXXX."` (five `X`
= `SHORT_BINUNICODE` opcode, repeated, plus `.`) reached the raised 8-hit bar purely through
*repetition* of one single opcode byte — the threshold counted occurrences, not distinct opcode
types, so five copies of the same byte counted as five separate "hits." **Fix attempted:** count
*distinct* opcode bytes seen instead of total occurrences (a real pickle stream is built from several
genuinely different opcodes in sequence; coincidental matches tend to repeat one byte). Verified
against both known failures, shipped.

**Round 3 (caught locally within seconds of extended fuzzing, before it could reach CI):** a fuzz run
found `"Xc)r\x95\x94."` — seven bytes, each one a *different* member of the tracked opcode set,
concatenated with no operand data between them. This is the moment the actual root cause became
clear: **the heuristic — "does this blob contain matching bytes anywhere, in any order, for any
reason" — is not a fixable threshold problem.** A coverage-guided fuzzer can always construct a
minimal "alphabet soup" input containing literally every tracked opcode byte as a deliberate,
isolated byte, defeating *any* distinct-count or occurrence-count bar no matter how high it's set,
because the check never required the bytes to form a coherent, ordered *stream* — only to be present
somewhere. Raising the bar a fourth time would have shipped a fourth bug; the actual fix had to
change what the check requires, not just how many hits it needs.

**The actual fix:** stop trying to detect pickle-ness from opcode *density* anywhere in the buffer,
and check the one signal that is genuinely unambiguous and position-anchored: pickle protocol 2+
streams — which is what every modern `pickle.dump()`/`torch.save()` call produces by default —
*always* begin with the `PROTO` opcode (`0x80`) followed by a valid protocol version byte (0-5), at
byte offset 0, full stop. `IsPickle` is now exactly `data[0] == 0x80 && data[1] <= 5`. No format
checked here (safetensors' 8-byte length prefix, ONNX's protobuf field tag, GGUF's `"GGUF"` magic)
can produce that specific two-byte prefix by coincidence, and — critically, unlike the byte-anywhere
heuristic — a fuzzer cannot "construct" a false match by placing a few chosen bytes somewhere in an
otherwise-arbitrary buffer, because the check only ever looks at position 0.

**Accepted trade-off, now much narrower and explicit:** protocol 0/1 pickles (no `PROTO` prefix) are
no longer detected at all. This is a real, named gap, not a hidden one — but protocol 0/1 is legacy;
no current Python tooling produces it by default, and it was never reliably caught by the old
heuristic either (three of the tracked "opcode" bytes were protocol-4-only and could never appear in
a real protocol-0/1 stream in the first place, so the old fallback path's real-world detection power
was already close to nothing — it just happened to also be a source of false positives).

**Verified, this time with a run long enough to mean something:** 47.6 million fuzz executions over
5 minutes (`go test ./internal/pickle/ -fuzz=FuzzIsPickle_RealFormatsNotFlagged -fuzztime=300s`) with
zero failures, plus all 4 committed regression seeds (one per round above) and all pre-existing
pickle/safetensors unit tests passing. CI runs a 30s fuzz pass on every push as its own job
(`fuzz-pickle`) — continuous, not a one-time check, which is exactly what caught round 2 before it
reached a human reading the diff.

**The honest meta-lesson, worth stating for its own sake:** the first "fix" was verified against 30
seconds of fuzzing and looked done. It wasn't — CI caught it in 11 seconds on the very next run.
"Green once" and "actually fixed" are not the same claim, and the gap between them here was closed
only by treating a passing fuzz run as a data point, not a proof, and continuing to fuzz harder
before trusting the result.

## M3 admission latency benchmark

`bench/admission_latency_test.go` measures real Pod-create round-trip latency through a real
kube-apiserver (envtest) and a real ModelGate webhook server, for the full check pipeline (host-
access checks, signature verification via a fake always-signed verifier, and CRD-backed policy
resolution via a static exempt resolver — isolating the pipeline's own cost from cosign's and the
API server's variance). Results are committed as raw, reproducible JSON output in
`bench/results/admission_latency.json`, following the same "committed run output, not a hand-typed
number" discipline as the other projects in this portfolio.

**Measured** (200 pods, single local envtest process, Windows/amd64 dev machine — see the "what
this does and doesn't measure" caveat below before treating these as production numbers):

| Percentile | Latency |
|---|---|
| p50 | 2.24 ms |
| p90 | 3.24 ms |
| p99 | 6.16 ms |
| max | 12.13 ms |
| mean | 2.59 ms |

(Run-to-run variance on a shared dev machine is real and expected — a repeat run measured p50
2.19ms/p99 3.31ms; both are committed as what they are, single-machine measurements with normal
noise, not a single blessed number.) Effective throughput in this run: ~23,000 admissions/minute,
entirely bound by how fast a single
local Go test process can issue sequential `Create` calls against a single local `kube-apiserver`
process — not a measurement of a production cluster's ceiling.

**What this does and doesn't measure, stated plainly (this is the most important caveat in this
section):** there is no `kind`/kubelet cluster deployment in this repo (see the MVP section above
for why that was deferred), so this benchmark cannot and does not measure scheduling latency,
kubelet-side effects, a real multi-node control plane's API server load characteristics, or network
latency to a real (non-local) webhook Service. It measures exactly one thing precisely: the
wire-level cost of ModelGate's own admission review round trip against a real (if single-process)
Kubernetes API server. That is a real, useful, and previously unmeasured number — but it is a
component latency, not a cluster-scale benchmark, and should not be quoted as one.

**Why 200 pods, sequential, not concurrent:** the M3 plan asks for "a histogram of webhook response
time under N pods/minute." A single local envtest kube-apiserver process is not a realistic stand-in
for concurrent multi-client load (its own single-process bottlenecks would dominate the measurement
long before ModelGate's own logic would), so this benchmark measures sequential round-trip latency
rather than manufacturing a concurrency number that would mostly reflect envtest's, not ModelGate's,
limits. A concurrent, multi-client throughput ceiling is a `kind`/real-cluster question, tracked
alongside the deferred `kind` deployment.

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

## Skipping cosign's transparency-log (Rekor) check, deliberately

`CosignVerifier.VerifySignature` always passes `--insecure-ignore-tlog=true` to `cosign verify`.

**Why:** cosign's default behavior checks a signature against a transparency log (Rekor) in
addition to the public key, mainly to detect key compromise for *keyless* (Fulcio-based) signing.
ModelGate's trust anchor is the pinned public key itself, per the build plan's own stated MVP scope
("start with one hardcoded key; a real trust policy comes later") — Rekor adds little for a
statically pinned key an operator already controls. Requiring a reachable Rekor instance (public
sigstore or self-hosted) on *every single pod admission* would add a new external network
dependency to the hot admission path, and a new availability failure mode layered on top of the one
already measured in M2 (see the fail-open/fail-closed section above) — a real, live-only-network
requirement traded for tamper-evidence value that mostly doesn't apply to this trust model.

**Revisit if:** a future milestone adds keyless/Fulcio signing support, where Rekor becomes the
primary way to detect a compromised signing identity rather than an optional extra layer on top of
an already-pinned key.

## Pickle detection is opcode-based, not extension-based

`internal/pickle` checks for the pickle protocol's own `PROTO` opcode at a fixed position, rather
than trusting a `.pkl`/`.pt` file extension.

**Why:** an attacker controls the annotation/filename; a `.safetensors`-named file could contain a
pickle payload, and a legitimately-named `.pt` file is frequently a zip archive of one or more
pickled tensors (PyTorch's default save format), not a raw pickle stream. `IsPyTorchPickle` checks
both the raw-opcode case and the zip-with-`data.pkl`-entry case.

**Resolved in M3, not just documented — and not on the first, second, or third attempt.** The
original heuristic scanned for opcode *density* anywhere in the buffer; fuzzing against byte-
accurate safetensors/ONNX/GGUF framing broke three successive threshold-based fixes in a row before
landing on the actual robust design: checking for the `PROTO` opcode at a fixed, unambiguous
position instead of counting byte matches anywhere. See "M3 pickle false-positive measurement" below
for the full sequence of what was tried, what CI caught, and why "anywhere in the buffer" checks are
inherently unfixable by raising a threshold.

## `kind` cluster deployment: done, and it found four real bugs envtest couldn't

A full `kind` cluster deployment (real kubelet, real container runtime, the actual Docker image,
real TLS, real RBAC) is now built and was proven live: `deploy/manifests/{namespace,rbac,deployment}.yaml`,
`deploy/kind/deploy.sh` (generates the CA/server cert, applies everything, injects the CA bundle),
and `deploy/kind/sign-test-images.sh` (pushes and signs a real image pair on `ttl.sh`, a free public
ephemeral registry, since a pod's network can't reach a bare local Docker container by `localhost` —
that resolves to the pod itself, not the host).

**Every fixture in `deploy/kind/fixtures/` was run against a real, live kind cluster**: a genuinely
`cosign`-signed image was admitted, actually scheduled, and actually ran to completion; a genuinely
unsigned image, a privileged container, `hostNetwork`, and a `hostPath` volume were all rejected —
each with the real error message a cluster operator would actually see, not a simulated one.

**This was worth doing, past what envtest alone proves, because it found four real bugs that a
fake `ImageVerifier` (used everywhere else, including `test/cosign`'s registry-only integration
test) could never surface:**

1. **The Dockerfile never actually included the `cosign` binary.** `docs/DECISIONS.md`'s own
   "shelling out to cosign" section had already stated the trade-off ("at the cost of requiring the
   `cosign` binary to be present in the webhook's container image") — but the `Dockerfile` was never
   updated to actually do it. The documented requirement and the actual image had silently drifted
   apart; every real image signature check would have failed in production with "executable file
   not found" until this deployment attempt surfaced it. Fixed by copying the binary from the
   official `ghcr.io/sigstore/cosign/cosign` image into the final distroless stage.
2. **A cluster-wide `ValidatingWebhookConfiguration` with no `namespaceSelector` would have
   deadlocked the cluster's own control plane.** M1's "no `ModelGatePolicy` means deny" default
   applies to every namespace equally, including `kube-system` — installing the webhook without
   excluding it would have denied CoreDNS's and kube-proxy's own pod updates the moment it was
   installed. Fixed by adding a `namespaceSelector` excluding `kube-system` and the webhook's own
   namespace (`modelgate-system`) — a deliberate, minimal safety net, not a general policy
   exemption (M1's per-namespace `exempt` flag still exists and is still audited/logged for actual
   policy decisions; this is purely "don't let the webhook brick the cluster it's installed on").
3. **RBAC**: the webhook's `ServiceAccount` needs a `ClusterRole` granting `get`/`list`/`watch` on
   `modelgatepolicies.modelgate.dev` across all namespaces, since `internal/policy.Resolver` looks
   up whichever namespace a pod happens to be in. Not needed in unit tests (fake `client.Reader`) or
   envtest (a superuser `kubeconfig` by default) — only surfaced once running as an actual
   `ServiceAccount` with actual RBAC enforcement.
4. **`timeoutSeconds: 5` was too short once a real network call was involved.** The first live
   test with a real signed image timed out: `cosign verify`'s real TLS handshake + manifest +
   signature-layer fetch against a real registry took close to 8 seconds, not the near-instant
   response envtest's fake verifier always gives. Raised to 15s (empirically re-verified to work,
   not guessed) — a concrete, measured instance of the trade-off M2's fail-open/fail-closed section
   already named in the abstract: a slower check pipeline is now a real cost of `UPDATE`-watching
   and real cosign verification together, not just a theoretical one.

**This is now backed by a CI artifact, not only prose.** `deploy/kind/smoke.sh` runs the whole flow
(build the image, load it into kind, `deploy.sh`, push and sign a real image pair on ttl.sh, apply a
policy, then five fixtures) and exits non-zero unless the signed pod is admitted and the unsigned,
privileged, hostNetwork and hostPath pods are each denied *by the ModelGate webhook* (it checks the
denial message names the webhook and the specific reason, so an unrelated API error cannot pass).
The `kind-smoke` job in `.github/workflows/ci.yml` runs it on a fresh kind cluster on every push
and uploads the full output as the `kind-smoke-output` artifact. It passed on its first CI run
(run 35357672956); the artifact shows all six `SMOKE PASS` lines.

**Trade-offs of that job, stated plainly:** it pushes two throwaway images to `ttl.sh`, a free public
registry, on every run, so it depends on that service being up and on outbound network access, and it
is the slowest job (about 2.5 minutes). The earlier version of this section argued against CI for
exactly those reasons; running it anyway was judged better than leaving the flagship deployment
claim without a repeatable check. If ttl.sh flakiness becomes a problem, the alternative is an
in-cluster registry with TLS, which is more setup.

## Deferred (explicitly out of scope so far, tracked for future work)

- A reconciling controller for `ModelGatePolicy` (e.g. validating `cosignPublicKeyPEM` is
  well-formed PEM at creation time via a `Status` condition, rather than only at admission time) —
  not built. The webhook reads `Spec` directly on every request; `Status` is defined but unused.
  This is a reasonable follow-up, not a gap in the M1 plan, which only calls for CRD CRUD and
  namespace-based selection, both of which are done and tested.
- TOCTOU (artifact changes after admission) is not "deferred" — see its own section above; it is a
  permanent, architectural scope limit of an admission-webhook-only design, not a future task.
