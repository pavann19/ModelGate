# Bounded registry connections and artifact memory

22 November 2026. Local synthetic validation; not production certification.

## Resulting behavior

Operator-file-loaded registry policies now reuse bounded HTTP/TLS transports. Each registry client allows 8 active connections per endpoint, 16 idle connections total, 8 idle connections per endpoint and a 30-second idle timeout. Every admission still reads namespace policy, retrieves image/signature content and verifies against that namespace's current key. This is connection reuse, not a cache of admission approvals, signing keys, signature results or bearer tokens. Changed exported rules cannot reuse the previously compiled rule's transport. DNS/CIDR/socket checks, TLS verification, redirect refusal and proxy restrictions remain; shutdown releases idle sockets.

Artifact reads allocate once from the checked descriptor size and reject growth, shrinkage and read errors. Production handlers permit one artifact fetch/validation at a time, independently of the eight general admission slots. Excess artifact work is denied with a capacity message and must be retried. This reduces memory pressure at the cost of artifact parallelism: eight 64 MiB reads alone equalled the configured 512 MiB pod limit before other work. Header framing validates JSON-object syntax without materializing a map of copied raw values. Hash/pickle checks remain; no tensor-schema validation or runtime model binding was added.

## Local allocation measurements

Identical synthetic fixtures on frozen baseline/candidate, Windows amd64, Go 1.27.4, GOMAXPROCS=2. Three repetitions of five measured iterations; table values are medians. These are allocated bytes per operation, not process RSS or a guaranteed container memory ceiling.

| Operation | Before bytes/op | After bytes/op | Reduction |
|---|---:|---:|---:|
| Read 64 MiB artifact | 165,348,396 | 67,117,948 | 59.4% |
| Check 8 MiB JSON-object header | 8,398,452 | 120 | 99.9986% |

Read allocations/op fell from 46 to 7; header allocations/op reported 8 to 0 at benchmark precision. The remaining 120 bytes/op is retained; this is not a zero-byte claim. No OOM/restart experiment was performed.

## Local admission measurements and regression

Frozen measurement baseline `3cc8747152c37ff4b9091ef0f87ac4b7b97c7774` plus a common native harness; measured candidate source hashes are in the [selected evidence](evidence/resource-improvements-20261122/summary.json). These pre-publication observations do not describe later commits automatically. API-server/registry fixture code can differ from the publication base; hosted CI validates the exact PR separately.

Private envtest Kubernetes 1.31.0 API server/etcd and synthetic TLS OCI registry; concurrency 1; sequential baseline/candidate/candidate/baseline runs. Each run alternates enabled/API-baseline order, checks 3 warmups/workload and retains 32 observations/cell. Nearest-rank quantiles below pool 64 observations/workload/implementation. Total: 512 API timings, including 256 intentionally unenforced API-baseline controls; every enabled timing checks an observed webhook callback and real policy/registry/crypto work.

| Containers | p50 before → after ms | p95 before → after ms | p99 before → after ms |
|---|---:|---:|---:|
| 1 | 17.2910 → 9.0532 | **25.8169 → 35.3461** | 51.0964 → 87.8574 |
| 8, same image | 18.4193 → 9.8343 | **29.0811 → 15.5769** | 32.6113 → 28.8570 |

Eight-container p95 improved 46.4%; **single-container p95 worsened 36.9%**. Medians improved for both. API-baseline tails also varied, but the cause is not established. No universal latency improvement, statistical significance, production capacity or SLO is accepted. Single-container tail evaluation remains open. The historical October 85.7% result has a different implementation/workload/baseline; do not combine the percentages or relabel it as this candidate.

The selected evidence preserves all four final runs and every allocation repetition. Local preliminary attempts included timeouts/failures and exploratory mixed latency results; these remain retained privately and were excluded from this predeclared frozen-source comparison. Sanitization omits local paths, process identities, bulk logs and hardware identity; numerical samples and the negative result remain unchanged. Text hashes normalize CRLF to LF for cross-platform checkouts. Source hashes and samples allow recomputation, not independent proof that a benchmark ran.

## Validation and reproduction

Pre-publication frozen-source local regression passed 180 test events across 10 packages, including overlapping parents/subtests/fuzz seeds. The opt-in external live registry server test skipped. Real registry/signature interoperability, namespace/key changes, TLS/redirect/authentication negatives, API-server Fail/Ignore faults and bounded pool/configuration regressions executed. Seven added real API/crypto controls admitted signed updates/init/ephemeral containers and rejected their unsigned counterparts, with callbacks observed. The older mock-verifier bypass suite remains separate. Artifact regressions cover saturation/recovery, file-size boundaries and synthetic size changes/I/O errors.

Differential framing fuzz used the original map-based object-acceptance oracle: 45,727 executions in 10 seconds without a discrepancy. `go vet` passed; isolated runner receipts recorded no owned processes after cleanup. Finite tests do not prove general security. These are local observations; hosted CI status belongs to the PR/check run, not this historical count.

Recompute saved numerical evidence without starting services:

```sh
python3 -B hack/check-resource-improvement-evidence.py
# Optional: require the current measured source files to match their saved hashes.
python3 -B hack/check-resource-improvement-evidence.py --check-current-source
```

Relevant isolated commands (see [security demonstration prerequisites](security/DEMONSTRATION.md) for envtest/oracle setup):

```sh
go test ./internal/... ./cmd/... ./api/... ./test/... -p=1 -count=1 -timeout=150s
go test ./internal/artifact -run '^$' -fuzz '^FuzzHeaderFramingCompatibility$' -fuzztime=10s -parallel=1
go test ./internal/artifact ./internal/webhook -run '^$' -bench '^Benchmark(HeaderFraming8MiB|FileArtifactFetcher64MiB)$' -benchtime=5x -benchmem -count=3 -p=1
```

Native API execution also requires `MODELGATE_NATIVE_ADMISSION=1`, `KUBEBUILDER_ASSETS` and a fresh `MODELGATE_EVIDENCE_DIR`; Windows process fixtures require the bounded runner. Use new synthetic fixture outputs and no existing cluster. Revert the source commit with matching deployment artifacts to roll back; no CRD/storage migration was introduced. Operator registry configuration continues to require a reviewed process restart for changes.

General production readiness, maintained-version coverage, full provenance/attestation enforcement, deployed lifecycle/CNI, built-image/OS scans and host HA remain separate gates. Original 24-hour acceptance is incomplete after the user-directed 15-hour stop; no soak was restarted by this work.
