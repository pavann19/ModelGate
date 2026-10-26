# Testing and evaluation

Use Go 1.27.3. Run:

```sh
go test ./internal/... ./api/... ./cmd/...
go test -race ./...
go vet ./...
go build ./...
go mod verify
go test ./internal/pickle -fuzz=FuzzIsPickle_RealFormatsNotFlagged -fuzztime=30s
```

The full and race suites require external prerequisites. Unavailable prerequisites are failures or
explicit skips, not successful integration results. Windows race builds require a compatible C compiler.
`hack/preflight.ps1` resolves pinned setup-envtest and Kubernetes 1.31.0 assets; export the printed
KUBEBUILDER_ASSETS path before `go test ./test/e2e/... -v -timeout 120s`.

| Suite | Actual boundary |
| --- | --- |
| internal | Unit tests; fake policy/image/file dependencies where specified; production tag rejection and real file-limit regressions |
| test/e2e | Real envtest API server and webhook TLS; fake image verifier/artifact fetcher |
| test/e2e/failurepolicy | Real API server transport failure semantics; Fail and intentionally insecure Ignore controls |
| test/cosign | Real TLS OCI registry fixture on a private interface, real ECDSA signatures and real pinned cosign production verifier; missing binaries skip locally but fail in CI |
| deploy/kind/private-registry-smoke.py | Actual hardened image, raw RBAC/TLS/admission, private TLS OCI fixture and real cosign on kind; server dry-runs, no kubelet claim |
| bench | 200 sequential envtest Pod creates; static fake policy resolver and always-successful fake signature verifier |

The benchmark does NOT measure real cosign latency, registry downloads, real CRD policy reads,
model-file verification, scheduling, kubelet behavior or cluster scale. Its tracked JSON is a historical
raw sample retained for reproducibility, not a product performance claim. Running it overwrites that
file; preserve the original and compare run provenance before publishing any result.

CI uses commit-pinned actions, Go 1.27.3, cosign 2.4.1 and Helm 3.16.4. Docker base/cosign source images are digest-pinned.
CI configures unit/race/build/vet, envtest, cosign, pickle fuzz, chart rendering and kind jobs.
Job definitions are reproducible instructions; execution and branch-protection status require live
verification. A pinned govulncheck command runs in the unit job. No image scanner, secret scanner or SBOM job is currently present.
Historical Azure JSON records publication coordinates/digest, not signed provenance or managed hosting.

The retained ttl.sh smoke is incompatible with registries that redirect signature requests. See [kind integration](KIND_DEMO.md); redirect refusal is preserved. Helm installation requires separate live validation beyond its rendering job.
