# Admission isolation and lifecycle

Identical container image references share successful signature verification only
within one admission request and its resolved namespace policy. Every new request
rechecks trust. Distinct regular, init and ephemeral images remain independently
verified. Linux artifact reads open nonblocking before checking descriptor type,
so a FIFO cannot hold admission open; other platforms retain regular file reads.

Readiness on internal port 8081 requires the serving listener and becomes false
on shutdown. Liveness checks process health independently of the registry. Deploy
binary and manifests together: older binaries lack the new probes and
--prestop-delay hook. Defaults request two replicas, a 40-second termination
grace, a 10-second endpoint withdrawal delay and a 25-second manager drain.
The disruption budget can block voluntary eviction of a single remaining replica;
node spread is a preference, not proof of host resilience. No CRD change is made.

For rollback retain the previous image, manifests and trust configuration. Restore
them together and repeat signed/unsigned controls; rollout undo does not restore
Secrets or policies. Keep fail-closed admission during registry failure.

Bounded source checks (Go toolchain from go.mod):

```sh
go test ./internal/... ./cmd/... ./api/... ./test/deployment -p=1 -count=1 -timeout=120s
```

Existing CI separately exercises Linux, real Cosign, envtest and Helm.
Fresh hosted CI and release-image validation remain required before promotion.
The retained lab observation stopped at the user's 15-hour checkpoint; the original
24-hour gate is incomplete. A matched eight-distinct-image concurrency-four control
regressed; no general speedup claim is supported. Local cached-image lab tools and
raw evidence are outside this source candidate. CNI enforcement and production
availability remain unverified.
