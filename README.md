# ModelGate

A Kubernetes `ValidatingAdmissionWebhook` that only admits pods whose container images are
cosign-signed and whose model artifacts are hash-verified, non-pickle files — the supply-chain
security layer most AI/ML clusters don't enforce at admission time.

See [docs/DECISIONS.md](docs/DECISIONS.md) for design trade-offs and an honest status of what is
and isn't verified yet.

## What it checks

1. **Image signatures** — every container (including init and ephemeral containers) must be signed
   with `cosign` against a pinned public key.
2. **Model artifacts** — a pod annotated `modelgate.dev/model-artifact: <id>` must reference an
   artifact on an allow-list, and that artifact must be a well-formed `safetensors` file (not a
   pickle in disguise) whose SHA-256 matches the allow-listed hash.
3. **Host-level access** — `hostPID`, `hostNetwork`, `hostPath` volumes, and `privileged: true`
   containers are denied unconditionally.

## Layout

- `internal/pickle` — opcode-based pickle detector (raw pickle streams and PyTorch zip archives).
- `internal/artifact` — safetensors header/hash validation.
- `internal/policy` — MVP static policy config (becomes a CRD in M1).
- `internal/webhook` — the admission `Handler` and cosign verifier.
- `cmd/webhook` — the server binary.

## Running tests

```bash
go test ./...
```

## Status

MVP admission logic, unit tests, and an `envtest` suite (real `kube-apiserver` + `etcd`, a real
`ValidatingWebhookConfiguration`, real TLS) all pass and run in CI — see
[test/e2e/envtest_test.go](test/e2e/envtest_test.go). Real cosign signature verification against
an actual signed/unsigned image pair, and a `kind`-cluster deployment for extra realism, are the
next gaps — see [docs/DECISIONS.md](docs/DECISIONS.md) for exactly what's verified so far.
