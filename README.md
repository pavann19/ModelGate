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

MVP admission logic and unit tests are done and green in CI. `kind`/`envtest` end-to-end
verification, deployment manifests, and TLS provisioning are the next milestone — see
[docs/DECISIONS.md](docs/DECISIONS.md) for exactly what's verified so far.
