# ModelGate

ModelGate is a Go Kubernetes validating admission webhook. It checks Pod CREATE/UPDATE and
UPDATE of `pods/ephemeralcontainers` against a namespace-scoped `ModelGatePolicy`.
This release candidate is under security review; it is not production-certified.

## Enforcement

- The production verifier requires `repository@sha256:<64 lowercase hex characters>` and verifies
  its cosign signature against the policy's public key. Mutable tags are denied.
- All regular, init and ephemeral container images are checked.
- `hostPID`, `hostIPC`, `hostNetwork`, `hostPath` and privileged containers are denied.
- An optional `modelgate.dev/model-artifact` annotation selects a policy-allow-listed local file
  in the webhook filesystem. Its SHA-256 and JSON-object safetensors framing are checked, and
  recognized pickle/PyTorch archives are rejected. This is not full tensor-schema validation.
- Missing, ambiguous or unreadable policies fail closed. Explicit policy exemptions bypass every
  check and require a reason. The installation excludes kube-system and the webhook namespace.

The artifact annotation is optional. ModelGate does not discover unannotated models, bind a
webhook-local file to workload mounts, enforce provenance/SBOMs, or monitor running containers.
Cosign transparency-log verification is disabled; the operator-managed public key is the trust root.

## Read and run

- [Architecture](docs/ARCHITECTURE.md)
- [Security and trust boundaries](SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Testing and evaluation](docs/TESTING.md)
- [Helm deployment](docs/HELM_INSTALL.md)
- [kind integration](docs/KIND_DEMO.md)
- [Admission examples](docs/DENY_EXAMPLES.md)
- [Historical ACR publication evidence](docs/AZURE_ACR_EVIDENCE.md)

Build with Go 1.27.3: `go build ./cmd/webhook`. The runtime image includes cosign 2.4.1.
Run dependency-free unit suites with `go test ./internal/... ./api/... ./cmd/...`.
`go test ./...` additionally requires envtest assets, Docker and cosign; it is not a unit-only command.
See the testing guide for prerequisite setup and the distinction between mocks and real infrastructure.

TLS provisioning, registry destination policy and ModelGatePolicy management are operator responsibilities.
[Registry security](docs/REGISTRY_SECURITY.md) describes required host/CIDR trust and private registry configuration.
The Helm chart requires a CA bundle; raw Kustomize manifests require CA injection before use.
Keep `failurePolicy: Fail`. A webhook outage blocks protected Pod admissions.

Metrics and structured decisions are available on port 8080 and container logs. Metrics are
unauthenticated; restrict access at the cluster network boundary. No managed production deployment,
real verification latency, throughput or scale claim is made.
