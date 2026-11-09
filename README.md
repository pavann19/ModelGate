# ModelGate

[Documentation index](docs/README.md) | [Verified baseline and remaining limits](docs/VERIFICATION.md)

ModelGate is a Go Kubernetes validating admission webhook. It checks Pod CREATE/UPDATE and
UPDATE of `pods/ephemeralcontainers` against a namespace-scoped `ModelGatePolicy`.
This release candidate is under security review; it is not production-certified.

The [platform case study](docs/CASE_STUDY.md) examines admission under concurrent load,
signing-key rotation, verification saturation and webhook outage/recovery. Three local runs
retained 1,840 API-level measurements with real registry traffic and cosign verification.
All 60 intentional-outage requests failed closed; admission resumed 6.05–9.21 seconds after
scale-up. These are single-node kind observations, with raw samples and contention limits
published alongside the results; they are not production capacity or availability guarantees.

Current [security demonstration](docs/security/DEMONSTRATION.md) documents bounded-v1 compatibility,
local test evidence and remaining deployment gates. No production readiness claim is made.

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
Provenance, keyless identity, transparency-log, expiry and revocation checks are unsupported;
the operator-managed public key is the trust root.

## Read and run

- [Platform case study](docs/CASE_STUDY.md)
- [Real admission load and failure experiment](docs/PLATFORM_EVALUATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security and trust boundaries](SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Testing and evaluation](docs/TESTING.md)
- [Admission lifecycle and upgrade limits](docs/ADMISSION_LIFECYCLE.md)
- [Optional proposal worker](agent/README.md)
- [Helm deployment](docs/HELM_INSTALL.md)
- [kind integration](docs/KIND_DEMO.md)
- [Admission examples](docs/DENY_EXAMPLES.md)
- [Historical ACR publication evidence](docs/AZURE_ACR_EVIDENCE.md)

Build with Go 1.27.3: `go build ./cmd/webhook`. The runtime uses bounded-v1 Go cryptography without an external verification executable.
Only PKIX PEM ECDSA P-256 keys and SHA-256/ASN.1 DER signatures are supported.
See the [verification contract](docs/engineering/architecture_decisions/ADR-001-bounded-verification.md).
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

The [hosted CI](https://github.com/pavann19/ModelGate/actions/runs/41319123152)
and [worker checks](https://github.com/pavann19/ModelGate/actions/runs/41319123148)
passed for runtime revision `e9af94f` on 1 November 2026, including Linux FIFO,
race, real-signature, API-server, Helm and kind integration checks. Each later
PR must pass its own checks before promotion. The retained local observation
stopped at 15 hours and does not satisfy the original 24-hour gate; a
distinct-image control regressed. See the lifecycle guide for the remaining limits.

## License

Original project code is licensed under [Apache-2.0](LICENSE). Dependency licenses
and distribution obligations are retained in [third-party notices](THIRD_PARTY_NOTICES.txt).

## Contributing and maintenance

See [contributing](CONTRIBUTING.md), [maintenance rules](MAINTAINING.md) and [security reporting](SECURITY.md). Changes reach `main` through reviewed PRs and required checks.
