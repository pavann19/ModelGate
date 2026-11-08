# Platform security and reliability

ModelGate protects Pod admission with deterministic policy resolution, registry destination
validation, explicit-key signature checks and bounded artifact checks. The analysis worker only
proposes runbook actions. It cannot change admission policy, keys, RBAC or acceptance results.

This is an engineering baseline aligned with the [Kubernetes security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/),
[application checklist](https://kubernetes.io/docs/concepts/security/application-security-checklist/)
and [webhook guidance](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/).
It is not a CIS certification, penetration-test report or production-readiness claim.

## Trust and exposure

| Actor or surface | Required boundary |
|---|---|
| Workload authors and registries | Untrusted input; cannot choose trust roots or registry destinations |
| Policy writers | Security administrators; an exemption intentionally bypasses checks, so tenants must never receive policy-write rights |
| Operator registry Secret | Credentials and allowed TLS endpoints/CIDRs; mounted read-only, never logged or sent to the model |
| Webhook identity | Only `list` on namespaced ModelGatePolicy objects across namespaces; API access is necessary, so its projected token remains enabled |
| Analysis identity | Dedicated ServiceAccount, no RBAC or mounted token; offline deployment has deny-all ingress/egress |
| Exempt namespaces | `kube-system` and the release namespace must be operator-only; Restricted PSA is a separate boundary |
| Metrics and probes | Internal only; metrics contain bounded outcome/reason labels, but still require network access control |

Admission requires outbound API, DNS, registry and approved token-service access. No LLM or
telemetry RPC is required. The registry transport rejects proxy inheritance, redirects, unapproved
destinations, metadata IPs, DNS rebinding and oversized responses. Explicit-key offline Cosign
verification does not establish transparency-log inclusion or image vulnerability status.

## Implemented controls

- Admission transport accepts POST only, bounds the body at 3 MiB, limits concurrent body decoders
  to 32, and applies 5-second body and 14-second response deadlines on the HTTP/1.1 TLS listener.
  TLS requires version 1.2 or newer. The dependency's separate header-read timeout is 32 seconds;
  connection/rate limits at the platform firewall remain necessary for connection floods.
- Pod JSON is bounded at 2 MiB and duplicate keys/trailing data/deep nesting are rejected before
  security decoding. Eight verification slots, a 12-second handler budget and request-local
  verification reuse remain separate controls. Saturation fails closed.
- Policy reads request at most two objects. Multiple policies or a continuation token are
  ambiguous and denied. Registry token JSON also rejects duplicate keys and conflicting token fields.
- Helm requires a digest-pinned webhook image by default, `failurePolicy: Fail`, at least two
  replicas and a 13–30 second admission timeout. Existing 15-second default is retained.
- Helm isolates webhook ingress and egress by default, with operator-specified API/registry
  addresses, scoped DNS, and optional namespace-scoped metrics access. No remote metrics rule
  exists by default. Broad `/0` CIDRs are rejected. Kubernetes validates final CIDR syntax.
  Setting `metrics.enabled=false` also disables the process listener and metrics Service port.
- Runtime containers use non-root identities, read-only roots, RuntimeDefault seccomp, dropped
  capabilities, no privilege escalation, bounded CPU/memory/storage and bounded temporary volumes.
  Service-link environment injection is disabled. The lab namespace enforces Restricted PSA v1.31.
- Startup/readiness/liveness, graceful termination, rolling updates, spread constraints and a PDB
  remain in place. Soft spreading and a PDB do not prove host-level availability.
- Image contexts exclude runtime databases, evidence, key material and coordination documents.
  Go dependency advisories are checked by pinned govulncheck; chart security regressions run in CI.

The bundled Cosign has been moved from v2.4.1 to the digest-pinned upstream v3.1.4 image;
integration assertions still require the exact binary version. A binary scan of the upstream
v3.1.4 executable still reports vulnerable symbols in its older Go standard library and ACR
credential helper. Offline local operands and the subprocess environment allowlist restrict
exposure, but do not make that scan pass. Binary/container release remains blocked on a
patched build and full image scan; a clean ModelGate source scan does not clear bundled tools.
The `Distribution binary security` workflow builds without publishing and scans both shipped Go
executables. It deliberately fails on findings; it is not an OS-package scanner or a waiver for
the known upstream binary findings.

## Installation and compatibility

Use the [Helm install guide](HELM_INSTALL.md) for release configuration. Raw manifests and the
root Kustomize entrypoint are local-kind fixtures, retaining `modelgate-webhook:kind`; they no
longer rewrite that image to `latest`. They do not provide webhook NetworkPolicy configuration.
The analysis manifest remains a separate single-worker, offline lab topology with a PVC.

Before upgrading an existing installation, export the non-secret effective chart values and
record the previous image digest, chart revision, CA identity and policy versions in operator
storage. Review image provenance/scans and use a disposable staging environment first.
Prepare actual network destinations, test the CNI's NAT behavior and DNS, ensure Restricted PSA
compatibility, then render/lint. Old tag-only values intentionally fail until a digest is supplied.
Never use the synthetic `hardening-test-values.yaml` to install a cluster.

After upgrade, check actual endpoint readiness, signed and unsigned admission controls,
namespace/key isolation, registry timeout, saturation, allowed API/registry/DNS connectivity and
denied unauthorized pod/metrics traffic. Test agent outage independently. Readiness does not
establish registry availability, certificate lifetime or policy correctness.

If rollout fails, preserve the failed observations and restore the previous reviewed chart/values
and digest. Retain the matching serving certificate/CA pair and operator registry configuration.
Do not fix an outage by changing failurePolicy to Ignore, exempting tenant namespaces or granting
wildcard RBAC. Restoring an older vulnerable image is an explicit security tradeoff, not an
automatic safe rollback. No queue/schema migration is introduced by this hardening change.

## Repeatable checks and remaining infrastructure work

```text
go build ./...
go vet ./...
go test ./internal/... ./cmd/... ./api/... ./test/deployment -p=1 -count=1 -timeout=120s
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -show verbose ./...
python -B -m unittest discover -s agent -v
helm lint deploy/helm -f deploy/helm/hardening-test-values.yaml
python -B hack/test_helm_hardening.py -v
```

The Helm regression uses PyYAML 6.0.3 and `HELM_BIN` may select an installed Helm executable.
The separately retained private audit is historical supporting tooling. NetworkPolicy selection is
not a traffic test; validate actual allowed/denied traffic only in an explicitly isolated target.

Before production, operators still need a supported Kubernetes/node/runtime version matrix,
CNI allow/deny tests, control-plane CIS review, API network restrictions, short-lived identities,
etcd encryption/KMS and audited backup/restore, certificate-expiry alerts/rotation, image/base and actual shipped-binary
scans and provenance, independent host failure domains, quotas and operational alerts/SLOs.
Do not apply a generic kube-apiserver/etcd configuration to an existing cluster without a reviewed
target-specific change plan. ModelGate cannot establish those host/provider controls from Helm.

The original 24-hour acceptance remains incomplete after the user stopped the historical run
at 15 hours. Historical lifecycle/rotation results are not validation of a new hardening candidate.
