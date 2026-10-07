# Security

ModelGate is an admission-time control with a pinned-public-key trust model. Do not grant workload
users write access to `ModelGatePolicy`, webhook configurations, webhook Deployment, serving Secrets,
or excluded namespaces: those privileges can replace the trust root or disable enforcement.
Kubernetes API authentication and RBAC authorize workloads and policies; the webhook does not
independently authorize `request.userInfo` or authenticate API-server clients with mutual TLS.
Serving HTTPS proves server identity when the API server validates the configured CA.
Restrict ingress to API-server connections using your platform's network controls.

Public keys are not secrets. Private signing keys are never loaded by the webhook; test scripts
create temporary keys. TLS private keys remain operator-provisioned Kubernetes Secrets.
Cosign skips transparency-log verification. This removes log inclusion/audit assurance and does not
provide compromise detection or revocation beyond replacement of the configured public key.

## Limitations

- Registry destinations require operator-approved endpoints and CIDRs, checked at numeric socket
  creation. All redirects are denied. See [registry security](docs/REGISTRY_SECURITY.md).
- Redirecting/CDN registries, plain HTTP and implicit Docker Hub aliases are not supported.
- Artifact annotations are optional and do not prove what bytes a workload loads. Approved local
  paths must be operator-controlled, immutable files. A 64 MiB limit excludes larger models.
- Safetensors validation checks framing, JSON object and hash, not tensor dtype/shape/offset validity.
- Protocol 0/1 pickle detection is incomplete. A format detector is not a sandbox or malware scanner.
- No full Pod Security Standard is implemented; use Kubernetes Pod Security Admission separately.
- Exempt policies and selector-excluded namespaces bypass every check.
- Running Pods are not revoked after policy or key changes.
- Metrics have no application authentication. Registry/verifier errors are generic and do not include upstream bodies or subprocess stderr.
- Fail-closed admission can interrupt cluster operations. One replica and TCP probes provide limited
  availability assurance; certificate rotation, registry access and recovery must be tested by operators.

Do not interpret passing mocked tests as evidence of production registry or deployment security.
Report vulnerabilities privately to the repository owner before disclosing exploit details publicly.
