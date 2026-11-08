# ModelGate threat model

Reviewed 4 November 2026. Scope: repository implementation and retained evidence, not a live cluster assessment or certification. This document supplements [the original threat model](../THREAT_MODEL.md); historical evidence is not automatically evidence for the current candidate. See [test matrix](DEMONSTRATION.md) for commands, evidence classes and gaps.

## Security objective and assets

A platform operator wants Kubernetes Pod admission to reject container images that are not approved by the namespace signing authority, reject selected unsafe Pod settings, and perform explicit local model-artifact format checks. Workload authors may create/update Pods but must not be able to change policy, trusted keys or webhook configuration. The protected assets are the admission decision, namespace-to-policy association, configured public keys and registry destinations, webhook TLS identity, controller availability, policy/audit integrity, and the independent analysis worker's bounded authority.

A signature authenticates a digest-bound statement from a configured key. It does not establish that a build was safe, that the signer was authorized by an external organization, that a vulnerability scan passed, or that a model artifact was produced by that build. A valid signed malicious image remains admissible under signature-only policy.

## Actors and authority

| Actor | Capability / assumption |
|---|---|
| Untrusted workload author | Submit Pod CREATE/UPDATE, init and ephemeral container changes, malformed metadata and artifact references within granted RBAC. Cannot edit ModelGatePolicy, exemption labels, admission registrations, Service endpoints, TLS Secrets or trust files. |
| Malicious registry or network peer | Return hostile manifests, signature metadata, redirects, authentication challenges, DNS answers, delays and malformed bodies. Cannot forge a trusted signature or a valid registry TLS certificate under uncompromised trust. |
| Compromised build/signing pipeline | Publish arbitrary correctly signed content when the configured private key is compromised. Signature-only admission cannot distinguish it from an approved release. |
| Platform/policy administrator | Trusted to choose namespace scope, keys, registry CIDRs and safe deployment. Can bypass or disable enforcement; this is an administrative trust boundary, not a defended adversary. |
| Host/filesystem administrator | Can replace executable, policy/trust files, mounted model data and evidence. Trusted; host compromise defeats this boundary. |
| Analysis model / job submitter | Untrusted text and proposals. No authority to change signing keys, policies, RBAC, exemptions, acceptance results or production resources. |

A tenant able to update its own security policy or exemption selectors falls outside the intended protection. Namespace separation requires separately administered Kubernetes RBAC; the custom resource alone is insufficient.

## Trust boundaries and data flow

1. The authenticated Kubernetes API server authorizes a workload request, then invokes the validating webhook over TLS. ModelGate validates the admission object and namespace consistency; Kubernetes remains responsible for authenticating the workload user.
2. The webhook resolves exactly one namespace policy through Kubernetes API access. Missing, ambiguous or inconsistent policy must deny. Policy writers and API-server integrity are trusted. Request-local reuse of verification results must never become a cross-request or cross-namespace approval cache.
3. Image references cross into registry I/O only after immutable digest and operator destination-policy validation. DNS results are checked and the transport dials approved numeric addresses; redirects and inherited proxy routes must not escape that boundary.
4. Registry content is untrusted until payload identity and cryptographic signature verification both succeed against the namespace public key. Repository, digest and payload subject must agree.
5. A local artifact reference crosses into the webhook filesystem. Regular-file/size/format restrictions reduce parser and FIFO attacks. This does not bind the file to the Pod's runtime volume or ensure it cannot later change.
6. Admission events cross into telemetry and an optional separate proposal worker. Logs, documents and model output are passive untrusted data. A prepared proposal is not an applied policy.
7. CI/build/deployment artifacts cross a release boundary. Source scans, distribution scans, image provenance, deployment configuration and runtime enforcement require separate evidence.

The webhook currently relies on server TLS and deployment network isolation; it does not implement application-level API-server client-certificate authorization. A direct caller can consume webhook resources but cannot create a Pod merely by calling the endpoint. Enforcing CNI/API-server traffic tests remain necessary.

## Supported verification semantics

The implementation inspected at mission entry uses key-based, offline Cosign-compatible signature verification, with controlled registry fetching and explicit repository/digest checks. Transparency-log inclusion is disabled in this mode. The configured public key is the trust anchor. Only key algorithms and signature encodings explicitly accepted and tested by the final verifier may be advertised as supported.

ADR-001 and bounded-v1 are implemented. Current unit, independent Cosign v3.1.4 interoperability, real TLS registry and native API-server integration passed. The runtime contains no Cosign subprocess. Only PKIX PEM ECDSA P-256/SHA-256/ASN.1 DER is supported; this is deliberately narrower than Cosign. Wrong-key, tampered-payload, malformed-signature, wrong-repository and wrong-digest negatives are retained. See the [demonstration](DEMONSTRATION.md) and selected samples for exact scope; no full Cosign compatibility follows.

**Not implemented as admission guarantees:** keyless OIDC identity/issuer constraints, Fulcio certificate validation, Rekor inclusion/freshness, build provenance predicates, in-toto attestation policy, attestation expiry, automated revocation checking and runtime eviction of already admitted Pods. A bare public-key signature has no intrinsic expiry date. Key replacement prevents future admissions under the removed key after a fresh policy read; it is not retrospective revocation. Do not describe missing/invalid image-signature tests as expired/missing-attestation tests.

## Threat and mitigation register

| ID | Threat / attack | Existing control and residual risk |
|---|---|---|
| T01 | Unsigned image, wrong key, payload alteration | Digest-bound payload and key-based signature check deny. Valid signed harmful content is outside this guarantee. Real-crypto integration is required; handler mocks cannot establish it. |
| T02 | Wrong repository/subject, digest swap, mutable-tag race | Production image parser requires immutable digest and signature payload identity consistency. Runtime image handling and registry correctness still matter. |
| T03 | Compromised key, substituted trust root, stale approval | Policy ownership and direct reads; no cross-request positive cache. An authorized policy writer or stolen signer can authorize malicious content. Operator key compromise procedure must remove key, review admissions and rebuild/redeploy affected workloads. No automatic revocation service. |
| T04 | Forged/missing/expired/revoked provenance or keyless identity confusion | Unsupported, not protected by signature-only mode. If required by deployment policy, do not deploy this mode as its substitute. Future implementation needs issuer/identity/predicate/subject/time/revocation semantics and negative controls. |
| T05 | Namespace crossover, missing or duplicate policy, exemption abuse | Namespace consistency, unique policy resolution and per-namespace key tests. Exemptions deliberately bypass checks and require privileged ownership and audit. Broad selectors can defeat protection. |
| T06 | Pod image update, unsigned init/ephemeral container, privilege escalation | UPDATE/subresource registration and all-container checks; selected privileged/host-access prohibitions. This is not the complete Kubernetes Restricted Pod Security Standard. Apply Pod Security Admission separately. |
| T07 | SSRF, redirect, DNS rebinding, credential-helper/proxy abuse | Operator registry policy, approved numeric-IP dialing, redirect rejection, bounded fetch/auth retry and restricted environment. Operator CIDR mistakes still permit unintended destinations; CNI defense requires runtime enforcement. |
| T08 | Malformed/ambiguous JSON, huge bodies, deep nesting, hostile token response | Strict bounded JSON, duplicate-key/depth checks, POST/body limits and decoder semaphore. Kubernetes API metadata limits do not substitute for direct-endpoint controls. Aggregate CPU/memory and network overhead need load evidence. |
| T09 | Slow registry, webhook flood, cancellation or FIFO retaining slots | Verification timeout, bounded admission slots, cancellation, body deadlines and Linux nonblocking regular-file open. Saturation denies and can disrupt legitimate deployments. Fail closed protects trust at the cost of availability. |
| T10 | Webhook outage, panic, invalid response, TLS failure, expired serving certificate | Kubernetes failurePolicy Fail rejects call failures; explicit webhook deny is independent of failurePolicy. Readiness/graceful drain/replicas and rotation runbooks help recovery. Ignore is an intentional bypass and must remain a test fixture rather than a production fix. Full failure-mode matrix needs fresh API-server tests. |
| T11 | Unsafe rollout, endpoint routing lag, node failure | Probes, disruption/rollout configuration and resource limits. Historical local lifecycle checks are not a current release check. Multiple kind nodes on one host are not host HA; PDB does not protect involuntary outages. |
| T12 | Malicious local model artifact / changed runtime artifact | Allowlisted formats, pickle rejection, bounded regular-file reading. These are format/heuristic checks, not proof of harmless model execution, semantic safety or a binding to an image/volume. |
| T13 | Audit tampering, sensitive errors, metric cardinality abuse | Bounded reason classes and structured events; redact keys/tokens/workload content before publication or worker ingestion. No tamper-evident external audit store is established. Trusted host/operator can alter local logs. Correlation fields are not cryptographic audit integrity. |
| T14 | Prompt injection, duplicate/replayed jobs, worker compromise | Separate worker, typed/schema/scope/source checks, durable idempotency/leases, bounded tools and proposal-only result. A lease is not exactly-once execution. Worker outage must not affect admission; a model's self-report cannot prove forbidden effects did not occur. |
| T15 | Supply-chain compromise of dependencies, build or release image | Pinned versions, source/binary scans and build/notice review. Historical source scan is not complete image or provenance assurance. The 3 November Cosign binary findings remain historical release blockers until the actual shipped distribution is rescanned. |
| T16 | Unsupported API/version, control-plane compromise, insecure cluster | Test actual versions and manifest schema; API-version compatibility requires real API-server checks. Helm cannot establish etcd encryption, node patching, API exposure, backup restoration, independent failure domains or cluster administrator integrity. |

## Operational response and validation priorities

For signing-key compromise, first preserve admission/audit identities and identify the affected scope. An authorized operator replaces/removes the key, verifies old-key denial and new-key admission, and reviews already running workloads separately. Never infer a prior signed image is safe because the current key changed.

For webhook unavailability, preserve fail-closed settings, inspect certificate dates/CA-Service identity, readiness/endpoints, API/registry connectivity and saturation. Restore the reviewed image/configuration/certificate pair. Changing failurePolicy or exempting a namespace is a consequential security downgrade requiring explicit operator action and an audit record.

For suspected registry SSRF or malformed-input abuse, preserve sanitized request identity, isolate only the approved destination path and reproduce against a loopback synthetic peer. Do not scan or alter other project resources. For hostile worker input, retain the bounded rejected job and demonstrate that no policy/trust write occurred.

Before claiming a hardened deployment, run the exact final image in a new isolated enforcing-CNI cluster: traffic allow/deny, TLS rotation, key rotation, API-server failure modes, namespace/key negatives, upgrade/rollback and worker-outage independence. Record Kubernetes/CNI/runtime/image/source/config identities. This mission must not touch shared Docker/Kubernetes state when safe isolation is uncertain. The previous 15-hour stop remains authoritative; no 24-hour restart is implied.

## Standards alignment and limits

The reference baseline is Kubernetes' [security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) and [webhook good practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/), not a claim of CIS, SOC 2, SLSA or other certification. Kubernetes documents that [Fail rejects webhook call errors](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/); explicit denial is distinct. Sigstore documents [separate signature and attestation verification](https://docs.sigstore.dev/cosign/verifying/verify/). References reviewed 4 November 2026; pin and test deployment versions rather than assuming latest documentation proves compatibility.
