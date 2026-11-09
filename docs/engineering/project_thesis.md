# ModelGate project thesis and alternatives

Reviewed 4 November 2026 against repository source and primary documentation. Capability claims are bounded by [the security test matrix](../security/DEMONSTRATION.md); this research is not a deployment receipt.

## User and problem

The target user is a Kubernetes platform engineer running a controlled ML-serving namespace. Workload authors need a clear allow/deny result before Pods run. The operator needs namespace-specific signing authority, immutable image references, explicit local model-format restrictions, predictable failure behavior, and evidence explaining why an unsafe deployment was rejected.

ModelGate's intended contract is deterministic admission: resolve a namespace policy, reject unsafe Pod settings, validate digest-bound image trust and explicit model-artifact inputs, and return a bounded decision. An optional separate worker groups sanitized incidents and prepares proposals. The model cannot grant admission or authorize its own policy changes.

This is a focused admission component. It is not a complete Kubernetes security platform, a general policy language, a model sandbox, provenance authority, vulnerability scanner, SIEM, key-management service or production availability guarantee. No customers, adoption, revenue or operational SLO are established by this repository.

## Alternatives and fit

| Alternative | Established role | ModelGate decision / trade-off |
|---|---|---|
| Native Kubernetes ValidatingAdmissionPolicy and Pod Security Admission | CEL validation inside the API server avoids webhook HTTP callouts for declarative object constraints; Pod Security Admission applies standardized Pod security controls. | Prefer these where object-local constraints suffice. A registry-backed cryptographic check requires external verification beyond native object expressions. ModelGate's selected host-access checks should not be presented as the complete Restricted standard. |
| Kyverno | Image verification policies already support signatures, attestations and richer authorities; Kubernetes policy engine with established image-validation interfaces. | Prefer for broad production policy requirements. ModelGate does not outperform or replace its policy breadth. A narrower custom implementation makes its exact trust/failure/resource boundaries easier to inspect, at the cost of maintaining them. |
| OPA Gatekeeper + external data | General admission constraints can consult an external provider. | Prefer when an organization already operates Rego constraints. ModelGate avoids adding a general policy-language/provider stack for its small fixed contract; loses generality and ecosystem integration. |
| Ratify + Gatekeeper | Existing cloud-native verification engine integration with admission enforcement. | Prefer when extensible OCI artifact verification is needed. ModelGate's current explicit-key signature checks have a substantially narrower supported trust model. |
| Sigstore/Cosign | Signing and verification tooling covering key-based/keyless workflows and attestations. | ModelGate composes a limited verification mode with Kubernetes policy; it does not invent signatures or implement the whole Sigstore trust system. Narrowing a bundled verifier may reduce shipped attack surface but creates an interoperability and maintenance obligation. |

Primary sources: [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/), [admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/), [Kyverno ImageValidatingPolicy](https://kyverno.io/docs/policy-types/image-validating-policy/), [Gatekeeper external data](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata/), [Ratify quickstart](https://ratify.dev/docs/quick-start/), and [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/). These establish alternatives' documented roles, not comparative benchmark results. Versions and deployed configuration require independent testing.

## Defensible contribution

There is no demonstrated novel cryptographic or admission-policy mechanism. The defensible contribution is a small, inspectable engineering integration: namespace-scoped digest/key enforcement, restricted registry transport, explicit local model-format checks, bounded request-local image reuse, and a durable proposal-only worker outside the synchronous security decision. The meaningful artifact is the evidence connecting malicious input and outage scenarios to actual domain outcomes.

This is an implementation emphasis, not proven superiority over Kyverno, Gatekeeper or Ratify. The local model-file check is also a limitation: it does not bind the checked file to the eventual runtime volume or image, so it cannot establish end-to-end model supply-chain integrity. The worker's existence alone is not evidence of recommendation quality or safer operations.

The smallest credible path to a stronger contribution is to publish a reproducible, bounded conformance demonstration for this narrow contract: real Cosign-signed and deliberately invalid payloads, registry redirect/DNS/JSON abuse, namespace/key changes, image-update and ephemeral-container bypass attempts, request cancellation/overload, and API-server fail-closed behavior. Retain failed controls and pair crypto tests with API-server enforcement. Reproduce on an isolated supported Kubernetes target and measure enabled-versus-disabled overhead without weakening trust semantics.

A future immutable model-artifact binding could improve the ML-specific value, but requires a separate design and validation across image/volume/runtime semantics. It is not claimed implemented. Adding provenance merely for a checklist without a defined builder/subject/predicate/freshness trust policy would weaken the thesis rather than complete it.

## Current evidence and release boundary

The repository retains earlier real-crypto, envtest, worker and local lifecycle evidence, plus hardening checks from 3 November. They remain historical until the final candidate's source/image/config identities are tied to fresh commands. Envtest is a private API server/etcd, not a CNI or complete cluster. The prior 15-hour user-stopped observation is not the original 24-hour acceptance pass; no new soak is authorized by this thesis.

At the 4 November review, bundled Cosign binary findings, final enforcing-CNI deployment validation, image distribution scans and compatibility coverage remain release concerns. The CLI has been removed from the runtime under ADR-001. Current source and Linux Go binary vulnerability scans found no known vulnerabilities, and actual Cosign interoperability plus real registry/API-server tests passed. A complete built-image OS scan and enforcing-CNI deployment remain unverified. Supported guarantees exclude provenance/attestation policy, keyless identity/issuer validation, certificate/attestation expiry and automated revocation.

Use “local candidate validated for the named test scope” only when the the exact candidate results justify it. Use production-ready only after explicitly scoped functional, security, deployment, recovery and reproducibility gates pass; no finite suite establishes general security or production availability.
