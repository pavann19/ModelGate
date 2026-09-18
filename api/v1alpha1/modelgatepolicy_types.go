package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ArtifactAllowListEntry pins one model artifact identifier to the SHA-256
// digest it must match. The identifier is whatever value pods carry in the
// modelgate.dev/model-artifact annotation.
type ArtifactAllowListEntry struct {
	// ID is the model artifact identifier referenced by a pod's
	// modelgate.dev/model-artifact annotation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`

	// SHA256 is the expected lowercase-hex SHA-256 digest of the artifact.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	SHA256 string `json:"sha256"`
}

// ModelGatePolicySpec defines the admission rules ModelGate enforces in the
// namespace this policy lives in.
type ModelGatePolicySpec struct {
	// CosignPublicKeyPEM is the PEM-encoded cosign public key every
	// container image in this namespace must be signed against.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	CosignPublicKeyPEM string `json:"cosignPublicKeyPEM"`

	// ArtifactAllowList lists the model artifacts permitted in this
	// namespace and the SHA-256 each must match.
	// +optional
	ArtifactAllowList []ArtifactAllowListEntry `json:"artifactAllowList,omitempty"`

	// Exempt, when true, disables all ModelGate checks for this namespace.
	// This is an explicit, auditable bypass (e.g. for kube-system-style
	// namespaces) -- it is never inferred, only ever set here. Every
	// exemption is logged by the webhook at admission time.
	// +optional
	// +kubebuilder:default=false
	Exempt bool `json:"exempt,omitempty"`

	// ExemptionReason is required documentation for why Exempt is set,
	// so an exemption is never silent even in the policy object itself.
	// +optional
	ExemptionReason string `json:"exemptionReason,omitempty"`
}

// ModelGatePolicyStatus is currently unused (no controller reconciles this
// object yet -- the webhook reads Spec directly on each admission request).
// It exists so the type satisfies the conventional Kubernetes object shape
// and status subresource wiring is a non-breaking follow-up.
type ModelGatePolicyStatus struct{}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=mgp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Exempt",type=boolean,JSONPath=`.spec.exempt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ModelGatePolicy declares the ModelGate admission rules for the namespace
// it is created in. Exactly one ModelGatePolicy per namespace is expected;
// if more than one exists, the webhook picks the oldest by creation
// timestamp and logs a warning rather than silently picking arbitrarily.
type ModelGatePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ModelGatePolicySpec   `json:"spec"`
	Status ModelGatePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ModelGatePolicyList is a list of ModelGatePolicy.
type ModelGatePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ModelGatePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ModelGatePolicy{}, &ModelGatePolicyList{})
}
