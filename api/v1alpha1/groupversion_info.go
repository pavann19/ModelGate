// Package v1alpha1 contains the ModelGatePolicy API: the CRD that moves the
// MVP's hardcoded checks (cosign key, artifact allow-list, namespace
// exemption) into declarative, per-namespace configuration.
//
// +kubebuilder:object:generate=true
// +groupName=modelgate.dev
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "modelgate.dev", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
