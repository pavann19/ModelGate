package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
)

func newFakeReader(t *testing.T, objs ...*modelgatev1alpha1.ModelGatePolicy) *fake.ClientBuilder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := modelgatev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	b := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	return b
}

func TestResolve_NoPolicyReturnsErrNoPolicy(t *testing.T) {
	c := newFakeReader(t).Build()
	r := NewResolver(c)
	_, err := r.Resolve(context.Background(), "empty-ns")
	if !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("expected ErrNoPolicy, got: %v", err)
	}
}

func TestResolve_ReturnsConfigFromPolicy(t *testing.T) {
	p := &modelgatev1alpha1.ModelGatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns-a"},
		Spec: modelgatev1alpha1.ModelGatePolicySpec{
			CosignPublicKeyPEM: "key-a",
			ArtifactAllowList: []modelgatev1alpha1.ArtifactAllowListEntry{
				{ID: "model-1", SHA256: "abc123"},
			},
		},
	}
	c := newFakeReader(t, p).Build()
	r := NewResolver(c)
	res, err := r.Resolve(context.Background(), "ns-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Exempt {
		t.Fatal("expected non-exempt resolution")
	}
	if res.Config.CosignPublicKeyPEM != "key-a" {
		t.Fatalf("expected key-a, got %q", res.Config.CosignPublicKeyPEM)
	}
	if h, ok := res.Config.ArtifactHash("model-1"); !ok || h != "abc123" {
		t.Fatalf("expected model-1 -> abc123, got %q, ok=%v", h, ok)
	}
}

func TestResolve_ExemptSkipsConfig(t *testing.T) {
	p := &modelgatev1alpha1.ModelGatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "kube-system"},
		Spec: modelgatev1alpha1.ModelGatePolicySpec{
			CosignPublicKeyPEM: "key-a",
			Exempt:             true,
			ExemptionReason:    "system namespace",
		},
	}
	c := newFakeReader(t, p).Build()
	r := NewResolver(c)
	res, err := r.Resolve(context.Background(), "kube-system")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Exempt {
		t.Fatal("expected exempt resolution")
	}
	if res.ExemptionReason != "system namespace" {
		t.Fatalf("expected exemption reason to be carried through, got %q", res.ExemptionReason)
	}
	if res.Config != nil {
		t.Fatal("expected Config to be nil for an exempt resolution")
	}
}

func TestResolve_NamespacesAreIsolated(t *testing.T) {
	pa := &modelgatev1alpha1.ModelGatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns-a"},
		Spec:       modelgatev1alpha1.ModelGatePolicySpec{CosignPublicKeyPEM: "key-a"},
	}
	pb := &modelgatev1alpha1.ModelGatePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns-b"},
		Spec:       modelgatev1alpha1.ModelGatePolicySpec{CosignPublicKeyPEM: "key-b"},
	}
	c := newFakeReader(t, pa, pb).Build()
	r := NewResolver(c)

	resA, err := r.Resolve(context.Background(), "ns-a")
	if err != nil {
		t.Fatal(err)
	}
	resB, err := r.Resolve(context.Background(), "ns-b")
	if err != nil {
		t.Fatal(err)
	}
	if resA.Config.CosignPublicKeyPEM != "key-a" || resB.Config.CosignPublicKeyPEM != "key-b" {
		t.Fatalf("expected each namespace to resolve its own policy, got %q and %q",
			resA.Config.CosignPublicKeyPEM, resB.Config.CosignPublicKeyPEM)
	}
}

func TestResolve_MultiplePoliciesInOneNamespacePicksOldest(t *testing.T) {
	older := &modelgatev1alpha1.ModelGatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "older", Namespace: "ns-a",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
		Spec: modelgatev1alpha1.ModelGatePolicySpec{CosignPublicKeyPEM: "old-key"},
	}
	newer := &modelgatev1alpha1.ModelGatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "newer", Namespace: "ns-a",
			CreationTimestamp: metav1.NewTime(time.Now()),
		},
		Spec: modelgatev1alpha1.ModelGatePolicySpec{CosignPublicKeyPEM: "new-key"},
	}
	c := newFakeReader(t, newer, older).Build()
	r := NewResolver(c)
	res, err := r.Resolve(context.Background(), "ns-a")
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.CosignPublicKeyPEM != "old-key" {
		t.Fatalf("expected the oldest policy (%q) to win, got %q", "old-key", res.Config.CosignPublicKeyPEM)
	}
}
