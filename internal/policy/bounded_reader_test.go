package policy

import (
	"context"
	"testing"

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type paginatedReader struct {
	client.Reader
	limit int64
}

func (r *paginatedReader) List(_ context.Context, output client.ObjectList, options ...client.ListOption) error {
	listOptions := &client.ListOptions{}
	for _, option := range options {
		option.ApplyToList(listOptions)
	}
	r.limit = listOptions.Limit
	list := output.(*modelgatev1alpha1.ModelGatePolicyList)
	list.Continue = "more-policies-exist"
	list.Items = []modelgatev1alpha1.ModelGatePolicy{{Spec: modelgatev1alpha1.ModelGatePolicySpec{
		Exempt: true, ExemptionReason: "must not hide other policies",
	}}}
	return nil
}

func TestPaginatedPolicyCannotGrantExemption(t *testing.T) {
	reader := &paginatedReader{}
	resolution, err := NewResolver(reader).Resolve(context.Background(), "tenant")
	if reader.limit != 2 {
		t.Fatalf("unbounded policy read: %d", reader.limit)
	}
	if err == nil || resolution.Exempt {
		t.Fatal("partial policy list granted exemption")
	}
}
