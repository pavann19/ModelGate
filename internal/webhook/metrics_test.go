package webhook

import (
	"context"
	"testing"

	"github.com/pavann19/modelgate/internal/policy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestHandleRecordsAllowedDecisionMetric(t *testing.T) {
	metric := admissionDecisions.WithLabelValues("allowed", "checks_passed")
	before := testutil.ToFloat64(metric)

	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, basicPod("good:latest")))
	if !resp.Allowed {
		t.Fatalf("expected allowed response, got %s", resp.Result.Message)
	}

	after := testutil.ToFloat64(metric)
	if after != before+1 {
		t.Fatalf("allowed decision counter delta = %v, want 1", after-before)
	}
}

func TestHandleRecordsBoundedDenialReasonMetric(t *testing.T) {
	metric := admissionDecisions.WithLabelValues("denied", "image_signature")
	before := testutil.ToFloat64(metric)

	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, basicPod("unsigned:latest")))
	if resp.Allowed {
		t.Fatal("expected unsigned image to be denied")
	}

	after := testutil.ToFloat64(metric)
	if after != before+1 {
		t.Fatalf("image-signature denial counter delta = %v, want 1", after-before)
	}
}
