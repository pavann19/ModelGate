package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestOutcomesDoNotConfuseTransportFailureWithPolicyDenial(t *testing.T) {
	for _, tc := range []struct{ message, want string }{
		{`admission webhook "validate-pods.modelgate.dev" denied the request: unsigned or invalid image`, "policy_denied"},
		{`admission webhook "validate-pods.modelgate.dev" denied the request: admission capacity exhausted; retry later`, "saturated"},
		{`failed calling webhook: connection refused`, "webhook_unavailable"},
		{`pods is forbidden: User cannot create resource pods`, "request_error"},
		{`context deadline exceeded`, "request_error"},
	} {
		if got := outcome(errors.New(tc.message)); got != tc.want {
			t.Fatalf("%q classified %q, want %q", tc.message, got, tc.want)
		}
	}
	if outcome(nil) != "allowed" {
		t.Fatal("successful API admission misclassified")
	}
	if matches("policy_denied", "webhook_unavailable") || matches("overload", "request_error") || matches("saturation", "allowed") {
		t.Fatal("failure boundary weakened")
	}
}

func TestMeasurementUsesDryRunAndDoesNotRetryRateLimits(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/api/v1/namespaces/eval/pods" || r.URL.Query().Get("dryRun") != "All" {
			t.Error("request could persist a workload or address the wrong API resource")
		}
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"TooManyRequests","message":"API throttled","code":429}`))
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	s := measure(context.Background(), client, "eval", "registry.example/image@sha256:abc", 7)
	if calls.Load() != 1 || s.Outcome != "request_error" || s.Index != 7 {
		t.Fatalf("rate-limit retry or misclassification: calls=%d sample=%+v", calls.Load(), s)
	}
}

func TestNearestRankRetainsTailOutlier(t *testing.T) {
	values := make([]float64, 100)
	for i := range values {
		values[i] = float64(i + 1)
	}
	values[99] = 10000
	if percentile(values, .50) != 50 || percentile(values, .95) != 95 || percentile(values, .99) != 99 || percentile(values, 1) != 10000 {
		t.Fatal("nearest-rank percentile incorrect")
	}
}
