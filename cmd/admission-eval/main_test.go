package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"

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
		var pod corev1.Pod
		if err := json.NewDecoder(r.Body).Decode(&pod); err != nil {
			t.Error(err)
		}
		if len(pod.Spec.Containers) != 8 {
			t.Errorf("wrong workload: %d containers", len(pod.Spec.Containers))
		}
		seen := map[string]bool{}
		for _, c := range pod.Spec.Containers {
			if seen[c.Name] || c.Image != "registry.example/image@sha256:abc" {
				t.Error("invalid duplicate-image workload")
			}
			seen[c.Name] = true
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
	s := measure(context.Background(), client, "eval", "registry.example/image@sha256:abc", 7, 8)
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

func TestDistinctImageControlPreservesEachReference(t *testing.T) {
	images := []string{"registry.example/signed0@sha256:a", "registry.example/signed1@sha256:b"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pod corev1.Pod
		if err := json.NewDecoder(r.Body).Decode(&pod); err != nil {
			t.Error(err)
		}
		if len(pod.Spec.Containers) != 8 {
			t.Fatal("wrong container count")
		}
		for i, c := range pod.Spec.Containers {
			if c.Image != images[i%2] {
				t.Error("distinct image collapsed")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"fixture"}}`))
	}))
	defer server.Close()
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if got := measureImages(context.Background(), client, "eval", images, 1, 8); got.Outcome != "allowed" {
		t.Fatal(got)
	}
}
