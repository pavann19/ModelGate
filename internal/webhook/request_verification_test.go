package webhook

import (
	"context"
	"fmt"
	"testing"

	"github.com/pavann19/modelgate/internal/policy"
	corev1 "k8s.io/api/core/v1"
)

type countingVerifier struct {
	calls int
	key   string
	fail  bool
}

func (v *countingVerifier) VerifySignature(_ context.Context, _, key string) error {
	v.calls++
	if v.fail || key != v.key {
		return fmt.Errorf("verification denied")
	}
	return nil
}

func TestHandle_VerifiesDuplicateImagesOncePerRequest(t *testing.T) {
	v := &countingVerifier{key: "key-a"}
	cfg := &policy.Config{CosignPublicKeyPEM: "key-a"}
	h := NewHandler(resolverFor("default", cfg))
	h.Verifier = v
	pod := basicPod("registry.example/model@sha256:abc")
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar", Image: pod.Spec.Containers[0].Image})
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: pod.Spec.Containers[0].Image}}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: pod.Spec.Containers[0].Image}}}
	req := podRequest(t, pod)
	if !h.Handle(context.Background(), req).Allowed || v.calls != 1 {
		t.Fatalf("expected one verification for duplicate images, calls=%d", v.calls)
	}
	if !h.Handle(context.Background(), req).Allowed || v.calls != 2 {
		t.Fatalf("verification reused across requests, calls=%d", v.calls)
	}
	// A previously successful request must not hide an outage.
	v.fail = true
	if h.Handle(context.Background(), req).Allowed {
		t.Fatal("cached success bypassed verifier failure")
	}
	v.fail = false
	cfg.CosignPublicKeyPEM = "key-b"
	if h.Handle(context.Background(), req).Allowed {
		t.Fatal("cached success bypassed key rotation")
	}
	// A second namespace must not inherit the first namespace's success.
	h.Resolver = resolverFor("other", cfg)
	pod.Namespace = "other"
	if h.Handle(context.Background(), podRequest(t, pod)).Allowed {
		t.Fatal("cross-namespace verification reused")
	}
}

func TestHandle_DistinctImagesStillVerified(t *testing.T) {
	for _, kind := range []string{"regular", "init", "ephemeral"} {
		t.Run(kind, func(t *testing.T) {
			pod := basicPod("good")
			bad := corev1.Container{Name: "bad", Image: "bad"}
			switch kind {
			case "regular":
				pod.Spec.Containers = append(pod.Spec.Containers, bad)
			case "init":
				pod.Spec.InitContainers = []corev1.Container{bad}
			case "ephemeral":
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "bad", Image: "bad"}}}
			}
			h := NewHandler(resolverFor("default", &policy.Config{}))
			h.Verifier = &fakeVerifier{signedImages: map[string]bool{"good": true}}
			if h.Handle(context.Background(), podRequest(t, pod)).Allowed {
				t.Fatal("distinct unsigned image admitted")
			}
		})
	}
}
