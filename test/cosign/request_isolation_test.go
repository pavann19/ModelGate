package cosign

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pavann19/modelgate/internal/policy"
	"github.com/pavann19/modelgate/internal/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type namespaceKeys map[string]string

func (r namespaceKeys) Resolve(_ context.Context, ns string) (policy.Resolution, error) {
	key, ok := r[ns]
	if !ok {
		return policy.Resolution{}, policy.ErrNoPolicy
	}
	return policy.Resolution{Config: &policy.Config{CosignPublicKeyPEM: key}}, nil
}

func TestRepeatedImagesRespectRealSignaturesAndPolicyChanges(t *testing.T) {
	requireTool(t, "cosign")
	f := newTLSRegistry(t)
	keys := namespaceKeys{"tenant-a": f.publicKey, "tenant-b": f.otherPublicKey}
	h := webhook.NewHandler(keys)
	h.Verifier = webhook.CosignVerifier{RegistryPolicy: f.policy}
	check := func(namespace, repo string, allowed bool) {
		t.Helper()
		pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "repeated", Namespace: namespace}}
		for i := 0; i < 8; i++ {
			pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: string(rune('a' + i)), Image: f.image(repo)})
		}
		raw, err := json.Marshal(pod)
		if err != nil {
			t.Fatal(err)
		}
		response := h.Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Namespace: namespace, Object: runtime.RawExtension{Raw: raw}}})
		if response.Allowed != allowed {
			t.Fatalf("namespace=%s repo=%s allowed=%v, response=%+v", namespace, repo, allowed, response)
		}
	}
	check("tenant-a", "signed", true)
	check("tenant-b", "signed", false)
	check("tenant-b", "wrong-signature", true) // This fixture is genuinely signed by the second key.
	keys["tenant-a"] = f.otherPublicKey
	check("tenant-a", "signed", false)
	check("tenant-a", "wrong-signature", true)
	for _, repo := range []string{"unsigned", "wrong-artifact", "wrong-repository", "bad-content", "malformed-signature"} {
		check("tenant-a", repo, false)
	}
	keys["tenant-a"] = f.publicKey
	check("tenant-a", "signed", true)
}
