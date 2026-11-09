package failurepolicy

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	registrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

// A real isolated API server exercises injected transport faults. Overload is
// an injected 503 here; actual decoder saturation/recovery has separate tests.
func TestFailurePolicyFaultMatrix(t *testing.T) {
	environment := &envtest.Environment{}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Logf("fixture stop: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	api, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "modelgate-fault-fixture"}}
	if err := api.Create(ctx, namespace); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []registrationv1.FailurePolicyType{registrationv1.Fail, registrationv1.Ignore} {
		for _, fault := range []string{"timeout", "connection-refused", "invalid-response", "panic", "overload"} {
			t.Run(string(policy)+"/"+fault, func(t *testing.T) {
				var failing atomic.Bool
				var observed atomic.Int32
				server := httptest.NewTLSServer(mgwebhook.BoundedAdmissionHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					observed.Add(1)
					if failing.Load() {
						switch fault {
						case "timeout":
							select {
							case <-r.Context().Done():
							case <-time.After(2 * time.Second):
							}
							return
						case "invalid-response":
							_, _ = w.Write([]byte("invalid-json"))
							return
						case "panic":
							panic("synthetic-panic-no-sensitive-output")
						case "overload":
							http.Error(w, "synthetic saturation", 503)
							return
						}
					}
					var review admissionv1.AdmissionReview
					if err := json.NewDecoder(r.Body).Decode(&review); err != nil || review.Request == nil {
						http.Error(w, "invalid review", 400)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Response: &admissionv1.AdmissionResponse{UID: review.Request.UID, Allowed: true}})
				})))
				defer server.Close()
				ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
				id := strings.ToLower(string(policy)) + "-" + fault
				url := server.URL
				timeout := int32(1)
				sideEffects := registrationv1.SideEffectClassNone
				hook := &registrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "modelgate-fault-" + id}, Webhooks: []registrationv1.ValidatingWebhook{{
					Name: id + ".fixture.modelgate.dev", AdmissionReviewVersions: []string{"v1"}, FailurePolicy: &policy, TimeoutSeconds: &timeout, SideEffects: &sideEffects,
					ClientConfig:   registrationv1.WebhookClientConfig{URL: &url, CABundle: ca},
					ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"modelgate.dev/fault": id}},
					Rules:          []registrationv1.RuleWithOperations{{Operations: []registrationv1.OperationType{registrationv1.Create}, Rule: registrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}}}},
				}}}
				if err := api.Create(ctx, hook); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := api.Delete(ctx, hook); err != nil {
						t.Logf("hook cleanup: %v", err)
					}
				}()
				create := func() error {
					pod := namedPod("fault-" + id)
					pod.Namespace = namespace.Name
					pod.Labels = map[string]string{"modelgate.dev/fault": id}
					requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					return api.Create(requestCtx, pod, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				}
				deadline := time.Now().Add(10 * time.Second)
				for {
					if err := create(); err != nil {
						t.Fatalf("healthy control: %v", err)
					}
					if observed.Load() > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("API server never called healthy fixture; refusing a bypass-based pass")
					}
					time.Sleep(100 * time.Millisecond)
				}
				failing.Store(true)
				beforeFault := observed.Load()
				if fault == "connection-refused" {
					server.Close()
				}
				failure := create()
				if (failure == nil) != (policy == registrationv1.Ignore) {
					t.Fatalf("fault=%s policy=%s unexpected admission error=%v", fault, policy, failure)
				}
				if policy == registrationv1.Fail && (!apierrors.IsInternalError(failure) || !strings.Contains(failure.Error(), hook.Webhooks[0].Name)) {
					t.Fatalf("failure did not identify this webhook call: %v", failure)
				}
				if fault != "connection-refused" && observed.Load() <= beforeFault {
					t.Fatal("failing request never reached fault fixture")
				}
				t.Logf("actual API server: healthy observed, injected=%s, policy=%s, admitted=%t", fault, policy, failure == nil)
			})
		}
	}
}
