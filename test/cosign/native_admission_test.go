package cosign

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	modelgatev1 "github.com/pavann19/modelgate/api/v1alpha1"
	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
	registrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Native API/crypto demonstration, not a kubelet/CNI/production deployment test.
// Fixture-only object selection intentionally creates a measurable API baseline.
func TestNativeAdmissionTrustAndOverhead(t *testing.T) {
	if os.Getenv("MODELGATE_NATIVE_ADMISSION") != "1" {
		t.Skip("explicit isolated native API profile required")
	}
	fixture := newTLSRegistry(t)
	environment := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crd")}, ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Logf("fixture stop (Windows job runner owns final cleanup): %v", err)
		}
	})
	scheme := k8sruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := modelgatev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	api, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, ns := range []string{"native-trust", "native-no-policy"} {
		if err := api.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"modelgate.dev/native": "fixture"}}}); err != nil {
			t.Fatal(err)
		}
	}
	trust := &modelgatev1.ModelGatePolicy{ObjectMeta: metav1.ObjectMeta{Name: "trusted", Namespace: "native-trust"}, Spec: modelgatev1.ModelGatePolicySpec{CosignPublicKeyPEM: fixture.publicKey}}
	if err := api.Create(ctx, trust); err != nil {
		t.Fatal(err)
	}
	handler := mgwebhook.NewHandler(policy.NewResolver(api))
	handler.Verifier = mgwebhook.CosignVerifier{RegistryPolicy: fixture.policy}
	handler.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	var called atomic.Int32
	admit := &admission.Webhook{Handler: handler}
	server := httptest.NewTLSServer(mgwebhook.BoundedAdmissionHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Add(1); admit.ServeHTTP(w, r) })))
	defer server.Close()
	url := server.URL
	failure := registrationv1.Fail
	timeout := int32(15)
	sideEffects := registrationv1.SideEffectClassNone
	hook := &registrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "native-trust-fixture"}, Webhooks: []registrationv1.ValidatingWebhook{{
		Name: "native.fixture.modelgate.dev", FailurePolicy: &failure, TimeoutSeconds: &timeout, SideEffects: &sideEffects,
		AdmissionReviewVersions: []string{"v1"}, ClientConfig: registrationv1.WebhookClientConfig{URL: &url, CABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"modelgate.dev/native": "fixture"}},
		ObjectSelector:    &metav1.LabelSelector{MatchLabels: map[string]string{"modelgate.dev/enforce": "fixture"}},
		Rules:             []registrationv1.RuleWithOperations{{Operations: []registrationv1.OperationType{registrationv1.Create}, Rule: registrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}}}},
	}}}
	if err := api.Create(ctx, hook); err != nil {
		t.Fatal(err)
	}
	create := func(ns, repo string, enforced bool, containers int) error {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "native-probe", Namespace: ns}, Spec: corev1.PodSpec{}}
		if enforced {
			pod.Labels = map[string]string{"modelgate.dev/enforce": "fixture"}
		}
		for i := 0; i < containers; i++ {
			pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: fmtName(i), Image: fixture.image(repo)})
		}
		request, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return api.Create(request, pod, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := create("native-trust", "signed", true, 1); err != nil {
			t.Fatal(err)
		}
		if called.Load() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("webhook was never observed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	falseAllows, falseDenies := 0, 0
	for _, repo := range []string{"signed", "unsigned", "wrong-signature", "wrong-repository", "wrong-artifact", "malformed-signature", "redirect-untrusted", "auth-untrusted", "bad-content"} {
		err := create("native-trust", repo, true, 1)
		if repo == "signed" {
			if err != nil {
				falseDenies++
				t.Errorf("valid image denied: %v", err)
			}
		} else if err == nil {
			falseAllows++
			t.Errorf("negative image admitted: %s", repo)
		} else if !apierrors.IsForbidden(err) {
			t.Errorf("negative %s was transport failure, not policy denial: %v", repo, err)
		}
	}
	if err := create("native-no-policy", "signed", true, 1); !apierrors.IsForbidden(err) {
		t.Fatalf("missing policy must deny: %v", err)
	}
	trust.Spec.CosignPublicKeyPEM = fixture.otherPublicKey
	if err := api.Update(ctx, trust); err != nil {
		t.Fatal(err)
	}
	if err := create("native-trust", "signed", true, 1); !apierrors.IsForbidden(err) {
		t.Fatalf("old key accepted after rotation: %v", err)
	}
	trust.Spec.CosignPublicKeyPEM = fixture.publicKey
	if err := api.Update(ctx, trust); err != nil {
		t.Fatal(err)
	}
	if err := create("native-trust", "signed", true, 1); err != nil {
		t.Fatalf("restored key positive control: %v", err)
	}
	type sample struct {
		Mode        string `json:"mode"`
		Containers  int    `json:"containers"`
		Nanoseconds int64  `json:"nanoseconds"`
	}
	samples := []sample{}
	first := time.Now()
	if err := create("native-trust", "signed", true, 1); err != nil {
		t.Fatal(err)
	}
	firstLatency := time.Since(first).Nanoseconds()
	for _, containers := range []int{1, 8} {
		for i := 0; i < 3; i++ {
			if err := create("native-trust", "signed", true, containers); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < 32; i++ {
			for j := 0; j < 2; j++ {
				// Reverse pair order on alternating iterations to limit order bias.
				enforced := (i+j)%2 == 0
				mode := "api-baseline"
				if enforced {
					mode = "admission-enabled"
				}
				beforeCalls := called.Load()
				started := time.Now()
				err := create("native-trust", "signed", enforced, containers)
				ns := time.Since(started).Nanoseconds()
				if err != nil {
					falseDenies++
					t.Fatalf("measured positive control failed: %v", err)
				}
				if enforced && called.Load() <= beforeCalls {
					t.Fatal("enabled measurement bypassed webhook")
				}
				if !enforced && called.Load() != beforeCalls {
					t.Fatal("baseline unexpectedly called webhook")
				}
				samples = append(samples, sample{mode, containers, ns})
			}
		}
	}
	quantiles := map[string]any{}
	for _, containers := range []int{1, 8} {
		for _, mode := range []string{"api-baseline", "admission-enabled"} {
			values := []int64{}
			var total int64
			for _, s := range samples {
				if s.Mode == mode && s.Containers == containers {
					values = append(values, s.Nanoseconds)
					total += s.Nanoseconds
				}
			}
			sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
			q := map[string]any{"count": len(values), "successful_requests_per_active_second": float64(len(values)) * 1e9 / float64(total)}
			for _, p := range []float64{.50, .90, .95, .99} {
				q[fmtPercent(p)] = float64(values[int(math.Ceil(p*float64(len(values))))-1]) / 1e6
			}
			quantiles[mode+"-"+fmtName(containers)] = q
		}
	}
	version, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	info, err := version.ServerVersion()
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{"schema_version": 1, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "kubernetes": info.GitVersion, "concurrency": 1, "warmups_per_workload": 3, "samples": samples, "summary": quantiles, "false_allows": falseAllows, "false_denies": falseDenies, "first_observed_measured_request_ns": firstLatency, "cache_semantics": "No cross-request trust cache; first observation is after correctness controls, not a cold process launch", "scope": "Native API server dry-run + real namespace policy read + TLS registry + real bounded crypto; API baseline deliberately excludes fixture webhook through object selector, never use that selector in production", "resource_scope": "See isolated runner receipt for whole-command CPU/peak process-tree memory; includes compilation/setup; no per-phase CPU or production capacity claim"}
	if directory := os.Getenv("MODELGATE_EVIDENCE_DIR"); directory != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		file, err := os.OpenFile(filepath.Join(directory, "admission-performance.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(data); err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
	t.Logf("actual API and cryptographic controls: false_allows=%d false_denies=%d; retained %d measured requests", falseAllows, falseDenies, len(samples))
}

func fmtName(i int) string        { return strconv.Itoa(i) }
func fmtPercent(p float64) string { return "p" + strconv.Itoa(int(p*100)) + "_ms" }
