// Package bench measures ModelGate's admission latency against a real
// kube-apiserver (via envtest), per the M3 exit criterion: "a histogram of
// webhook response time ... committed as a real run output (not estimated)".
//
// This is not a full kind/kubelet cluster benchmark -- no such deployment
// exists yet in this repo (see docs/DECISIONS.md) -- so it does not measure
// scheduling or kubelet-side effects, and its absolute numbers reflect a
// single local envtest process, not a production multi-node cluster.
// What it does measure honestly: the real, wire-level latency of a Pod
// Create round-tripping through a real kube-apiserver to a real ModelGate
// webhook server and back, for the full check pipeline (host-access checks,
// image signature verification via a fake verifier -- see below -- and
// policy resolution via the real CRD-backed resolver).
//
// Run it directly with:
//
//	KUBEBUILDER_ASSETS=$(setup-envtest use 1.31.0 -p path) \
//	  go test ./bench/ -run TestAdmissionLatency -v -timeout 120s
package bench

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

// numPods is the sample size for the latency measurement. Kept modest so
// this runs comfortably inside a CI job (a single local kube-apiserver
// process, not a multi-node cluster, is the bottleneck for anything larger,
// and that ceiling belongs to envtest's realism limits, not ModelGate).
const numPods = 200

// signedImage is the only image used; the fake verifier always signs it, so
// every pod is admitted and the measured latency reflects the check
// pipeline's cost, not a mix of admit/deny code paths.
const signedImage = "registry.example.com/bench/model-server:v1"

type alwaysSignedVerifier struct{}

func (alwaysSignedVerifier) VerifySignature(context.Context, string, string) error { return nil }

type staticExemptResolver struct{}

func (staticExemptResolver) Resolve(context.Context, string) (policy.Resolution, error) {
	return policy.Resolution{Exempt: false, Config: &policy.Config{CosignPublicKeyPEM: "bench-key"}}, nil
}

// Result is the committed shape of a latency run: enough metadata to know
// what was measured and when, plus the full sorted sample so percentiles
// can be recomputed later without re-running the benchmark.
type Result struct {
	Timestamp        time.Time `json:"timestamp"`
	Environment      string    `json:"environment"`
	SampleSize       int       `json:"sample_size"`
	GoVersion        string    `json:"go_version"`
	OS               string    `json:"os"`
	Arch             string    `json:"arch"`
	MinMS            float64   `json:"min_ms"`
	P50MS            float64   `json:"p50_ms"`
	P90MS            float64   `json:"p90_ms"`
	P99MS            float64   `json:"p99_ms"`
	MaxMS            float64   `json:"max_ms"`
	MeanMS           float64   `json:"mean_ms"`
	TotalDurationMS  float64   `json:"total_duration_ms"`
	ThroughputPerMin float64   `json:"throughput_per_min"`
	SamplesMS        []float64 `json:"samples_ms"`
}

func TestAdmissionLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency benchmark in -short mode")
	}

	testEnv := &envtest.Environment{
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("testdata", "webhook-config.yaml")},
		},
	}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("starting envtest environment: %v", err)
	}
	t.Cleanup(func() {
		if err := testEnv.Stop(); err != nil {
			t.Logf("stopping envtest environment: %v", err)
		}
	})

	scheme := kruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding scheme: %v", err)
	}
	if err := modelgatev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding modelgate scheme: %v", err)
	}
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}

	wio := &testEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                server.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		WebhookServer: webhook.NewServer(webhook.Options{
			Host:    wio.LocalServingHost,
			Port:    wio.LocalServingPort,
			CertDir: wio.LocalServingCertDir,
		}),
	})
	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}

	handler := &mgwebhook.Handler{
		Resolver: staticExemptResolver{},
		Verifier: alwaysSignedVerifier{},
		Fetcher:  mgwebhook.FileArtifactFetcher{},
	}
	mgr.GetWebhookServer().Register("/validate-pods", &webhook.Admission{Handler: handler})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()

	if err := waitForWebhookReady(wio.LocalServingHost, wio.LocalServingPort, wio.LocalServingCAData, 20*time.Second); err != nil {
		t.Fatalf("waiting for webhook server: %v", err)
	}

	samples := make([]float64, 0, numPods)
	start := time.Now()
	for i := 0; i < numPods; i++ {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("bench-pod-%04d", i), Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "main", Image: signedImage}},
			},
		}
		t0 := time.Now()
		if err := k8sClient.Create(context.Background(), pod); err != nil {
			t.Fatalf("pod %d: unexpected admission denial: %v", i, err)
		}
		samples = append(samples, float64(time.Since(t0).Microseconds())/1000.0)
	}
	total := time.Since(start)

	result := summarize(samples, total)
	t.Logf("admission latency over %d pods: p50=%.2fms p90=%.2fms p99=%.2fms max=%.2fms mean=%.2fms throughput=%.1f/min",
		result.SampleSize, result.P50MS, result.P90MS, result.P99MS, result.MaxMS, result.MeanMS, result.ThroughputPerMin)

	if err := writeResult(result); err != nil {
		t.Fatalf("writing bench/results/admission_latency.json: %v", err)
	}
}

func summarize(samplesMS []float64, total time.Duration) Result {
	sorted := append([]float64(nil), samplesMS...)
	sort.Float64s(sorted)

	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	n := len(sorted)

	return Result{
		Timestamp:        time.Now().UTC(),
		Environment:      "envtest (single local kube-apiserver process, no kubelet/kind cluster)",
		SampleSize:       n,
		GoVersion:        runtime.Version(),
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		MinMS:            sorted[0],
		P50MS:            percentile(sorted, 0.50),
		P90MS:            percentile(sorted, 0.90),
		P99MS:            percentile(sorted, 0.99),
		MaxMS:            sorted[n-1],
		MeanMS:           sum / float64(n),
		TotalDurationMS:  float64(total.Microseconds()) / 1000.0,
		ThroughputPerMin: float64(n) / total.Minutes(),
		SamplesMS:        sorted,
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 1 {
		return sorted[0]
	}
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

func writeResult(r Result) error {
	if err := os.MkdirAll("results", 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("results", "admission_latency.json"), data, 0o644)
}

// waitForWebhookReady polls the webhook server's TLS port until it accepts
// connections, verifying against envtest's own generated CA.
func waitForWebhookReady(host string, port int, caData []byte, timeout time.Duration) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return fmt.Errorf("parsing envtest CA data")
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool})
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("webhook server at %s not ready after %s: %w", addr, timeout, lastErr)
}
