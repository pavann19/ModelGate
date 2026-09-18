// Package failurepolicy proves, against a real kube-apiserver, that the
// ValidatingWebhookConfiguration's failurePolicy actually behaves as
// documented when the ModelGate webhook itself goes unreachable mid-test:
// failurePolicy: Fail must deny, and failurePolicy: Ignore must admit. This
// is the M2 exit criterion -- measured for real, not asserted from reading
// the Kubernetes docs.
//
// It is a separate package (not part of test/e2e) because each scenario
// needs its own envtest.Environment with a different ValidatingWebhookConfig
// installed, and boots/tears down its own environment per test rather than
// sharing one via TestMain, since the whole point is starting and then
// killing the webhook process within a single test.
package failurepolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

// alwaysExemptResolver isolates these tests from the admission rules
// themselves (already covered by test/e2e and internal/webhook's unit
// tests): every request is exempted, so while the webhook is reachable
// every pod is admitted, and the only thing that can cause a denial is the
// failurePolicy path once the webhook goes away.
type alwaysExemptResolver struct{}

func (alwaysExemptResolver) Resolve(_ context.Context, _ string) (policy.Resolution, error) {
	return policy.Resolution{Exempt: true, ExemptionReason: "failurepolicy test: always exempt"}, nil
}

func TestFailurePolicy_Fail_DeniesOnceWebhookIsKilled(t *testing.T) {
	runScenario(t, "webhook-fail.yaml", func(t *testing.T, before, after error) {
		if before != nil {
			t.Fatalf("expected the first pod (webhook reachable) to be admitted, got: %v", before)
		}
		if after == nil {
			t.Fatal("expected the second pod (webhook killed, failurePolicy: Fail) to be denied")
		}
		if !apierrors.IsForbidden(after) && !apierrors.IsInternalError(after) && !apierrors.IsTimeout(after) && !apierrors.IsServiceUnavailable(after) {
			t.Fatalf("expected an admission-rejection error class for an unreachable Fail-policy webhook, got: %v", after)
		}
	})
}

func TestFailurePolicy_Ignore_AdmitsOnceWebhookIsKilled(t *testing.T) {
	runScenario(t, "webhook-ignore.yaml", func(t *testing.T, before, after error) {
		if before != nil {
			t.Fatalf("expected the first pod (webhook reachable) to be admitted, got: %v", before)
		}
		if after != nil {
			t.Fatalf("expected the second pod (webhook killed, failurePolicy: Ignore) to still be admitted, got: %v", after)
		}
	})
}

// runScenario boots a fresh envtest environment with the named webhook
// config, starts a real ModelGate webhook server, creates one pod (proving
// the webhook is up and reachable), kills the webhook server (simulating
// the deployment going down mid-operation), then creates a second pod and
// hands both Create errors to check.
func runScenario(t *testing.T, webhookConfigFile string, check func(t *testing.T, before, after error)) {
	t.Helper()

	testEnv := &envtest.Environment{
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("testdata", webhookConfigFile)},
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

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding scheme: %v", err)
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

	handler := mgwebhook.NewHandler(alwaysExemptResolver{})
	mgr.GetWebhookServer().Register("/validate-pods", &webhook.Admission{Handler: handler})

	ctx, cancel := context.WithCancel(context.Background())
	mgrErr := make(chan error, 1)
	go func() { mgrErr <- mgr.Start(ctx) }()

	if err := waitForPort(wio.LocalServingHost, wio.LocalServingPort, wio.LocalServingCAData, true, 20*time.Second); err != nil {
		cancel()
		t.Fatalf("waiting for webhook server to come up: %v", err)
	}

	beforeErr := k8sClient.Create(context.Background(), namedPod("before-kill"))

	// Kill the webhook: cancel the manager's context, which triggers
	// controller-runtime's graceful shutdown and closes the TLS listener --
	// the in-process equivalent of the webhook Deployment being terminated.
	cancel()
	select {
	case <-mgrErr:
	case <-time.After(10 * time.Second):
		t.Fatal("manager did not shut down after context cancellation")
	}
	if err := waitForPort(wio.LocalServingHost, wio.LocalServingPort, wio.LocalServingCAData, false, 10*time.Second); err != nil {
		t.Fatalf("waiting for webhook server to go down: %v", err)
	}

	afterErr := k8sClient.Create(context.Background(), namedPod("after-kill"))

	check(t, beforeErr, afterErr)
}

func namedPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "example.com/whatever:v1"}},
		},
	}
}

// waitForPort polls the webhook's TLS port until it either accepts (wantUp)
// or refuses (!wantUp) connections, verifying against envtest's own CA
// rather than skipping verification.
func waitForPort(host string, port int, caData []byte, wantUp bool, timeout time.Duration) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return fmt.Errorf("parsing envtest CA data")
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool})
		up := err == nil
		if conn != nil {
			conn.Close()
		}
		if up == wantUp {
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if wantUp {
		return fmt.Errorf("webhook server at %s not ready after %s: %w", addr, timeout, lastErr)
	}
	return fmt.Errorf("webhook server at %s still accepting connections after %s", addr, timeout)
}

var _ admission.Handler = (*mgwebhook.Handler)(nil)
