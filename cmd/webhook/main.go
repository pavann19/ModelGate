// Command webhook runs the ModelGate ValidatingAdmissionWebhook server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

func main() {
	var (
		metricsAddr        = flag.String("metrics-bind-address", ":8443", "metrics endpoint address")
		certDir            = flag.String("cert-dir", "/tmp/k8s-webhook-server/serving-certs", "webhook TLS cert directory")
		registryPolicyPath = flag.String("registry-policy-file", "/etc/modelgate/registry-policy.json", "operator-owned registry destination policy")
		webhookPort        = flag.Int("webhook-port", 9443, "webhook server port")
		probeAddr          = flag.String("health-probe-bind-address", ":8081", "internal health probe address")
		prestopDelay       = flag.Duration("prestop-delay", 0, "bounded standalone termination hook delay (at most 10s)")
	)
	flag.Parse()
	// Distroless has no sleep binary. Kubernetes removes terminating endpoints
	// before invoking this helper; keep the existing listener alive while that
	// update propagates, then SIGTERM starts the bounded manager drain.
	if *prestopDelay != 0 {
		if *prestopDelay < 0 || *prestopDelay > 10*time.Second {
			exitf("prestop delay must be positive and at most 10s")
		}
		time.Sleep(*prestopDelay)
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx := ctrl.SetupSignalHandler()
	shutdownTimeout := 25 * time.Second
	registryPolicy, err := mgwebhook.LoadRegistryPolicy(*registryPolicyPath)
	if err != nil {
		exitf("registry destination policy is invalid: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		exitf("adding client-go scheme: %v", err)
	}
	if err := modelgatev1alpha1.AddToScheme(scheme); err != nil {
		exitf("adding modelgate scheme: %v", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 server.Options{BindAddress: *metricsAddr},
		HealthProbeBindAddress:  *probeAddr,
		GracefulShutdownTimeout: &shutdownTimeout,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:    *webhookPort,
			CertDir: *certDir,
		}),
	})
	if err != nil {
		exitf("creating manager: %v", err)
	}

	// Use the direct API reader, not the cached client: a ModelGatePolicy
	// created moments before a pod in the same namespace must never be
	// missed because an informer hasn't synced yet.
	resolver := policy.NewResolver(mgr.GetAPIReader())
	handler := mgwebhook.NewHandler(resolver)
	handler.Verifier = mgwebhook.CosignVerifier{RegistryPolicy: registryPolicy}

	mgr.GetWebhookServer().Register("/validate-pods", &webhook.Admission{Handler: handler})
	if err := mgr.AddHealthzCheck("process", healthz.Ping); err != nil {
		exitf("registering liveness: %v", err)
	}
	if err := mgr.AddReadyzCheck("serving", servingCheck(ctx, mgr.GetWebhookServer().StartedChecker())); err != nil {
		exitf("registering readiness: %v", err)
	}

	if err := mgr.Start(ctx); err != nil {
		exitf("running manager: %v", err)
	}
}

// Readiness includes a real TLS handshake, and turns false as soon as shutdown
// starts. Liveness deliberately does not depend on registry/model availability.
func servingCheck(ctx context.Context, started healthz.Checker) healthz.Checker {
	return func(r *http.Request) error {
		if ctx.Err() != nil {
			return errors.New("draining")
		}
		return started(r)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
