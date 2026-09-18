// Command webhook runs the ModelGate ValidatingAdmissionWebhook server.
package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

func main() {
	var (
		metricsAddr = flag.String("metrics-bind-address", ":8443", "metrics endpoint address")
		certDir     = flag.String("cert-dir", "/tmp/k8s-webhook-server/serving-certs", "webhook TLS cert directory")
		webhookPort = flag.Int("webhook-port", 9443, "webhook server port")
	)
	flag.Parse()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		exitf("adding client-go scheme: %v", err)
	}
	if err := modelgatev1alpha1.AddToScheme(scheme); err != nil {
		exitf("adding modelgate scheme: %v", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:  scheme,
		Metrics: server.Options{BindAddress: *metricsAddr},
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

	mgr.GetWebhookServer().Register("/validate-pods", &webhook.Admission{Handler: handler})

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		exitf("running manager: %v", err)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
