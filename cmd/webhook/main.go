// Command webhook runs the ModelGate ValidatingAdmissionWebhook server.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

func main() {
	var (
		metricsAddr = flag.String("metrics-bind-address", ":8443", "metrics endpoint address")
		certDir     = flag.String("cert-dir", "/tmp/k8s-webhook-server/serving-certs", "webhook TLS cert directory")
		policyPath  = flag.String("policy-file", "/etc/modelgate/policy.json", "path to the MVP policy JSON file")
		webhookPort = flag.Int("webhook-port", 9443, "webhook server port")
	)
	flag.Parse()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		exitf("adding client-go scheme: %v", err)
	}

	cfg, err := loadPolicy(*policyPath)
	if err != nil {
		exitf("loading policy: %v", err)
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

	handler, err := mgwebhook.NewHandler(cfg)
	if err != nil {
		exitf("creating webhook handler: %v", err)
	}

	mgr.GetWebhookServer().Register("/validate-pods", &webhook.Admission{Handler: handler})

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		exitf("running manager: %v", err)
	}
}

func loadPolicy(path string) (*policy.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg policy.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

var _ admission.Handler = (*mgwebhook.Handler)(nil)
