// Package e2e exercises the ModelGate admission Handler through a real
// Kubernetes API server (envtest: a real kube-apiserver + etcd, no kubelet)
// and a real ValidatingWebhookConfiguration -- proving the wiring, TLS, and
// admission-rule plumbing actually work together, not just the Handle()
// logic in isolation (that's covered by internal/webhook's unit tests).
package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
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

	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

// signedImage/unsignedImage stand in for real cosign-signed/unsigned image
// references. Real cosign verification is unit-tested separately
// (internal/webhook/verifier.go shells to the real cosign binary); this
// suite fakes the verifier so it can prove the *webhook plumbing* -- API
// server, TLS, ValidatingWebhookConfiguration routing, Handle() dispatch --
// without needing a real signed image and registry in CI.
const (
	signedImage   = "registry.example.com/good/model-server:v1"
	unsignedImage = "registry.example.com/evil/model-server:v1"
)

var goodArtifactData = buildSafetensors(`{"__metadata__":{}}`, []byte{1, 2, 3, 4})

const goodArtifactID = "resnet50-v1"

var testK8sClient client.Client

// TestMain starts one shared envtest environment (kube-apiserver + etcd)
// and one shared webhook server for every test in this package, since each
// is expensive to boot. Individual tests only vary which pod they submit.
func TestMain(m *testing.M) {
	code, err := runWithEnv(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runWithEnv(m *testing.M) (int, error) {
	testEnv := &envtest.Environment{
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join("testdata", "webhook-config.yaml")},
		},
	}

	cfg, err := testEnv.Start()
	if err != nil {
		return 0, fmt.Errorf("starting envtest environment: %w", err)
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "stopping envtest environment: %v\n", err)
		}
	}()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return 0, fmt.Errorf("adding scheme: %w", err)
	}

	testK8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return 0, fmt.Errorf("creating client: %w", err)
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
		return 0, fmt.Errorf("creating manager: %w", err)
	}

	handler := &mgwebhook.Handler{
		Policy: &policy.Config{
			ArtifactAllowList: map[string]string{
				goodArtifactID: sha256Hex(goodArtifactData),
			},
		},
		Verifier: &fakeVerifier{signed: map[string]bool{signedImage: true}},
		Fetcher:  &fakeFetcher{data: map[string][]byte{goodArtifactID: goodArtifactData}},
	}
	mgr.GetWebhookServer().Register("/validate-pods", &webhook.Admission{Handler: handler})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgrErr := make(chan error, 1)
	go func() { mgrErr <- mgr.Start(ctx) }()

	if err := waitForWebhookReady(wio.LocalServingHost, wio.LocalServingPort, wio.LocalServingCAData, 20*time.Second); err != nil {
		return 0, fmt.Errorf("waiting for webhook server: %w", err)
	}

	code := m.Run()

	cancel()
	select {
	case err := <-mgrErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "manager exited with error: %v\n", err)
		}
	case <-time.After(5 * time.Second):
	}

	return code, nil
}

// fakeVerifier and fakeFetcher mirror internal/webhook's test fakes; they
// are redeclared here (rather than imported, since they're unexported in
// that package) to keep the e2e suite import-clean.
type fakeVerifier struct{ signed map[string]bool }

func (f *fakeVerifier) VerifySignature(_ context.Context, image string) error {
	if f.signed[image] {
		return nil
	}
	return fmt.Errorf("image %q is not signed", image)
}

type fakeFetcher struct{ data map[string][]byte }

func (f *fakeFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	d, ok := f.data[ref]
	if !ok {
		return nil, fmt.Errorf("no fixture for %q", ref)
	}
	return d, nil
}

func buildSafetensors(header string, body []byte) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(header)))
	buf = append(buf, header...)
	buf = append(buf, body...)
	return buf
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func namedPod(name, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: image}},
		},
	}
}

func TestEnvtest_AdmitsSignedPod(t *testing.T) {
	pod := namedPod("good-pod", signedImage)
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("expected signed pod to be admitted through the real webhook, got: %v", err)
	}
}

func TestEnvtest_RejectsUnsignedImage(t *testing.T) {
	pod := namedPod("unsigned-pod", unsignedImage)
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected pod with unsigned image to be rejected by the real webhook")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

func TestEnvtest_RejectsPrivilegedContainer(t *testing.T) {
	priv := true
	pod := namedPod("privileged-pod", signedImage)
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &priv}
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected privileged pod to be rejected by the real webhook")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

func TestEnvtest_RejectsHostNetwork(t *testing.T) {
	pod := namedPod("hostnetwork-pod", signedImage)
	pod.Spec.HostNetwork = true
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected hostNetwork pod to be rejected by the real webhook")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

func TestEnvtest_RejectsHostPathVolume(t *testing.T) {
	pod := namedPod("hostpath-pod", signedImage)
	pod.Spec.Volumes = []corev1.Volume{{
		Name:         "hostvol",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}},
	}}
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected hostPath pod to be rejected by the real webhook")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

func TestEnvtest_AdmitsValidModelArtifact(t *testing.T) {
	pod := namedPod("model-pod", signedImage)
	pod.Annotations = map[string]string{mgwebhook.ModelArtifactAnnotation: goodArtifactID}
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("expected pod with valid, allow-listed model artifact to be admitted, got: %v", err)
	}
}

func TestEnvtest_RejectsArtifactNotOnAllowList(t *testing.T) {
	pod := namedPod("unknown-model-pod", signedImage)
	pod.Annotations = map[string]string{mgwebhook.ModelArtifactAnnotation: "not-on-allow-list"}
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected pod referencing an unlisted model artifact to be rejected")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

// waitForWebhookReady polls the webhook server's TLS port until it accepts
// connections, since the manager's Start() returns before the webhook
// listener is guaranteed to be up. It verifies against envtest's own
// generated CA rather than skipping verification.
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
