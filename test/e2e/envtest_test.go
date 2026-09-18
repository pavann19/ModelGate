// Package e2e exercises the ModelGate admission Handler through a real
// Kubernetes API server (envtest: a real kube-apiserver + etcd, no kubelet),
// a real ValidatingWebhookConfiguration, and real ModelGatePolicy CRD
// objects -- proving the wiring, TLS, CRD schema, and per-namespace policy
// selection all work together end to end, not just Handle() logic and
// Resolve() logic in isolation (that's covered by internal/webhook's and
// internal/policy's own unit tests).
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

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
	"github.com/pavann19/modelgate/internal/policy"
	mgwebhook "github.com/pavann19/modelgate/internal/webhook"
)

// signedImage/unsignedImage stand in for real cosign-signed/unsigned image
// references. Real cosign verification is unit-tested separately
// (internal/webhook/verifier.go shells to the real cosign binary); this
// suite fakes the verifier so it can prove the *webhook and CRD plumbing* --
// API server, TLS, ValidatingWebhookConfiguration routing, ModelGatePolicy
// lookup, Handle() dispatch -- without needing a real signed image/registry.
const (
	signedImage   = "registry.example.com/good/model-server:v1"
	unsignedImage = "registry.example.com/evil/model-server:v1"
	testCosignKey = "-----BEGIN PUBLIC KEY-----\ntest-key-not-real\n-----END PUBLIC KEY-----"

	defaultNamespace  = "default"
	exemptNamespace   = "exempt-ns"
	noPolicyNamespace = "no-policy-ns"
	strictNamespace   = "strict-ns"
)

var goodArtifactData = buildSafetensors(`{"__metadata__":{}}`, []byte{1, 2, 3, 4})

const goodArtifactID = "resnet50-v1"

var testK8sClient client.Client

// TestMain starts one shared envtest environment (kube-apiserver + etcd,
// with the ModelGatePolicy CRD installed) and one shared webhook server for
// every test in this package, since each is expensive to boot. It also
// seeds the namespaces and ModelGatePolicy objects the tests select between.
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
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "deploy", "crd")},
		ErrorIfCRDPathMissing: true,
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
		return 0, fmt.Errorf("adding client-go scheme: %w", err)
	}
	if err := modelgatev1alpha1.AddToScheme(scheme); err != nil {
		return 0, fmt.Errorf("adding modelgate scheme: %w", err)
	}

	testK8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return 0, fmt.Errorf("creating client: %w", err)
	}

	if err := seedNamespacesAndPolicies(testK8sClient); err != nil {
		return 0, fmt.Errorf("seeding fixtures: %w", err)
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

	// testK8sClient reads directly from the API server (it is not the
	// manager's cached client), which is exactly the freshness property
	// production wants from the resolver -- see internal/policy.Resolver.
	resolver := &policy.Resolver{Reader: testK8sClient}
	handler := &mgwebhook.Handler{
		Resolver: resolver,
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

// seedNamespacesAndPolicies creates the namespaces and ModelGatePolicy
// objects the tests select between: "default" (an artifact allow-list),
// "exempt-ns" (Exempt: true), "strict-ns" (a policy that never matches the
// unsigned test image), and "no-policy-ns" (deliberately left without a
// ModelGatePolicy, to exercise the fail-closed path).
func seedNamespacesAndPolicies(c client.Client) error {
	ctx := context.Background()

	for _, ns := range []string{exemptNamespace, noPolicyNamespace, strictNamespace} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
			return fmt.Errorf("creating namespace %q: %w", ns, err)
		}
	}

	policies := []modelgatev1alpha1.ModelGatePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "default-policy", Namespace: defaultNamespace},
			Spec: modelgatev1alpha1.ModelGatePolicySpec{
				CosignPublicKeyPEM: testCosignKey,
				ArtifactAllowList: []modelgatev1alpha1.ArtifactAllowListEntry{
					{ID: goodArtifactID, SHA256: sha256Hex(goodArtifactData)},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "strict-policy", Namespace: strictNamespace},
			Spec:       modelgatev1alpha1.ModelGatePolicySpec{CosignPublicKeyPEM: testCosignKey},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "exempt-policy", Namespace: exemptNamespace},
			Spec: modelgatev1alpha1.ModelGatePolicySpec{
				CosignPublicKeyPEM: testCosignKey,
				Exempt:             true,
				ExemptionReason:    "test fixture: exempt namespace",
			},
		},
	}
	for _, p := range policies {
		if err := c.Create(ctx, &p); err != nil {
			return fmt.Errorf("creating ModelGatePolicy %s/%s: %w", p.Namespace, p.Name, err)
		}
	}
	return nil
}

// fakeVerifier and fakeFetcher mirror internal/webhook's test fakes; they
// are redeclared here (rather than imported, since they're unexported in
// that package) to keep the e2e suite import-clean.
type fakeVerifier struct{ signed map[string]bool }

func (f *fakeVerifier) VerifySignature(_ context.Context, image, _ string) error {
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

func namedPod(namespace, name, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: image}},
		},
	}
}

func TestEnvtest_AdmitsSignedPod(t *testing.T) {
	pod := namedPod(defaultNamespace, "good-pod", signedImage)
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("expected signed pod to be admitted through the real webhook, got: %v", err)
	}
}

func TestEnvtest_RejectsUnsignedImage(t *testing.T) {
	pod := namedPod(defaultNamespace, "unsigned-pod", unsignedImage)
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
	pod := namedPod(defaultNamespace, "privileged-pod", signedImage)
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
	pod := namedPod(defaultNamespace, "hostnetwork-pod", signedImage)
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
	pod := namedPod(defaultNamespace, "hostpath-pod", signedImage)
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
	pod := namedPod(defaultNamespace, "model-pod", signedImage)
	pod.Annotations = map[string]string{mgwebhook.ModelArtifactAnnotation: goodArtifactID}
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("expected pod with valid, allow-listed model artifact to be admitted, got: %v", err)
	}
}

func TestEnvtest_RejectsArtifactNotOnAllowList(t *testing.T) {
	pod := namedPod(defaultNamespace, "unknown-model-pod", signedImage)
	pod.Annotations = map[string]string{mgwebhook.ModelArtifactAnnotation: "not-on-allow-list"}
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected pod referencing an unlisted model artifact to be rejected")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

// --- M1: ModelGatePolicy CRD selection and exemption tests ---

func TestEnvtest_NamespaceWithoutPolicyIsDeniedFailClosed(t *testing.T) {
	pod := namedPod(noPolicyNamespace, "orphan-pod", signedImage)
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected a pod in a namespace with no ModelGatePolicy to be denied")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

func TestEnvtest_ExemptNamespaceBypassesChecks(t *testing.T) {
	// The exempt namespace's policy still names testCosignKey, but the
	// fake verifier only signs signedImage -- so admitting unsignedImage
	// here proves the Exempt flag actually short-circuits verification
	// rather than just having a permissive artifact list.
	pod := namedPod(exemptNamespace, "exempt-pod", unsignedImage)
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("expected pod in an exempt namespace to be admitted regardless of image signature, got: %v", err)
	}
}

func TestEnvtest_DifferentNamespacesEnforceIndependently(t *testing.T) {
	// strict-ns has a real (non-exempt) policy, so the same unsigned image
	// that was admitted in exempt-ns must be rejected here -- proving
	// policy selection is per-namespace, not a global fallback.
	pod := namedPod(strictNamespace, "strict-pod", unsignedImage)
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected strict-ns's own (non-exempt) policy to reject the unsigned image")
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
