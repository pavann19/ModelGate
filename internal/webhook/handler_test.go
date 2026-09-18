package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/pavann19/modelgate/internal/policy"
)

// fakeVerifier lets tests control which images pass signature verification
// without shelling out to the real cosign binary.
type fakeVerifier struct {
	signedImages map[string]bool
}

func (f *fakeVerifier) VerifySignature(_ context.Context, image, _ string) error {
	if f.signedImages[image] {
		return nil
	}
	return fmt.Errorf("image %q is not signed", image)
}

// fakeFetcher returns canned artifact bytes by ref, so artifact validation
// can be exercised without real files.
type fakeFetcher struct {
	data map[string][]byte
}

func (f *fakeFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	d, ok := f.data[ref]
	if !ok {
		return nil, fmt.Errorf("no fixture for %q", ref)
	}
	return d, nil
}

// fakeResolver returns a canned Resolution per namespace, so policy
// selection can be exercised without a real CRD-backed client.
type fakeResolver struct {
	byNamespace map[string]policy.Resolution
	err         error
}

func (f *fakeResolver) Resolve(_ context.Context, namespace string) (policy.Resolution, error) {
	if f.err != nil {
		return policy.Resolution{}, f.err
	}
	r, ok := f.byNamespace[namespace]
	if !ok {
		return policy.Resolution{}, policy.ErrNoPolicy
	}
	return r, nil
}

func resolverFor(namespace string, cfg *policy.Config) *fakeResolver {
	return &fakeResolver{byNamespace: map[string]policy.Resolution{namespace: {Config: cfg}}}
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

func podRequest(t *testing.T, pod *corev1.Pod) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: pod.Namespace,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func basicPod(image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: image}},
		},
	}
}

func TestHandle_AdmitsSignedPod(t *testing.T) {
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, basicPod("good:latest")))
	if !resp.Allowed {
		t.Fatalf("expected pod with signed image to be admitted, got denied: %s", resp.Result.Message)
	}
}

func TestHandle_RejectsUnsignedImage(t *testing.T) {
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, basicPod("evil:latest")))
	if resp.Allowed {
		t.Fatal("expected pod with unsigned image to be denied")
	}
}

func TestHandle_RejectsPrivilegedContainer(t *testing.T) {
	priv := true
	pod := basicPod("good:latest")
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &priv}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected privileged pod to be denied")
	}
}

func TestHandle_RejectsHostNetwork(t *testing.T) {
	pod := basicPod("good:latest")
	pod.Spec.HostNetwork = true
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected hostNetwork pod to be denied")
	}
}

func TestHandle_RejectsHostPathVolume(t *testing.T) {
	pod := basicPod("good:latest")
	pod.Spec.Volumes = []corev1.Volume{{
		Name:         "hostvol",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}},
	}}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected hostPath volume pod to be denied")
	}
}

func TestHandle_RejectsInitContainerUnsignedImage(t *testing.T) {
	pod := basicPod("good:latest")
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "evil-init:latest"}}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected pod with unsigned init container image to be denied")
	}
}

func TestHandle_RejectsEphemeralContainerUnsignedImage(t *testing.T) {
	pod := basicPod("good:latest")
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", Image: "evil-debug:latest",
		},
	}}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected pod with unsigned ephemeral container image (kubectl debug bypass) to be denied")
	}
}

func TestHandle_AdmitsValidModelArtifact(t *testing.T) {
	artifactData := buildSafetensors(`{"__metadata__":{}}`, []byte{1, 2, 3})
	pod := basicPod("good:latest")
	pod.Annotations = map[string]string{ModelArtifactAnnotation: "model-a"}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{ArtifactAllowList: map[string]string{
			"model-a": sha256Hex(artifactData),
		}}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{data: map[string][]byte{"model-a": artifactData}},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if !resp.Allowed {
		t.Fatalf("expected pod with valid model artifact to be admitted, got: %s", resp.Result.Message)
	}
}

func TestHandle_RejectsPickleModelArtifact(t *testing.T) {
	pickleData := []byte{
		0x80, 0x04, 0x95, 0x06, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x8c, 0x02, 'h', 'i', 0x94, '.',
	}
	pod := basicPod("good:latest")
	pod.Annotations = map[string]string{ModelArtifactAnnotation: "model-b"}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{ArtifactAllowList: map[string]string{
			"model-b": sha256Hex(pickleData),
		}}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{data: map[string][]byte{"model-b": pickleData}},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected pod with pickle model artifact to be denied")
	}
}

func TestHandle_RejectsArtifactNotOnAllowList(t *testing.T) {
	pod := basicPod("good:latest")
	pod.Annotations = map[string]string{ModelArtifactAnnotation: "unknown-model"}
	h := &Handler{
		Resolver: resolverFor("default", &policy.Config{ArtifactAllowList: map[string]string{}}),
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if resp.Allowed {
		t.Fatal("expected pod referencing an artifact not on the allow-list to be denied")
	}
}

func TestHandle_DeniesWhenNoPolicyExistsForNamespace(t *testing.T) {
	h := &Handler{
		Resolver: &fakeResolver{byNamespace: map[string]policy.Resolution{}},
		Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, basicPod("good:latest")))
	if resp.Allowed {
		t.Fatal("expected pod in a namespace with no ModelGatePolicy to be denied (fail closed)")
	}
}

func TestHandle_ExemptNamespaceBypassesAllChecks(t *testing.T) {
	pod := basicPod("totally-unsigned:latest")
	pod.Spec.HostNetwork = true // would be denied outright if checks ran
	h := &Handler{
		Resolver: &fakeResolver{byNamespace: map[string]policy.Resolution{
			"default": {Exempt: true, ExemptionReason: "kube-system-style bypass for test"},
		}},
		Verifier: &fakeVerifier{signedImages: map[string]bool{}},
		Fetcher:  &fakeFetcher{},
	}
	resp := h.Handle(context.Background(), podRequest(t, pod))
	if !resp.Allowed {
		t.Fatalf("expected exempt namespace to bypass all checks, got denied: %s", resp.Result.Message)
	}
}

func TestHandle_DifferentNamespacesGetDifferentPolicies(t *testing.T) {
	h := &Handler{
		Resolver: &fakeResolver{byNamespace: map[string]policy.Resolution{
			"strict": {Config: &policy.Config{}},
			"loose":  {Exempt: true, ExemptionReason: "test"},
		}},
		Verifier: &fakeVerifier{signedImages: map[string]bool{}}, // nothing is signed
		Fetcher:  &fakeFetcher{},
	}

	strictPod := basicPod("unsigned:latest")
	strictPod.Namespace = "strict"
	if resp := h.Handle(context.Background(), podRequest(t, strictPod)); resp.Allowed {
		t.Fatal("expected the strict namespace's policy to reject the unsigned image")
	}

	loosePod := basicPod("unsigned:latest")
	loosePod.Namespace = "loose"
	if resp := h.Handle(context.Background(), podRequest(t, loosePod)); !resp.Allowed {
		t.Fatalf("expected the loose (exempt) namespace to admit the same pod, got: %s", resp.Result.Message)
	}
}
