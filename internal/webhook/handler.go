// Package webhook implements the ModelGate ValidatingAdmissionWebhook: it
// admits a pod only if every container image is cosign-signed against the
// key from the pod namespace's ModelGatePolicy, any model-artifact
// annotation points at a hash-verified safetensors file on that policy's
// allow-list, and the pod does not request privileged/host-level access --
// unless the namespace's policy explicitly (and only explicitly) exempts it.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/pavann19/modelgate/internal/artifact"
	"github.com/pavann19/modelgate/internal/policy"
)

// ArtifactFetcher retrieves the raw bytes of a model artifact referenced by
// a pod annotation (a local path or URL). It is an interface so tests can
// supply fixture bytes without touching a filesystem or network.
type ArtifactFetcher interface {
	Fetch(ctx context.Context, ref string) ([]byte, error)
}

// FileArtifactFetcher reads model artifacts from the local filesystem,
// which is the expected case in-cluster: the artifact is mounted into the
// webhook pod (e.g. via a shared volume or init step) at the referenced path.
type FileArtifactFetcher struct{}

func (FileArtifactFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	return os.ReadFile(ref)
}

// PolicyResolver looks up the enforcement policy for a pod's namespace.
// internal/policy.Resolver is the production implementation, backed by the
// ModelGatePolicy CRD; tests supply a fake.
type PolicyResolver interface {
	Resolve(ctx context.Context, namespace string) (policy.Resolution, error)
}

// ModelArtifactAnnotation is the pod annotation key carrying the identifier
// of the model artifact to validate, e.g. "modelgate.dev/model-artifact".
const ModelArtifactAnnotation = "modelgate.dev/model-artifact"

// Handler is the admission.Handler implementation backing the
// ValidatingWebhookConfiguration. It is deliberately free of controller-
// runtime manager wiring so its rules can be exercised directly in unit
// tests; cmd/webhook/main.go wires it into a real manager and server.
type Handler struct {
	Resolver PolicyResolver
	Verifier ImageVerifier
	Fetcher  ArtifactFetcher
	Logger   *slog.Logger
}

// NewHandler builds a Handler with production defaults (real cosign
// verification via the CLI, filesystem artifact fetch) backed by resolver.
func NewHandler(resolver PolicyResolver) *Handler {
	return &Handler{
		Resolver: resolver,
		Verifier: CosignVerifier{},
		Fetcher:  FileArtifactFetcher{},
	}
}

// Handle implements admission.Handler. It resolves the pod namespace's
// policy first (an exemption or a missing policy short-circuits everything
// else), then runs the MVP checks in a fixed order -- host-level access
// denial first (cheapest, no I/O), then image signatures, then artifact
// validation -- so the response's Reason names the first violation found.
func (h *Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decoding pod: %w", err))
	}

	namespace := req.Namespace
	if namespace == "" {
		namespace = pod.Namespace
	}

	resolution, err := h.Resolver.Resolve(ctx, namespace)
	if err != nil {
		if errors.Is(err, policy.ErrNoPolicy) {
			return admission.Denied(fmt.Sprintf("no ModelGatePolicy exists for namespace %q; failing closed", namespace))
		}
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("resolving policy for namespace %q: %w", namespace, err))
	}

	if resolution.Exempt {
		h.logger().Warn("admitting pod without ModelGate checks: namespace is exempt",
			"namespace", namespace, "pod", pod.Name, "reason", resolution.ExemptionReason)
		return admission.Allowed(fmt.Sprintf("namespace %q is exempt from ModelGate checks: %s", namespace, resolution.ExemptionReason))
	}
	cfg := resolution.Config

	if reason, denied := checkHostAccess(&pod.Spec); denied {
		return admission.Denied(reason)
	}

	for _, c := range allPodContainers(&pod.Spec) {
		if err := h.Verifier.VerifySignature(ctx, c.Image, cfg.CosignPublicKeyPEM); err != nil {
			return admission.Denied(fmt.Sprintf("unsigned or invalid image %q: %v", c.Image, err))
		}
	}

	if ref, ok := pod.Annotations[ModelArtifactAnnotation]; ok {
		if reason, denied := h.checkModelArtifact(ctx, cfg, ref); denied {
			return admission.Denied(reason)
		}
	}

	return admission.Allowed("all ModelGate checks passed")
}

func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// checkHostAccess rejects privileged containers and host-level namespace/
// volume access outright -- these are always denied and are not subject to
// per-namespace policy configuration, only to the whole-namespace Exempt flag.
func checkHostAccess(spec *corev1.PodSpec) (reason string, denied bool) {
	if spec.HostPID {
		return "hostPID is not permitted", true
	}
	if spec.HostNetwork {
		return "hostNetwork is not permitted", true
	}
	for _, vol := range spec.Volumes {
		if vol.HostPath != nil {
			return fmt.Sprintf("hostPath volume %q is not permitted", vol.Name), true
		}
	}
	for _, c := range allPodContainers(spec) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return fmt.Sprintf("privileged container %q is not permitted", c.Name), true
		}
	}
	return "", false
}

// allPodContainers returns every container spec that can carry an image:
// regular containers, init containers, and ephemeral containers (the
// `kubectl debug` bypass vector called out in the M3 adversarial suite).
func allPodContainers(spec *corev1.PodSpec) []corev1.Container {
	all := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers)+len(spec.EphemeralContainers))
	all = append(all, spec.Containers...)
	all = append(all, spec.InitContainers...)
	for _, ec := range spec.EphemeralContainers {
		all = append(all, corev1.Container(ec.EphemeralContainerCommon))
	}
	return all
}

// checkModelArtifact fetches and validates the artifact referenced by ref
// against the policy allow-list. A ref not present in the allow-list is a
// denial, not a silent pass.
func (h *Handler) checkModelArtifact(ctx context.Context, cfg *policy.Config, ref string) (reason string, denied bool) {
	expectedHash, ok := cfg.ArtifactHash(ref)
	if !ok {
		return fmt.Sprintf("model artifact %q is not on the allow-list", ref), true
	}
	data, err := h.Fetcher.Fetch(ctx, ref)
	if err != nil {
		return fmt.Sprintf("could not fetch model artifact %q: %v", ref, err), true
	}
	if err := artifact.Validate(data, expectedHash); err != nil {
		return fmt.Sprintf("model artifact %q failed validation: %v", ref, err), true
	}
	return "", false
}
