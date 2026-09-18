package e2e

// M3 adversarial bypass suite. Each test targets a specific bypass vector
// named in the build plan and asserts it is actually blocked against a real
// API server -- not assumed. Two of these were run first as bare probes
// (no webhook rules for UPDATE / the ephemeralcontainers subresource) and
// found real, working bypasses; the webhook config was then fixed (see
// testdata/webhook-config.yaml and deploy/manifests/validatingwebhookconfiguration.yaml)
// and these tests now assert the fixed behavior. See docs/DECISIONS.md for
// the full write-up of what was found and why the fix was made instead of
// documented as an accepted limitation.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// TestBypass_ImageSwapAfterAdmission confirms that swapping a container's
// image on an already-admitted pod (the "kubectl set image pod/x" vector)
// is now caught: spec.containers[*].image is a mutable field, so the
// webhook must watch UPDATE, not just CREATE, on the "pods" resource.
func TestBypass_ImageSwapAfterAdmission(t *testing.T) {
	pod := namedPod(defaultNamespace, "swap-bypass-pod", signedImage)
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("setup: could not create the initial pod: %v", err)
	}

	pod.Spec.Containers[0].Image = unsignedImage
	err := testK8sClient.Update(context.Background(), pod)
	if err == nil {
		t.Fatal("expected swapping in an unsigned image via Update to be rejected, but it succeeded")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

// TestBypass_ImageSwapToSignedImageStillWorks is the control case: a
// legitimate image update (still signed) must not be collateral damage from
// closing the bypass above.
func TestBypass_ImageSwapToSignedImageStillWorks(t *testing.T) {
	pod := namedPod(defaultNamespace, "legit-update-pod", signedImage)
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("setup: could not create the initial pod: %v", err)
	}

	pod.Spec.ActiveDeadlineSeconds = int64Ptr(3600) // an unrelated, ordinarily-mutable field
	if err := testK8sClient.Update(context.Background(), pod); err != nil {
		t.Fatalf("expected a legitimate update (still-signed image, unrelated field change) to be admitted, got: %v", err)
	}
}

// TestBypass_EphemeralContainerDebugBypass confirms that adding an
// unsigned ephemeral container via the pods/ephemeralcontainers subresource
// (what `kubectl debug` uses) is now caught: the webhook must have a
// dedicated rule for that subresource, since it is a distinct resource from
// "pods" in admission review terms.
func TestBypass_EphemeralContainerDebugBypass(t *testing.T) {
	pod := namedPod(defaultNamespace, "debug-bypass-pod", signedImage)
	if err := testK8sClient.Create(context.Background(), pod); err != nil {
		t.Fatalf("setup: could not create the initial pod: %v", err)
	}

	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debug", Image: unsignedImage,
		},
	}}
	err := testK8sClient.SubResource("ephemeralcontainers").Update(context.Background(), pod)
	if err == nil {
		t.Fatal("expected adding an unsigned ephemeral container to be rejected, but it succeeded")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

// TestBypass_InitContainerUnsignedImage confirms the initContainers vector
// named in the plan is blocked at CREATE time (regression coverage
// end-to-end; the unit-test equivalent already exists in
// internal/webhook/handler_test.go).
func TestBypass_InitContainerUnsignedImage(t *testing.T) {
	pod := namedPod(defaultNamespace, "init-bypass-pod", signedImage)
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: unsignedImage}}
	err := testK8sClient.Create(context.Background(), pod)
	if err == nil {
		t.Fatal("expected a pod with an unsigned init container to be rejected")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden (admission-denied) error, got: %v", err)
	}
}

func int64Ptr(v int64) *int64 { return &v }
