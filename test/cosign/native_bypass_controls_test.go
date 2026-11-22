package cosign

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Couple actual API operations to real TLS registry/signature verification.
// The older bypass suite intentionally uses a mock verifier and stays separate.
func nativeBypassControls(t *testing.T, ctx context.Context, api client.Client, f tlsRegistryFixture, calls *atomic.Int32) int {
	t.Helper()
	check := func(name string, allow bool, action func() error) {
		t.Helper()
		before := calls.Load()
		err := action()
		if calls.Load() <= before {
			t.Fatalf("%s did not reach the actual webhook", name)
		}
		if allow && err != nil {
			t.Fatalf("%s positive control denied: %v", name, err)
		}
		if !allow && (!apierrors.IsForbidden(err) || !strings.Contains(err.Error(), "native.fixture.modelgate.dev")) {
			t.Fatalf("%s was not denied by this webhook: %v", name, err)
		}
		t.Logf("real API/crypto bypass control %s: expected_allow=%v PASS", name, allow)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "native-bypass", Namespace: "native-trust", Labels: map[string]string{"modelgate.dev/enforce": "fixture"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: f.image("signed")}}}}
	check("signed-persisted-pod", true, func() error { return api.Create(ctx, pod) })
	for _, tc := range []struct {
		repo  string
		allow bool
	}{{"signed0", true}, {"unsigned", false}} {
		updated := pod.DeepCopy()
		updated.Spec.Containers[0].Image = f.image(tc.repo)
		check("image-update-"+tc.repo, tc.allow, func() error {
			return api.Update(ctx, updated, &client.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
		})
	}
	for _, tc := range []struct {
		repo  string
		allow bool
	}{{"signed", true}, {"unsigned", false}} {
		updated := pod.DeepCopy()
		updated.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: f.image(tc.repo)}}}
		check("ephemeral-"+tc.repo, tc.allow, func() error {
			return api.SubResource("ephemeralcontainers").Update(ctx, updated, &client.SubResourceUpdateOptions{UpdateOptions: client.UpdateOptions{DryRun: []string{metav1.DryRunAll}}})
		})
	}
	for _, tc := range []struct {
		repo  string
		allow bool
	}{{"signed", true}, {"unsigned", false}} {
		withInit := pod.DeepCopy()
		withInit.Name = "native-init-probe"
		withInit.ResourceVersion = ""
		withInit.UID = ""
		withInit.Spec.InitContainers = []corev1.Container{{Name: "init", Image: f.image(tc.repo)}}
		check("init-"+tc.repo, tc.allow, func() error {
			return api.Create(ctx, withInit, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		})
	}
	return 7
}
