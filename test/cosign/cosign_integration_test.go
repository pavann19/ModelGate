// Package cosign tests real cosign 2.4.1 against a TLS OCI registry and real signatures.
package cosign

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pavann19/modelgate/internal/webhook"
)

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		// In CI a missing tool means the job is misconfigured; skipping there
		// would report a green run for a test that never executed.
		if os.Getenv("CI") != "" {
			t.Fatalf("%q not found on PATH in CI: refusing to skip (this test must actually run there)", name)
		}
		t.Skipf("skipping: %q not found on PATH (this test verifies real cosign behavior and needs it installed)", name)
	}
}

func TestCosignVerifier_RealSignedAndUnsignedImages(t *testing.T) {
	requireTool(t, "cosign")
	version, err := exec.Command("cosign", "version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "GitVersion:    v2.4.1") {
		t.Fatalf("expected pinned cosign v2.4.1: %s", version)
	}
	fixture := newTLSRegistry(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("COSIGN_REPOSITORY", "untrusted.example/override")
	verifier := webhook.CosignVerifier{RegistryPolicy: fixture.policy}
	for _, tc := range []struct {
		name, repo, key string
		allow           bool
	}{
		{"signed", "signed", fixture.publicKey, true},
		{"unsigned", "unsigned", fixture.publicKey, false},
		{"wrong-key", "signed", fixture.otherPublicKey, false},
		{"wrong-signature", "wrong-signature", fixture.publicKey, false},
		{"wrong-artifact", "wrong-artifact", fixture.publicKey, false},
		{"wrong-repository", "wrong-repository", fixture.publicKey, false},
		{"malformed-signature", "malformed-signature", fixture.publicKey, false},
		{"unsupported-key", "signed", fixture.unsupportedPublicKey, false},
		{"bad-content-digest", "bad-content", fixture.publicKey, false},
		{"redirect-untrusted", "redirect-untrusted", fixture.publicKey, false},
		{"redirect-private", "redirect-private", fixture.publicKey, false},
		{"redirect-loopback", "redirect-loopback", fixture.publicKey, false},
		{"auth-untrusted", "auth-untrusted", fixture.publicKey, false},
		{"authenticated-private-registry", "authenticated", fixture.publicKey, true},
		{"timeout", "slow-registry", fixture.publicKey, false},
		{"partial-response", "partial-response", fixture.publicKey, false},
		{"oversized-manifest", "oversized-manifest", fixture.publicKey, false},
		{"secret-error", "secret-error", fixture.publicKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err := verifier.VerifySignature(ctx, fixture.image(tc.repo), tc.key)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v error=%v", tc.allow, err)
			}
			if err != nil && strings.Contains(err.Error(), "DO-NOT-LEAK") {
				t.Fatal("signature/error secret leaked")
			}
			t.Logf("production verifier allow=%v error=%v", err == nil, err)
		})
	}
	t.Run("mutable-tag", func(t *testing.T) {
		if verifier.VerifySignature(context.Background(), fixture.host+"/signed:latest", fixture.publicKey) == nil {
			t.Fatal("mutable tag accepted")
		}
	})
	t.Run("untrusted-destination", func(t *testing.T) {
		if verifier.VerifySignature(context.Background(), "untrusted.example/signed@"+fixture.digest, fixture.publicKey) == nil {
			t.Fatal("untrusted registry accepted")
		}
	})
	t.Run("tls-failure", func(t *testing.T) {
		p := *fixture.policy
		r := p.Registries[0]
		r.CAPEM = ""
		p.Registries = []webhook.RegistryRule{r}
		if (webhook.CosignVerifier{RegistryPolicy: &p}).VerifySignature(context.Background(), fixture.image("signed"), fixture.publicKey) == nil {
			t.Fatal("untrusted TLS accepted")
		}
	})
	t.Run("unavailable-registry", func(t *testing.T) {
		p := *fixture.policy
		r := p.Registries[0]
		r.Endpoints = append([]webhook.RegistryEndpoint(nil), r.Endpoints...)
		r.Host = fixture.ip + ":1"
		r.Endpoints[0].Host = r.Host
		p.Registries = []webhook.RegistryRule{r}
		if (webhook.CosignVerifier{RegistryPolicy: &p}).VerifySignature(context.Background(), r.Host+"/signed@"+fixture.digest, fixture.publicKey) == nil {
			t.Fatal("unavailable registry accepted")
		}
	})
}
