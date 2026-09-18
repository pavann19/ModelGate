// Package cosign closes the last named gap from the MVP: internal/webhook's
// CosignVerifier had only ever been exercised against a fake ImageVerifier,
// in both the unit tests and the envtest suites. This test runs it against
// a REAL cosign binary, a real (local) OCI registry, and a real signed and
// a real unsigned image, proving "rejects unsigned images" is an actual,
// verified claim rather than one covered only by a fake.
//
// It needs `docker` and `cosign` on PATH, and network access to pull a
// small base image (alpine) if not already cached locally. Locally it skips
// if either binary is missing, the same pattern test/e2e uses for
// KUBEBUILDER_ASSETS. In CI (CI env var set) a missing tool is a hard
// failure instead, so the job can never go green without having run it.
package cosign

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavann19/modelgate/internal/webhook"
)

const (
	registryPort      = "5511" // an uncommon port, unlikely to collide with a real registry
	registryContainer = "modelgate-cosign-integration-registry"
	baseImage         = "alpine:3.20"
	otherImage        = "alpine:3.19" // genuinely different content/digest, not just a different tag
	signedRef         = "localhost:5511/modelgate-cosign-test:signed"
	unsignedRef       = "localhost:5511/modelgate-cosign-test:unsigned"
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
	requireTool(t, "docker")
	requireTool(t, "cosign")

	run(t, "docker", "rm", "-f", registryContainer) // best-effort cleanup from a prior interrupted run
	if err := runErr(t, "docker", "run", "-d", "--rm", "-p", registryPort+":5000", "--name", registryContainer, "registry:2"); err != nil {
		t.Fatalf("starting local test registry: %v", err)
	}
	t.Cleanup(func() { run(t, "docker", "rm", "-f", registryContainer) })

	if err := waitForRegistry("http://localhost:"+registryPort+"/v2/", 20*time.Second); err != nil {
		t.Fatalf("local registry did not become ready: %v", err)
	}

	for _, img := range []string{baseImage, otherImage} {
		if err := runErr(t, "docker", "pull", img); err != nil {
			t.Fatalf("pulling %s: %v", img, err)
		}
	}
	if err := runErr(t, "docker", "tag", baseImage, signedRef); err != nil {
		t.Fatalf("tagging signed image: %v", err)
	}
	if err := runErr(t, "docker", "push", signedRef); err != nil {
		t.Fatalf("pushing signed image: %v", err)
	}
	if err := runErr(t, "docker", "tag", otherImage, unsignedRef); err != nil {
		t.Fatalf("tagging unsigned image: %v", err)
	}
	if err := runErr(t, "docker", "push", unsignedRef); err != nil {
		t.Fatalf("pushing unsigned image: %v", err)
	}

	keyDir := t.TempDir()
	cmd := exec.Command("cosign", "generate-key-pair")
	cmd.Dir = keyDir
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating cosign key pair: %v: %s", err, out)
	}
	privKeyPath := filepath.Join(keyDir, "cosign.key")
	pubKeyPath := filepath.Join(keyDir, "cosign.pub")
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("reading generated public key: %v", err)
	}

	// Sign ONLY signedRef. unsignedRef is a genuinely different image
	// (different digest, see the otherImage comment above) that is never
	// signed at all -- this is deliberately not "the same image under two
	// tags," since cosign associates a signature with a digest, and two
	// tags of identical content would both appear signed.
	signCmd := exec.Command("cosign", "sign", "--key", privKeyPath,
		"--tlog-upload=false", "--yes", signedRef)
	signCmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if out, err := signCmd.CombinedOutput(); err != nil {
		t.Fatalf("signing %s: %v: %s", signedRef, err, out)
	}

	verifier := webhook.CosignVerifier{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := verifier.VerifySignature(ctx, signedRef, string(pubKeyPEM)); err != nil {
		t.Fatalf("expected the real signed image to verify successfully, got: %v", err)
	}
	if err := verifier.VerifySignature(ctx, unsignedRef, string(pubKeyPEM)); err == nil {
		t.Fatal("expected the real unsigned image to fail verification, but it succeeded")
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	_ = runErr(t, name, args...)
}

func runErr(t *testing.T, name string, args ...string) error {
	t.Helper()
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	t.Logf("$ %s %s\n%s", name, args, out.String())
	return err
}

func waitForRegistry(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("registry at %s not ready after %s: %w", url, timeout, lastErr)
}
