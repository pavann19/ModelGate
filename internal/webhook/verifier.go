package webhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
)

// ImageVerifier checks that a container image reference is signed by the
// given trusted public key. The key is passed per-call (rather than fixed
// at construction) because, since M1, the key comes from the resolved
// ModelGatePolicy for the pod's namespace and can differ per request.
type ImageVerifier interface {
	VerifySignature(ctx context.Context, image, publicKeyPEM string) error
}

// CosignVerifier shells out to the `cosign` CLI to verify an image's
// signature against a pinned public key. Shelling out (rather than vendoring
// cosign's Go internals) keeps this binary's dependency tree small and
// matches how cosign is normally operated in CI/CD.
type CosignVerifier struct{}

// VerifySignature writes publicKeyPEM to a temp file and runs
// `cosign verify --key <path> <image>`, returning nil only if cosign exits 0.
func (CosignVerifier) VerifySignature(ctx context.Context, image, publicKeyPEM string) error {
	keyPath, cleanup, err := writeTempKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("writing cosign key for image %q: %w", image, err)
	}
	defer cleanup()

	cmd := exec.CommandContext(ctx, "cosign", "verify", "--key", keyPath, image)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("image %q failed signature verification: %v: %s", image, err, stderr.String())
	}
	return nil
}

func writeTempKey(pemKey string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "modelgate-cosign-*.pub")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp file: %w", err)
	}
	if _, err := f.WriteString(pemKey); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, fmt.Errorf("writing key: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}
