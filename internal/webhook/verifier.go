package webhook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
)

// ImageVerifier checks that a container image reference is signed by a
// trusted key. It is an interface so admission logic can be unit-tested
// with a fake, without shelling out to the real cosign binary.
type ImageVerifier interface {
	VerifySignature(ctx context.Context, image string) error
}

// CosignVerifier shells out to the `cosign` CLI to verify an image's
// signature against a pinned public key. Shelling out (rather than vendoring
// cosign's Go internals) keeps this binary's dependency tree small and
// matches how cosign is normally operated in CI/CD.
type CosignVerifier struct {
	// PublicKeyPath is a filesystem path to the PEM-encoded cosign public key.
	PublicKeyPath string
}

// NewCosignVerifier writes pemKey to a temp file and returns a verifier that
// checks images against it.
func NewCosignVerifier(pemKey string) (*CosignVerifier, error) {
	f, err := os.CreateTemp("", "modelgate-cosign-*.pub")
	if err != nil {
		return nil, fmt.Errorf("creating cosign key temp file: %w", err)
	}
	if _, err := f.WriteString(pemKey); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing cosign key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &CosignVerifier{PublicKeyPath: f.Name()}, nil
}

// VerifySignature runs `cosign verify --key <path> <image>` and returns nil
// only if cosign exits 0, meaning it found a valid signature.
func (v *CosignVerifier) VerifySignature(ctx context.Context, image string) error {
	cmd := exec.CommandContext(ctx, "cosign", "verify", "--key", v.PublicKeyPath, image)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("image %q failed signature verification: %v: %s", image, err, stderr.String())
	}
	return nil
}
