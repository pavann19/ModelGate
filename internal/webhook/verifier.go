package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ImageVerifier checks that a container image reference is signed by the
// given trusted public key. The key is passed per-call (rather than fixed
// at construction) because the key comes from the resolved
// ModelGatePolicy for the pod's namespace and can differ per request.
type ImageVerifier interface {
	VerifySignature(ctx context.Context, image, publicKeyPEM string) error
}

// CosignVerifier fetches digest-bound OCI signature payloads through the
// controlled registry transport, then invokes offline cosign cryptography.
type CosignVerifier struct{ RegistryPolicy *RegistryPolicy }

// VerifySignature writes publicKeyPEM to a temp file and runs
// offline `cosign verify-blob` on local payload/signature/key files. Registry
// and payload identity validation precede every cryptographic verification.
//
// Transparency-log verification is disabled. The configured public key is
// the trust anchor; log inclusion and audit assurance are outside this mode.
func (v CosignVerifier) VerifySignature(ctx context.Context, image, publicKeyPEM string) error {
	id, err := parseImage(image)
	if err != nil {
		return err
	}
	client, err := v.RegistryPolicy.forImage(id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	payloads, err := client.signatures(ctx, id)
	if err != nil {
		return err
	}
	keyPath, cleanup, err := writeTempKey(publicKeyPEM)
	if err != nil {
		return errors.New("cannot prepare verification key")
	}
	defer cleanup()
	dir, err := os.MkdirTemp("", "modelgate-signature-*")
	if err != nil {
		return errors.New("cannot prepare signature files")
	}
	defer os.RemoveAll(dir)
	for _, p := range payloads {
		sigPath := filepath.Join(dir, "signature")
		blobPath := filepath.Join(dir, "payload")
		if os.WriteFile(sigPath, []byte(p.Signature), 0600) != nil || os.WriteFile(blobPath, p.Data, 0600) != nil {
			return errors.New("cannot prepare signature files")
		}
		cmd := exec.CommandContext(ctx, "cosign", "verify-blob", "--key", keyPath, "--signature", sigPath, "--offline", "--insecure-ignore-tlog=true", blobPath)
		// All operands are local files and explicit-key offline verification needs
		// no registry/keyless/TUF downloads. Do not inherit destination overrides,
		// credential helpers, proxy settings or a Docker credential configuration.
		cmd.Env = offlineEnvironment()
		var stderr boundedOutput
		cmd.Stderr = &stderr
		cmd.WaitDelay = time.Second
		if cmd.Run() == nil {
			return nil
		}
		if ctx.Err() != nil {
			return errors.New("signature verification canceled or timed out")
		}
	}
	return errors.New("signature verification failed")
}
func offlineEnvironment() []string {
	var env []string
	for _, name := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	// These proxies are defensive: offline operands prevent network use; any
	// unexpected future HTTP path must fail against an unusable proxy.
	env = append(env, "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "ALL_PROXY=http://127.0.0.1:1", "NO_PROXY=", "COSIGN_EXPERIMENTAL=0")
	return env
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

// boundedOutput drains subprocess stderr without retaining unbounded registry output.
type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	const limit = 4096
	if remaining := limit - b.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
