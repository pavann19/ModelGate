package webhook

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func detachedFixture(t *testing.T) (*ecdsa.PrivateKey, string, []byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"critical":{"type":"cosign container image signature"}}`)
	hash := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), payload, base64.StdEncoding.EncodeToString(sig)
}

func TestDetachedSignatureBoundedContract(t *testing.T) {
	key, public, payload, signature := detachedFixture(t)
	parsed, err := parseVerificationKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDetachedSignature(context.Background(), parsed, payload, signature); err != nil {
		t.Fatal(err)
	}
	other, _, _, _ := detachedFixture(t)
	raw, _ := base64.StdEncoding.DecodeString(signature)
	for _, tc := range []struct {
		name    string
		key     *ecdsa.PublicKey
		payload []byte
		sig     string
	}{
		{"wrong-key", &other.PublicKey, payload, signature},
		{"tampered-payload", &key.PublicKey, append(append([]byte(nil), payload...), ' '), signature},
		{"empty-payload", parsed, nil, signature},
		{"oversized-payload", parsed, make([]byte, 65537), signature},
		{"malformed-base64", parsed, payload, "DO-NOT-LEAK"},
		{"newline-base64", parsed, payload, signature + "\n"},
		{"empty-signature", parsed, payload, ""},
		{"oversized-signature", parsed, payload, strings.Repeat("A", 16385)},
		{"invalid-DER", parsed, payload, base64.StdEncoding.EncodeToString([]byte{1, 2, 3})},
		{"trailing-DER", parsed, payload, base64.StdEncoding.EncodeToString(append(raw, 0))},
		{"nil-key", nil, payload, signature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyDetachedSignature(context.Background(), tc.key, tc.payload, tc.sig); err == nil {
				t.Fatal("invalid signature accepted")
			} else if strings.Contains(err.Error(), "DO-NOT-LEAK") {
				t.Fatal("untrusted input leaked")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if verifyDetachedSignature(canceled, parsed, payload, signature) == nil {
		t.Fatal("canceled signature accepted")
	}
}

func TestDetachedKeyContract(t *testing.T) {
	_, public, _, _ := detachedFixture(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ed, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []any{&p384.PublicKey, ed, &rsaKey.PublicKey} {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = parseVerificationKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))); err == nil {
			t.Fatal("unsupported algorithm accepted")
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", 16385), "untrusted prefix\n" + public, public + public, public + "secret suffix", strings.Replace(public, "PUBLIC KEY", "CERTIFICATE", 2), "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n" + public} {
		if _, err := parseVerificationKey(bad); err == nil {
			t.Fatal("ambiguous key accepted")
		}
	}
}

// Cosign is an independent test oracle, never a production dependency.
func TestDetachedSignatureCosignInteroperability(t *testing.T) {
	binary, err := exec.LookPath("cosign")
	if err != nil {
		if os.Getenv("MODELGATE_REQUIRE_COSIGN_ORACLE") == "1" {
			t.Fatal("pinned Cosign oracle missing")
		}
		t.Skip("pinned Cosign v3.1.4 not on PATH")
	}
	version, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "GitVersion:    v3.1.4") {
		t.Fatalf("expected pinned Cosign v3.1.4: %s", version)
	}
	_, public, payload, sig := detachedFixture(t)
	_, wrong, _, _ := detachedFixture(t)
	dir := t.TempDir()
	for _, tc := range []struct {
		name, key, sig string
		payload        []byte
		allow          bool
	}{
		{"valid", public, sig, payload, true},
		{"wrong-key", wrong, sig, payload, false},
		{"tampered", public, sig, append(append([]byte(nil), payload...), ' '), false},
		{"invalid-signature", public, "invalid", payload, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := filepath.Join(dir, "key.pub")
			blobPath := filepath.Join(dir, "payload")
			sigPath := filepath.Join(dir, "signature")
			for name, data := range map[string][]byte{keyPath: []byte(tc.key), blobPath: tc.payload, sigPath: []byte(tc.sig)} {
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "verify-blob", "--key", keyPath, "--signature", sigPath, "--offline", "--insecure-ignore-tlog=true", blobPath)
			cmd.Env = offlineEnvironment()
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.allow {
				t.Fatalf("oracle allow=%v error=%v output=%s", tc.allow, err, out)
			}
			parsed, _ := parseVerificationKey(tc.key)
			if (verifyDetachedSignature(ctx, parsed, tc.payload, tc.sig) == nil) != tc.allow {
				t.Fatal("Go/oracle disagreement")
			}
		})
	}
}

func FuzzBoundedVerificationKey(f *testing.F) {
	f.Add("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		key, err := parseVerificationKey(input)
		if err == nil && (key == nil || key.Curve != elliptic.P256()) {
			t.Fatal("unsupported key accepted")
		}
	})
}
