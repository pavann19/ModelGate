package webhook

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// ImageVerifier verifies an image using the operator-owned namespace key.
type ImageVerifier interface {
	VerifySignature(ctx context.Context, image, publicKeyPEM string) error
}

// CosignVerifier verifies legacy Cosign payloads under the bounded-v1 contract:
// explicit PKIX ECDSA P-256 key, SHA-256, ASN.1 signature. Other key algorithms,
// keyless identities, transparency proofs and attestations are unsupported.
// The historical name is retained for source compatibility, not general Cosign compatibility.
type CosignVerifier struct{ RegistryPolicy *RegistryPolicy }

func (v CosignVerifier) VerifySignature(ctx context.Context, image, publicKeyPEM string) error {
	id, err := parseImage(image)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errors.New("signature verification canceled or timed out")
	}
	key, err := parseVerificationKey(publicKeyPEM)
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
	for _, p := range payloads {
		if err := verifyDetachedSignature(ctx, key, p.Data, p.Signature); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return errors.New("signature verification canceled or timed out")
		}
	}
	return errors.New("signature verification failed")
}

func parseVerificationKey(keyPEM string) (*ecdsa.PublicKey, error) {
	fail := errors.New("verification key must be a single PKIX ECDSA P-256 PUBLIC KEY")
	if len(keyPEM) == 0 || len(keyPEM) > 16*1024 {
		return nil, fail
	}
	// pem.Decode otherwise skips arbitrary leading text. Do not accept it.
	trimmed := strings.TrimSpace(keyPEM)
	if strings.Count(trimmed, "-----BEGIN ") != 1 || !strings.HasPrefix(trimmed, "-----BEGIN PUBLIC KEY-----") {
		return nil, fail
	}
	block, rest := pem.Decode([]byte(trimmed))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fail
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fail
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fail
	}
	return key, nil
}

func verifyDetachedSignature(ctx context.Context, key *ecdsa.PublicKey, payload []byte, encoded string) error {
	fail := errors.New("signature verification failed")
	if ctx.Err() != nil {
		return errors.New("signature verification canceled or timed out")
	}
	if key == nil || key.Curve != elliptic.P256() || len(payload) == 0 || len(payload) > 64*1024 || len(encoded) == 0 || len(encoded) > 16*1024 {
		return fail
	}
	// Strict requires canonical padding bits; reject CR/LF ignored by DecodeString.
	if strings.ContainsAny(encoded, "\r\n") {
		return fail
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) > 72 || len(signature) == 0 {
		return fail
	}
	hash := sha256.Sum256(payload)
	valid := ecdsa.VerifyASN1(key, hash[:], signature)
	if ctx.Err() != nil {
		return errors.New("signature verification canceled or timed out")
	}
	if !valid {
		return fail
	}
	return nil
}
