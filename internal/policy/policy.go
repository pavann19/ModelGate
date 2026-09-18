// Package policy holds the MVP policy configuration for ModelGate: the
// cosign public key used to verify image signatures, and the allow-list of
// model artifact SHA-256 hashes. In M1 this is replaced by a ModelGatePolicy
// CRD; for the MVP it is loaded once from static config so the admission
// logic can be built and tested independently of CRD plumbing.
package policy

// Config is the MVP, hardcoded policy: one cosign public key for image
// signature verification, and a map of artifact name -> expected SHA-256.
type Config struct {
	// CosignPublicKeyPEM is the PEM-encoded public key every container image
	// must be signed against.
	CosignPublicKeyPEM string

	// ArtifactAllowList maps a model-artifact annotation value (the artifact
	// identifier) to its expected SHA-256 hex digest.
	ArtifactAllowList map[string]string
}

// ArtifactHash looks up the expected SHA-256 for the given artifact
// identifier. The second return value is false if the artifact is not on
// the allow-list at all, which callers should treat as a rejection.
func (c *Config) ArtifactHash(artifact string) (string, bool) {
	if c == nil || c.ArtifactAllowList == nil {
		return "", false
	}
	h, ok := c.ArtifactAllowList[artifact]
	return h, ok
}
