// Package policy provides namespace admission configuration.
package policy

// Config is a per-request policy snapshot: one cosign public key for image
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
