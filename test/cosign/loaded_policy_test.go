package cosign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pavann19/modelgate/internal/webhook"
)

// Exercise the same operator-file loading path used by the executable.
func loadFixturePolicy(t *testing.T, p *webhook.RegistryPolicy) *webhook.RegistryPolicy {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry-policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := webhook.LoadRegistryPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}
