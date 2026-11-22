package webhook

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadedRegistryPoolBoundsAndPolicyChanges(t *testing.T) {
	rule := RegistryRule{Host: "registry.test", Endpoints: []RegistryEndpoint{{Host: "registry.test", CIDRs: []string{"10.0.0.0/8"}}}}
	raw, err := json.Marshal(RegistryPolicy{Registries: []RegistryRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadRegistryPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.CloseIdleConnections)
	id, err := parseImage("registry.test/repo@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.forImage(id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.forImage(id)
	if err != nil || a != b || !a.shared {
		t.Fatal("loaded immutable rule did not reuse transport")
	}
	tr := a.client.Transport.(*http.Transport)
	if tr.MaxConnsPerHost != 8 || tr.MaxIdleConns != 16 || tr.MaxIdleConnsPerHost != 8 || tr.IdleConnTimeout != 30*time.Second || tr.Proxy != nil {
		t.Fatal("connection pool lacks declared bounds or inherits proxies")
	}
	// Removing trust must not recover an old approved transport, even when a
	// caller copies a loaded value and changes its exported configuration.
	copy := *p
	changed := rule
	changed.Endpoints = []RegistryEndpoint{{Host: "registry.test", CIDRs: []string{"invalid"}}}
	copy.Registries = []RegistryRule{changed}
	if _, err := copy.forImage(id); err == nil {
		t.Fatal("changed invalid destination reused cached trust")
	}
	copy.Registries = nil
	if _, err := copy.forImage(id); err == nil {
		t.Fatal("removed destination reused cached trust")
	}
	changed = rule
	changed.Password = "synthetic-new-password"
	copy.Registries = []RegistryRule{changed}
	c, err := copy.forImage(id)
	if err != nil || c == a || c.shared {
		t.Fatal("changed credentials reused cached client")
	}
	if c != nil {
		c.client.CloseIdleConnections()
	}
}
