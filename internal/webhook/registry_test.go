package webhook

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryReferenceAmbiguity(t *testing.T) {
	for _, ref := range []string{"repo@sha256:" + strings.Repeat("a", 64), "REGISTRY.example/a@sha256:" + strings.Repeat("a", 64), "registry.example./a@sha256:" + strings.Repeat("a", 64), "registry.example/a:tag@sha256:" + strings.Repeat("a", 64), "registry.example/a/../b@sha256:" + strings.Repeat("a", 64), "user@registry.example/a@sha256:" + strings.Repeat("a", 64), "[::ffff:127.0.0.1]/a@sha256:" + strings.Repeat("a", 64)} {
		if (CosignVerifier{}).VerifySignature(context.Background(), ref, "unused") == nil {
			t.Fatalf("ambiguous reference accepted: %s", ref)
		}
	}
}
func TestRegistryForbiddenAddressRepresentations(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1", "169.254.169.254", "169.254.170.2", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "100.100.100.200", "fd00:ec2::254"} {
		ip := netip.MustParseAddr(address)
		if !forbiddenIP(ip) {
			t.Fatalf("forbidden address accepted: %s", address)
		}
	}
}
func TestRegistryDNSCheckedAtNumericDial(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var ip string
	for _, a := range addrs {
		p, _, _ := net.ParseCIDR(a.String())
		if p != nil && p.To4() != nil && p.IsPrivate() && !p.IsLoopback() {
			ip = p.String()
			break
		}
	}
	if ip == "" {
		t.Fatal("need a non-loopback private interface for actual socket test")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	host := "registry.test:" + port
	c, err := newRegistryClient(RegistryRule{Host: host, Endpoints: []RegistryEndpoint{{Host: host, CIDRs: []string{ip + "/32"}}}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	c.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr(ip)}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	conn, err := c.dial(context.Background(), "tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	conn.Close()
	if calls != 1 || actual != ip {
		t.Fatalf("DNS/socket identity changed: calls=%d destination=%s", calls, actual)
	}
	if _, err := c.dial(context.Background(), "tcp", host); err == nil {
		t.Fatal("rebound loopback DNS accepted")
	}
	if _, err := c.dial(context.Background(), "tcp", "alternate.test:"+port); err == nil {
		t.Fatal("alternate host accepted")
	}
	c.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(ip), netip.MustParseAddr("169.254.169.254")}, nil
	}
	if _, err := c.dial(context.Background(), "tcp", host); err == nil {
		t.Fatal("mixed allowed/metadata DNS accepted")
	}
}
func TestRegistryPolicyMalformedMissingAndDuplicate(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.json")
	for _, body := range []string{`{"registries":[]}`, `{"registries":[],"registries":[{}]}`, `{"registries":[],"unknown":true}`, `{"registries":[]} {}`, `{"registries":[{"host":"registry.test","endpoints":[]}]}`, `{"registries":[{"host":"registry.test","endpoints":[{"host":"registry.test","cidrs":["invalid"]}]}]}`} {
		os.WriteFile(file, []byte(body), 0600)
		if _, err := LoadRegistryPolicy(file); err == nil {
			t.Fatalf("bad policy accepted: %s", body)
		}
	}
	if _, err := LoadRegistryPolicy(file + "missing"); err == nil {
		t.Fatal("missing policy accepted")
	}
	if (CosignVerifier{}).VerifySignature(context.Background(), "registry.test/a@sha256:"+strings.Repeat("a", 64), "key") == nil {
		t.Fatal("missing destination policy allowed")
	}
}
func TestRegistryProxyEnvironmentNotInherited(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://credential-secret@untrusted.test:8080")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("COSIGN_REPOSITORY", "untrusted.test/override")
	t.Setenv("DOCKER_CONFIG", "secret-config")
	for _, s := range offlineEnvironment() {
		if strings.Contains(s, "credential-secret") || strings.HasPrefix(s, "COSIGN_REPOSITORY=") || strings.HasPrefix(s, "DOCKER_CONFIG=") || s == "NO_PROXY=*" {
			t.Fatalf("unsafe subprocess environment %q", s)
		}
	}
}

func TestSecurityJSONDuplicateKeysAndDepth(t *testing.T) {
	for _, b := range []string{`{"critical":{"image":{"digest":"a","digest":"b"}}}`, strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), `{} {}`} {
		if rejectAmbiguousJSON([]byte(b)) == nil {
			t.Fatal("ambiguous security JSON accepted")
		}
	}
	if rejectAmbiguousJSON([]byte(`{"valid":[{"value":1}]}`)) != nil {
		t.Fatal("valid JSON rejected")
	}
}
