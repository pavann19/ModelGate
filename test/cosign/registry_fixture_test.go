package cosign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/pavann19/modelgate/internal/webhook"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type tlsRegistryFixture struct {
	host, ip, digest, publicKey, otherPublicKey, unsupportedPublicKey string
	policy                                                            *webhook.RegistryPolicy
}

func (f tlsRegistryFixture) image(repo string) string { return f.host + "/" + repo + "@" + f.digest }
func localPrivateIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && ip.IsPrivate() {
			return ip.String()
		}
	}
	t.Fatal("real TLS registry tests need a non-loopback private interface")
	return ""
}
func fixtureDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func newTLSRegistry(t *testing.T) tlsRegistryFixture {
	t.Helper()
	ip := localPrivateIP(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := func(k *ecdsa.PrivateKey) string {
		b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
	}
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test registry"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(ip)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := tlsRegistryFixture{ip: ip, host: listener.Addr().String(), publicKey: pub(key), otherPublicKey: pub(other)}
	// Real OCI image manifest; verification retrieves actual content-addressed bytes.
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0},"layers":[]}`)
	fixture.digest = fixtureDigest(manifest)
	unsupported, _ := asn1.Marshal(struct {
		Algorithm struct{ OID asn1.ObjectIdentifier }
		Key       asn1.BitString
	}{Algorithm: struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 3, 4}}, Key: asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24}})
	fixture.unsupportedPublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: unsupported}))
	routes := map[string][]byte{}
	for _, repo := range []string{"signed", "unsigned", "wrong-signature", "wrong-artifact", "wrong-repository", "malformed-signature", "bad-content", "redirect-untrusted", "redirect-private", "redirect-loopback", "auth-untrusted", "authenticated", "slow-registry", "partial-response", "oversized-manifest", "secret-error"} {
		routes["/v2/"+repo+"/manifests/"+fixture.digest] = manifest
		if repo == "bad-content" {
			routes["/v2/"+repo+"/manifests/"+fixture.digest] = []byte(`{"schemaVersion":2}`)
		}
		if repo == "unsigned" {
			continue
		}
		digest := fixture.digest
		identity := fixture.host + "/" + repo
		if repo == "wrong-artifact" {
			digest = "sha256:" + strings.Repeat("0", 64)
		}
		if repo == "wrong-repository" {
			identity = fixture.host + "/other"
		}
		payload, _ := json.Marshal(map[string]any{"critical": map[string]any{"identity": map[string]string{"docker-reference": identity}, "image": map[string]string{"docker-manifest-digest": digest}, "type": "cosign container image signature"}, "optional": nil})
		hash := sha256.Sum256(payload)
		signingKey := key
		if repo == "wrong-signature" {
			signingKey = other
		}
		sig, err := ecdsa.SignASN1(rand.Reader, signingKey, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		signature := base64.StdEncoding.EncodeToString(sig)
		if repo == "malformed-signature" {
			signature = "not base64 secret-marker-DO-NOT-LEAK"
		}
		pd := fixtureDigest(payload)
		sm, _ := json.Marshal(map[string]any{"schemaVersion": 2, "layers": []any{map[string]any{"digest": pd, "size": len(payload), "annotations": map[string]string{"dev.cosignproject.cosign/signature": signature}}}})
		routes["/v2/"+repo+"/manifests/sha256-"+strings.TrimPrefix(fixture.digest, "sha256:")+".sig"] = sm
		routes["/v2/"+repo+"/blobs/"+pd] = payload
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/slow-registry/") {
			select {
			case <-r.Context().Done():
			case <-time.After(15 * time.Second):
			}
			return
		}
		if strings.Contains(r.URL.Path, "/partial-response/") {
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("short"))
			return
		}
		if strings.Contains(r.URL.Path, "/oversized-manifest/") {
			w.Write([]byte(strings.Repeat("x", 1024*1024+1)))
			return
		}
		if strings.Contains(r.URL.Path, "/secret-error/") {
			w.WriteHeader(500)
			w.Write([]byte("private-registry-password DO-NOT-LEAK"))
			return
		}
		if r.URL.Path == "/token" {
			user, password, ok := r.BasicAuth()
			if !ok || user != "test-user" || password != "private-registry-password" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"token":"test-registry-token"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/authenticated/") && r.Header.Get("Authorization") != "Bearer test-registry-token" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+fixture.host+`/token",service="fixture",scope="repository:authenticated:pull"`)
			w.WriteHeader(401)
			return
		}
		if strings.Contains(r.URL.Path, "/redirect-") {
			target := "https://attacker.example/steal"
			if strings.Contains(r.URL.Path, "redirect-private") {
				target = "https://192.168.1.1/secret"
			}
			if strings.Contains(r.URL.Path, "redirect-loopback") {
				target = "http://127.0.0.1:8080/metrics"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		if strings.Contains(r.URL.Path, "/auth-untrusted/") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://untrusted.example/token",service="bad",scope="pull"`)
			w.WriteHeader(401)
			return
		}
		b, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Write(b)
	}))
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: certKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	fixture.policy = &webhook.RegistryPolicy{Registries: []webhook.RegistryRule{{Host: fixture.host, Username: "test-user", Password: "private-registry-password", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Endpoints: []webhook.RegistryEndpoint{{Host: fixture.host, CIDRs: []string{ip + "/32"}}}}}}
	return fixture
}

// Explicit fixture-server mode for actual Kubernetes integration; never a product fallback.
func TestLiveRegistryServer(t *testing.T) {
	if os.Getenv("MODELGATE_LIVE_REGISTRY_SERVER") != "1" {
		t.Skip("fixture-server mode is launched separately by live integration")
	}
	f := newTLSRegistry(t)
	b, err := json.Marshal(map[string]any{"registryPolicy": f.policy, "publicKey": f.publicKey, "otherPublicKey": f.otherPublicKey, "digest": f.digest, "host": f.host})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("REGISTRY_BOOTSTRAP=" + string(b))
	time.Sleep(15 * time.Minute)
}
