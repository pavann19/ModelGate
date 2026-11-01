package webhook

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RegistryPolicy is operator-owned, separate from namespace signing policies.
// Each registry has its own complete set of permitted TLS endpoints and IP ranges.
var errRegistryRedirect = errors.New("registry redirects are forbidden")

type RegistryPolicy struct {
	Registries []RegistryRule `json:"registries"`
}
type RegistryRule struct {
	Host      string             `json:"host"`
	Endpoints []RegistryEndpoint `json:"endpoints"`
	CAPEM     string             `json:"caPEM,omitempty"`
	Username  string             `json:"username,omitempty"`
	Password  string             `json:"password,omitempty"`
}
type RegistryEndpoint struct {
	Host  string   `json:"host"`
	CIDRs []string `json:"cidrs"`
}
type registryClient struct {
	rule      RegistryRule
	endpoints map[string][]netip.Prefix
	client    *http.Client
	lookup    func(context.Context, string, string) ([]netip.Addr, error)
}
type imageIdentity struct{ registry, repository, digest string }

var repositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
var hostPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
var shaPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func parseImage(image string) (imageIdentity, error) {
	fail := fmt.Errorf("image must use an immutable explicit-registry/repository@sha256 digest reference")
	ref, digest, ok := strings.Cut(image, "@")
	host, repo, hasRepo := strings.Cut(ref, "/")
	if !ok || !hasRepo || !shaPattern.MatchString(digest) || !repositoryPattern.MatchString(repo) {
		return imageIdentity{}, fail
	}
	authority, err := canonicalAuthority(host)
	if err != nil || authority != host {
		return imageIdentity{}, fail
	}
	return imageIdentity{host, repo, digest}, nil
}
func canonicalAuthority(s string) (string, error) {
	u, err := url.Parse("https://" + s)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Host != s {
		return "", errors.New("invalid endpoint")
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || strings.ToLower(host) != host || strings.Contains(host, "%") {
		return "", errors.New("invalid endpoint")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4In6() || ip.String() != host {
			return "", errors.New("ambiguous IP")
		}
	} else if regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){3}$`).MatchString(host) {
		return "", errors.New("ambiguous IPv4 address")
	} else if !hostPattern.MatchString(host) || !strings.Contains(host, ".") {
		return "", errors.New("explicit DNS endpoint required")
	}
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return "", errors.New("ambiguous port")
	}
	addr := net.JoinHostPort(host, port)
	if _, err := net.LookupPort("tcp", port); err != nil || regexp.MustCompile(`^[0-9]+$`).FindString(port) != port {
		return "", errors.New("invalid port")
	}
	// Keep the external authority exactly as configured, with default 443 optional.
	if u.Port() == "" {
		if strings.Contains(host, ":") {
			return "[" + host + "]", nil
		}
		return host, nil
	}
	return addr, nil
}
func LoadRegistryPolicy(path string) (*RegistryPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open registry policy")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(b) > 1024*1024 {
		return nil, errors.New("invalid registry policy size")
	}
	if rejectAmbiguousJSON(b) != nil {
		return nil, errors.New("ambiguous registry policy JSON")
	}
	var p RegistryPolicy
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return nil, errors.New("invalid registry policy JSON")
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing registry policy JSON")
	}
	seen := map[string]bool{}
	for _, r := range p.Registries {
		if seen[r.Host] {
			return nil, errors.New("duplicate registry")
		}
		seen[r.Host] = true
		if _, err := newRegistryClient(r); err != nil {
			return nil, err
		}
	}
	if len(p.Registries) == 0 {
		return nil, errors.New("registry policy must explicitly trust at least one registry")
	}
	return &p, nil
}
func (p *RegistryPolicy) forImage(id imageIdentity) (*registryClient, error) {
	if p != nil {
		for _, r := range p.Registries {
			if r.Host == id.registry {
				return newRegistryClient(r)
			}
		}
	}
	return nil, errors.New("registry destination is not trusted")
}
func newRegistryClient(r RegistryRule) (*registryClient, error) {
	if authority, err := canonicalAuthority(r.Host); err != nil || authority != r.Host {
		return nil, errors.New("invalid registry authority")
	}
	c := &registryClient{rule: r, endpoints: map[string][]netip.Prefix{}, lookup: net.DefaultResolver.LookupNetIP}
	for _, e := range r.Endpoints {
		a, err := canonicalAuthority(e.Host)
		if err != nil || a != e.Host || len(e.CIDRs) == 0 {
			return nil, errors.New("invalid registry endpoint")
		}
		u, _ := url.Parse("https://" + a)
		dialAddr := net.JoinHostPort(u.Hostname(), u.Port())
		if u.Port() == "" {
			dialAddr = net.JoinHostPort(u.Hostname(), "443")
		}
		if _, exists := c.endpoints[dialAddr]; exists {
			return nil, errors.New("duplicate registry endpoint")
		}
		for _, s := range e.CIDRs {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().Is4In6() || p.Masked() != p {
				return nil, errors.New("invalid endpoint CIDR")
			}
			c.endpoints[dialAddr] = append(c.endpoints[dialAddr], p)
		}
	}
	u, _ := url.Parse("https://" + r.Host)
	a := net.JoinHostPort(u.Hostname(), u.Port())
	if u.Port() == "" {
		a = net.JoinHostPort(u.Hostname(), "443")
	}
	if len(c.endpoints[a]) == 0 {
		return nil, errors.New("registry must have its own approved endpoint")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if r.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(r.CAPEM)) {
		return nil, errors.New("invalid registry CA")
	}
	tr := &http.Transport{Proxy: nil, DialContext: c.dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 32 * 1024, DisableCompression: true}
	c.client = &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errRegistryRedirect }}
	return c, nil
}
func forbiddenIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip == netip.MustParseAddr("100.100.100.200") || ip == netip.MustParseAddr("fd00:ec2::254") {
		return true
	}
	return !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
func (c *registryClient) dial(ctx context.Context, network, authority string) (net.Conn, error) {
	prefixes, ok := c.endpoints[authority]
	if !ok {
		return nil, errors.New("untrusted network endpoint")
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, errors.New("ambiguous network endpoint")
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = c.lookup(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("registry DNS failed")
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("registry DNS returned no addresses")
	}
	for _, ip := range ips {
		allowed := false
		for _, p := range prefixes {
			if p.Contains(ip.Unmap()) {
				allowed = true
			}
		}
		if forbiddenIP(ip) || !allowed {
			return nil, errors.New("registry address is forbidden")
		}
	}
	// Resolve once; the dialer receives a numeric IP, so DNS cannot change the
	// connection destination between policy validation and socket creation.
	for _, ip := range ips {
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("approved registry connection failed")
}
func (c *registryClient) get(ctx context.Context, rawURL, authorization string, limit int64) ([]byte, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return nil, nil, errors.New("invalid registry URL")
	}
	a := net.JoinHostPort(u.Hostname(), u.Port())
	if u.Port() == "" {
		a = net.JoinHostPort(u.Hostname(), "443")
	}
	if _, ok := c.endpoints[a]; !ok {
		return nil, nil, errors.New("untrusted registry endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, errors.New("invalid registry request")
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, errRegistryRedirect) {
			return nil, nil, errRegistryRedirect
		}
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			return nil, nil, errors.New("registry TLS verification failed")
		}
		var networkError net.Error
		if ctx.Err() != nil || (errors.As(err, &networkError) && networkError.Timeout()) {
			return nil, nil, errors.New("registry request timed out")
		}
		return nil, nil, errors.New("registry request failed")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, nil, errors.New("registry response exceeds bounds or is incomplete")
	}
	return b, resp, nil
}

var bearerFields = regexp.MustCompile(`([a-z]+)="([^"\r\n]*)"`)

func (c *registryClient) fetch(ctx context.Context, path string, limit int64) ([]byte, error) {
	rawURL := "https://" + c.rule.Host + path
	b, resp, err := c.get(ctx, rawURL, "", limit)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(challenge, "Bearer ") {
			return nil, errors.New("unsupported registry authentication")
		}
		fields := map[string]string{}
		for _, m := range bearerFields.FindAllStringSubmatch(challenge, -1) {
			if _, ok := fields[m[1]]; ok {
				return nil, errors.New("ambiguous authentication challenge")
			}
			fields[m[1]] = m[2]
		}
		realm, err := url.Parse(fields["realm"])
		if err != nil || realm.Scheme != "https" || realm.User != nil || realm.Fragment != "" {
			return nil, errors.New("invalid authentication endpoint")
		}
		q := realm.Query()
		q.Set("service", fields["service"])
		q.Set("scope", fields["scope"])
		realm.RawQuery = q.Encode()
		auth := ""
		if c.rule.Username != "" {
			req, _ := http.NewRequest("GET", "https://unused.invalid", nil)
			req.SetBasicAuth(c.rule.Username, c.rule.Password)
			auth = req.Header.Get("Authorization")
		}
		tokenBody, tr, err := c.get(ctx, realm.String(), auth, 64*1024)
		if err != nil || tr.StatusCode != 200 {
			return nil, errors.New("registry authentication failed")
		}
		var token struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(tokenBody, &token) != nil {
			return nil, errors.New("invalid registry token")
		}
		if token.Token == "" {
			token.Token = token.AccessToken
		}
		if token.Token == "" {
			return nil, errors.New("missing registry token")
		}
		b, resp, err = c.get(ctx, rawURL, "Bearer "+token.Token, limit)
		if err != nil {
			return nil, err
		}
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return nil, errors.New("no signatures found or artifact unavailable")
		}
		return nil, errors.New("registry rejected request")
	}
	return b, nil
}
func checkDigest(b []byte, digest string) error {
	sum := sha256.Sum256(b)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return errors.New("registry content digest mismatch")
	}
	return nil
}

type signaturePayload struct {
	Data      []byte
	Signature string
}

func (c *registryClient) signatures(ctx context.Context, id imageIdentity) ([]signaturePayload, error) {
	defer c.client.Transport.(*http.Transport).CloseIdleConnections()
	manifest, err := c.fetch(ctx, "/v2/"+id.repository+"/manifests/"+id.digest, 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	if err = checkDigest(manifest, id.digest); err != nil {
		return nil, err
	}
	raw, err := c.fetch(ctx, "/v2/"+id.repository+"/manifests/sha256-"+strings.TrimPrefix(id.digest, "sha256:")+".sig", 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("signature manifest: %w", err)
	}
	var m struct {
		SchemaVersion int `json:"schemaVersion"`
		Layers        []struct {
			Digest      string            `json:"digest"`
			Size        int64             `json:"size"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if rejectAmbiguousJSON(raw) != nil || json.Unmarshal(raw, &m) != nil || m.SchemaVersion != 2 || len(m.Layers) == 0 || len(m.Layers) > 16 {
		return nil, errors.New("invalid signature manifest")
	}
	var out []signaturePayload
	for _, l := range m.Layers {
		sig := l.Annotations["dev.cosignproject.cosign/signature"]
		if !shaPattern.MatchString(l.Digest) || l.Size < 0 || l.Size > 64*1024 || len(sig) == 0 || len(sig) > 16*1024 {
			return nil, errors.New("invalid signature descriptor")
		}
		data, err := c.fetch(ctx, "/v2/"+id.repository+"/blobs/"+l.Digest, 64*1024)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != l.Size || checkDigest(data, l.Digest) != nil {
			return nil, errors.New("invalid signature payload digest")
		}
		var payload struct {
			Critical struct {
				Identity struct {
					Reference string `json:"docker-reference"`
				} `json:"identity"`
				Image struct {
					Digest string `json:"docker-manifest-digest"`
				} `json:"image"`
				Type string `json:"type"`
			} `json:"critical"`
		}
		if rejectAmbiguousJSON(data) != nil || json.Unmarshal(data, &payload) != nil || payload.Critical.Image.Digest != id.digest || payload.Critical.Identity.Reference != id.registry+"/"+id.repository || payload.Critical.Type != "cosign container image signature" {
			return nil, errors.New("signature does not bind the requested repository and digest")
		}
		out = append(out, signaturePayload{Data: data, Signature: sig})
	}
	return out, nil
}

// Reject duplicate JSON keys rather than accepting last-value precedence in a trust document.
func rejectAmbiguousJSON(b []byte) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds bounds")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON key")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
