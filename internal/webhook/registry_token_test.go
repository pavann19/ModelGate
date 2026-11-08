package webhook

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

type tokenTransport struct {
	token         string
	calls         int
	challenge     string
	authorization string
}

func (tr *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.calls++
	if tr.calls == 1 {
		challenge := tr.challenge
		if challenge == "" {
			challenge = `Bearer realm="https://registry.test/token"`
		}
		return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": []string{challenge}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	if tr.calls == 3 {
		tr.authorization = req.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("artifact"))}, nil
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tr.token))}, nil
}

func TestAmbiguousRegistryTokenRejected(t *testing.T) {
	for _, token := range []string{`{"token":"first","token":"second"}`, `{"token":"first","TOKEN":"second"}`, `{"access_token":"first","acce\u017fs_token":"second"}`, `{"token":"first","access_token":"second"}`, `{"token":"first"} {}`} {
		transport := &tokenTransport{token: token}
		c := &registryClient{rule: RegistryRule{Host: "registry.test"},
			endpoints: map[string][]netip.Prefix{"registry.test:443": {}},
			client:    &http.Client{Transport: transport}}
		if _, err := c.fetch(context.Background(), "/v2/repo/manifests/test", 1024); err == nil || transport.calls != 2 {
			t.Fatal("ambiguous registry token used to retry authenticated request")
		}
	}
}

func TestRegistryTokenPositiveControls(t *testing.T) {
	for _, body := range []string{`{"token":"valid"}`, `{"access_token":"valid"}`, `{"token":"valid","access_token":"valid","expires_in":300}`} {
		tr := &tokenTransport{token: body}
		c := &registryClient{rule: RegistryRule{Host: "registry.test"}, endpoints: map[string][]netip.Prefix{"registry.test:443": {}}, client: &http.Client{Transport: tr}}
		got, err := c.fetch(context.Background(), "/v2/repo/manifests/test", 1024)
		if err != nil || string(got) != "artifact" || tr.calls != 3 || tr.authorization != "Bearer valid" {
			t.Fatalf("valid token failed: body=%s got=%s err=%v calls=%d", body, got, err, tr.calls)
		}
	}
}

func TestRegistryMalformedChallengeDoesNotRequestToken(t *testing.T) {
	for _, challenge := range []string{
		`Bearer junk realm="https://registry.test/token"`,
		`Bearer realm="https://registry.test/token", REALM="https://other.test/token"`,
		`Bearer realm="https://registry.test/token",`,
		`Bearer realm="https://registry.test/token" garbage`,
		`Bearer realm="https://other.test/token"`,
	} {
		tr := &tokenTransport{token: `{"token":"valid"}`, challenge: challenge}
		c := &registryClient{rule: RegistryRule{Host: "registry.test", Username: "synthetic", Password: "fixture"}, endpoints: map[string][]netip.Prefix{"registry.test:443": {}}, client: &http.Client{Transport: tr}}
		if _, err := c.fetch(context.Background(), "/v2/repo/manifests/test", 1024); err == nil || tr.calls != 1 {
			t.Fatalf("challenge reached token endpoint: %q calls=%d err=%v", challenge, tr.calls, err)
		}
	}
}
