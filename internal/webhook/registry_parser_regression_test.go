package webhook

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryJSONRejectsCaseFoldAmbiguity(t *testing.T) {
	for _, body := range []string{
		`{"host":"trusted.test","HOST":"other.test"}`,
		`{"layers":[],"Layers":[{}]}`,
		`{"critical":{"image":{"docker-manifest-digest":"a","DOCKER-MANIFEST-DIGEST":"b"}}}`,
		`{"token":"a","to\u212aen":"b"}`,
		`{"access_token":"a","acce\u017fs_token":"b"}`,
	} {
		if rejectRegistryJSON([]byte(body)) == nil {
			t.Fatalf("case-fold ambiguity accepted: %s", body)
		}
	}
	// Kubernetes map keys are case-sensitive. Registry-specific strictness must
	// not change the workload parser's treatment of legitimate metadata maps.
	if err := rejectAmbiguousJSON([]byte(`{"metadata":{"labels":{"Team":"a","team":"b"}}}`)); err != nil {
		t.Fatalf("case-sensitive workload keys rejected: %v", err)
	}
	if rejectRegistryJSON([]byte("{\"token\":\"\xff\"}")) == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestBearerChallengePositiveControls(t *testing.T) {
	for _, body := range []string{
		`Bearer realm="https://registry.test/token"`,
		`bearer Realm="https://registry.test/token", service="registry.test", scope="repository:repo:pull"`,
	} {
		fields, err := parseBearerChallenge(body)
		if err != nil || fields["realm"] != "https://registry.test/token" {
			t.Fatalf("valid challenge rejected: %q %v", body, err)
		}
	}
}

func FuzzRegistryJSONKeys(f *testing.F) {
	for _, seed := range []string{`{"token":"a"}`, `{"token":"a","TOKEN":"b"}`, `{"nested":[{"k":"v"}]}`, `{"access_token":"a","acce\u017fs_token":"b"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 64*1024 {
			return
		}
		if rejectRegistryJSON([]byte(body)) == nil && !json.Valid([]byte(body)) {
			t.Fatal("invalid JSON accepted")
		}
	})
}

func FuzzBearerChallenge(f *testing.F) {
	f.Add(`Bearer realm="https://registry.test/token",service="registry.test"`)
	f.Add(`Bearer realm="a",REALM="b"`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 32*1024 {
			return
		}
		fields, err := parseBearerChallenge(body)
		if err == nil && len(fields) == 0 {
			t.Fatal("empty challenge accepted")
		}
		for key := range fields {
			if key != strings.ToLower(key) {
				t.Fatal("noncanonical field key")
			}
		}
	})
}
