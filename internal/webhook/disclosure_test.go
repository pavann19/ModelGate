package webhook

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pavann19/modelgate/internal/policy"
	"k8s.io/apimachinery/pkg/runtime"
)

type leakingVerifier struct{}

func (leakingVerifier) VerifySignature(context.Context, string, string) error {
	return errors.New("Bearer FAKE-CREDENTIAL-DO-NOT-LEAK")
}

func TestPodTypedFieldsAreCaseSensitiveButMetadataMapsRemainValid(t *testing.T) {
	h := NewHandler(resolverFor("default", &policy.Config{}))
	h.Verifier = &fakeVerifier{signedImages: map[string]bool{"good": true}}
	for _, body := range []string{
		`{"metadata":{"namespace":"default"},"spec":{"hostNetwork":true,"HostNetwork":false,"containers":[{"name":"main","image":"good"}]}}`,
		`{"metadata":{"namespace":"default"},"Spec":{"containers":[{"name":"main","image":"good"}]}}`,
		`{"metadata":{"namespace":"default"},"spec":{"containers":[{"name":"main","image":"good","securityContext":{"privileged":true,"Privileged":false}}]}}`,
	} {
		req := podRequest(t, basicPod("good"))
		req.Object = runtime.RawExtension{Raw: []byte(body)}
		if h.Handle(context.Background(), req).Allowed {
			t.Fatal("case-ambiguous typed Pod fields admitted")
		}
	}
	pod := basicPod("good")
	pod.Labels = map[string]string{"Team": "one", "team": "two"}
	if !h.Handle(context.Background(), podRequest(t, pod)).Allowed {
		t.Fatal("case-sensitive metadata maps rejected")
	}
}

func TestDependencyErrorsAndExemptionsDoNotDiscloseSecrets(t *testing.T) {
	for _, scenario := range []string{"policy", "verifier", "exempt"} {
		t.Run(scenario, func(t *testing.T) {
			var output bytes.Buffer
			h := NewHandler(resolverFor("default", &policy.Config{}))
			h.Logger = slog.New(slog.NewJSONHandler(&output, nil))
			h.Verifier = leakingVerifier{}
			if scenario == "policy" {
				h.Resolver = &fakeResolver{err: errors.New("Bearer FAKE-CREDENTIAL-DO-NOT-LEAK")}
			}
			if scenario == "exempt" {
				h.Resolver = &fakeResolver{byNamespace: map[string]policy.Resolution{"default": {Exempt: true, ExemptionReason: "Bearer FAKE-CREDENTIAL-DO-NOT-LEAK"}}}
			}
			response := h.Handle(context.Background(), podRequest(t, basicPod("synthetic")))
			if response.Allowed != (scenario == "exempt") {
				t.Fatal("decision semantics changed")
			}
			if strings.Contains(response.Result.Message+output.String(), "FAKE-CREDENTIAL") {
				t.Fatal("sensitive dependency/exemption text disclosed")
			}
		})
	}
}

func TestHTTPPanicFailsWithoutDisclosureAndReleasesSlot(t *testing.T) {
	h := BoundedAdmissionHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("Bearer FAKE-CREDENTIAL-DO-NOT-LEAK") }))
	for i := 0; i < 40; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
		if w.Code != 500 || strings.Contains(w.Body.String(), "FAKE-CREDENTIAL") {
			t.Fatal("panic leaked or decoder slot was retained")
		}
	}
}
