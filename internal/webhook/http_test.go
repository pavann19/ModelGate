package webhook

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestAdmissionSlowBodyDeadline(t *testing.T) {
	server := httptest.NewTLSServer(BoundedAdmissionHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "incomplete body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	defer server.Close()
	connection, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // isolated ephemeral test certificate
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprint(connection, "POST /validate-pods HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatalf("server did not bound slow body read: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("slow incomplete body accepted: %d", response.StatusCode)
	}
}

func TestAmbiguousPodRejectedBeforePolicyLookup(t *testing.T) {
	// A nil resolver deliberately detects any attempt to proceed past decoding.
	h := NewHandler(nil)
	for _, raw := range []string{
		`{"metadata":{"namespace":"default"},"spec":{"hostNetwork":true,"hostNetwork":false}}`,
		`{"spec":{"containers":[]},"spec":{}}`,
		`{} {}`,
		strings.Repeat(" ", 2*1024*1024+1),
	} {
		req := admission.Request{}
		req.Object = runtime.RawExtension{Raw: []byte(raw)}
		resp := h.Handle(context.Background(), req)
		if resp.Allowed || resp.Result == nil || resp.Result.Code != http.StatusBadRequest {
			t.Fatal("ambiguous/oversized object reached policy resolution")
		}
	}
}

func TestAdmissionTransportBoundsBodyAndMethod(t *testing.T) {
	h := BoundedAdmissionHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		method, body string
		status       int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, "{}", http.StatusNoContent},
		{http.MethodPost, strings.Repeat("x", 3*1024*1024+1), http.StatusRequestEntityTooLarge},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, "/validate-pods", strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("%s: got %d want %d", tc.method, w.Code, tc.status)
		}
	}
}

func TestAdmissionTransportSaturationAndRecovery(t *testing.T) {
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	h := BoundedAdmissionHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
		}()
	}
	for i := 0; i < 32; i++ {
		<-entered
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("saturation returned %d", w.Code)
	}
	close(release)
	wg.Wait()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusNoContent {
		t.Fatal("capacity not released")
	}
}
