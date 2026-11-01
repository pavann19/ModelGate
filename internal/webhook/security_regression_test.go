package webhook

import (
	"context"
	"github.com/pavann19/modelgate/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCosignVerifierRejectsMutableAndMalformedReferences(t *testing.T) {
	for _, ref := range []string{"registry.example/a:latest", "registry.example/a", "--help", "a@sha256:abc", "a@sha512:" + strings.Repeat("a", 128)} {
		if err := (CosignVerifier{}).VerifySignature(context.Background(), ref, "unused"); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%q did not fail digest validation: %v", ref, err)
		}
	}
}
func TestHandleProductionVerifierRejectsMutableTag(t *testing.T) {
	h := &Handler{Resolver: resolverFor("default", &policy.Config{}), Verifier: CosignVerifier{}}
	if h.Handle(context.Background(), podRequest(t, basicPod("registry.example/a:latest"))).Allowed {
		t.Fatal("mutable tag admitted")
	}
}
func TestHandleRejectsHostIPC(t *testing.T) {
	h := &Handler{Resolver: resolverFor("default", &policy.Config{}), Verifier: &fakeVerifier{signedImages: map[string]bool{"good:latest": true}}}
	pod := basicPod("good:latest")
	pod.Spec.HostIPC = true
	if h.Handle(context.Background(), podRequest(t, pod)).Allowed {
		t.Fatal("hostIPC admitted")
	}
}
func TestHandleRejectsNamespaceMismatchAndNilConfig(t *testing.T) {
	h := &Handler{Resolver: resolverFor("other", &policy.Config{})}
	req := podRequest(t, basicPod("x"))
	req.Namespace = "other"
	if h.Handle(context.Background(), req).Allowed {
		t.Fatal("namespace mismatch admitted")
	}
	h.Resolver = resolverFor("default", nil)
	if h.Handle(context.Background(), podRequest(t, basicPod("x"))).Allowed {
		t.Fatal("nil config admitted")
	}
}
func TestFileFetcherRejectsOversizeDirectoryAndCancellation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "large")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxArtifactBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, ref := range []string{dir, file} {
		if _, err := (FileArtifactFetcher{}).Fetch(context.Background(), ref); err == nil {
			t.Fatalf("accepted %q", ref)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (FileArtifactFetcher{}).Fetch(ctx, file); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}
func TestBoundedOutput(t *testing.T) {
	var b boundedOutput
	data := []byte(strings.Repeat("x", 8192))
	n, err := b.Write(data)
	if err != nil || n != len(data) || b.Len() != 4096 {
		t.Fatalf("unbounded or short write: %d %d %v", n, b.Len(), err)
	}
}

func TestProductionHandlerSaturationAndCancellationDeny(t *testing.T) {
	h := NewHandler(resolverFor("default", &policy.Config{}))
	for i := 0; i < cap(h.slots); i++ {
		h.slots <- struct{}{}
	}
	if h.Handle(context.Background(), podRequest(t, basicPod("x"))).Allowed {
		t.Fatal("saturation bypassed checks")
	}
	for len(h.slots) > 0 {
		<-h.slots
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h.Handle(ctx, podRequest(t, basicPod("x"))).Allowed {
		t.Fatal("canceled request admitted")
	}
	if len(h.slots) != 0 {
		t.Fatal("slot leaked")
	}
}

type blockingResolver struct {
	entered chan struct{}
	release chan struct{}
}

func (r blockingResolver) Resolve(ctx context.Context, ns string) (policy.Resolution, error) {
	r.entered <- struct{}{}
	select {
	case <-r.release:
		return policy.Resolution{Exempt: true, ExemptionReason: "test"}, nil
	case <-ctx.Done():
		return policy.Resolution{}, ctx.Err()
	}
}
func TestProductionHandlerConcurrentSaturation(t *testing.T) {
	r := blockingResolver{entered: make(chan struct{}, 8), release: make(chan struct{})}
	h := NewHandler(r)
	req := podRequest(t, basicPod("x"))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.Handle(context.Background(), req) }()
	}
	for i := 0; i < 8; i++ {
		<-r.entered
	}
	if h.Handle(context.Background(), req).Allowed {
		t.Fatal("ninth request admitted while saturated")
	}
	close(r.release)
	wg.Wait()
	if len(h.slots) != 0 {
		t.Fatal("slots leaked after concurrent requests")
	}
}
