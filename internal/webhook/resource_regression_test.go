package webhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pavann19/modelgate/internal/policy"
)

type heldArtifactFetcher struct {
	entered chan struct{}
	release chan struct{}
	data    []byte
	calls   *atomic.Int32
}

func (f heldArtifactFetcher) Fetch(ctx context.Context, _ string) ([]byte, error) {
	if f.calls.Add(1) > 1 {
		return nil, errors.New("overlap reached fetcher")
	}
	close(f.entered)
	select {
	case <-f.release:
		return f.data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestArtifactCapacityDeniesWithoutFetchingAndRecovers(t *testing.T) {
	data := buildSafetensors(`{}`, []byte{1, 2})
	cfg := &policy.Config{ArtifactAllowList: map[string]string{"fixture": sha256Hex(data)}}
	h := NewHandler(nil)
	f := heldArtifactFetcher{entered: make(chan struct{}), release: make(chan struct{}), data: data, calls: new(atomic.Int32)}
	h.Fetcher = f
	done := make(chan bool, 1)
	go func() { _, denied := h.checkModelArtifact(context.Background(), cfg, "fixture"); done <- denied }()
	select {
	case <-f.entered:
	case <-time.After(time.Second):
		t.Fatal("first fetch did not start")
	}
	reason, denied := h.checkModelArtifact(context.Background(), cfg, "fixture")
	if !denied || !strings.Contains(reason, "capacity exhausted") {
		close(f.release)
		<-done
		t.Fatalf("overlapping allocation was not denied: %q %v", reason, denied)
	}
	close(f.release)
	if <-done {
		t.Fatal("valid in-flight artifact was denied")
	}
	h.Fetcher = &fakeFetcher{data: map[string][]byte{"fixture": data}}
	if reason, denied := h.checkModelArtifact(context.Background(), cfg, "fixture"); denied {
		t.Fatalf("artifact capacity did not recover: %s", reason)
	}
	// A failed fetch must release capacity too.
	h.Fetcher = &fakeFetcher{}
	if _, denied := h.checkModelArtifact(context.Background(), cfg, "fixture"); !denied {
		t.Fatal("missing artifact allowed")
	}
	h.Fetcher = &fakeFetcher{data: map[string][]byte{"fixture": data}}
	if _, denied := h.checkModelArtifact(context.Background(), cfg, "fixture"); denied {
		t.Fatal("capacity leaked after failure")
	}
}

func TestArtifactSnapshotRejectsGrowthShrinkAndReadFailure(t *testing.T) {
	for _, tc := range []struct {
		data string
		size int64
	}{{"abcd", 3}, {"ab", 3}, {"", -1}, {"", maxArtifactBytes + 1}} {
		if _, err := readArtifactSnapshot(strings.NewReader(tc.data), tc.size); err == nil {
			t.Fatalf("changed/invalid snapshot accepted: %+v", tc)
		}
	}
	if _, err := readArtifactSnapshot(failingArtifactReader{}, 3); err == nil {
		t.Fatal("I/O error ignored")
	}
}

type failingArtifactReader struct{}

func (failingArtifactReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}

func TestFileFetcherExactSizeBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 8192, maxArtifactBytes} {
		path := filepath.Join(t.TempDir(), "fixture")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(int64(size)); err != nil {
			t.Fatal(err)
		}
		f.Close()
		got, err := (FileArtifactFetcher{}).Fetch(context.Background(), path)
		if err != nil || len(got) != size {
			t.Fatalf("size=%d got=%d err=%v", size, len(got), err)
		}
		if !bytes.Equal(got[:min(len(got), 8)], make([]byte, min(len(got), 8))) {
			t.Fatal("content changed")
		}
	}
}

// The same benchmark is copied unchanged to the frozen baseline for comparison.
func BenchmarkFileArtifactFetcher64MiB(b *testing.B) {
	path := filepath.Join(b.TempDir(), "synthetic-artifact")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.CopyN(f, zeroReader{}, maxArtifactBytes); err != nil {
		b.Fatal(err)
	}
	f.Close()
	b.ReportAllocs()
	b.SetBytes(maxArtifactBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := (FileArtifactFetcher{}).Fetch(context.Background(), path)
		if err != nil || len(data) != maxArtifactBytes {
			b.Fatalf("read failed: %v", err)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
