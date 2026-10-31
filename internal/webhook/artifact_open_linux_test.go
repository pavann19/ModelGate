//go:build linux

package webhook

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pavann19/modelgate/internal/policy"
	"golang.org/x/sys/unix"
)

func TestFileArtifactFetcherRejectsFIFOWithoutWriter(t *testing.T) {
	ref := filepath.Join(t.TempDir(), "artifact.pipe")
	if err := unix.Mkfifo(ref, 0600); err != nil {
		t.Fatal(err)
	}
	// A symlink must not bypass the descriptor's file-type check.
	link := filepath.Join(t.TempDir(), "artifact.link")
	if err := os.Symlink(ref, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ref, link} {
		done := make(chan error, 1)
		go func() { _, err := (FileArtifactFetcher{}).Fetch(context.Background(), path); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("FIFO accepted")
			}
		case <-time.After(time.Second):
			// Release a blocked baseline open so the regression test leaves no goroutine behind.
			fd, err := unix.Open(ref, unix.O_RDWR|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			<-done
			unix.Close(fd)
			t.Fatal("FIFO blocked admission despite having no readable artifact")
		}
	}
}

func TestFIFOArtifactsDoNotRetainAdmissionSlots(t *testing.T) {
	ref := filepath.Join(t.TempDir(), "artifact.pipe")
	if err := unix.Mkfifo(ref, 0600); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(resolverFor("default", &policy.Config{ArtifactAllowList: map[string]string{ref: "unused"}}))
	h.Verifier = &fakeVerifier{signedImages: map[string]bool{"good": true}}
	pod := basicPod("good")
	pod.Annotations = map[string]string{ModelArtifactAnnotation: ref}
	req := podRequest(t, pod)
	// Keep a nonblocking writer open: even a connected, silent FIFO must be rejected.
	fd, err := unix.Open(ref, unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.Handle(context.Background(), req).Allowed {
				t.Error("FIFO artifact admitted")
			}
		}()
	}
	wg.Wait()
	if len(h.slots) != 0 {
		t.Fatal("admission slots retained")
	}
	if !h.Handle(context.Background(), podRequest(t, basicPod("good"))).Allowed {
		t.Fatal("valid request rejected after FIFO requests")
	}
}

func TestNonblockingArtifactOpenPreservesRegularFiles(t *testing.T) {
	ref := filepath.Join(t.TempDir(), "regular")
	want := []byte("regular artifact bytes")
	if err := os.WriteFile(ref, want, 0600); err != nil {
		t.Fatal(err)
	}
	link := ref + ".link"
	if err := os.Symlink(ref, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ref, link} {
		got, err := (FileArtifactFetcher{}).Fetch(context.Background(), path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("regular artifact read changed: %q %v", got, err)
		}
	}
}
