package pickle

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestIsPickle_RealPickle(t *testing.T) {
	// Protocol-4 pickle of the string "hi", produced by:
	// pickletools.dis(pickle.dumps("hi", protocol=4))
	data := []byte{
		0x80, 0x04, 0x95, 0x06, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x8c, 0x02, 'h', 'i', 0x94, '.',
	}
	if !IsPickle(data) {
		t.Fatal("expected real pickle stream to be detected")
	}
}

func TestIsPickle_SafetensorsNotFlagged(t *testing.T) {
	// safetensors: 8-byte little-endian header length + JSON header.
	header := []byte(`{"__metadata__":{}}`)
	buf := new(bytes.Buffer)
	var lenBytes [8]byte
	n := len(header)
	for i := 0; i < 8; i++ {
		lenBytes[i] = byte(n >> (8 * i))
	}
	buf.Write(lenBytes[:])
	buf.Write(header)
	if IsPickle(buf.Bytes()) {
		t.Fatal("safetensors header must not be classified as pickle")
	}
}

func TestIsPickle_RandomBytesNotFlagged(t *testing.T) {
	data := []byte("just some plain text, not a pickle at all")
	if IsPickle(data) {
		t.Fatal("plain text must not be classified as pickle")
	}
}

func TestIsPyTorchPickle_ZipWithDataPkl(t *testing.T) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	f, err := w.Create("archive/data.pkl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0x80, 0x02, '.'}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !IsPyTorchPickle(buf.Bytes()) {
		t.Fatal("expected zip-based .pt archive with data.pkl to be detected")
	}
}

func TestIsPyTorchPickle_PlainZipNotFlagged(t *testing.T) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	f, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if IsPyTorchPickle(buf.Bytes()) {
		t.Fatal("zip without a pickle entry must not be flagged")
	}
}
