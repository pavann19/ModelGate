package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func buildSafetensors(t *testing.T, header string, body []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], uint64(len(header)))
	buf.Write(lenBytes[:])
	buf.WriteString(header)
	buf.Write(body)
	return buf.Bytes()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestValidate_GoodSafetensors(t *testing.T) {
	data := buildSafetensors(t, `{"__metadata__":{"format":"pt"}}`, []byte{1, 2, 3, 4})
	if err := Validate(data, sha256Hex(data)); err != nil {
		t.Fatalf("expected valid safetensors to pass, got %v", err)
	}
}

func TestValidate_HashMismatch(t *testing.T) {
	data := buildSafetensors(t, `{"__metadata__":{}}`, []byte{1, 2, 3})
	err := Validate(data, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

func TestValidate_RejectsPickle(t *testing.T) {
	pickleData := []byte{
		0x80, 0x04, 0x95, 0x06, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x8c, 0x02, 'h', 'i', 0x94, '.',
	}
	err := Validate(pickleData, sha256Hex(pickleData))
	if err == nil {
		t.Fatal("expected pickle to be rejected even with matching hash")
	}
}

func TestValidate_RejectsMalformedHeader(t *testing.T) {
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3}
	err := Validate(data, sha256Hex(data))
	if err == nil {
		t.Fatal("expected implausible header length to be rejected")
	}
}

func TestValidate_RejectsInvalidJSONHeader(t *testing.T) {
	data := buildSafetensors(t, `not json`, []byte{1})
	err := Validate(data, sha256Hex(data))
	if err == nil {
		t.Fatal("expected non-JSON header to be rejected")
	}
}
