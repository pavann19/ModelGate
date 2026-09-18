// Package artifact validates model artifact files: it confirms a file is a
// well-formed safetensors file (not a disguised pickle) and that its SHA-256
// matches an expected value from an allow-list.
package artifact

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/pavann19/modelgate/internal/pickle"
)

// maxHeaderLen guards against a maliciously large declared header length
// causing an out-of-memory read; safetensors headers are JSON metadata and
// are expected to be small.
const maxHeaderLen = 100 * 1024 * 1024 // 100 MiB

// ErrPickleDetected is returned when the artifact contains pickle opcodes
// or a PyTorch pickle archive instead of a safetensors payload.
var ErrPickleDetected = fmt.Errorf("artifact: pickle-serialized data detected, refusing to admit")

// ErrNotSafetensors is returned when the artifact's header cannot be parsed
// as a valid safetensors header.
var ErrNotSafetensors = fmt.Errorf("artifact: not a valid safetensors file")

// ErrHashMismatch is returned when the artifact's SHA-256 does not match
// the expected value from the allow-list.
var ErrHashMismatch = fmt.Errorf("artifact: SHA-256 does not match allow-list entry")

// Validate checks that data is a well-formed safetensors file whose SHA-256
// digest equals expectedSHA256Hex (case-insensitive hex). It first checks
// for pickle signatures, since a disguised pickle must never be admitted
// even if it happens to also pass a loose header check.
func Validate(data []byte, expectedSHA256Hex string) error {
	if pickle.IsPyTorchPickle(data) {
		return ErrPickleDetected
	}
	if err := checkSafetensorsHeader(data); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	want := normalizeHex(expectedSHA256Hex)
	if got != want {
		return fmt.Errorf("%w: got %s, want %s", ErrHashMismatch, got, want)
	}
	return nil
}

// checkSafetensorsHeader verifies the magic-byte/header structure of a
// safetensors file: an 8-byte little-endian header length, followed by that
// many bytes of valid JSON forming an object.
func checkSafetensorsHeader(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: file too short for header length", ErrNotSafetensors)
	}
	headerLen := binary.LittleEndian.Uint64(data[:8])
	if headerLen == 0 || headerLen > maxHeaderLen {
		return fmt.Errorf("%w: implausible header length %d", ErrNotSafetensors, headerLen)
	}
	if uint64(len(data)) < 8+headerLen {
		return fmt.Errorf("%w: declared header length exceeds file size", ErrNotSafetensors)
	}
	header := data[8 : 8+headerLen]
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(header, &parsed); err != nil {
		return fmt.Errorf("%w: header is not valid JSON: %v", ErrNotSafetensors, err)
	}
	return nil
}

func normalizeHex(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r >= 'A' && r <= 'F' {
			r += 'a' - 'A'
		}
		out = append(out, byte(r))
	}
	return string(out)
}
