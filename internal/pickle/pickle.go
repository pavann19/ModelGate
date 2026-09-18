// Package pickle detects Python pickle-serialized data by checking for the
// PROTO opcode pickle protocol 2+ streams always begin with, so model
// artifacts that are secretly pickles (e.g. a .pt file, which is really a
// zip of pickled tensors) can be rejected.
package pickle

import (
	"archive/zip"
	"bytes"
	"errors"
)

// maxProtocolVersion is the highest pickle protocol version defined as of
// this writing (protocols 0-5 exist; see cpython's pickle.HIGHEST_PROTOCOL).
const maxProtocolVersion = 5

// IsPickle reports whether data is a pickle protocol 2+ stream: it must
// start with the PROTO opcode (0x80) followed by a valid protocol version
// byte (0-5).
//
// This package previously tried to also catch protocol 0/1 pickles (which
// don't have a PROTO prefix) and used opcode-density heuristics -- "does
// this data contain several of a small set of known opcode byte values" --
// for both cases. Fuzzing (internal/pickle/fuzz_test.go) repeatedly broke
// that approach: a coverage-guided fuzzer can trivially construct a short
// "alphabet soup" input containing every tracked opcode byte value as a
// literal, deliberately placed byte, defeating any distinct-count or
// occurrence-count threshold no matter how high it's raised -- three
// separate threshold increases were each fuzzed out within the same
// session (see the git history and the committed regression seeds in
// internal/pickle/testdata/fuzz/). A "does this data contain matching
// bytes anywhere" check can never be robust against an adversary (or a
// fuzzer) who can choose the bytes; only a check anchored to a specific,
// unambiguous position is.
//
// PROTO + a valid version byte at position 0 is exactly that: every
// pickle.dump() call from any modern Python (protocol 2 has been the
// default or higher since Python 3.0, and torch.save/model serialization
// tooling always goes through pickle.dump) produces a stream starting
// with these exact two bytes, and no other model format this package has
// been checked against (safetensors, ONNX, GGUF) can produce that prefix
// by coincidence -- their own magic bytes/framing occupy that position.
// Protocol 0/1 pickles (no PROTO prefix) are legacy, not what any current
// tooling produces by default, and are now an explicit, accepted gap
// rather than a heuristic that looked like coverage but wasn't robust.
func IsPickle(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return data[0] == 0x80 && data[1] <= maxProtocolVersion
}

// IsPyTorchPickle reports whether data is a PyTorch .pt/.pth file using the
// legacy or zip-based format, both of which embed one or more pickled
// tensors. PyTorch zip archives contain a "data.pkl" (or "*/data.pkl") entry.
func IsPyTorchPickle(data []byte) bool {
	if IsPickle(data) {
		return true
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range r.File {
		if isPickleEntryName(f.Name) {
			return true
		}
	}
	return false
}

func isPickleEntryName(name string) bool {
	return bytes.HasSuffix([]byte(name), []byte("data.pkl")) ||
		bytes.HasSuffix([]byte(name), []byte(".pkl"))
}

// ErrNotPickle is returned by callers that expect a definitive classification
// but received data too short to analyze.
var ErrNotPickle = errors.New("pickle: input too short to classify")
