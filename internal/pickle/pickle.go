// Package pickle detects Python pickle-serialized data by scanning for
// pickle protocol opcodes, so model artifacts that are secretly pickles
// (e.g. a .pt file, which is really a zip of pickled tensors) can be rejected.
package pickle

import (
	"archive/zip"
	"bytes"
	"errors"
)

// pickleOpcodes are byte values that only make sense at the start of a
// pickle stream or that are strong signals of pickle protocol framing.
// See https://github.com/python/cpython/blob/main/Lib/pickle.py opcode table.
var protocolMagic = []byte{0x80} // PROTO opcode, followed by a version byte 0-5

// knownOpcodes is a small set of opcodes that appear in virtually every
// real pickle stream. Requiring several distinct hits (not just one stray
// byte) keeps the false-positive rate low on arbitrary binary files.
var knownOpcodes = map[byte]bool{
	0x80: true, // PROTO
	'.':  true, // STOP
	'}':  true, // EMPTY_DICT
	']':  true, // EMPTY_LIST
	')':  true, // EMPTY_TUPLE
	'q':  true, // BINPUT
	'r':  true, // LONG_BINPUT
	'X':  true, // SHORT_BINUNICODE / BINUNICODE
	'c':  true, // GLOBAL
	0x95: true, // FRAME
	0x8c: true, // SHORT_BINUNICODE (protocol 4+)
	0x94: true, // MEMOIZE
}

// minOpcodeHitsWithProto is the bar for pickle streams that start with the
// PROTO opcode (0x80): a real protocol 2+ pickle of virtually any non-empty
// object clears this easily (FRAME/MEMOIZE/BINPUT alone account for most
// of it), and starting with 0x80 is itself a strong, specific signal -- no
// other model format this package has been checked against
// (safetensors, ONNX, GGUF) begins with that byte.
const minOpcodeHitsWithProto = 4

// minOpcodeHitsFallback is the (much higher) bar for the fallback path used
// for protocol 0/1 pickles, which don't start with PROTO. That path's only
// other signal is "ends with STOP ('.')", which is a 1/256 coincidence on
// arbitrary bytes -- and fuzzing found that a legitimate safetensors file
// (whose JSON header routinely contains two or more '}' from its per-tensor
// objects, itself contributing to the opcode count) combined with tensor
// data that happens to end in 0x2E reached the old 4-hit bar purely by
// chance. Raising this fallback path's bar to 8 keeps PROTO-prefixed
// (protocol 2+) detection exactly as sensitive while cutting that
// coincidence rate by roughly 4000x, at the cost of missing some very
// short/trivial protocol-0/1 pickles -- an acceptable trade for real model
// artifacts, which are never that trivial. See
// internal/pickle/fuzz_test.go for the fuzz harness that found this.
const minOpcodeHitsFallback = 8

// IsPickle reports whether data looks like a raw Python pickle stream.
func IsPickle(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	minHits := minOpcodeHitsFallback
	if bytes.HasPrefix(data, protocolMagic) {
		minHits = minOpcodeHitsWithProto
	} else if data[len(data)-1] != '.' {
		// Some pickles omit PROTO (protocol 0/1) but still end in STOP
		// ('.'). Without either signal, this isn't plausibly a pickle.
		return false
	}

	hits := 0
	for _, b := range data {
		if knownOpcodes[b] {
			hits++
			if hits >= minHits {
				return true
			}
		}
	}
	return false
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
