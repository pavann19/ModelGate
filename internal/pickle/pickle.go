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

const minOpcodeHits = 4

// IsPickle reports whether data looks like a raw Python pickle stream.
// It requires a PROTO opcode near the start and a minimum number of
// distinct-position opcode hits to avoid false positives on arbitrary bytes.
func IsPickle(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	if !bytes.HasPrefix(data, protocolMagic) {
		// Some pickles omit PROTO (protocol 0/1) but still end in STOP ('.').
		// Require it to at least end with STOP and have opcode density.
		if len(data) == 0 || data[len(data)-1] != '.' {
			return false
		}
	}
	hits := 0
	for _, b := range data {
		if knownOpcodes[b] {
			hits++
			if hits >= minOpcodeHits {
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
