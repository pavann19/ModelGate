package artifact

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// Keep the original object-framing acceptance oracle while removing its
// allocations from production. This does not claim tensor-schema validation.
func FuzzHeaderFramingCompatibility(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `[]`, `{"x":[1,null]}`, `{"x":1,"x":2}`, "{\"x\":\"\xff\"}", `{} {}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		if len(header) > 256*1024 {
			return
		}
		var original map[string]json.RawMessage
		want := json.Unmarshal([]byte(header), &original) == nil && original != nil
		data := make([]byte, 8+len(header))
		binary.LittleEndian.PutUint64(data, uint64(len(header)))
		copy(data[8:], header)
		if got := checkSafetensorsHeader(data) == nil; got != want {
			t.Fatalf("framing acceptance changed: got=%v want=%v header=%q", got, want, header)
		}
	})
}

func TestHeaderObjectFramingControls(t *testing.T) {
	for _, header := range []string{`[]`, `null`, `true`, `42`, `"object"`, `{} {}`, `{"a":}`, ""} {
		data := buildSafetensors(t, header, nil)
		if err := Validate(data, sha256Hex(data)); err == nil {
			t.Fatalf("non-object/invalid header accepted: %q", header)
		}
	}
	for _, header := range []string{`{}`, " \n{\"x\":[1,true,null,{\"y\":\"z\"}]} \t", `{"__metadata__":{"format":"pt"}}`} {
		data := buildSafetensors(t, header, []byte{0, 1, 2})
		if err := Validate(data, sha256Hex(data)); err != nil {
			t.Fatalf("valid object rejected: %v", err)
		}
	}
}

func BenchmarkHeaderFraming8MiB(b *testing.B) {
	header := `{"__metadata__":{"synthetic":"` + strings.Repeat("x", 8*1024*1024) + `"}}`
	data := make([]byte, 8+len(header))
	binary.LittleEndian.PutUint64(data, uint64(len(header)))
	copy(data[8:], header)
	b.ReportAllocs()
	b.SetBytes(int64(len(header)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := checkSafetensorsHeader(data); err != nil {
			b.Fatal(err)
		}
	}
}
