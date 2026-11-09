package webhook

import (
	"bytes"
	"os"
)

// Historical regression helpers; no production subprocess remains.
func offlineEnvironment() []string {
	var env []string
	for _, name := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	// These proxies are defensive: offline operands prevent network use; any
	// unexpected future HTTP path must fail against an unusable proxy.
	env = append(env, "HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1", "ALL_PROXY=http://127.0.0.1:1", "NO_PROXY=", "COSIGN_EXPERIMENTAL=0")
	return env
}

// boundedOutput drains subprocess stderr without retaining unbounded registry output.
type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	const limit = 4096
	if remaining := limit - b.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
