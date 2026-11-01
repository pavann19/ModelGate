//go:build !linux

package webhook

import "os"

func openArtifact(ref string) (*os.File, error) {
	return os.Open(ref)
}
