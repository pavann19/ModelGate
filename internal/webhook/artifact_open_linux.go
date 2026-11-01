//go:build linux

package webhook

import (
	"os"
	"syscall"
)

// Open nonblocking before inspecting the descriptor. A path or symlink to a
// FIFO otherwise waits for a writer before Fetch can reject its file type;
// checking the path first would introduce a stat/open replacement race.
func openArtifact(ref string) (*os.File, error) {
	return os.OpenFile(ref, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
