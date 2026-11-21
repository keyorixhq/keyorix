package admin

// A test that swaps the process-wide log output must not hand the logger a bare
// bytes.Buffer: goroutines started by other tests in this package (storage's
// trigger-integrity check, started by every storage.CreateStorage on Postgres
// and never stopped by the tests that discard the storage) keep calling
// log.Printf after their test ended, so they write into whichever buffer the
// running test installed while that test reads it. #4501 failed in the merge
// queue and the scheduled run with exactly that data race.

import (
	"bytes"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
)

// lockedLogBuffer is an io.Writer safe for concurrent Write and read.
type lockedLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns a copy of everything written so far.
func (b *lockedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Lines returns the copied log lines that contain substr.
func (b *lockedLogBuffer) Lines(substr string) []string {
	var out []string
	for l := range strings.SplitSeq(b.String(), "\n") {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return out
}

// captureLog routes the standard logger into a lockedLogBuffer until the test
// ends, then restores stderr.
func captureLog(t *testing.T) *lockedLogBuffer {
	t.Helper()
	b := &lockedLogBuffer{}
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return b
}
