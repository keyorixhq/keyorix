//go:build unix

package tlsreload

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReloader_FIFOAtKeyPathIsRefusedNotBlocked: a FIFO at the key path must be
// refused at once; a blocking open(2) would hang New (and, on a later tick, every
// handshake behind the reloader's lock).
func TestReloader_FIFOAtKeyPathIsRefusedNotBlocked(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	fifo := filepath.Join(dir, "fifo.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := New(certFile, fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("New accepted a FIFO as the key file")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("New blocked on a FIFO key path")
	}
}
