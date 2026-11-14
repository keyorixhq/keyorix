package tlsreload

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkReloader_UnchangedTick measures what one CheckInterval tick costs when
// nothing changed: open, stat and read both files, SHA-256 them, compare. This is the
// steady-state cost paid once per interval by the first handshake after it elapses.
func BenchmarkReloader_UnchangedTick(b *testing.B) {
	dir := b.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	certPEM, keyPEM := genPair(b, 1)
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		b.Fatal(err)
	}
	r, err := New(certFile, keyFile)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r.mu.Lock()
		r.reloadLocked()
		r.mu.Unlock()
	}
}
