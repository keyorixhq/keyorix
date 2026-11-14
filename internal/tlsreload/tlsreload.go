// Package tlsreload serves a TLS certificate from a cert/key file pair and picks up
// a rotated pair without a restart (cert-manager, ACME clients and operators
// replace the files in place; before this the HTTP and gRPC listeners kept the pair
// they loaded at start until the process restarted, and served an expired
// certificate in the meantime).
//
// The files are re-checked at most once per CheckInterval, from the TLS handshake
// itself (tls.Config.GetCertificate), so there is no goroutine and no file watcher.
// A change is detected by the content of the pair (a SHA-256 over the certificate
// and the key bytes), not by file times: `cp -p`, `rsync -t` and a restore from
// backup keep the old modification time, and a swap through a symlink can keep
// size and inode as well, so none of those are reliable signals. Hashing two small
// files per tick is cheap. A changed pair is parsed and validated as a whole, from
// the same bytes that were hashed; if it does not load (a half-written rotation, a
// key that does not match the certificate) the previous pair keeps being served and
// the failure is logged, and the next check tries again.
package tlsreload

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// CheckInterval bounds how often a handshake re-reads the cert and key files.
// A rotated certificate is served within this long of being written.
var CheckInterval = 30 * time.Second

// Reloader holds the current certificate for one cert/key file pair.
type Reloader struct {
	certFile, keyFile string

	mu        sync.Mutex
	cert      *tls.Certificate
	digest    [sha256.Size]byte // content hash of the pair currently served
	lastCheck time.Time
}

// New loads the pair once and fails if it does not load, so a broken
// configuration still stops the server at start.
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	certPEM, keyPEM, digest, err := r.read()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	r.cert, r.digest, r.lastCheck = &cert, digest, time.Now()
	return r, nil
}

// GetCertificate is the tls.Config.GetCertificate hook.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastCheck) >= CheckInterval {
		r.lastCheck = time.Now()
		r.reloadLocked()
	}
	return r.cert, nil
}

func (r *Reloader) reloadLocked() {
	certPEM, keyPEM, digest, err := r.read()
	if err != nil {
		log.Printf("TLS certificate reload: %v (still serving the previous certificate)", err)
		return
	}
	if digest == r.digest {
		return
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// Leave the digest unchanged so the next check retries: a rotation
		// that writes the cert and the key one after the other is caught on the
		// check after the second write.
		log.Printf("TLS certificate reload: %s changed but does not load: %v (still serving the previous certificate)", r.certFile, err)
		return
	}
	r.cert, r.digest = &cert, digest
	log.Printf("TLS certificate reloaded from %s", r.certFile)
}

// read returns the contents of the cert and key files and a digest over both. The
// lengths are part of the digest so moving bytes from the end of one file to the
// start of the other cannot produce the same value.
func (r *Reloader) read() (certPEM, keyPEM []byte, digest [sha256.Size]byte, err error) {
	certPEM, err = os.ReadFile(r.certFile)
	if err != nil {
		return nil, nil, digest, fmt.Errorf("TLS certificate file: %w", err)
	}
	keyPEM, err = os.ReadFile(r.keyFile)
	if err != nil {
		return nil, nil, digest, fmt.Errorf("TLS key file: %w", err)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d:%d:", len(certPEM), len(keyPEM))
	h.Write(certPEM)
	h.Write(keyPEM)
	h.Sum(digest[:0])
	return certPEM, keyPEM, digest, nil
}
