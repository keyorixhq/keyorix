// Package tlsreload serves a TLS certificate from a cert/key file pair and picks up
// a rotated pair without a restart (cert-manager, ACME clients and operators
// replace the files in place; before this the HTTP and gRPC listeners kept the pair
// they loaded at start until the process restarted, and served an expired
// certificate in the meantime).
//
// The files are re-read at most once per CheckInterval, from the TLS handshake
// itself (tls.Config.GetCertificate), so there is no goroutine and no file watcher.
// A change is detected from the content (a SHA-256 digest of both files) and from the
// identity of each file (size, modification time, os.SameFile), not from the
// modification time alone: a replacement made with cp -p, rsync -t, a restore from
// backup or a secret-store mount keeps the old mtime and is still noticed. A changed
// pair is parsed and validated as a whole, from the same bytes that were digested; if
// it does not load (a half-written rotation, a key that does not match the
// certificate) the previous pair keeps being served and the failure is logged, and the
// next check tries again. Neither key bytes nor digests are logged.
package tlsreload

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// CheckInterval bounds how often a handshake re-reads the cert and key files.
// A rotated certificate is served within this long of being written.
var CheckInterval = 30 * time.Second

// maxFileSize bounds what is read from either file; a certificate chain or a key is a
// few KB, so anything near this is not one and is treated as unreadable.
const maxFileSize = 1 << 20

// Reloader holds the current certificate for one cert/key file pair.
type Reloader struct {
	certFile, keyFile string

	mu        sync.Mutex
	cert      *tls.Certificate
	loaded    snapshot // what cert was parsed from
	lastCheck time.Time
}

// snapshot is one consistent read of the pair: the bytes that are parsed, the digest of
// exactly those bytes, and the identity (size, mtime, file) of each file as seen through
// the handle that was read. Parsing the bytes of the snapshot, not re-opening the files,
// means the digest and the served pair can never describe different file states.
type snapshot struct {
	certInfo, keyInfo os.FileInfo
	certPEM, keyPEM   []byte
	digest            [sha256.Size]byte
}

// New loads the pair once and fails if it does not load, so a broken
// configuration still stops the server at start.
func New(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	snap, err := r.read()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(snap.certPEM, snap.keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	r.cert, r.loaded, r.lastCheck = &cert, snap.forget(), time.Now()
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
	snap, err := r.read()
	if err != nil {
		log.Printf("TLS certificate reload: %v (still serving the previous certificate)", err)
		return
	}
	if !snap.changedFrom(r.loaded) {
		return
	}
	cert, err := tls.X509KeyPair(snap.certPEM, snap.keyPEM)
	if err != nil {
		// r.loaded stays as it was, so the next check sees the change again and
		// retries: a rotation that writes the cert and the key one after the other
		// is caught on the check after the second write.
		log.Printf("TLS certificate reload: %s changed but does not load: %v (still serving the previous certificate)", r.certFile, err)
		return
	}
	r.cert, r.loaded = &cert, snap.forget()
	log.Printf("TLS certificate reloaded from %s", r.certFile)
}

// read takes one snapshot of both files. Each is opened once and read and stat'ed
// through the same handle, following symlinks (a Kubernetes secret mount is a
// symlink to a timestamped directory).
func (r *Reloader) read() (snapshot, error) {
	var s snapshot
	var err error
	if s.certPEM, s.certInfo, err = readFile(r.certFile); err != nil {
		return snapshot{}, fmt.Errorf("TLS certificate file: %w", err)
	}
	if s.keyPEM, s.keyInfo, err = readFile(r.keyFile); err != nil {
		return snapshot{}, fmt.Errorf("TLS key file: %w", err)
	}
	h := sha256.New()
	var n [8]byte
	for _, b := range [][]byte{s.certPEM, s.keyPEM} {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:]) // length prefix: moving a byte from one file to the other changes the digest
		h.Write(b)
	}
	copy(s.digest[:], h.Sum(nil))
	return s, nil
}

func readFile(path string) ([]byte, os.FileInfo, error) {
	// OpenRegular opens non-blocking and refuses a FIFO or device, so a mis-pointed
	// path cannot hang a handshake while the reloader's lock is held.
	f, fi, err := secretenv.OpenRegular(path, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxFileSize {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	return b, fi, nil
}

// changedFrom reports whether the pair differs from the one that was loaded: any file
// replaced (different file, size or mtime) or any byte different. The content digest is
// what catches a replacement that preserved size, mtime and identity; the stat
// comparison costs nothing extra and also notices a swapped file with equal content.
func (s snapshot) changedFrom(prev snapshot) bool {
	return s.digest != prev.digest ||
		!sameFile(s.certInfo, prev.certInfo) ||
		!sameFile(s.keyInfo, prev.keyInfo)
}

func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// forget drops the file contents, keeping only the identity and digest that
// changedFrom compares, so key bytes are not retained between checks.
func (s snapshot) forget() snapshot {
	s.certPEM, s.keyPEM = nil, nil
	return s
}
