package tlsreload

// Tests for #4146: a replacement that keeps the old mtime (cp -p, rsync -t, a restore
// from backup, a secret-store mount) must still be served after the next check.
//
// What these do not cover: a replacement that is byte-identical to what is loaded
// (nothing to notice), and filesystems that cannot report an identity at all (the
// content comparison is what catches those; it is exercised by the same-size case).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genPair returns a self-signed ECDSA cert/key PEM pair with the given serial.
func genPair(t testing.TB, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func mtimeOf(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

// overwriteKeepingMtime rewrites path in place (same inode) and restores its mtime.
func overwriteKeepingMtime(t *testing.T, path string, data []byte) {
	t.Helper()
	old := mtimeOf(t, path)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

// replaceKeepingMtime swaps path for a new file (new inode, as cp -p or rsync -t do)
// carrying the old mtime.
func replaceKeepingMtime(t *testing.T, path string, data []byte) {
	t.Helper()
	old := mtimeOf(t, path)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// servedCoherent returns the served serial and fails the test if the served key does
// not belong to the served certificate (the fail-closed property).
func servedCoherent(t *testing.T, r *Reloader) int64 {
	t.Helper()
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("served key is %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}
	if !priv.PublicKey.Equal(leaf.PublicKey) {
		t.Fatalf("MISMATCHED pair served (serial %d)", leaf.SerialNumber.Int64())
	}
	return leaf.SerialNumber.Int64()
}

func newReloaderFor(t *testing.T, certFile, keyFile string) *Reloader {
	t.Helper()
	withCheckInterval(t, 0)
	r, err := New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestReloader_MtimePreservingReplaceIsServed: the pair is replaced and both files get
// their old mtime back; the next tick must serve the new certificate.
func TestReloader_MtimePreservingReplaceIsServed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace func(*testing.T, string, []byte)
	}{
		{"in place (same inode)", overwriteKeepingMtime},
		{"new file (cp -p, rsync -t)", replaceKeepingMtime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
			writePair(t, certFile, keyFile, 1)
			r := newReloaderFor(t, certFile, keyFile)
			if got := servedCoherent(t, r); got != 1 {
				t.Fatalf("serial %d, want 1", got)
			}
			certPEM, keyPEM := genPair(t, 2)
			tc.replace(t, certFile, certPEM)
			tc.replace(t, keyFile, keyPEM)
			if got := servedCoherent(t, r); got != 2 {
				t.Fatalf("after an mtime-preserving rotation: serial %d, want 2 (the old certificate is still served)", got)
			}
		})
	}
}

// TestReloader_SameSizeSameMtimeDifferentBytes: the two files keep size, mtime and
// inode; only the bytes differ.
func TestReloader_SameSizeSameMtimeDifferentBytes(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	oldCert, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	r := newReloaderFor(t, certFile, keyFile)

	// The DER signature length varies by a byte or two, so draw until the new files
	// are exactly as long as the old ones.
	var certPEM, keyPEM []byte
	for range 500 {
		certPEM, keyPEM = genPair(t, 2)
		if len(certPEM) == len(oldCert) && len(keyPEM) == len(oldKey) {
			break
		}
		certPEM = nil
	}
	if certPEM == nil {
		t.Fatal("could not generate a replacement pair of the same size")
	}
	if bytes.Equal(certPEM, oldCert) || bytes.Equal(keyPEM, oldKey) {
		t.Fatal("replacement is not different")
	}
	overwriteKeepingMtime(t, certFile, certPEM)
	overwriteKeepingMtime(t, keyFile, keyPEM)
	if got := servedCoherent(t, r); got != 2 {
		t.Fatalf("same size, same mtime, same inode, new bytes: serial %d, want 2", got)
	}
}

// TestReloader_KubernetesSymlinkSwap: tls.crt and tls.key are symlinks through a
// ..data link that is swapped atomically to a new timestamped directory, and the new
// files carry the old mtime. The link files themselves never change.
func TestReloader_KubernetesSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	v1, v2 := filepath.Join(dir, "..v1"), filepath.Join(dir, "..v2")
	for _, d := range []string{v1, v2} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writePair(t, filepath.Join(v1, "tls.crt"), filepath.Join(v1, "tls.key"), 1)
	data := filepath.Join(dir, "..data")
	if err := os.Symlink("..v1", data); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	r := newReloaderFor(t, certFile, keyFile)
	if got := servedCoherent(t, r); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}

	certPEM, keyPEM := genPair(t, 2)
	for name, b := range map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM} {
		p := filepath.Join(v2, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		old := mtimeOf(t, filepath.Join(v1, name))
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	tmpLink := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink("..v2", tmpLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmpLink, data); err != nil {
		t.Fatal(err)
	}
	if got := servedCoherent(t, r); got != 2 {
		t.Fatalf("after the ..data swap: serial %d, want 2", got)
	}
}

// TestReloader_MtimePreservingHalfRotationNeverServesMismatch: the certificate is
// replaced first and the key second, both keeping their mtime. In between, the new
// certificate and the old key do not match and must not be served; once the key
// follows, the new pair is.
func TestReloader_MtimePreservingHalfRotationNeverServesMismatch(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r := newReloaderFor(t, certFile, keyFile)

	certPEM, keyPEM := genPair(t, 2)
	overwriteKeepingMtime(t, certFile, certPEM)
	for i := range 3 { // the mismatch window spans several ticks
		if got := servedCoherent(t, r); got != 1 {
			t.Fatalf("tick %d inside the mismatch window: serial %d, want the previous pair (1)", i, got)
		}
	}
	overwriteKeepingMtime(t, keyFile, keyPEM)
	if got := servedCoherent(t, r); got != 2 {
		t.Fatalf("after the key followed: serial %d, want 2", got)
	}

	// The same in the other order: key first, then certificate.
	certPEM, keyPEM = genPair(t, 3)
	overwriteKeepingMtime(t, keyFile, keyPEM)
	if got := servedCoherent(t, r); got != 2 {
		t.Fatalf("key replaced first: serial %d, want the previous pair (2)", got)
	}
	overwriteKeepingMtime(t, certFile, certPEM)
	if got := servedCoherent(t, r); got != 3 {
		t.Fatalf("after the certificate followed: serial %d, want 3", got)
	}
}

// TestReloader_LogsNeverCarryKeyMaterialOrDigest: neither a failed nor a successful
// reload writes key bytes, a PEM header of the key, or a hex digest of either file
// to the log.
func TestReloader_LogsNeverCarryKeyMaterialOrDigest(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r := newReloaderFor(t, certFile, keyFile)

	newCert, newKey := genPair(t, 2)
	oldKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	overwriteKeepingMtime(t, certFile, newCert) // mismatch: logged as a failed reload
	servedCoherent(t, r)
	overwriteKeepingMtime(t, keyFile, newKey) // completes the pair: logged as reloaded
	servedCoherent(t, r)

	out := buf.String()
	if !strings.Contains(out, "reloaded") {
		t.Fatalf("expected a reload line in the log, got:\n%s", out)
	}
	secrets := []string{"PRIVATE KEY"}
	for _, key := range [][]byte{oldKey, newKey} {
		body := strings.Split(string(key), "\n")[1] // first base64 line of the key
		secrets = append(secrets, body)
	}
	for _, f := range [][]byte{oldCert, oldKey, newCert, newKey, append(append([]byte{}, newCert...), newKey...), append(append([]byte{}, oldCert...), oldKey...)} {
		sum := sha256.Sum256(f)
		secrets = append(secrets, hex.EncodeToString(sum[:])[:16])
	}
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("log contains %q:\n%s", s, out)
		}
	}
}
