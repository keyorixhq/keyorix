package tlsreload

// FuzzReloaderFailClosed drives the certificate Reloader through fuzz-chosen
// sequences of on-disk file states and asserts it never serves a bad pair.
//
// The cert/key files on disk are mutated into the states an operator, a
// cert-manager rotation, an ACME client, or an attacker with write access to the
// key directory can produce: a fresh valid pair, an expired pair, a
// not-yet-valid pair, a cert whose key was replaced (mismatch), the key replaced
// before the cert (the classic half-rotation race), a truncated PEM, an empty
// file, a deleted file, a symlink swapped to a different pair's cert, and the
// mtime-preserving variants of a full-pair, cert-only and key-only replacement
// (cp -p, rsync -t, a restore: #4146). After
// each mutation the harness reads the certificate the Reloader would hand a
// client and checks it against a reference computed independently from the same
// files with the standard library's own loader.
//
// Oracles (all must hold after every step):
//
//   - A (non-empty config): GetCertificate never returns (nil,nil); the served
//     tls.Certificate always carries a leaf cert and a private key.
//   - B (no mismatch ever served): the served leaf's public key always matches
//     the served private key. This is the load-bearing security property — a
//     mismatched cert/key is never handed to a client under any sequence.
//   - C (differential / documented keep-old-cert policy): because CheckInterval
//     is pinned to 0 here, the Reloader re-checks on every handshake, so the pair
//     it serves must EXACTLY equal the reference: if the current on-disk files
//     load as a coherent pair with the standard library, that pair; otherwise the
//     last pair that did (the previous good certificate is retained, never
//     dropped, never replaced by a non-loading one). This encodes
//     internal/tlsreload's documented behaviour: "if it does not load ... the
//     previous pair keeps being served" (package doc, reloadLocked).
//
// What this does NOT verify: it does not exercise permission-denied reads (the
// host runs these tests as root, which bypasses mode bits, so a chmod-000 state
// would not fail-closed and is deliberately omitted rather than silently pass);
// it does not test the 30s CheckInterval timing window (it pins the interval to
// 0 to make the differential exact); it does not assert TLS protocol-version
// floors (that lives in the listener's tls.Config, not the Reloader — see the
// handshake harness); and it does not cover concurrent GetCertificate callers
// (the mutex is exercised by the race detector elsewhere, not here).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// poolPair is one pre-generated, internally-coherent cert/key pair plus its PEM
// bytes and an identity (serial + key fingerprint) used to recognise it once it
// is served back.
type poolPair struct {
	serial  int64
	keyFP   string // hex of the marshalled EC private key — distinguishes keys
	certPEM []byte
	keyPEM  []byte
}

// buildPool generates a fixed, deterministic-enough set of valid pairs once per
// fuzz process (outside the per-input loop, so key generation is not on the hot
// path). Validity windows vary so expired / not-yet-valid / normal states are
// all represented; every pair is internally coherent (its key matches its cert)
// and loads cleanly with tls.LoadX509KeyPair regardless of its time window
// (the loader does not check NotBefore/NotAfter).
func buildPool(t testing.TB) []poolPair {
	t.Helper()
	now := time.Now()
	windows := []struct{ notBefore, notAfter time.Time }{
		{now.Add(-time.Hour), now.Add(time.Hour)},                 // normal
		{now.Add(-48 * time.Hour), now.Add(-24 * time.Hour)},      // expired
		{now.Add(24 * time.Hour), now.Add(48 * time.Hour)},        // not yet valid
		{now.Add(-time.Hour), now.Add(10 * 365 * 24 * time.Hour)}, // long-lived
	}
	pool := make([]poolPair, 0, len(windows))
	for i, w := range windows {
		serial := int64(1000 + i)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "localhost"},
			DNSNames:     []string{"localhost"},
			NotBefore:    w.notBefore,
			NotAfter:     w.notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		kder, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pool = append(pool, poolPair{
			serial:  serial,
			keyFP:   fingerprint(kder),
			certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
		})
	}
	return pool
}

func fingerprint(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 16)
	// A short, cheap fingerprint: first 8 bytes is plenty to tell distinct
	// P-256 keys apart for this harness.
	for i := 0; i < len(b) && i < 8; i++ {
		out = append(out, hexdigits[b[i]>>4], hexdigits[b[i]&0xf])
	}
	return string(out)
}

// servedIdentity reads the certificate the Reloader would serve and returns its
// serial and key fingerprint, after checking oracles A and B. A non-nil error is
// a harness-level fatal (GetCertificate itself never returns an error here).
func servedIdentity(t *testing.T, r *Reloader) (serial int64, keyFP string) {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("oracle A: GetCertificate returned an error: %v", err)
	}
	// Oracle A: never an empty config.
	if cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatalf("oracle A: served an empty/partial certificate: %+v", cert)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("oracle A: served leaf does not parse: %v", err)
	}
	// Oracle B: the served private key must match the served leaf public key —
	// a cert/key mismatch must never be handed to a client.
	signer, ok := cert.PrivateKey.(interface{ Public() crypto.PublicKey })
	if !ok {
		t.Fatalf("oracle B: served private key is not a signer")
	}
	priv, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("oracle B: served private key public half is not ECDSA")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("oracle B: served leaf public key is not ECDSA")
	}
	if !priv.Equal(pub) {
		t.Fatalf("oracle B: served cert/key MISMATCH (serial %d) — leaf public key does not match private key", leaf.SerialNumber.Int64())
	}
	return leaf.SerialNumber.Int64(), privKeyFP(t, cert.PrivateKey)
}

// privKeyFP fingerprints a served private key the same way buildPool fingerprints
// the pool keys, so a served pair can be matched back to the pool entry.
func privKeyFP(t *testing.T, k any) string {
	t.Helper()
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("served private key is not *ecdsa.PrivateKey: %T", k)
	}
	der, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatalf("marshal served key: %v", err)
	}
	return fingerprint(der)
}

// referenceIdentity loads the current on-disk files with the standard library,
// exactly as the Reloader does. ok reports whether they form a coherent pair.
func referenceIdentity(t *testing.T, certFile, keyFile string) (serial int64, keyFP string, ok bool) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return 0, "", false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return 0, "", false
	}
	return leaf.SerialNumber.Int64(), privKeyFP(t, cert.PrivateKey), true
}

func FuzzReloaderFailClosed(f *testing.F) {
	pool := buildPool(f)
	if len(pool) < 2 {
		f.Fatal("need at least two pool pairs")
	}

	// A handful of seed programs covering the interesting transitions.
	f.Add([]byte{0x00, 0x11, 0x22, 0x33}) // valid→cert-only→key-only→truncate
	f.Add([]byte{0x40, 0x51, 0x62})       // empty→delete→symlink
	f.Add([]byte{0x21, 0x02, 0x13})       // key-replaced-before-cert then full
	f.Add([]byte{0x33, 0x44, 0x00})       // garbage, empty, then recover
	f.Add([]byte{0x71})                   // full pair replaced, mtimes preserved (#4146)
	f.Add([]byte{0x82, 0x72})             // cert first (mismatch window), then the pair, mtimes preserved
	f.Add([]byte{0x83, 0x73, 0x81, 0x00}) // key first, then the pair, then a cert-only, then a new-mtime pair

	f.Fuzz(func(t *testing.T, program []byte) {
		withCheckInterval(t, 0) // re-check on every handshake → exact differential

		dir := t.TempDir()
		certFile := filepath.Join(dir, "tls.crt")
		keyFile := filepath.Join(dir, "tls.key")

		// Canonical on-disk copies of each pool pair's cert, for symlink swaps.
		poolDir := filepath.Join(dir, "pool")
		if err := os.MkdirAll(poolDir, 0o700); err != nil {
			t.Fatal(err)
		}
		poolCertPath := make([]string, len(pool))
		for i, p := range pool {
			poolCertPath[i] = filepath.Join(poolDir, "cert"+string(rune('a'+i)))
			if err := os.WriteFile(poolCertPath[i], p.certPEM, 0o600); err != nil {
				t.Fatal(err)
			}
		}

		// Start from a known-good, currently-valid pair (pool[0] is the normal
		// window). New() must succeed on it.
		mtime := time.Now()
		writeFile := func(path string, b []byte) {
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			mtime = mtime.Add(time.Second) // strictly increasing, always detected
			_ = os.Chtimes(path, mtime, mtime)
		}
		writeFile(certFile, pool[0].certPEM)
		writeFile(keyFile, pool[0].keyPEM)

		// writeKeepMtime rewrites path in place and restores the mtime it had, the way
		// cp -p / rsync -t / a restore do. A missing file is created with a fresh mtime.
		writeKeepMtime := func(path string, b []byte) {
			if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
				// Writing through the link would corrupt the pool copy it points at.
				_ = os.Remove(path)
			}
			fi, err := os.Stat(path)
			if err != nil {
				writeFile(path, b)
				return
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Chtimes(path, fi.ModTime(), fi.ModTime())
		}

		r, err := New(certFile, keyFile)
		if err != nil {
			t.Fatalf("New on a known-good pair failed: %v", err)
		}

		// The last identity the reference considers coherent — the pair the
		// Reloader must keep serving when the current files do not load.
		lastSerial, lastKeyFP := pool[0].serial, pool[0].keyFP

		step := func() {
			rs, rk, ok := referenceIdentity(t, certFile, keyFile)
			var wantSerial int64
			var wantKeyFP string
			if ok {
				wantSerial, wantKeyFP = rs, rk
				lastSerial, lastKeyFP = rs, rk
			} else {
				wantSerial, wantKeyFP = lastSerial, lastKeyFP
			}
			gotSerial, gotKeyFP := servedIdentity(t, r)
			if gotSerial != wantSerial || gotKeyFP != wantKeyFP {
				t.Fatalf("oracle C: served (serial=%d key=%s), want (serial=%d key=%s) [reference-loads=%v]",
					gotSerial, gotKeyFP, wantSerial, wantKeyFP, ok)
			}
		}

		for _, b := range program {
			op := b >> 4
			arg := int(b&0x0f) % len(pool)
			switch op % 9 {
			case 0: // write a full, coherent pool pair (valid/expired/not-yet-valid)
				writeFile(certFile, pool[arg].certPEM)
				writeFile(keyFile, pool[arg].keyPEM)
			case 1: // replace only the cert (mismatch unless it matches current key)
				writeFile(certFile, pool[arg].certPEM)
			case 2: // replace only the key (the half-rotation race: key before cert)
				writeFile(keyFile, pool[arg].keyPEM)
			case 3: // truncated / garbage cert PEM
				writeFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ntrunc"))
			case 4: // empty cert file
				writeFile(certFile, nil)
			case 5: // delete the cert file
				_ = os.Remove(certFile)
			case 6: // swap the cert file for a symlink to another pool pair's cert
				_ = os.Remove(certFile)
				_ = os.Symlink(poolCertPath[arg], certFile)
				// Bump the symlink target's mtime so the change is detected via
				// os.Stat (which follows the link).
				mtime = mtime.Add(time.Second)
				_ = os.Chtimes(poolCertPath[arg], mtime, mtime)
			case 7: // full pair replaced in place, both mtimes preserved
				writeKeepMtime(certFile, pool[arg].certPEM)
				writeKeepMtime(keyFile, pool[arg].keyPEM)
			case 8: // one file replaced, mtime preserved: cert for an even arg, key for an odd one
				if arg%2 == 0 {
					writeKeepMtime(certFile, pool[arg].certPEM)
				} else {
					writeKeepMtime(keyFile, pool[arg].keyPEM)
				}
			}
			step()
		}
	})
}
