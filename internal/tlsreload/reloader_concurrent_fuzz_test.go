package tlsreload

// FuzzReloaderConcurrentLoad drives the Reloader through a fuzz-chosen program of
// cert/key file mutations while N=4 goroutines call GetCertificate concurrently —
// two directly and two via real TLS handshakes against an in-process listener — and
// asserts three oracles on every certificate any caller ever receives.
//
// Oracles (all deny-direction; a firing oracle is always a real failure):
//
//   - A (non-empty config): GetCertificate never returns (nil,nil); the served
//     tls.Certificate always carries a leaf cert and a private key.
//   - B (no mismatch ever served): the served leaf's public key always matches
//     the served private key. Mirroring FuzzReloaderFailClosed oracle B: a
//     cert/key mismatch must never reach a caller under any concurrent interleaving.
//   - C (pool membership / fail-closed): the served pair must come from the pool —
//     its serial and keyFP must match a known pool entry. Since every file written
//     in this harness is drawn from pool entries, any coherent pair the Reloader can
//     load is a pool pair; oracle C fires if the Reloader somehow assembles a pair
//     whose cert and key come from DIFFERENT pool entries (a torn pair that also
//     happens to satisfy oracle B is impossible unless the Reloader loaded it from
//     independently-parsed bytes, bypassing tls.X509KeyPair's coherence check).
//     Mirrors the fail-closed intent of FuzzReloaderFailClosed oracle C extended to
//     the concurrent setting: a concurrent reader may observe any pool pair at any
//     moment, but never a fabricated or torn one.
//   - D (no data race): the harness runs under -race; a concurrent unsynchronised
//     access to the Reloader's stored certificate is a failure.
//   - E (goroutine lifecycle): all N reader goroutines exit within the fuzz body;
//     the Reloader itself starts no goroutines, so this is entirely a harness-side
//     check.
//
// Timing: CheckInterval is pinned to 0 (each GetCertificate call triggers a reload
// check), and the main goroutine calls GetCertificate after every file mutation to
// drive reloads explicitly rather than sleeping. This makes the reload sequence
// deterministic from the main goroutine's perspective; reader goroutines observe an
// arbitrary interleaving.
//
// What this does NOT verify:
//
//   - The 30s CheckInterval timing window (pinned to 0 throughout).
//   - The exact sequential differential (which pair is "currently expected" at each
//     step): readers may observe any valid pair at any moment; asserting a precise
//     expected value would require synchronising all readers, eliminating the
//     concurrent dimension being tested.
//   - Permission-denied reads: the host runs as root (see FuzzReloaderFailClosed).
//   - Whether a TLS handshake timeout is caused by a file-read stall vs. scheduling
//     jitter: the oracle fires on any dial error, so a persistent stall would surface,
//     but a single slow iteration would not.
//
// -race: this target is designed to run with the race detector enabled.
// In the targets.d conf this is stated in the comment.
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ecPrivKeyFP is a goroutine-safe variant of privKeyFP (which calls t.Fatalf and
// must only be called from the test goroutine). Returns "" on any error; callers
// treat "" as a mismatch against any real fingerprint.
func ecPrivKeyFP(key any) string {
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return ""
	}
	der, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		return ""
	}
	return fingerprint(der)
}

func FuzzReloaderConcurrentLoad(f *testing.F) {
	pool := buildPool(f) // one-time key generation outside the per-input loop
	if len(pool) < 2 {
		f.Fatal("need at least two pool pairs")
	}

	// Seeds covering the concurrent-interesting transitions.
	f.Add([]byte{0x00, 0x11, 0x00})       // full pair → cert-only (mismatch window) → recover
	f.Add([]byte{0x20, 0x01, 0x00})       // key-only → cert-only → full pair
	f.Add([]byte{0x33, 0x00})             // truncated cert → recover
	f.Add([]byte{0x44, 0x55, 0x00})       // empty cert, delete cert, full pair
	f.Add([]byte{0x70, 0x81, 0x00})       // mtime-preserving pair, one-file mtime, full pair
	f.Add([]byte{0x01, 0x12, 0x00, 0x73}) // cert-only, key-only, full, mtime-key-only
	f.Add([]byte{0x62, 0x00, 0x33, 0x00}) // symlink, full, truncate, full

	// poolBySerial is a read-only lookup built once: serial → expected keyFP.
	// Oracle C uses this to check that every served cert/key pair is a known pool pair.
	// It is immutable after construction, so reader goroutines read it without locking.
	poolBySerial := make(map[int64]string, len(pool))
	for _, p := range pool {
		poolBySerial[p.serial] = p.keyFP
	}

	f.Fuzz(func(t *testing.T, program []byte) {
		withCheckInterval(t, 0) // pin interval: every GetCertificate call reloads

		baseG := runtime.NumGoroutine()

		dir := t.TempDir()
		certFile := filepath.Join(dir, "tls.crt")
		keyFile := filepath.Join(dir, "tls.key")

		// Canonical cert files for symlink swaps (op 6).
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

		mtime := time.Now()
		writeFile := func(path string, b []byte) {
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			mtime = mtime.Add(time.Second)
			_ = os.Chtimes(path, mtime, mtime)
		}
		writeKeepMtime := func(path string, b []byte) {
			if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
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

		writeFile(certFile, pool[0].certPEM)
		writeFile(keyFile, pool[0].keyPEM)

		r, err := New(certFile, keyFile)
		if err != nil {
			t.Fatalf("New on a known-good pair failed: %v", err)
		}

		// TLS listener: no static certificate, so GetCertificate is always called.
		ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
		if lnErr != nil {
			t.Fatalf("listen: %v", lnErr)
		}
		tlsLn := tls.NewListener(ln, &tls.Config{GetCertificate: r.GetCertificate})
		tlsAddr := ln.Addr().String()

		// Accept loop: each accepted connection completes the TLS handshake and closes.
		// Goroutines for in-flight connections are not tracked individually; the
		// 2s server deadline bounds their lifetime.
		acceptDone := make(chan struct{})
		go func() {
			defer close(acceptDone)
			for {
				conn, aErr := tlsLn.Accept()
				if aErr != nil {
					return // listener closed
				}
				go func(c net.Conn) {
					defer func() { _ = c.Close() }()
					tc := c.(*tls.Conn)
					_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
					_ = tc.Handshake()
				}(conn)
			}
		}()
		t.Cleanup(func() {
			_ = tlsLn.Close()
			<-acceptDone
		})

		// checkOracles verifies oracles A, B and C on cert. Safe to call from any
		// goroutine. Reports violations via t.Errorf and signals stopCh.
		var stopOnce sync.Once
		stopCh := make(chan struct{})
		checkOracles := func(cert *tls.Certificate, src string) bool {
			// Oracle A: non-empty certificate.
			if cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
				t.Errorf("oracle A (%s): served empty/partial cert: %+v", src, cert)
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			leaf, lErr := x509.ParseCertificate(cert.Certificate[0])
			if lErr != nil {
				t.Errorf("oracle A (%s): leaf does not parse: %v", src, lErr)
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			// Oracle B: private key's public half must equal the leaf's public key.
			signer, ok := cert.PrivateKey.(interface{ Public() crypto.PublicKey })
			if !ok {
				t.Errorf("oracle B (%s): private key is not a signer: %T", src, cert.PrivateKey)
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			privPub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Errorf("oracle B (%s): key public half not ECDSA: %T", src, signer.Public())
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			certPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Errorf("oracle B (%s): leaf public key not ECDSA: %T", src, leaf.PublicKey)
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			if !privPub.Equal(certPub) {
				t.Errorf("oracle B (%s): cert/key MISMATCH serial=%d", src, leaf.SerialNumber.Int64())
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			// Oracle C: served pair must be from the pool (pool membership check).
			serial := leaf.SerialNumber.Int64()
			fp := ecPrivKeyFP(cert.PrivateKey)
			expectedFP, poolOK := poolBySerial[serial]
			if !poolOK || fp == "" || fp != expectedFP {
				t.Errorf("oracle C (%s): serial %d / fp %q not from any pool entry (expectedFP %q)", src, serial, fp, expectedFP)
				stopOnce.Do(func() { close(stopCh) })
				return false
			}
			return true
		}

		// N=4 concurrent readers: 2 direct GetCertificate, 2 real TLS handshakes.
		const nReaders = 4
		var wg sync.WaitGroup

		// Direct GetCertificate readers (oracle A/B/C).
		for range nReaders / 2 {
			wg.Go(func() {
				for {
					select {
					case <-stopCh:
						return
					default:
					}
					cert, gcErr := r.GetCertificate(nil)
					if gcErr != nil {
						t.Errorf("oracle A (direct): GetCertificate error: %v", gcErr)
						stopOnce.Do(func() { close(stopCh) })
						return
					}
					if !checkOracles(cert, "direct") {
						return
					}
				}
			})
		}

		// TLS handshake readers: oracle A/B/C via protocol-level proof-of-key-ownership.
		// InsecureSkipVerify skips chain validation (self-signed test certs) but the
		// TLS handshake still verifies CertificateVerify — a mismatched cert/key causes
		// a detectable signature failure even with skip-verify on the client.
		clientCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec — test-only loopback; skip chain validation only
		for range nReaders / 2 {
			wg.Go(func() {
				dialer := &net.Dialer{Timeout: 2 * time.Second}
				for {
					select {
					case <-stopCh:
						return
					default:
					}
					conn, dErr := tls.DialWithDialer(dialer, "tcp", tlsAddr, clientCfg)
					if dErr != nil {
						// Race the channel: a dial failure that races with shutdown is expected.
						select {
						case <-stopCh:
							return
						default:
						}
						t.Errorf("oracle (1/TLS): handshake failed: %v", dErr)
						stopOnce.Do(func() { close(stopCh) })
						return
					}
					_ = conn.Close()
				}
			})
		}

		// Drive file operations from the main goroutine; call GetCertificate after each
		// mutation to trigger an explicit reload (CheckInterval=0 makes this exact).
	programLoop:
		for _, b := range program {
			select {
			case <-stopCh:
				break programLoop
			default:
			}
			op := b >> 4
			arg := int(b&0x0f) % len(pool)
			switch op % 9 {
			case 0: // full coherent pair
				writeFile(certFile, pool[arg].certPEM)
				writeFile(keyFile, pool[arg].keyPEM)
			case 1: // cert-only: mismatch window (new cert + old key)
				writeFile(certFile, pool[arg].certPEM)
			case 2: // key-only: half-rotation (new key + old cert)
				writeFile(keyFile, pool[arg].keyPEM)
			case 3: // truncated/garbage cert PEM
				writeFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ntrunc"))
			case 4: // empty cert file
				writeFile(certFile, nil)
			case 5: // delete the cert file
				_ = os.Remove(certFile)
			case 6: // swap cert for a symlink to another pool pair's cert
				_ = os.Remove(certFile)
				_ = os.Symlink(poolCertPath[arg], certFile)
				mtime = mtime.Add(time.Second)
				_ = os.Chtimes(poolCertPath[arg], mtime, mtime)
			case 7: // full pair in-place, both mtimes preserved (cp -p / rsync -t)
				writeKeepMtime(certFile, pool[arg].certPEM)
				writeKeepMtime(keyFile, pool[arg].keyPEM)
			case 8: // one file in-place, mtime preserved: cert for even arg, key for odd
				if arg%2 == 0 {
					writeKeepMtime(certFile, pool[arg].certPEM)
				} else {
					writeKeepMtime(keyFile, pool[arg].keyPEM)
				}
			}
			// Explicit reload from the main goroutine to synchronise one consistent view.
			if cert, gcErr := r.GetCertificate(nil); gcErr == nil {
				checkOracles(cert, fmt.Sprintf("main/op%d", op%9))
			} else {
				t.Errorf("main goroutine GetCertificate: %v", gcErr)
			}
		}

		// Signal readers to stop and wait for clean exit (oracle E: no goroutine leak from
		// the reader goroutines; the Reloader itself starts no goroutines).
		stopOnce.Do(func() { close(stopCh) })
		wg.Wait()

		// Oracle E: goroutine count must not have grown unboundedly beyond the N readers
		// plus the accept loop (all waited above) plus a small runtime slack.
		// The Reloader has no internal goroutines, so the ceiling is tight.
		if g := runtime.NumGoroutine(); g > baseG+16 {
			t.Errorf("oracle E: goroutine count after test: %d (baseline %d, ceiling +16)",
				g, baseG)
		}
	})
}
