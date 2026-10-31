package encryption

import (
	"bytes"
	"crypto/fips140"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// FIPSSelfTestError names the boot self-test path that failed. Err is the
// refusal itself: an error the path returned, a wrong round-trip result, or a
// panic from the Go FIPS 140-3 module (under GODEBUG=fips140=only a
// non-approved primitive or parameter panics rather than erroring), recovered
// and converted so the server can say which path it was.
type FIPSSelfTestError struct {
	Path string
	Err  error
}

func (e *FIPSSelfTestError) Error() string {
	return fmt.Sprintf("fips140 self-test failed on %s: %v", e.Path, e.Err)
}

func (e *FIPSSelfTestError) Unwrap() error { return e.Err }

// fipsSelfTestPath is one boot self-test path: a name the refusal reports and a
// round trip over the same primitives and helpers the runtime path uses, with a
// throwaway random key.
type fipsSelfTestPath struct {
	name string
	run  func() error
}

// fipsSelfTestPaths lists every AEAD / KEK-derived-key path the server uses at
// runtime. A var, not a const table, only so the tests can substitute a failing
// path; production code never changes it.
//
// The backup path is the backup-manifest key derivation plus the HMAC-SHA256
// signature backupfmt.SignManifest puts on a manifest under it (a backup's row
// data is already DEK ciphertext, covered by the secret path; the key files it
// carries are the DEK-wrap path). backupfmt itself is not imported: it would
// pull internal/storage into this package.
var fipsSelfTestPaths = []fipsSelfTestPath{
	{"DEK wrap/unwrap (AES-256-GCM under the KEK)", selfTestDEKWrap},
	{"secret encrypt/decrypt (AES-256-GCM under the DEK, with AAD, chunked, fingerprint)", selfTestSecretAEAD},
	{"KEK derivation from passphrase (PBKDF2-HMAC-SHA256)", selfTestPassphraseKEK},
	{"evidence-signing key derivation (HKDF-SHA256 + HMAC-SHA256)", selfTestKEKDerivedMAC(deriveEvidenceSignKey)},
	{"audit-checkpoint key derivation (HKDF-SHA256 + HMAC-SHA256)", selfTestKEKDerivedMAC(deriveAuditCheckpointKey)},
	{"backup-manifest key derivation and signature (HKDF-SHA256 + HMAC-SHA256)", selfTestKEKDerivedMAC(auditverify.DeriveBackupManifestKey)},
}

var (
	fipsSelfTestMu     sync.Mutex
	fipsSelfTestRan    bool
	fipsSelfTestResult error
)

// RunFIPSSelfTest exercises every path in fipsSelfTestPaths once, with a
// throwaway key, when the Go FIPS 140-3 module is enforced
// (GODEBUG=fips140=only), and returns a *FIPSSelfTestError naming the first
// path that fails. When FIPS 140-only mode is not enforced it does nothing and
// returns nil: there is no self-test cost outside that mode. The result is
// remembered for FIPSSelfTestPostureLine.
func RunFIPSSelfTest() error {
	if !fips140.Enforced() {
		return nil
	}
	err := runFIPSSelfTestPaths(fipsSelfTestPaths)
	fipsSelfTestMu.Lock()
	fipsSelfTestRan, fipsSelfTestResult = true, err
	fipsSelfTestMu.Unlock()
	return err
}

// BootFIPSSelfTest is the server's boot hook: RunFIPSSelfTest, then the
// posture line logged on success. The caller refuses to start on an error.
func BootFIPSSelfTest() error {
	if err := RunFIPSSelfTest(); err != nil {
		return err
	}
	log.Print(FIPSSelfTestPostureLine())
	return nil
}

// FIPSSelfTestPostureLine is the posture/status line for the boot self-test:
// whether FIPS 140-only mode is enforced in this process and, if it is, the
// self-test result. Outside that mode it says the self-test was not run rather
// than implying it passed. It reports the runtime mode only, never a
// validation or compliance claim (see FIPS140ModeLine).
func FIPSSelfTestPostureLine() string {
	if !fips140.Enforced() {
		return "fips140 enforced: no (self-test not run)"
	}
	fipsSelfTestMu.Lock()
	ran, res := fipsSelfTestRan, fipsSelfTestResult
	fipsSelfTestMu.Unlock()
	switch {
	case !ran:
		return "fips140 enforced: yes, self-test not run in this process"
	case res != nil:
		return "fips140 enforced: yes, self-test FAILED: " + res.Error()
	default:
		return fmt.Sprintf("fips140 enforced: yes, self-test passed (%d paths)", len(fipsSelfTestPaths))
	}
}

func runFIPSSelfTestPaths(paths []fipsSelfTestPath) error {
	for _, p := range paths {
		if err := runFIPSSelfTestPath(p); err != nil {
			return &FIPSSelfTestError{Path: p.name, Err: err}
		}
	}
	return nil
}

func runFIPSSelfTestPath(p fipsSelfTestPath) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return p.run()
}

func selfTestRandomKey(n int) ([]byte, error) {
	k := make([]byte, n)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("random key: %w", err)
	}
	return k, nil
}

var errSelfTestMismatch = errors.New("round trip returned different bytes")
var errSelfTestTamperAccepted = errors.New("tampered ciphertext was accepted")

func selfTestDEKWrap() error {
	kek, err := selfTestRandomKey(32)
	if err != nil {
		return err
	}
	defer wipeBytes(kek)
	dek, err := selfTestRandomKey(32)
	if err != nil {
		return err
	}
	defer wipeBytes(dek)
	wrapped, err := wrapKey(dek, kek)
	if err != nil {
		return err
	}
	got, err := unwrapKey(wrapped, kek)
	if err != nil {
		return err
	}
	defer wipeBytes(got)
	if !bytes.Equal(got, dek) {
		return errSelfTestMismatch
	}
	wrapped[len(wrapped)-1] ^= 0x01
	if k, err := unwrapKey(wrapped, kek); err == nil {
		wipeBytes(k)
		return errSelfTestTamperAccepted
	}
	return nil
}

func selfTestSecretAEAD() error {
	dek, err := selfTestRandomKey(32)
	if err != nil {
		return err
	}
	defer wipeBytes(dek)
	es, err := NewEncryptionService(dek)
	if err != nil {
		return err
	}
	defer es.WipeDEK()
	plaintext := []byte("keyorix fips140 boot self-test")
	aad := SecretAAD(1, 1, 1)
	enc, err := es.EncryptWithAAD(plaintext, "selftest", aad)
	if err != nil {
		return err
	}
	ser, err := SerializeEncryptedData(enc)
	if err != nil {
		return err
	}
	enc, err = DeserializeEncryptedData(ser)
	if err != nil {
		return err
	}
	got, err := es.DecryptWithAAD(enc, aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, plaintext) {
		return errSelfTestMismatch
	}
	if _, err := es.DecryptWithAAD(enc, SecretAAD(1, 1, 2)); err == nil {
		return errors.New("ciphertext opened under a different AAD")
	}
	plain, err := es.Encrypt(plaintext, "selftest")
	if err != nil {
		return err
	}
	if got, err = es.Decrypt(plain); err != nil {
		return err
	} else if !bytes.Equal(got, plaintext) {
		return errSelfTestMismatch
	}
	chunks, err := es.EncryptChunked(bytes.Repeat(plaintext, 4), 16, "selftest")
	if err != nil {
		return err
	}
	if got, err = es.DecryptChunked(chunks); err != nil {
		return err
	} else if !bytes.Equal(got, bytes.Repeat(plaintext, 4)) {
		return errSelfTestMismatch
	}
	if _, err := es.Fingerprint(); err != nil {
		return err
	}
	return nil
}

func selfTestPassphraseKEK() error {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("random salt: %w", err)
	}
	// One iteration: the self-test checks the primitive is accepted, not the
	// work factor (DefaultKEKIterations would add about 100 ms to every boot).
	kek := GenerateKEK("fips140-self-test", salt, 1)
	defer wipeBytes(kek)
	if len(kek) != 32 {
		return fmt.Errorf("PBKDF2 returned %d bytes, want 32", len(kek))
	}
	return nil
}

func selfTestKEKDerivedMAC(derive func([]byte) ([]byte, string, error)) func() error {
	return func() error {
		kek, err := selfTestRandomKey(32)
		if err != nil {
			return err
		}
		defer wipeBytes(kek)
		key, id, err := derive(kek)
		if err != nil {
			return err
		}
		defer wipeBytes(key)
		if len(key) != 32 || id == "" {
			return fmt.Errorf("derived a %d-byte key with id %q, want 32 bytes and an id", len(key), id)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("keyorix fips140 boot self-test"))
		if len(mac.Sum(nil)) != sha256.Size {
			return errors.New("HMAC-SHA256 returned the wrong length")
		}
		return nil
	}
}
