package crypto

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader is an io.Reader that always fails — used to deterministically
// exercise the crypto/rand failure branches in generateAndWrap/ensureSalt/Split
// without any real entropy exhaustion. crypto/rand.Reader is a package-level
// var, so swapping it for the duration of a test (single-goroutine, no
// t.Parallel anywhere in this package) is a legitimate way to reach an
// otherwise-untriggerable error path.
type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) { return 0, errors.New("injected rand failure") }

// withFailingRand swaps crypto/rand.Reader for the duration of fn and restores
// the original afterward, even if fn fails.
func withFailingRand(t *testing.T, fn func()) {
	t.Helper()
	old := cryptorand.Reader
	cryptorand.Reader = failingReader{}
	defer func() { cryptorand.Reader = old }()
	fn()
}

// ---- TPMKeyProvider: error-path coverage for generateAndSeal and seal ----

// errorOpener returns an opener that always fails, exercising the open-failure
// branch inside seal() — and therefore the seal-failure branch in generateAndSeal().
func errorOpener(msg string) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) {
		return nil, errors.New(msg)
	}
}

// TestTPMProvider_SealOpenFailure covers the branch in seal() where the TPM open
// call fails.  The failure propagates through generateAndSeal() on first run (no
// blob file exists) and surfaces as a "seal failed" error.
func TestTPMProvider_SealOpenFailure(t *testing.T) {
	dir := t.TempDir()
	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = errorOpener("tpm: open failed: device not found")

	_, err := p.KEK()
	require.Error(t, err)
	// The error should mention seal failed (from generateAndSeal) or be the raw
	// open error propagated through seal.
	assert.True(t,
		containsAny(err.Error(), "seal failed", "open failed", "device not found"),
		"unexpected error: %v", err)
}

// TestTPMProvider_UnsealOpenFailure covers the branch in unseal() where the TPM
// open call fails after a valid blob has been written.
func TestTPMProvider_UnsealOpenFailure(t *testing.T) {
	dir := t.TempDir()

	// First, seal with the simulator to produce a valid blob.
	sealer := NewTPMKeyProvider("", dir, "kek.tpm")
	sealer.open = simOpener(t, 42)
	_, err := sealer.KEK()
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dir, "kek.tpm"))

	// Now use an opener that always fails to exercise the unseal open-failure path.
	unsealer := NewTPMKeyProvider("", dir, "kek.tpm")
	unsealer.open = errorOpener("tpm: open failed")

	_, err = unsealer.KEK()
	require.Error(t, err)
}

// TestTPMProvider_GenerateAndSeal_PersistFailure exercises the SecureWriteFileSync
// error path inside generateAndSeal: the seal succeeds but the directory is
// read-only so the blob cannot be persisted.
func TestTPMProvider_GenerateAndSeal_PersistFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; read-only dir test cannot be enforced")
	}

	dir := t.TempDir()
	// Make the directory read-only after creating it so writes fail.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = simOpener(t, 7)

	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist sealed blob")
}

// TestTPMProvider_Seal_DirectCall_OpenError directly tests seal() via the
// unexported method, ensuring the open-error-returns-zero-value branch is hit.
func TestTPMProvider_Seal_DirectCall_OpenError(t *testing.T) {
	p := NewTPMKeyProvider("", "", "x.tpm")
	p.open = errorOpener("open: no device")

	_, err := p.seal([]byte("secret"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open: no device")
}

// ---- KMSKeyProvider: generateAndWrap error paths ----

// TestKMSProvider_GenerateAndWrap_PersistFailure exercises the SecureWriteFileSync
// error path inside generateAndWrap: KMS encrypt succeeds but the directory is
// read-only, so the wrapped blob cannot be written.
func TestKMSProvider_GenerateAndWrap_PersistFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; read-only dir test cannot be enforced")
	}

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	p := NewKMSKeyProvider(&fakeKMS{tag: "k"}, "test-kms", dir, "kek.kms")
	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist wrapped KEK")
}

// TestKMSKeyProvider_Client_ReturnsConfiguredClient covers the Client() getter,
// which lets a caller (encryption.Service.wireKMSAuditSink) type-assert the
// underlying KMSClient to a concrete backend for backend-specific wiring.
func TestKMSKeyProvider_Client_ReturnsConfiguredClient(t *testing.T) {
	kms := &fakeKMS{tag: "cmk-A"}
	p := NewKMSKeyProvider(kms, "aws-kms", t.TempDir(), "kek.kms")
	assert.Same(t, kms, p.Client(), "Client() must return the exact KMSClient the provider was built with")
}

// TestKMSKeyProvider_ReadWrappedKEK_PathEscapeFails covers the "read wrapped
// KEK" error branch in KEK(): the wrapped-key file exists (so KEK() takes the
// read path, not generateAndWrap) but is a symlink escaping baseDir, so
// SafeReadFile's containment check rejects it.
func TestKMSKeyProvider_ReadWrappedKEK_PathEscapeFails(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.bin")
	require.NoError(t, os.WriteFile(target, []byte("not a real wrapped kek"), 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "kek.kms")))

	_, err := NewKMSKeyProvider(&fakeKMS{tag: "x"}, "aws-kms", dir, "kek.kms").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read wrapped KEK")
}

// TestKMSKeyProvider_GenerateAndWrap_RandFailure covers generateAndWrap's
// io.ReadFull(rand.Reader, ...) error branch on first run.
func TestKMSKeyProvider_GenerateAndWrap_RandFailure(t *testing.T) {
	dir := t.TempDir()
	withFailingRand(t, func() {
		_, err := NewKMSKeyProvider(&fakeKMS{tag: "x"}, "aws-kms", dir, "kek.kms").KEK()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "generate KEK")
	})
	assert.NoFileExists(t, filepath.Join(dir, "kek.kms"), "no wrapped blob persisted when KEK generation itself fails")
}

// ---- PasswordKeyProvider: ensureSalt error paths ----

// TestPasswordKeyProvider_EnsureSalt_RandFailure covers the salt-generation
// io.ReadFull(rand.Reader, ...) error branch on first run.
func TestPasswordKeyProvider_EnsureSalt_RandFailure(t *testing.T) {
	dir := t.TempDir()
	withFailingRand(t, func() {
		_, err := NewPasswordKeyProvider("passphrase", dir, "kek.salt").KEK()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate salt")
	})
}

// TestPasswordKeyProvider_EnsureSalt_WriteFailure covers the
// SecureWriteFileSync error branch when persisting a freshly generated salt:
// the directory is read-only so the write cannot happen.
func TestPasswordKeyProvider_EnsureSalt_WriteFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; read-only dir test cannot be enforced")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	_, err := NewPasswordKeyProvider("passphrase", dir, "kek.salt").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write salt")
}

// TestPasswordKeyProvider_EnsureSalt_ReadFailure covers the SafeReadFile error
// branch when an existing salt file is actually a symlink escaping baseDir.
func TestPasswordKeyProvider_EnsureSalt_ReadFailure(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "salt.bin")
	require.NoError(t, os.WriteFile(target, make([]byte, saltSize), 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "kek.salt")))

	_, err := NewPasswordKeyProvider("passphrase", dir, "kek.salt").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read salt")
}

// ---- FileKeyProvider: read failure ----

// TestFileKeyProvider_KEK_ReadFailure covers the os.ReadFile error branch: the
// configured path passes the Stat + permission-bits check (it's a directory
// with owner-only mode) but cannot be read as file content.
func TestFileKeyProvider_KEK_ReadFailure(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "kek-is-a-dir")
	require.NoError(t, os.Mkdir(sub, 0700))

	_, err := NewFileKeyProvider(sub).KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

// NOTE: Split's `if _, err := rand.Read(coeffs[1:]); err != nil` branch
// (shamir.go) is NOT covered by a test. Since Go 1.24, crypto/rand.Read (the
// package-level function, as opposed to io.ReadFull(rand.Reader, ...)) is
// documented to "never return an error" and instead calls runtime.fatal
// (crashing the process irrecoverably) if the underlying Reader fails — see
// crypto/rand.Read's doc comment and https://go.dev/issue/66821. Swapping
// rand.Reader to a failing implementation to exercise this branch therefore
// crashes the test binary instead of returning an error, so this defensive
// branch is dead code under the current Go runtime and cannot be reached from
// a unit test without patching the standard library. Left uncovered
// deliberately rather than done via a test that kills the test process.

// ---- combineKEK: below-embedded-threshold with otherwise-valid reconstruction ----

// TestCombineKEK_BelowEmbeddedThreshold covers the "insufficient shares
// supplied vs. the threshold embedded in the payload" branch directly. This
// branch is unreachable via the normal SplitKEK/ShamirKeyProvider path because
// combining fewer shares than the ACTUAL polynomial degree used at split time
// almost always fails the magic check first (garbage reconstruction). To
// isolate the embedded-threshold check, this crafts a payload whose declared
// threshold byte (5) is higher than the REAL Shamir threshold used to split it
// (2), so 2 shares reconstruct correctly (magic + KEK intact) while still
// being fewer than the byte the payload claims is required.
func TestCombineKEK_BelowEmbeddedThreshold(t *testing.T) {
	kek := testKEK()
	payload := append([]byte{}, kekShareMagic...)
	payload = append(payload, byte(5)) // claims threshold=5
	payload = append(payload, kek...)

	shares, err := Split(payload, 5, 2) // actually only needs 2 shares to reconstruct
	require.NoError(t, err)

	_, err = combineKEK(shares[:2], nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shares supplied but the split requires")
}

// ---- TPMKeyProvider: remaining error/wiring branches ----

// TestNewTPMKeyProvider_DefaultOpen_AttemptsRealDevice covers the default
// `open` closure built by NewTPMKeyProvider (only ever overridden with a
// simulator in every other test in this package). There is no real TPM device
// in this test environment, so the call is expected to fail — the point is to
// prove the closure is wired to the configured device path at all, not that a
// real TPM is present.
func TestNewTPMKeyProvider_DefaultOpen_AttemptsRealDevice(t *testing.T) {
	p := NewTPMKeyProvider("/dev/nonexistent-tpm-for-test", "", "x.tpm")
	require.NotNil(t, p.open)
	_, err := p.open()
	assert.Error(t, err, "opening a nonexistent TPM device must fail, proving open() actually targets p.devicePath")
}

// TestTPMKeyProvider_ReadSealedBlob_PathEscapeFails covers the "read sealed
// blob" SafeReadFile error branch: the blob path exists but is a symlink
// escaping baseDir.
func TestTPMKeyProvider_ReadSealedBlob_PathEscapeFails(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "blob.bin")
	require.NoError(t, os.WriteFile(target, []byte("{}"), 0600))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "kek.tpm")))

	p := newTPMProvider(t, dir, 11)
	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read sealed blob")
}

// NOTE: generateAndSeal's `if _, err := rand.Read(kek); err != nil` branch
// (tpm_provider.go) is likewise not covered — it calls the crypto/rand.Read
// package function directly, which (see the Split note above, same Go 1.24+
// behavior) crashes the process instead of returning an error when the
// underlying Reader fails, so it cannot be exercised from a unit test.

// TestTPMKeyProvider_Unseal_DecodePublicFailure covers unseal()'s
// tpm2.Unmarshal[TPM2BPublic] error branch: the stored blob is valid JSON with
// the right shape, but the "public" bytes don't decode as a TPM2B public
// structure.
func TestTPMKeyProvider_Unseal_DecodePublicFailure(t *testing.T) {
	dir := t.TempDir()
	writeSealedBlobFile(t, dir, "kek.tpm", tpmSealedBlob{
		Public:  []byte("not a valid TPM2B public structure"),
		Private: []byte{0x00, 0x02, 0xAB, 0xCD},
	})

	p := newTPMProvider(t, dir, 13)
	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode sealed public")
}

// TestTPMKeyProvider_Unseal_DecodePrivateFailure covers unseal()'s
// tpm2.Unmarshal[TPM2BPrivate] error branch: a genuinely-sealed public blob
// (from a real seal) paired with corrupt private bytes.
func TestTPMKeyProvider_Unseal_DecodePrivateFailure(t *testing.T) {
	dir := t.TempDir()
	sealer := newTPMProvider(t, dir, 14)
	blob, err := sealer.seal(testKEK())
	require.NoError(t, err)

	writeSealedBlobFile(t, dir, "kek.tpm", tpmSealedBlob{
		Public:  blob.Public,
		Private: []byte("not a valid TPM2B private structure"),
	})

	p := newTPMProvider(t, dir, 14)
	_, err = p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode sealed private")
}

// countingFailAfter wraps a real transport.TPMCloser (backed by the in-process
// simulator) and fails every Send call after the first n succeed. Each tpm2
// command used by seal()/unseal() here issues exactly one Send (no HMAC/policy
// sessions), so this lets a test target one SPECIFIC command in a
// seal/unseal sequence — e.g. let CreatePrimary succeed but fail the following
// Create/Load/Unseal command — against a real simulator backend, rather than
// failing the whole TPM connection outright (which errorOpener already covers).
type countingFailAfter struct {
	transport.TPMCloser
	n     int
	calls int
}

func (f *countingFailAfter) Send(input []byte) ([]byte, error) {
	f.calls++
	if f.calls > f.n {
		return nil, errors.New("injected TPM command failure")
	}
	return f.TPMCloser.Send(input)
}

// failAfterOpener returns an opener over the fixed-seed simulator whose TPM
// connection fails every command after the first n succeed.
func failAfterOpener(t *testing.T, seed int64, n int) func() (transport.TPMCloser, error) {
	t.Helper()
	inner := simOpener(t, seed)
	return func() (transport.TPMCloser, error) {
		tp, err := inner()
		if err != nil {
			return nil, err
		}
		return &countingFailAfter{TPMCloser: tp, n: n}, nil
	}
}

// TestTPMKeyProvider_Seal_CreatePrimaryFailure covers seal()'s createPrimary
// error branch: the TPM connection opens fine, but the very first command
// (CreatePrimary) fails.
func TestTPMKeyProvider_Seal_CreatePrimaryFailure(t *testing.T) {
	dir := t.TempDir()
	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = failAfterOpener(t, 101, 0)

	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create primary")
}

// TestTPMKeyProvider_Seal_CreateSealedObjectFailure covers seal()'s
// tpm2.Create error branch: CreatePrimary succeeds, but the following Create
// (the actual seal command) fails.
func TestTPMKeyProvider_Seal_CreateSealedObjectFailure(t *testing.T) {
	dir := t.TempDir()
	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = failAfterOpener(t, 102, 1)

	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create sealed object")
}

// TestTPMKeyProvider_Unseal_CreatePrimaryFailure covers unseal()'s
// createPrimary error branch, using a genuinely-sealed blob from a prior
// successful seal so KEK() reaches the unseal path at all.
func TestTPMKeyProvider_Unseal_CreatePrimaryFailure(t *testing.T) {
	dir := t.TempDir()
	_, err := newTPMProvider(t, dir, 103).KEK()
	require.NoError(t, err)

	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = failAfterOpener(t, 103, 0)

	_, err = p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create primary")
}

// TestTPMKeyProvider_Unseal_UnsealCommandFailure covers unseal()'s final
// tpm2.Unseal error branch: createPrimary and Load both succeed (same TPM,
// same seed as the original seal, so the blob loads fine) but the Unseal
// command itself fails.
func TestTPMKeyProvider_Unseal_UnsealCommandFailure(t *testing.T) {
	dir := t.TempDir()
	_, err := newTPMProvider(t, dir, 104).KEK()
	require.NoError(t, err)

	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = failAfterOpener(t, 104, 2)

	_, err = p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unseal:")
}

// writeSealedBlobFile persists a tpmSealedBlob as the JSON file KEK() expects
// to find at baseDir/name, mirroring generateAndSeal's on-disk format.
func writeSealedBlobFile(t *testing.T, baseDir, name string, blob tpmSealedBlob) {
	t.Helper()
	out, err := json.Marshal(blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, name), out, 0600))
}

// helper: reports whether s contains any of the given substrings.
func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && len(s) >= len(n) {
			for i := 0; i <= len(s)-len(n); i++ {
				if s[i:i+len(n)] == n {
					return true
				}
			}
		}
	}
	return false
}
