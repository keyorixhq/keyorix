package encryption

// FIPS-GCM-NONCE-1 (ENCRYPTION-HARDEN-1 item 3): the service AEAD and the
// key-file wrap moved from cipher.NewGCM with a nonce read from crypto/rand to
// cipher.NewGCMWithRandomNonce, because Go's FIPS 140-3 mode
// (GODEBUG=fips140=only) refuses a caller-supplied GCM nonce. Data at rest must
// not notice. These tests pin both directions:
//
//   - testdata/gcm_legacy_vectors.json was written by the PRE-change code on
//     main 8387d64ed (a throwaway generator calling NewEncryptionService.Encrypt,
//     EncryptWithAAD, EncryptChunked and wrapKey; test keys only). The current
//     code must open every vector, and the wire layout is checked byte by byte.
//   - Output of the current code must open under the pre-change code path,
//     reproduced here as legacyGCMOpen (cipher.NewGCM, nonce passed explicitly).
//   - TestGCM_FIPS140OnlyMode re-runs this test binary with
//     GODEBUG=fips140=only and drives every AEAD path there, legacy vectors
//     included. On the pre-change code NewEncryptionService itself failed.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type legacyGCMVectors struct {
	DEKHex  string `json:"dek_hex"`
	KEKHex  string `json:"kek_hex"`
	Service []struct {
		Name      string          `json:"name"`
		AADHex    *string         `json:"aad_hex"`
		Plaintext string          `json:"plaintext_hex"`
		Encrypted json.RawMessage `json:"encrypted_data"`
	} `json:"service"`
	Chunked struct {
		Plaintext string            `json:"plaintext_hex"`
		Chunks    []json.RawMessage `json:"chunks"`
	} `json:"chunked"`
	Wrapped []struct {
		Plain   string `json:"plain_hex"`
		Wrapped string `json:"wrapped_hex"`
	} `json:"wrapped_keys"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func loadLegacyGCMVectors(t *testing.T) legacyGCMVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/gcm_legacy_vectors.json")
	require.NoError(t, err)
	var v legacyGCMVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Service, "fixture has no service vectors")
	require.NotEmpty(t, v.Chunked.Chunks, "fixture has no chunked vectors")
	require.NotEmpty(t, v.Wrapped, "fixture has no wrapped-key vectors")
	return v
}

// checkLegacyGCMVectors opens every pre-change vector with the current code.
// Shared by the default run and the fips140=only child.
func checkLegacyGCMVectors(t *testing.T) {
	t.Helper()
	v := loadLegacyGCMVectors(t)
	svc, err := NewEncryptionService(mustHex(t, v.DEKHex))
	require.NoError(t, err)

	for _, vec := range v.Service {
		ed, err := DeserializeEncryptedData(vec.Encrypted)
		require.NoError(t, err, vec.Name)
		want := mustHex(t, vec.Plaintext)
		nonce, err := base64.StdEncoding.DecodeString(ed.Metadata.Nonce)
		require.NoError(t, err, vec.Name)
		assert.Len(t, nonce, 12, "%s: stored nonce length", vec.Name)
		assert.Len(t, ed.Data, len(want)+16, "%s: Data must be ciphertext||tag only", vec.Name)

		var got []byte
		if vec.AADHex == nil {
			got, err = svc.Decrypt(ed)
		} else {
			got, err = svc.DecryptWithAAD(ed, mustHex(t, *vec.AADHex))
		}
		require.NoError(t, err, "%s: a ciphertext written by the pre-change code no longer opens", vec.Name)
		assert.True(t, bytes.Equal(want, got), "%s: plaintext mismatch", vec.Name)
	}

	var chunks []*EncryptedData
	for _, raw := range v.Chunked.Chunks {
		ed, err := DeserializeEncryptedData(raw)
		require.NoError(t, err)
		chunks = append(chunks, ed)
	}
	got, err := svc.DecryptChunked(chunks)
	require.NoError(t, err, "pre-change chunked ciphertext no longer opens")
	assert.Equal(t, mustHex(t, v.Chunked.Plaintext), got)

	kek := mustHex(t, v.KEKHex)
	for _, w := range v.Wrapped {
		wrapped, plain := mustHex(t, w.Wrapped), mustHex(t, w.Plain)
		assert.Len(t, wrapped, 12+len(plain)+16, "wrapped key layout is nonce(12)||ciphertext||tag(16)")
		got, err := unwrapKey(wrapped, kek)
		require.NoError(t, err, "a key wrapped by the pre-change code no longer unwraps")
		assert.Equal(t, plain, got)
	}
}

func TestGCMCompat_LegacyVectorsOpen(t *testing.T) {
	checkLegacyGCMVectors(t)
}

// legacyGCMOpen is the pre-change decryption path: cipher.NewGCM with the
// nonce passed in explicitly.
func legacyGCMOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// TestGCMCompat_NewOutputOpensUnderLegacyCode: a binary from before this change
// (a rollback, or an older replica during a rolling upgrade) must still read
// what the current code writes. Random plaintext and AAD lengths, including 0.
func TestGCMCompat_NewOutputOpensUnderLegacyCode(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("the pre-change cipher.NewGCM path is refused under fips140=only by design")
	}
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	svc, err := NewEncryptionService(append([]byte(nil), dek...))
	require.NoError(t, err)

	for i := range 64 {
		pt := make([]byte, i*7%97)
		_, _ = rand.Read(pt)
		aad := make([]byte, i%5*3)
		_, _ = rand.Read(aad)

		ed, err := svc.EncryptWithAAD(pt, "v1", aad)
		require.NoError(t, err)
		nonce, err := base64.StdEncoding.DecodeString(ed.Metadata.Nonce)
		require.NoError(t, err)
		require.Len(t, nonce, 12)
		got, err := legacyGCMOpen(dek, nonce, ed.Data, aad)
		require.NoError(t, err, "pre-change code cannot open a current EncryptWithAAD ciphertext")
		require.True(t, bytes.Equal(pt, got))

		plain, err := svc.Encrypt(pt, "v1")
		require.NoError(t, err)
		nonce, err = base64.StdEncoding.DecodeString(plain.Metadata.Nonce)
		require.NoError(t, err)
		got, err = legacyGCMOpen(dek, nonce, plain.Data, nil)
		require.NoError(t, err, "pre-change code cannot open a current Encrypt ciphertext")
		require.True(t, bytes.Equal(pt, got))

		wrapped, err := wrapKey(pt, dek)
		require.NoError(t, err)
		require.Len(t, wrapped, 12+len(pt)+16)
		got, err = legacyGCMOpen(dek, wrapped[:12], wrapped[12:], nil)
		require.NoError(t, err, "pre-change unwrapKey cannot open a current wrapKey output")
		require.True(t, bytes.Equal(pt, got))
	}
}

// TestGCMCompat_TamperFails: flipping any byte of the nonce, ciphertext or tag,
// or changing the AAD, is refused, for the service and the key wrap.
func TestGCMCompat_TamperFails(t *testing.T) {
	svc, err := NewEncryptionService(bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	pt, aad := []byte("tamper-me"), []byte("1:2:3")
	ed, err := svc.EncryptWithAAD(pt, "v1", aad)
	require.NoError(t, err)

	nonce, err := base64.StdEncoding.DecodeString(ed.Metadata.Nonce)
	require.NoError(t, err)
	for i := range nonce {
		bad := *ed
		n := append([]byte(nil), nonce...)
		n[i] ^= 0x01
		bad.Metadata.Nonce = base64.StdEncoding.EncodeToString(n)
		_, err := svc.DecryptWithAAD(&bad, aad)
		require.Error(t, err, "nonce byte %d flipped", i)
	}
	for i := range ed.Data {
		bad := *ed
		bad.Data = append([]byte(nil), ed.Data...)
		bad.Data[i] ^= 0x80
		_, err := svc.DecryptWithAAD(&bad, aad)
		require.Error(t, err, "ciphertext/tag byte %d flipped", i)
	}
	_, err = svc.DecryptWithAAD(ed, []byte("1:2:4"))
	require.Error(t, err, "wrong AAD accepted")

	short := *ed
	short.Metadata.Nonce = base64.StdEncoding.EncodeToString(nonce[:11])
	_, err = svc.DecryptWithAAD(&short, aad)
	require.ErrorContains(t, err, "invalid nonce length 11")

	kek := bytes.Repeat([]byte{9}, 32)
	wrapped, err := wrapKey(pt, kek)
	require.NoError(t, err)
	for i := range wrapped {
		bad := append([]byte(nil), wrapped...)
		bad[i] ^= 0x01
		_, err := unwrapKey(bad, kek)
		require.Error(t, err, "wrapped byte %d flipped", i)
	}
	_, err = unwrapKey(wrapped[:11], kek)
	require.ErrorContains(t, err, "wrapped key too short")
}

// TestNoCallerSuppliedGCMNonce is the class guard: TestGCM_FIPS140OnlyMode only
// drives the paths it knows about, so a new cipher.NewGCM / NewGCMWithNonceSize
// / NewGCMWithTagSize call (all take the nonce from the caller, all refused by
// fips140=only) anywhere in this package tree's production code fails here.
// Recognised forms: the three constructor names as written in source; an
// aliased crypto/cipher import would slip past it.
func TestNoCallerSuppliedGCMNonce(t *testing.T) {
	forbidden := regexp.MustCompile(`cipher\.NewGCM(WithNonceSize|WithTagSize)?\(`)
	scanned := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking this package's own source
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			if forbidden.MatchString(line) {
				t.Errorf("%s:%d: caller-supplied GCM nonce (refused under GODEBUG=fips140=only); use cipher.NewGCMWithRandomNonce: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, scanned, 10, "scanned too few files: the walk is not looking at this package")
}

const fipsChildEnv = "KEYORIX_GCM_FIPS_CHILD"

// TestGCM_FIPS140OnlyMode re-runs itself with GODEBUG=fips140=only (the setting
// is read at process start, so it needs a child process) and, in the child,
// drives every AEAD path of this package: service Encrypt/Decrypt, the AAD and
// chunked variants, wrapKey/unwrapKey, and the pre-change vectors. Before
// FIPS-GCM-NONCE-1 the child failed at NewEncryptionService ("use of GCM with
// arbitrary IVs is not allowed in FIPS 140-only mode").
func TestGCM_FIPS140OnlyMode(t *testing.T) {
	if os.Getenv(fipsChildEnv) == "1" {
		require.True(t, fips140.Enforced(), "child must run with GODEBUG=fips140=only")
		runFIPSOnlyAEADPaths(t)
		return
	}
	if testing.Short() {
		t.Skip("spawns a child test process")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGCM_FIPS140OnlyMode$", "-test.count=1", "-test.v") // #nosec G204 -- re-runs this test binary
	cmd.Env = append(os.Environ(), fipsChildEnv+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "AEAD paths fail under GODEBUG=fips140=only:\n%s", out)
	require.Contains(t, string(out), "--- PASS: TestGCM_FIPS140OnlyMode", "child did not run the test:\n%s", out)
}

func runFIPSOnlyAEADPaths(t *testing.T) {
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	svc, err := NewEncryptionService(dek)
	require.NoError(t, err, "NewEncryptionService")

	ed, err := svc.Encrypt([]byte("plain"), "v1")
	require.NoError(t, err, "Encrypt")
	got, err := svc.Decrypt(ed)
	require.NoError(t, err, "Decrypt")
	assert.Equal(t, "plain", string(got))

	ed, err = svc.EncryptWithAAD([]byte("with-aad"), "v1", []byte("1:2:3"))
	require.NoError(t, err, "EncryptWithAAD")
	got, err = svc.DecryptWithAAD(ed, []byte("1:2:3"))
	require.NoError(t, err, "DecryptWithAAD")
	assert.Equal(t, "with-aad", string(got))

	chunks, err := svc.EncryptChunked([]byte("chunked-plaintext-under-fips-only"), 8, "v1")
	require.NoError(t, err, "EncryptChunked")
	got, err = svc.DecryptChunked(chunks)
	require.NoError(t, err, "DecryptChunked")
	assert.Equal(t, "chunked-plaintext-under-fips-only", string(got))

	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	wrapped, err := wrapKey(dek, kek)
	require.NoError(t, err, "wrapKey")
	unwrapped, err := unwrapKey(wrapped, kek)
	require.NoError(t, err, "unwrapKey")
	assert.Equal(t, dek, unwrapped)

	checkLegacyGCMVectors(t)

	assert.Equal(t, "Go FIPS 140-3 mode: enforced (GODEBUG=fips140=only)", FIPS140ModeLine())
}

func TestFIPS140ModeLine_Default(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("process runs with GODEBUG=fips140 set; the enforced case is checked in TestGCM_FIPS140OnlyMode")
	}
	assert.Equal(t, "Go FIPS 140-3 mode: off", FIPS140ModeLine())
}
